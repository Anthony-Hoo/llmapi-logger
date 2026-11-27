package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/storage"
)

// The capture setting saved from the management UI (design H.3): how many
// times the unified write path retries a CommitAudit that failed with a
// retryable error. The configuration file's audit.commit_retries stays the
// base; a saved section overrides it. The value in use lives in the
// Manager's atomic (SetCommitRetries), so no request reads the store for it.

// CaptureEditableSettings are the fields the page edits.
type CaptureEditableSettings struct {
	CommitRetries int `json:"commit_retries"`
}

// Where the capture setting in use comes from.
const (
	CaptureSettingsSourceFile  = "file"
	CaptureSettingsSourceSaved = "saved"
)

// CaptureSettingsView is GET /api/v1/settings/audit-capture.
type CaptureSettingsView struct {
	// Source is "saved" when a saved section overrides the file.
	Source    string                  `json:"source"`
	UpdatedNS int64                   `json:"updated_ns,string,omitempty"`
	Settings  CaptureEditableSettings `json:"settings"`
	// File is what the configuration file says, i.e. what a reset returns to.
	File CaptureEditableSettings `json:"file"`
	// WritePath is audit.write_path from the configuration file, shown
	// read-only: the legacy path does not use the retry count.
	WritePath string `json:"write_path"`
}

// ErrInvalidSettings wraps a validation message that names the field and its
// limits.
var ErrInvalidSettings = errors.New("audit: invalid capture settings")

// ErrSettingsUnavailable wraps a failure to read the saved section from the
// store (not a missing row, nor a row that no longer decodes or validates),
// or the absence of a store. Reads then answer with the configuration file;
// every write refuses with it and saves nothing.
var ErrSettingsUnavailable = errors.New("audit: saved capture settings could not be read")

// SettingsMessage returns the field message of an ErrInvalidSettings error,
// and "" for any other error.
func SettingsMessage(err error) string {
	if !errors.Is(err, ErrInvalidSettings) {
		return ""
	}
	return strings.TrimPrefix(err.Error(), ErrInvalidSettings.Error()+": ")
}

// SettingsStore persists saved sections.
type SettingsStore interface {
	LoadRuntimeSettings(ctx context.Context, section string) (storage.RuntimeSettings, error)
	SaveRuntimeSettings(ctx context.Context, row storage.RuntimeSettings) error
	DeleteRuntimeSettings(ctx context.Context, section string) error
}

// CommitRetrySetter receives the retry count in use: the Manager.
type CommitRetrySetter interface {
	SetCommitRetries(int)
}

// CaptureSettingsOptions assemble a CaptureSettings.
type CaptureSettingsOptions struct {
	// FileRetries is audit.commit_retries from the configuration file.
	FileRetries int
	// WritePath is audit.write_path from the configuration file.
	WritePath string
	// Store is nil when the audit store could not be opened: reads answer
	// with the file, writes refuse with ErrSettingsUnavailable.
	Store SettingsStore
	// Manager receives the value in use at start, on save and on reset.
	Manager CommitRetrySetter
	Logger  *slog.Logger
	// Now replaces the clock of the version stamps; nil is time.Now.
	Now func() time.Time
}

// CaptureSettings reads and changes the saved capture section and hands the
// value in use to the Manager.
type CaptureSettings struct {
	settingsMu sync.Mutex
	file       CaptureEditableSettings
	writePath  string
	saved      SettingsStore
	manager    CommitRetrySetter
	logger     *slog.Logger
	now        func() time.Time
	// settingsNS is the highest version this service has stored or read,
	// guarded by settingsMu; see saveSettings.
	settingsNS int64
}

// NewCaptureSettings assembles the service and applies the saved section, if
// any, to the Manager. A saved section that cannot be read or no longer
// validates is ignored with a warning: the file's value applies.
func NewCaptureSettings(ctx context.Context, options CaptureSettingsOptions) (*CaptureSettings, error) {
	if err := validateCaptureSettings(CaptureEditableSettings{CommitRetries: options.FileRetries}); err != nil {
		return nil, err
	}
	if options.Manager == nil {
		return nil, errors.New("audit: capture settings need a manager")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	service := &CaptureSettings{
		file: CaptureEditableSettings{CommitRetries: options.FileRetries}, writePath: options.WritePath,
		saved: options.Store, manager: options.Manager, logger: options.Logger, now: options.Now,
	}
	service.loadSavedSettings(ctx)
	return service, nil
}

func validateCaptureSettings(settings CaptureEditableSettings) error {
	if settings.CommitRetries < 0 || settings.CommitRetries > MaxCommitRetries {
		return fmt.Errorf("%w: audit.commit_retries must be between 0 and %d", ErrInvalidSettings, MaxCommitRetries)
	}
	return nil
}

// readSaved returns the saved section and when it was saved; the file and 0
// when nothing is saved.
func (service *CaptureSettings) readSaved(ctx context.Context) (CaptureEditableSettings, int64, error) {
	if service.saved == nil {
		return service.file, 0, fmt.Errorf("%w: no store", ErrSettingsUnavailable)
	}
	row, err := service.saved.LoadRuntimeSettings(ctx, storage.SettingsAuditCapture)
	if errors.Is(err, sql.ErrNoRows) {
		return service.file, 0, nil
	}
	if err != nil {
		return service.file, 0, fmt.Errorf("%w: %w", ErrSettingsUnavailable, err)
	}
	var saved struct {
		CommitRetries *int `json:"commit_retries"`
	}
	decoder := json.NewDecoder(strings.NewReader(row.Settings))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return service.file, 0, err
	}
	if saved.CommitRetries == nil {
		return service.file, 0, errors.New("audit: saved capture settings lack commit_retries")
	}
	edited := CaptureEditableSettings{CommitRetries: *saved.CommitRetries}
	if err := validateCaptureSettings(edited); err != nil {
		return service.file, 0, err
	}
	return edited, row.UpdatedAtNS, nil
}

// loadSavedSettings applies the saved section at startup.
func (service *CaptureSettings) loadSavedSettings(ctx context.Context) {
	effective, updatedNS, err := service.readSaved(ctx)
	switch {
	case err == nil:
		service.settingsNS = updatedNS
	case service.saved == nil:
		// No store at all: the audit storage is unavailable, which is logged
		// where it is opened.
		effective = service.file
	default:
		effective = service.file
		service.logger.Warn("saved audit capture settings ignored", "error_category", "runtime_settings_invalid")
	}
	service.manager.SetCommitRetries(effective.CommitRetries)
}

func (service *CaptureSettings) view(effective CaptureEditableSettings, updatedNS int64) CaptureSettingsView {
	view := CaptureSettingsView{
		Source: CaptureSettingsSourceFile, UpdatedNS: updatedNS, Settings: effective, File: service.file, WritePath: service.writePath,
	}
	if updatedNS != 0 {
		view.Source = CaptureSettingsSourceSaved
	}
	return view
}

// currentFor returns the section in use and its version (0 when the file
// applies). For a read (write false) a store read failure falls back to the
// file; for a write it fails with ErrSettingsUnavailable. A row that was read
// but cannot be used is the file-applies state for both and stays writable.
// The caller holds settingsMu.
func (service *CaptureSettings) currentFor(ctx context.Context, write bool) (CaptureEditableSettings, int64, error) {
	effective, updatedNS, err := service.readSaved(ctx)
	if write && errors.Is(err, ErrSettingsUnavailable) {
		return CaptureEditableSettings{}, 0, err
	}
	if err != nil {
		effective, updatedNS = service.file, 0
	}
	return effective, updatedNS, nil
}

// Get returns the setting in use and where it comes from.
func (service *CaptureSettings) Get(ctx context.Context) (CaptureSettingsView, error) {
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	effective, updatedNS, _ := service.currentFor(ctx, false)
	return service.view(effective, updatedNS), nil
}

// Update validates, saves and applies a change. Commits that start afterwards
// retry as many times as it says; no restart is needed.
func (service *CaptureSettings) Update(ctx context.Context, edited CaptureEditableSettings) (CaptureSettingsView, error) {
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	_, replaced, err := service.currentFor(ctx, true)
	if err != nil {
		return CaptureSettingsView{}, err
	}
	if err := validateCaptureSettings(edited); err != nil {
		return CaptureSettingsView{}, err
	}
	encoded, err := json.Marshal(edited)
	if err != nil {
		return CaptureSettingsView{}, err
	}
	// The clock, raised above every version this service stored or read and
	// above the one replaced, so two successive saves never share a version.
	version := max(service.now().UnixNano(), service.settingsNS+1, replaced+1)
	row := storage.RuntimeSettings{Section: storage.SettingsAuditCapture, Settings: string(encoded), UpdatedAtNS: version}
	if err := service.saved.SaveRuntimeSettings(ctx, row); err != nil {
		return CaptureSettingsView{}, err
	}
	service.settingsNS = version
	service.manager.SetCommitRetries(edited.CommitRetries)
	service.logger.Info("audit capture settings saved", "commit_retries", edited.CommitRetries)
	return service.view(edited, version), nil
}

// Reset drops the saved section; the configuration file applies again.
func (service *CaptureSettings) Reset(ctx context.Context) (CaptureSettingsView, error) {
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	if _, _, err := service.currentFor(ctx, true); err != nil {
		return CaptureSettingsView{}, err
	}
	if err := service.saved.DeleteRuntimeSettings(ctx, storage.SettingsAuditCapture); err != nil {
		return CaptureSettingsView{}, err
	}
	service.manager.SetCommitRetries(service.file.CommitRetries)
	service.logger.Info("audit capture settings reset to the configuration file", "commit_retries", service.file.CommitRetries)
	return service.view(service.file, 0), nil
}
