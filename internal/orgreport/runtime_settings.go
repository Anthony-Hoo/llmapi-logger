package orgreport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
)

// Settings saved from the management UI (doc 23 section 3, "页面上可改的项").
// The configuration file stays the base: a saved section replaces the idle
// gap, the ranked clients and the anomaly thresholds. The time zone and the
// first weekday are read from the file only: they place the boundaries of
// weeks that are already stored.

// EditableSettings are the fields the page edits.
type EditableSettings struct {
	IdleGapSeconds        int      `json:"idle_gap_seconds"`
	RankedClients         []string `json:"ranked_clients"`
	MaxConcurrentRoots    int      `json:"max_concurrent_roots"`
	MaxSingleRequestRoots int      `json:"max_single_request_roots"`
}

// Where the settings in use come from.
const (
	SettingsSourceFile  = "file"
	SettingsSourceSaved = "saved"
)

// SettingsView is GET /api/v1/settings/org-reports.
type SettingsView struct {
	// Source is "saved" when a saved section overrides the file.
	Source    string           `json:"source"`
	UpdatedNS int64            `json:"updated_ns,string,omitempty"`
	Settings  EditableSettings `json:"settings"`
	// File is what the configuration file says, i.e. what a reset returns to.
	File EditableSettings `json:"file"`
	// Timezone and WeekStart are read from the configuration file only.
	Timezone  string `json:"timezone"`
	WeekStart string `json:"week_start"`
}

// ErrInvalidSettings wraps a validation message that names a field and its
// limits.
var ErrInvalidSettings = errors.New("orgreport: invalid settings")

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

func editableOf(section config.OrgReportsConfig) EditableSettings {
	clients := append([]string{}, section.RankedClients...)
	sort.Strings(clients)
	return EditableSettings{
		IdleGapSeconds: section.IdleGapSeconds, RankedClients: clients,
		MaxConcurrentRoots: section.Anomaly.MaxConcurrentRoots, MaxSingleRequestRoots: section.Anomaly.MaxSingleRequestRoots,
	}
}

// overlaySettings returns file with the editable fields replaced. Client keys
// are trimmed; blanks are dropped.
func overlaySettings(file config.OrgReportsConfig, edited EditableSettings) config.OrgReportsConfig {
	out := file
	out.IdleGapSeconds = edited.IdleGapSeconds
	out.RankedClients = make([]string, 0, len(edited.RankedClients))
	for _, client := range edited.RankedClients {
		if client = strings.TrimSpace(client); client != "" {
			out.RankedClients = append(out.RankedClients, client)
		}
	}
	out.Anomaly.MaxConcurrentRoots, out.Anomaly.MaxSingleRequestRoots = edited.MaxConcurrentRoots, edited.MaxSingleRequestRoots
	return out
}

// settingsFor validates a candidate section and converts it, keeping what the
// page cannot edit from the settings in use.
func (service *Service) settingsFor(candidate config.OrgReportsConfig) (Settings, error) {
	if err := config.ValidateOrgReportsRuntime(candidate); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidSettings, err.Error())
	}
	next := service.settingsNow()
	next.IdleGap = time.Duration(candidate.IdleGapSeconds) * time.Second
	next.RankedClients = make(map[string]bool, len(candidate.RankedClients))
	for _, client := range candidate.RankedClients {
		next.RankedClients[client] = true
	}
	next.MaxConcurrentRoots, next.MaxSingleRequestRoots = candidate.Anomaly.MaxConcurrentRoots, candidate.Anomaly.MaxSingleRequestRoots
	return next, nil
}

// readSaved returns the saved section laid over the file and when it was
// saved; 0 when nothing is saved.
func (service *Service) readSaved(ctx context.Context) (config.OrgReportsConfig, int64, error) {
	if service.saved == nil {
		return service.file, 0, nil
	}
	row, err := service.saved.LoadRuntimeSettings(ctx, storage.SettingsOrgReports)
	if errors.Is(err, sql.ErrNoRows) {
		return service.file, 0, nil
	}
	if err != nil {
		return service.file, 0, err
	}
	var edited EditableSettings
	decoder := json.NewDecoder(strings.NewReader(row.Settings))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&edited); err != nil {
		return service.file, 0, err
	}
	return overlaySettings(service.file, edited), row.UpdatedAtNS, nil
}

// loadSavedSettings applies the saved section at startup. One that cannot be
// read or no longer validates is ignored with a warning: the service starts
// on the file's values.
func (service *Service) loadSavedSettings(ctx context.Context) {
	candidate, updatedNS, err := service.readSaved(ctx)
	if err == nil && updatedNS != 0 {
		var next Settings
		if next, err = service.settingsFor(candidate); err == nil {
			service.settings.Store(&next)
		}
	}
	if err != nil {
		service.logger.Warn("saved org report settings ignored", "error_category", "runtime_settings_invalid")
	}
}

func (service *Service) settingsView(effective config.OrgReportsConfig, updatedNS int64) SettingsView {
	public := service.settingsNow().Public()
	view := SettingsView{
		Source: SettingsSourceFile, UpdatedNS: updatedNS, Settings: editableOf(effective), File: editableOf(service.file),
		Timezone: public.Timezone, WeekStart: public.WeekStart,
	}
	if updatedNS != 0 {
		view.Source = SettingsSourceSaved
	}
	return view
}

// EditableSettings returns the settings in use and where they come from.
func (service *Service) EditableSettings(ctx context.Context) (SettingsView, error) {
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	effective, updatedNS, err := service.readSaved(ctx)
	if err == nil && updatedNS != 0 {
		_, err = service.settingsFor(effective)
	}
	if err != nil {
		// The saved section is unusable; the service runs on the file.
		effective, updatedNS = service.file, 0
	}
	return service.settingsView(effective, updatedNS), nil
}

// UpdateSettings validates, saves and applies a change. Weeks that are not
// frozen are computed with the new values at once; a frozen week keeps its
// snapshot until it is regenerated.
func (service *Service) UpdateSettings(ctx context.Context, edited EditableSettings) (SettingsView, error) {
	if service.saved == nil {
		return SettingsView{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	candidate := overlaySettings(service.file, edited)
	next, err := service.settingsFor(candidate)
	if err != nil {
		return SettingsView{}, err
	}
	encoded, err := json.Marshal(editableOf(candidate))
	if err != nil {
		return SettingsView{}, err
	}
	row := storage.RuntimeSettings{Section: storage.SettingsOrgReports, Settings: string(encoded), UpdatedAtNS: service.now().UnixNano()}
	if err := service.saved.SaveRuntimeSettings(ctx, row); err != nil {
		return SettingsView{}, err
	}
	service.applySettings(next)
	service.logger.Info("org report settings saved")
	return service.settingsView(candidate, row.UpdatedAtNS), nil
}

// ResetSettings drops the saved section; the configuration file applies again.
func (service *Service) ResetSettings(ctx context.Context) (SettingsView, error) {
	if service.saved == nil {
		return SettingsView{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	next, err := service.settingsFor(service.file)
	if err != nil {
		return SettingsView{}, err
	}
	if err := service.saved.DeleteRuntimeSettings(ctx, storage.SettingsOrgReports); err != nil {
		return SettingsView{}, err
	}
	service.applySettings(next)
	service.logger.Info("org report settings reset to the configuration file")
	return service.settingsView(service.file, 0), nil
}

// applySettings swaps the settings and drops every cached live week, which
// was computed with the old ones.
func (service *Service) applySettings(next Settings) {
	service.settings.Store(&next)
	service.job.cacheMu.Lock()
	service.job.cache = nil
	service.job.cacheMu.Unlock()
}
