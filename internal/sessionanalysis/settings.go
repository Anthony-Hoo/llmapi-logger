package sessionanalysis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Settings saved from the management UI (doc 24 section 4, "页面上可改的项").
// The configuration file stays the base: a saved section replaces the fields
// below and nothing else. Whether session analysis runs at all, the local-only
// guard of the model address (allow_non_local), what makes a session eligible
// and the pack budget are read from the file only.

// EditableLLM is the model stage as the page edits it. The API key is not
// part of it: it travels separately and is never returned.
type EditableLLM struct {
	Enabled          bool   `json:"enabled"`
	BaseURL          string `json:"base_url"`
	Model            string `json:"model"`
	StructuredOutput string `json:"structured_output"`
	ContextTokens    int    `json:"context_tokens"`
	DisableThinking  bool   `json:"disable_thinking"`
	MaxOutputTokens  int    `json:"max_output_tokens"`
	MaxConcurrency   int    `json:"max_concurrency"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	MaxSessionsRun   int    `json:"max_sessions_per_run"`
}

// EditableSettings are the fields the page edits.
type EditableSettings struct {
	RunAt         string      `json:"run_at"`
	L1SettleHours int         `json:"l1_settle_hours"`
	LLM           EditableLLM `json:"llm"`
}

// Where the model API key in use comes from.
const (
	KeyNone  = "none"  // no key is sent
	KeyFile  = "file"  // the configuration file's key
	KeySaved = "saved" // a key saved from the page
)

// Where the settings in use come from.
const (
	SourceFile  = "file"
	SourceSaved = "saved"
)

// FileOnlySettings are shown read-only: they come from the configuration
// file and the page cannot change them.
type FileOnlySettings struct {
	AllowNonLocal       bool `json:"allow_non_local"`
	SessionIdleMinutes  int  `json:"session_idle_minutes"`
	MinUserTurns        int  `json:"min_user_turns"`
	MinActiveSeconds    int  `json:"min_active_seconds"`
	PackMaxTokens       int  `json:"pack_max_tokens"`
	PromptReserveTokens int  `json:"prompt_reserve_tokens"`
}

// SettingsView is GET /api/v1/settings/session-analysis.
type SettingsView struct {
	// Source is "saved" when a saved section overrides the file.
	Source    string           `json:"source"`
	UpdatedNS int64            `json:"updated_ns,string,omitempty"`
	Settings  EditableSettings `json:"settings"`
	// APIKey says where the key in use comes from; the key itself is never
	// returned.
	APIKey string `json:"api_key"`
	// File is what the configuration file says, i.e. what a reset returns to.
	File       EditableSettings `json:"file"`
	FileAPIKey bool             `json:"file_api_key"`
	FileOnly   FileOnlySettings `json:"file_only"`
	// Running reports a run in progress: a change is picked up by the run
	// after it.
	Running bool `json:"running"`
}

// SettingsUpdate is the body of PUT /api/v1/settings/session-analysis and of
// the connection test. APIKey: absent keeps the key in use, an empty string
// sends none, anything else is saved.
type SettingsUpdate struct {
	EditableSettings
	APIKey *string `json:"api_key,omitempty"`
}

// ErrInvalidSettings wraps a validation message that is safe to show: it
// names a field and its limits, never a secret.
var ErrInvalidSettings = errors.New("sessionanalysis: invalid settings")

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

// savedSection is the JSON stored in runtime_settings.settings.
type savedSection struct {
	EditableSettings
	// APIKey is KeyNone, KeyFile or KeySaved; with KeySaved the key itself is
	// in secret_enc.
	APIKey string `json:"api_key"`
}

func editableOf(analysis config.SessionAnalysisConfig) EditableSettings {
	return EditableSettings{
		RunAt: analysis.RunAt, L1SettleHours: analysis.L1SettleHours,
		LLM: EditableLLM{
			Enabled: analysis.LLM.Enabled, BaseURL: analysis.LLM.BaseURL, Model: analysis.LLM.Model,
			StructuredOutput: analysis.LLM.StructuredOutput, ContextTokens: analysis.LLM.ContextTokens,
			DisableThinking: analysis.LLM.DisableThinking, MaxOutputTokens: analysis.LLM.MaxOutputTokens,
			MaxConcurrency: analysis.LLM.MaxConcurrency, TimeoutSeconds: analysis.LLM.TimeoutSeconds,
			MaxSessionsRun: analysis.LLM.MaxSessionsRun,
		},
	}
}

// overlay returns file with the editable fields and the key replaced.
func overlay(file config.SessionAnalysisConfig, edited EditableSettings, apiKey string) config.SessionAnalysisConfig {
	out := file
	out.RunAt, out.L1SettleHours = strings.TrimSpace(edited.RunAt), edited.L1SettleHours
	llm := edited.LLM
	out.LLM = config.SessionAnalysisLLM{
		Enabled: llm.Enabled, BaseURL: strings.TrimSpace(llm.BaseURL), Model: strings.TrimSpace(llm.Model), APIKey: apiKey,
		// The page never loosens the local-only guard.
		AllowNonLocal:    file.LLM.AllowNonLocal,
		StructuredOutput: llm.StructuredOutput, ContextTokens: llm.ContextTokens, DisableThinking: llm.DisableThinking,
		MaxOutputTokens: llm.MaxOutputTokens, MaxConcurrency: llm.MaxConcurrency, TimeoutSeconds: llm.TimeoutSeconds,
		MaxSessionsRun: llm.MaxSessionsRun,
	}
	return out
}

func settingsKeyAAD() ([]byte, error) {
	return security.AAD("runtime_settings", storage.SettingsSessionAnalysis, "api_key")
}

// validateCandidate applies the configuration file's checks. The model
// fields are checked even while the stage is switched off, so a saved section
// can be switched on later without another edit.
func validateCandidate(candidate config.SessionAnalysisConfig, requireModel bool) error {
	checked := candidate
	if requireModel || strings.TrimSpace(checked.LLM.Model) != "" {
		checked.LLM.Enabled = true
	}
	if err := config.ValidateSessionAnalysisRuntime(checked); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidSettings, err.Error())
	}
	return nil
}

// buildModel returns the client of a validated configuration; a nil
// interface when the stage is off.
func buildModel(candidate config.SessionAnalysisConfig) (Completer, string, error) {
	if !candidate.LLM.Enabled {
		return nil, "", nil
	}
	client, err := NewLLMClient(candidate.LLM, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the model client rejected the address", ErrInvalidSettings)
	}
	return client, client.Model(), nil
}

// LoadEffectiveConfig overlays the saved section, if any, on the file's
// section at startup. A saved section that can no longer be read, decrypted or
// validated against the file is ignored with one warning: the service starts
// on the file's values rather than not at all.
func LoadEffectiveConfig(ctx context.Context, file config.SessionAnalysisConfig, store SettingsStore, cipher security.Cipher, logger *slog.Logger) config.SessionAnalysisConfig {
	effective, _, _, err := loadSaved(ctx, file, store, cipher)
	if err != nil {
		if logger != nil {
			logger.Warn("saved session analysis settings ignored", "error_category", "runtime_settings_invalid")
		}
		return file
	}
	return effective
}

// loadSaved returns the effective configuration, where the key comes from and
// when the section was saved (0: nothing saved, the file applies).
func loadSaved(ctx context.Context, file config.SessionAnalysisConfig, store SettingsStore, cipher security.Cipher) (config.SessionAnalysisConfig, string, int64, error) {
	fileKey := KeyNone
	if file.LLM.APIKey != "" {
		fileKey = KeyFile
	}
	if store == nil {
		return file, fileKey, 0, nil
	}
	row, err := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis)
	if errors.Is(err, sql.ErrNoRows) {
		return file, fileKey, 0, nil
	}
	if err != nil {
		return file, fileKey, 0, err
	}
	var saved savedSection
	decoder := json.NewDecoder(strings.NewReader(row.Settings))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return file, fileKey, 0, err
	}
	apiKey, keySource := "", KeyNone
	switch saved.APIKey {
	case KeyNone:
	case KeyFile:
		apiKey, keySource = file.LLM.APIKey, fileKey
	case KeySaved:
		aad, err := settingsKeyAAD()
		if err != nil {
			return file, fileKey, 0, err
		}
		plaintext, err := cipher.Decrypt(aad, row.SecretEnc)
		if err != nil {
			return file, fileKey, 0, err
		}
		apiKey, keySource = string(plaintext), KeySaved
		clear(plaintext)
	default:
		return file, fileKey, 0, errors.New("sessionanalysis: unknown saved key source")
	}
	effective := overlay(file, saved.EditableSettings, apiKey)
	if err := validateCandidate(effective, false); err != nil {
		return file, fileKey, 0, err
	}
	return effective, keySource, row.UpdatedAtNS, nil
}

// SettingsApplier is the running part a change is handed to: the Runner.
type SettingsApplier interface {
	Apply(configuration config.SessionAnalysisConfig, llm Completer) error
	Running() bool
}

// SettingsService reads and changes the saved section and hands every change
// to the running batch and query service.
type SettingsService struct {
	mu      sync.Mutex
	file    config.SessionAnalysisConfig
	store   SettingsStore
	cipher  security.Cipher
	applier SettingsApplier
	query   *QueryService
	logger  *slog.Logger
	now     func() time.Time
	// probe is replaced in tests.
	probe func(ctx context.Context, candidate config.SessionAnalysisConfig) ProbeResult
}

// NewSettingsService assembles the service. file is the configuration file's
// section, untouched by any saved value. query may be nil.
func NewSettingsService(file config.SessionAnalysisConfig, store SettingsStore, cipher security.Cipher, applier SettingsApplier, query *QueryService, logger *slog.Logger) (*SettingsService, error) {
	if store == nil || cipher == nil || applier == nil {
		return nil, errors.New("sessionanalysis: settings need a store, a cipher and a runner")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SettingsService{file: file, store: store, cipher: cipher, applier: applier, query: query, logger: logger, now: time.Now, probe: probeModel}, nil
}

func (service *SettingsService) view(effective config.SessionAnalysisConfig, keySource string, updatedNS int64) SettingsView {
	view := SettingsView{
		Source: SourceFile, UpdatedNS: updatedNS, Settings: editableOf(effective), APIKey: keySource,
		File: editableOf(service.file), FileAPIKey: service.file.LLM.APIKey != "",
		FileOnly: FileOnlySettings{
			AllowNonLocal: service.file.LLM.AllowNonLocal, SessionIdleMinutes: service.file.SessionIdleMinutes,
			MinUserTurns: service.file.MinUserTurns, MinActiveSeconds: service.file.MinActiveSeconds,
			PackMaxTokens: service.file.Pack.MaxTokens, PromptReserveTokens: config.SessionPromptReserveTokens,
		},
		Running: service.applier.Running(),
	}
	if updatedNS != 0 {
		view.Source = SourceSaved
	}
	return view
}

// Get returns the settings in use.
func (service *SettingsService) Get(ctx context.Context) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	effective, keySource, updatedNS, err := loadSaved(ctx, service.file, service.store, service.cipher)
	if err != nil {
		// The saved section is unusable; the service runs on the file.
		effective, keySource, updatedNS = service.file, KeyNone, 0
		if service.file.LLM.APIKey != "" {
			keySource = KeyFile
		}
	}
	return service.view(effective, keySource, updatedNS), nil
}

// candidate resolves an update against what is in use: the configuration it
// would produce, and where its key comes from.
func (service *SettingsService) candidate(ctx context.Context, update SettingsUpdate) (config.SessionAnalysisConfig, string, error) {
	current, keySource, _, err := loadSaved(ctx, service.file, service.store, service.cipher)
	if err != nil {
		current, keySource = service.file, KeyNone
		if service.file.LLM.APIKey != "" {
			keySource = KeyFile
		}
	}
	apiKey := current.LLM.APIKey
	if update.APIKey != nil {
		apiKey, keySource = *update.APIKey, KeySaved
		if apiKey == "" {
			keySource = KeyNone
		}
	}
	return overlay(service.file, update.EditableSettings, apiKey), keySource, nil
}

// Update validates, saves and applies a change. The saved section overrides
// the configuration file from now on, including after a restart.
func (service *SettingsService) Update(ctx context.Context, update SettingsUpdate) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	candidate, keySource, err := service.candidate(ctx, update)
	if err != nil {
		return SettingsView{}, err
	}
	if err := validateCandidate(candidate, false); err != nil {
		return SettingsView{}, err
	}
	model, modelName, err := buildModel(candidate)
	if err != nil {
		return SettingsView{}, err
	}
	encoded, err := json.Marshal(savedSection{EditableSettings: editableOf(candidate), APIKey: keySource})
	if err != nil {
		return SettingsView{}, err
	}
	row := storage.RuntimeSettings{Section: storage.SettingsSessionAnalysis, Settings: string(encoded), UpdatedAtNS: service.now().UnixNano()}
	if keySource == KeySaved {
		aad, err := settingsKeyAAD()
		if err != nil {
			return SettingsView{}, err
		}
		if row.SecretEnc, err = service.cipher.Encrypt(aad, []byte(candidate.LLM.APIKey)); err != nil {
			return SettingsView{}, err
		}
	}
	if err := service.store.SaveRuntimeSettings(ctx, row); err != nil {
		return SettingsView{}, err
	}
	if err := service.apply(candidate, model, modelName); err != nil {
		return SettingsView{}, err
	}
	// Values are not logged: the address and the model name describe where
	// session content is sent.
	service.logger.Info("session analysis settings saved", "llm_enabled", candidate.LLM.Enabled)
	return service.view(candidate, keySource, row.UpdatedAtNS), nil
}

// Reset drops the saved section; the configuration file applies again.
func (service *SettingsService) Reset(ctx context.Context) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := validateCandidate(service.file, false); err != nil {
		return SettingsView{}, err
	}
	model, modelName, err := buildModel(service.file)
	if err != nil {
		return SettingsView{}, err
	}
	if err := service.store.DeleteRuntimeSettings(ctx, storage.SettingsSessionAnalysis); err != nil {
		return SettingsView{}, err
	}
	if err := service.apply(service.file, model, modelName); err != nil {
		return SettingsView{}, err
	}
	service.logger.Info("session analysis settings reset to the configuration file")
	keySource := KeyNone
	if service.file.LLM.APIKey != "" {
		keySource = KeyFile
	}
	return service.view(service.file, keySource, 0), nil
}

func (service *SettingsService) apply(candidate config.SessionAnalysisConfig, model Completer, modelName string) error {
	if err := service.applier.Apply(candidate, model); err != nil {
		return err
	}
	if service.query != nil {
		service.query.SetModel(modelName)
	}
	return nil
}

// ProbeResult is the outcome of the connection test. It carries no model
// output: only whether the call worked and how the answer ended.
type ProbeResult struct {
	OK bool `json:"ok"`
	// Category of a failure: invalid_address, unreachable, timeout,
	// http_status or bad_response.
	Error      string `json:"error,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
	// Truncated: the answer hit the output limit. Reasoned: the model sent
	// reasoning although thinking was switched off. ValidJSON: the answer was
	// a JSON object.
	Truncated    bool  `json:"truncated"`
	Reasoned     bool  `json:"reasoned"`
	ValidJSON    bool  `json:"valid_json"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

const maxProbeTimeout = 60 * time.Second

// probeModel sends one fixed, synthetic request to the candidate endpoint.
// Nothing from any session is sent.
func probeModel(ctx context.Context, candidate config.SessionAnalysisConfig) ProbeResult {
	llm := candidate.LLM
	llm.Enabled = true
	client, err := NewLLMClient(llm, nil)
	if err != nil {
		return ProbeResult{Error: "invalid_address"}
	}
	timeout := time.Duration(llm.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > maxProbeTimeout {
		timeout = maxProbeTimeout
	}
	callContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	completion, err := client.Complete(callContext, []ChatMessage{
		{Role: "system", Content: `连接测试。只输出 JSON：{"ok": true}`},
		{Role: "user", Content: "ping"},
	}, map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"ok"},
		"properties": map[string]any{"ok": map[string]any{"type": "boolean"}},
	})
	result := ProbeResult{LatencyMS: time.Since(started).Milliseconds()}
	if err != nil {
		var status *StatusError
		switch {
		case errors.As(err, &status):
			result.Error, result.HTTPStatus = "http_status", status.Code
		case errors.Is(err, ErrNonLocalPeer):
			result.Error = "invalid_address"
		case errors.Is(err, context.DeadlineExceeded) || callContext.Err() != nil:
			result.Error = "timeout"
		case strings.Contains(err.Error(), "malformed model response"):
			result.Error = "bad_response"
		default:
			result.Error = "unreachable"
		}
		return result
	}
	var object map[string]any
	result.ValidJSON = json.Unmarshal([]byte(cleanModelOutput(completion.Content)), &object) == nil && object != nil
	result.OK, result.HTTPStatus = true, 200
	result.Truncated, result.Reasoned = completion.Truncated, completion.Reasoned
	result.InputTokens, result.OutputTokens = completion.InputTokens, completion.OutputTokens
	return result
}

// Test checks an update without saving it: the same validation, then one
// synthetic call to the model endpoint.
func (service *SettingsService) Test(ctx context.Context, update SettingsUpdate) (ProbeResult, error) {
	service.mu.Lock()
	candidate, _, err := service.candidate(ctx, update)
	probe := service.probe
	service.mu.Unlock()
	if err != nil {
		return ProbeResult{}, err
	}
	if err := validateCandidate(candidate, true); err != nil {
		return ProbeResult{}, err
	}
	return probe(ctx, candidate), nil
}
