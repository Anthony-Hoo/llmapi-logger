package sessionanalysis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
)

// Entry points that edit the saved analysis settings one field at a time
// (the agent facade, doc/features/25-agent-access.md section 8.2). The web
// route replaces the whole section; these merge only the fields given and
// refuse to write over a change made since the caller read the section. The
// API key is never part of a patch: it changes only through SetAPIKey and
// ClearAPIKey.
//
// The version of the section is SettingsView.UpdatedNS: the time the saved
// row was written, in Unix nanoseconds, and 0 while the configuration file
// applies (nothing saved, or a saved row that can no longer be used). Every
// save, a key change included, stamps a value above the previous one.

// AnyVersion makes a Check… entry skip the version comparison. The writing
// entries never accept it, because no section has a negative version.
const AnyVersion int64 = -1

// ErrVersionConflict means the section changed since the caller read the
// version it passed. Nothing was written.
var ErrVersionConflict = errors.New("sessionanalysis: settings changed since they were read")

// Version returns the section's version (UpdatedNS; 0 for the file).
func (view SettingsView) Version() int64 { return view.UpdatedNS }

// SettingsError is an ErrInvalidSettings failure that names the field, as
// the agent facade's field path ("run_at", "llm.max_concurrency"; "" when
// the failure concerns a value the page cannot edit). Message is the safe
// sentence the error has always carried (it never contains the API key) and
// Error() is unchanged, so SettingsMessage and the web mapping see no
// difference.
//
// Reason is a stable code of what is wrong (contract section 0.1 item 133):
// required, invalid_format, out_of_range, not_allowed_value (Allowed then
// lists the accepted values), not_local_address or invalid_value.
type SettingsError struct {
	Field   string
	Message string
	Reason  string
	Allowed []string
}

func (err *SettingsError) Error() string { return ErrInvalidSettings.Error() + ": " + err.Message }

// Unwrap makes errors.Is(err, ErrInvalidSettings) hold.
func (err *SettingsError) Unwrap() error { return ErrInvalidSettings }

// editableFields are the fields of EditableSettings, by configuration path.
var editableFields = map[string]bool{
	"run_at": true, "l1_settle_hours": true, "llm.enabled": true, "llm.base_url": true, "llm.model": true,
	"llm.structured_output": true, "llm.context_tokens": true, "llm.disable_thinking": true, "llm.max_output_tokens": true,
	"llm.max_concurrency": true, "llm.timeout_seconds": true, "llm.max_sessions_per_run": true, "llm.api_key": true,
}

// settingsError reads the field from the message: internal/config only
// returns text, which starts with the configuration path it checked.
func settingsError(message string) *SettingsError {
	failure := &SettingsError{Message: message, Reason: settingsReason(message)}
	if failure.Reason == ReasonNotAllowedValue && strings.HasPrefix(message, "session_analysis.llm.structured_output ") {
		failure.Allowed = append([]string{}, StructuredOutputs...)
	}
	switch {
	case message == "the model client rejected the address":
		failure.Field = "llm.base_url"
	case strings.HasPrefix(message, "session_analysis.pack.max_tokens + "):
		// The context budget: of the three terms only the context size and
		// the output limit are editable; the context size is the budget.
		failure.Field = "llm.context_tokens"
	case strings.HasPrefix(message, "session_analysis."):
		path, _, _ := strings.Cut(strings.TrimPrefix(message, "session_analysis."), " ")
		if editableFields[path] {
			failure.Field = path
		}
	}
	return failure
}

// Reasons of a SettingsError and a LabelError.
const (
	ReasonRequired        = "required"
	ReasonInvalidFormat   = "invalid_format"
	ReasonOutOfRange      = "out_of_range"
	ReasonNotAllowedValue = "not_allowed_value"
	ReasonNotLocalAddress = "not_local_address"
	ReasonInvalidValue    = "invalid_value"
)

// StructuredOutputs are the values llm.structured_output accepts.
var StructuredOutputs = []string{"json_schema", "json_object", "prompt"}

// settingsReason classifies a validation message of internal/config, which
// only returns text.
func settingsReason(message string) string {
	switch {
	case strings.Contains(message, " is required"), strings.Contains(message, "must not be empty"):
		return ReasonRequired
	case strings.Contains(message, "must be between"), strings.Contains(message, "exceeds llm.context_tokens"):
		return ReasonOutOfRange
	case strings.Contains(message, "structured_output must be"):
		return ReasonNotAllowedValue
	case strings.Contains(message, "must point to localhost"):
		return ReasonNotLocalAddress
	case strings.Contains(message, "must be HH:MM"), strings.Contains(message, "must be an http(s) URL"),
		strings.Contains(message, "must not contain line breaks"), message == "the model client rejected the address":
		return ReasonInvalidFormat
	}
	return ReasonInvalidValue
}

// LLMPatch names the model-stage fields to change; nil keeps the value.
// It has no API key field: decoding {"api_key": …} into it with
// DisallowUnknownFields fails.
type LLMPatch struct {
	Enabled          *bool   `json:"enabled,omitempty"`
	BaseURL          *string `json:"base_url,omitempty"`
	Model            *string `json:"model,omitempty"`
	StructuredOutput *string `json:"structured_output,omitempty"`
	ContextTokens    *int    `json:"context_tokens,omitempty"`
	DisableThinking  *bool   `json:"disable_thinking,omitempty"`
	MaxOutputTokens  *int    `json:"max_output_tokens,omitempty"`
	MaxConcurrency   *int    `json:"max_concurrency,omitempty"`
	TimeoutSeconds   *int    `json:"timeout_seconds,omitempty"`
	MaxSessionsRun   *int    `json:"max_sessions_per_run,omitempty"`
}

// SettingsPatch names the fields to change; nil keeps the value. run_at,
// llm.base_url and llm.model are trimmed, as the page does (overlay trims
// them for the web route too).
type SettingsPatch struct {
	RunAt         *string  `json:"run_at,omitempty"`
	L1SettleHours *int     `json:"l1_settle_hours,omitempty"`
	LLM           LLMPatch `json:"llm"`
}

// SettingsDiff is what a settings write would do. Version is the version
// the section had; Changed lists the changed field paths ("llm.model").
// It never contains the key; KeySource says where the key in use comes
// from, and a patch keeps it.
type SettingsDiff struct {
	Version   int64            `json:"version"`
	Before    EditableSettings `json:"before"`
	After     EditableSettings `json:"after"`
	Changed   []string         `json:"changed"`
	KeySource string           `json:"api_key"`
	// BeforeKeySource is where the key in use comes from before the change;
	// set by CheckReset, whose KeySource is the key after it.
	BeforeKeySource string `json:"api_key_before,omitempty"`
	// Stored reports, for CheckReset, that a saved section is stored, even one
	// that no longer decodes and so leaves version 0: resetting deletes it.
	Stored bool `json:"stored,omitempty"`
}

// CheckPatch runs every check Patch runs (the candidate validation and the
// model client's address check), without saving or applying anything.
// expectedVersion may be AnyVersion.
func (service *SettingsService) CheckPatch(ctx context.Context, expectedVersion int64, patch SettingsPatch) (SettingsDiff, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	diff, update, err := service.preparePatch(ctx, expectedVersion, patch, false)
	if err != nil {
		return SettingsDiff{}, err
	}
	candidate, _, _, err := service.candidate(ctx, update, false)
	if err != nil {
		return SettingsDiff{}, err
	}
	if err := validateCandidate(candidate, false); err != nil {
		return SettingsDiff{}, err
	}
	if _, _, err := buildModel(candidate); err != nil {
		return SettingsDiff{}, err
	}
	diff.After = editableOf(candidate)
	diff.Changed = changedSettings(diff.Before, diff.After)
	return diff, nil
}

// Patch merges patch into the section in use and saves it, only when the
// section's version still equals expectedVersion (0: the file applies);
// otherwise ErrVersionConflict and nothing is written. It goes through
// Update's validation, save and apply with the key "absent", i.e. kept.
func (service *SettingsService) Patch(ctx context.Context, expectedVersion int64, patch SettingsPatch) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	_, update, err := service.preparePatch(ctx, exact(expectedVersion), patch, true)
	if err != nil {
		return SettingsView{}, err
	}
	return service.update(ctx, update)
}

// CheckReset reports what ResetIfVersion would do. expectedVersion may be
// AnyVersion.
func (service *SettingsService) CheckReset(ctx context.Context, expectedVersion int64) (SettingsDiff, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	current, beforeKey, version := service.current(ctx)
	if expectedVersion != AnyVersion && version != expectedVersion {
		return SettingsDiff{}, ErrVersionConflict
	}
	if err := validateCandidate(service.file, false); err != nil {
		return SettingsDiff{}, err
	}
	if _, _, err := buildModel(service.file); err != nil {
		return SettingsDiff{}, err
	}
	fileKey := KeyNone
	if service.file.LLM.APIKey != "" {
		fileKey = KeyFile
	}
	before, after := editableOf(current), editableOf(service.file)
	return SettingsDiff{Version: version, Before: before, After: after, Changed: changedSettings(before, after), KeySource: fileKey, BeforeKeySource: beforeKey,
		Stored: version != 0 || service.savedRowStored(ctx)}, nil
}

// savedRowStored reports whether a saved section row exists at all, usable or
// not. A read failure counts as stored: only a missing row is known to leave
// nothing to reset.
func (service *SettingsService) savedRowStored(ctx context.Context) bool {
	if service.store == nil {
		return false
	}
	_, err := service.store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis)
	return !errors.Is(err, sql.ErrNoRows)
}

// ResetIfVersion drops the saved section only when its version still equals
// expectedVersion.
func (service *SettingsService) ResetIfVersion(ctx context.Context, expectedVersion int64) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	_, _, version, err := service.currentForWrite(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	if version != exact(expectedVersion) {
		return SettingsView{}, ErrVersionConflict
	}
	return service.reset(ctx)
}

// SetAPIKey saves a new model API key and changes nothing else: the settings
// in use are resubmitted as they are, inside the service lock, exactly as the
// page does when only the key field is filled in. The key is never returned
// (the view says KeySaved) and never logged. An empty key is refused; use
// ClearAPIKey.
func (service *SettingsService) SetAPIKey(ctx context.Context, key string) (SettingsView, error) {
	if key == "" {
		return SettingsView{}, &SettingsError{Field: "llm.api_key", Message: "session_analysis.llm.api_key must not be empty", Reason: ReasonRequired}
	}
	return service.replaceKey(ctx, key)
}

// ClearAPIKey stops sending a key and changes nothing else: the same as the
// page's empty key field (the view then says KeyNone; it does not fall back
// to the configuration file's key, which only Reset restores).
func (service *SettingsService) ClearAPIKey(ctx context.Context) (SettingsView, error) {
	return service.replaceKey(ctx, "")
}

// CheckClearAPIKey reports what ClearAPIKeyIfVersion would do: the section's
// version and where the key in use comes from (KeySource); Before and After
// are the settings, which a clear keeps. expectedVersion may be AnyVersion.
func (service *SettingsService) CheckClearAPIKey(ctx context.Context, expectedVersion int64) (SettingsDiff, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	current, keySource, version := service.current(ctx)
	if expectedVersion != AnyVersion && version != expectedVersion {
		return SettingsDiff{}, ErrVersionConflict
	}
	settings := editableOf(current)
	return SettingsDiff{Version: version, Before: settings, After: settings, Changed: []string{}, KeySource: keySource}, nil
}

// ClearAPIKeyIfVersion is ClearAPIKey only while the section's version still
// equals expectedVersion; otherwise ErrVersionConflict and nothing is
// written.
func (service *SettingsService) ClearAPIKeyIfVersion(ctx context.Context, expectedVersion int64) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	current, _, version, err := service.currentForWrite(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	if version != exact(expectedVersion) {
		return SettingsView{}, ErrVersionConflict
	}
	empty := ""
	return service.update(ctx, SettingsUpdate{EditableSettings: editableOf(current), APIKey: &empty})
}

func (service *SettingsService) replaceKey(ctx context.Context, key string) (SettingsView, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	// A key write resubmits the settings in use; it must never start from the
	// file's values because the saved row could not be read.
	current, _, _, err := service.currentForWrite(ctx)
	if err != nil {
		return SettingsView{}, err
	}
	return service.update(ctx, SettingsUpdate{EditableSettings: editableOf(current), APIKey: &key})
}

func exact(version int64) int64 {
	if version < 0 {
		return -2
	}
	return version
}

// preparePatch merges a patch into the section in use. For a write a store
// read failure is an error rather than the file. The caller holds mu.
func (service *SettingsService) preparePatch(ctx context.Context, expectedVersion int64, patch SettingsPatch, forWrite bool) (SettingsDiff, SettingsUpdate, error) {
	current, keySource, version, err := service.currentFor(ctx, forWrite)
	if err != nil {
		return SettingsDiff{}, SettingsUpdate{}, err
	}
	if expectedVersion != AnyVersion && version != expectedVersion {
		return SettingsDiff{}, SettingsUpdate{}, ErrVersionConflict
	}
	before := editableOf(current)
	edited := mergeSettingsPatch(before, patch)
	return SettingsDiff{Version: version, Before: before, After: edited, KeySource: keySource}, SettingsUpdate{EditableSettings: edited}, nil
}

// mergeSettingsPatch returns before with the patch's fields set and run_at,
// llm.base_url and llm.model trimmed, as the page does.
func mergeSettingsPatch(before EditableSettings, patch SettingsPatch) EditableSettings {
	edited := before
	if patch.RunAt != nil {
		edited.RunAt = *patch.RunAt
	}
	if patch.L1SettleHours != nil {
		edited.L1SettleHours = *patch.L1SettleHours
	}
	llm := patch.LLM
	setBool(&edited.LLM.Enabled, llm.Enabled)
	setString(&edited.LLM.BaseURL, llm.BaseURL)
	setString(&edited.LLM.Model, llm.Model)
	setString(&edited.LLM.StructuredOutput, llm.StructuredOutput)
	setInt(&edited.LLM.ContextTokens, llm.ContextTokens)
	setBool(&edited.LLM.DisableThinking, llm.DisableThinking)
	setInt(&edited.LLM.MaxOutputTokens, llm.MaxOutputTokens)
	setInt(&edited.LLM.MaxConcurrency, llm.MaxConcurrency)
	setInt(&edited.LLM.TimeoutSeconds, llm.TimeoutSeconds)
	setInt(&edited.LLM.MaxSessionsRun, llm.MaxSessionsRun)
	edited.RunAt, edited.LLM.BaseURL, edited.LLM.Model = strings.TrimSpace(edited.RunAt), strings.TrimSpace(edited.LLM.BaseURL), strings.TrimSpace(edited.LLM.Model)
	return edited
}

// ModelTargetFields are the fields that decide where a model request is
// sent: the address, and the guard that lets it leave the local network
// (file-only today, so no patch can change it, but compared all the same).
var ModelTargetFields = []string{"llm.base_url", "llm.allow_non_local"}

// TargetChange names the first of ModelTargetFields whose value differs
// between two configurations, "" when they send to the same place.
func TargetChange(before, after config.SessionAnalysisConfig) string {
	switch {
	case strings.TrimSpace(before.LLM.BaseURL) != strings.TrimSpace(after.LLM.BaseURL):
		return "llm.base_url"
	case before.LLM.AllowNonLocal != after.LLM.AllowNonLocal:
		return "llm.allow_non_local"
	}
	return ""
}

// KeyTargetError refuses a connection test that would send the key in use
// (the saved key or the configuration file's) to a destination that is not
// the one in effect. Field is the first differing field of
// ModelTargetFields. Nothing was sent.
type KeyTargetError struct {
	Field string
}

func (err *KeyTargetError) Error() string {
	return "sessionanalysis: the key in use is not sent to an address that is not in effect"
}

// TestPatch is the connection test of the agent facade: the settings in use
// with patch merged in (nothing saved), probed with key or, when key is nil,
// with the key in use. The key in use only goes to the destination in
// effect: when the merged settings would send the request elsewhere and the
// caller brought no key of its own, it refuses with *KeyTargetError before
// any request is made. The comparison and the probe's configuration come
// from one read under the service lock.
func (service *SettingsService) TestPatch(ctx context.Context, patch SettingsPatch, key *string) (ProbeResult, error) {
	service.mu.Lock()
	current, _, _ := service.current(ctx)
	edited := mergeSettingsPatch(editableOf(current), patch)
	apiKey := current.LLM.APIKey
	if key != nil {
		apiKey = *key
	}
	candidate := overlay(service.file, edited, apiKey)
	if key == nil && current.LLM.APIKey != "" {
		if field := TargetChange(current, candidate); field != "" {
			service.mu.Unlock()
			return ProbeResult{}, &KeyTargetError{Field: field}
		}
	}
	probe := service.probe
	service.mu.Unlock()
	if err := validateCandidate(candidate, true); err != nil {
		return ProbeResult{}, err
	}
	return probe(ctx, candidate), nil
}

func setBool(target *bool, value *bool) {
	if value != nil {
		*target = *value
	}
}

func setString(target *string, value *string) {
	if value != nil {
		*target = *value
	}
}

func setInt(target *int, value *int) {
	if value != nil {
		*target = *value
	}
}

func changedSettings(before, after EditableSettings) []string {
	changed := []string{}
	add := func(field string, differs bool) {
		if differs {
			changed = append(changed, field)
		}
	}
	add("run_at", before.RunAt != after.RunAt)
	add("l1_settle_hours", before.L1SettleHours != after.L1SettleHours)
	add("llm.enabled", before.LLM.Enabled != after.LLM.Enabled)
	add("llm.base_url", before.LLM.BaseURL != after.LLM.BaseURL)
	add("llm.model", before.LLM.Model != after.LLM.Model)
	add("llm.structured_output", before.LLM.StructuredOutput != after.LLM.StructuredOutput)
	add("llm.context_tokens", before.LLM.ContextTokens != after.LLM.ContextTokens)
	add("llm.disable_thinking", before.LLM.DisableThinking != after.LLM.DisableThinking)
	add("llm.max_output_tokens", before.LLM.MaxOutputTokens != after.LLM.MaxOutputTokens)
	add("llm.max_concurrency", before.LLM.MaxConcurrency != after.LLM.MaxConcurrency)
	add("llm.timeout_seconds", before.LLM.TimeoutSeconds != after.LLM.TimeoutSeconds)
	add("llm.max_sessions_per_run", before.LLM.MaxSessionsRun != after.LLM.MaxSessionsRun)
	return changed
}

// LabelError says which calibration label failed and which of its fields.
// Index is the label's position (-1 when the list itself is wrong), Field
// the JSON name ("session_id", "task_type", …, "friction"; "labels" for the
// count). It unwraps to the error Calibrate returns for the same input, and
// its text is that error's. Reason is out_of_range (the count), invalid_format
// (the session id) or not_allowed_value, with Allowed the field's values.
type LabelError struct {
	Index   int
	Field   string
	Err     error
	Reason  string
	Allowed []string
}

func (err *LabelError) Error() string { return err.Err.Error() }

// Unwrap returns Calibrate's error.
func (err *LabelError) Unwrap() error { return err.Err }

// ValidateCalibrationLabels checks labels exactly as Calibrate does before
// it compares them with stored facets: between 1 and 1000 labels, each a
// 64-hex session id and enum values from the vocabulary. It reads nothing
// and writes nothing; whether a facet exists is decided by Calibrate.
func ValidateCalibrationLabels(labels []CalibrationLabel) error {
	if err := ValidateCalibrationLabelCount(len(labels)); err != nil {
		return err
	}
	for index, label := range labels {
		if _, field, err := checkCalibrationLabel(label); err != nil {
			failure := &LabelError{Index: index, Field: field, Err: err, Reason: ReasonNotAllowedValue, Allowed: LabelValues(field)}
			if field == "session_id" {
				failure.Reason, failure.Allowed = ReasonInvalidFormat, nil
			}
			return failure
		}
	}
	return nil
}

// ValidateCalibrationLabelCount is ValidateCalibrationLabels' check of the
// number of labels alone, so a caller can refuse an over-long list before
// decoding its elements.
func ValidateCalibrationLabelCount(count int) error {
	if count == 0 || count > MaxCalibrationLabels {
		return &LabelError{Index: -1, Field: "labels", Err: invalid(fmt.Sprintf("between 1 and %d labels are required", MaxCalibrationLabels)), Reason: ReasonOutOfRange}
	}
	return nil
}

// LabelFields are the fields of a calibration label other than session_id,
// in the order the documentation lists them.
var LabelFields = []string{"task_type", "outcome", "collaboration", "work_relevance", "friction"}

// LabelValues returns the values a calibration label field accepts (for
// friction, the values of its list), nil for another field.
func LabelValues(field string) []string {
	switch field {
	case "task_type", "outcome", "collaboration", "work_relevance":
		return append([]string{}, enumFor(field)...)
	case "friction":
		return append([]string{}, FrictionKinds...)
	}
	return nil
}

// CalibrationAvailable reports Calibrate's first condition: the model stage
// is enabled and facets can be stored. Calibrate refuses otherwise.
func (service *QueryService) CalibrationAvailable() bool {
	return service != nil && service.facets != nil && service.modelName() != ""
}

// RunState is what TriggerRun depends on and what a caller about to trigger
// a run should know, read without a time range.
type RunState struct {
	// Available is false when no runner is attached: TriggerRun then fails.
	Available bool
	// Running reports a run in progress: TriggerRun then fails with
	// ErrRunInProgress.
	Running bool
	// LastRun is the latest batch run, nil when there has been none.
	LastRun *RunSummary
}

// RunState reads the runner state and the latest run. It starts nothing.
func (service *QueryService) RunState(ctx context.Context) (RunState, error) {
	state := RunState{Available: service.trigger != nil}
	if service.trigger != nil {
		state.Running = service.trigger.Running()
	}
	last, err := service.lastRun(ctx)
	if err != nil {
		return RunState{}, err
	}
	state.LastRun = last
	return state, nil
}
