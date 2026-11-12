package sessionanalysis

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
)

// settingsMemory is an in-memory SettingsStore.
type settingsMemory struct {
	mu   sync.Mutex
	rows map[string]storage.RuntimeSettings
	fail error
}

func (store *settingsMemory) LoadRuntimeSettings(_ context.Context, section string) (storage.RuntimeSettings, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fail != nil {
		return storage.RuntimeSettings{}, store.fail
	}
	row, ok := store.rows[section]
	if !ok {
		return storage.RuntimeSettings{}, sql.ErrNoRows
	}
	return row, nil
}

func (store *settingsMemory) SaveRuntimeSettings(_ context.Context, row storage.RuntimeSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.rows == nil {
		store.rows = map[string]storage.RuntimeSettings{}
	}
	store.rows[row.Section] = row
	return nil
}

func (store *settingsMemory) DeleteRuntimeSettings(_ context.Context, section string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.rows, section)
	return nil
}

// recordingApplier records what a settings change hands to the runner.
type recordingApplier struct {
	configs []config.SessionAnalysisConfig
	models  []Completer
	running bool
}

func (applier *recordingApplier) Apply(configuration config.SessionAnalysisConfig, llm Completer) error {
	applier.configs = append(applier.configs, configuration)
	applier.models = append(applier.models, llm)
	return nil
}

func (applier *recordingApplier) Running() bool { return applier.running }

// fileSection is a configuration file with the model stage on and a key.
func fileSection() config.SessionAnalysisConfig {
	return config.SessionAnalysisConfig{
		Enabled: true, RunAt: "02:00", SessionIdleMinutes: 120, L1SettleHours: 24, MinUserTurns: 2, MinActiveSeconds: 60,
		Pack: config.SessionAnalysisPack{MaxTokens: 6000},
		LLM: config.SessionAnalysisLLM{
			Enabled: true, BaseURL: "http://127.0.0.1:11434/v1", Model: "file-model", APIKey: "file-key-0001", StructuredOutput: "json_schema",
			ContextTokens: 16384, DisableThinking: true, MaxOutputTokens: 1500, MaxConcurrency: 1, TimeoutSeconds: 120, MaxSessionsRun: 300,
		},
	}
}

func settingsFixture(t *testing.T) (*SettingsService, *settingsMemory, *recordingApplier, *QueryService) {
	t.Helper()
	store, applier := &settingsMemory{}, &recordingApplier{}
	query, err := NewQueryService(newMemoryStore(), nil, testCipher(t), "file-model")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSettingsService(fileSection(), store, testCipher(t), applier, query, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return service, store, applier, query
}

func ptr(value string) *string { return &value }

func TestSettingsSaveOverridesTheFileAndKeepsTheKeySecret(t *testing.T) {
	ctx := context.Background()
	service, store, applier, query := settingsFixture(t)

	initial, err := service.Get(ctx)
	if err != nil || initial.Source != SourceFile || initial.APIKey != KeyFile || initial.Settings.LLM.Model != "file-model" || !initial.FileAPIKey ||
		initial.FileOnly.PackMaxTokens != 6000 || initial.FileOnly.AllowNonLocal {
		t.Fatalf("initial = %+v, %v", initial, err)
	}

	edited := initial.Settings
	edited.RunAt, edited.LLM.Model, edited.LLM.BaseURL, edited.LLM.MaxConcurrency = "03:30", "  page-model  ", "http://10.1.2.3:8000/v1", 4
	saved, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited, APIKey: ptr("page-key-9999")})
	if err != nil || saved.Source != SourceSaved || saved.APIKey != KeySaved || saved.Settings.LLM.Model != "page-model" || saved.Settings.RunAt != "03:30" ||
		saved.File.LLM.Model != "file-model" || saved.UpdatedNS == 0 {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	// The key is stored encrypted, apart from the settings, and no view carries it.
	row := store.rows[storage.SettingsSessionAnalysis]
	if strings.Contains(row.Settings, "page-key") || bytes.Contains(row.SecretEnc, []byte("page-key")) || len(row.SecretEnc) == 0 {
		t.Fatalf("stored row leaks the key: %q / %d bytes", row.Settings, len(row.SecretEnc))
	}
	for _, view := range []SettingsView{initial, saved} {
		encoded, _ := json.Marshal(view)
		if strings.Contains(string(encoded), "page-key") || strings.Contains(string(encoded), "file-key") {
			t.Fatalf("view carries a key: %s", encoded)
		}
	}
	// The running batch and the query service got the change.
	if len(applier.configs) != 1 || applier.configs[0].LLM.Model != "page-model" || applier.configs[0].LLM.APIKey != "page-key-9999" ||
		applier.configs[0].LLM.MaxConcurrency != 4 || applier.models[0] == nil || applier.models[0].Model() != "page-model" || query.modelName() != "page-model" {
		t.Fatalf("applied = %+v", applier.configs)
	}
	// What the page cannot edit stays the file's.
	if applied := applier.configs[0]; applied.Pack.MaxTokens != 6000 || applied.SessionIdleMinutes != 120 || applied.LLM.AllowNonLocal {
		t.Fatalf("file-only fields changed: %+v", applied)
	}

	// A later save without a key keeps the saved one; an empty key sends none.
	edited.LLM.MaxSessionsRun = 50
	if kept, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited}); err != nil || kept.APIKey != KeySaved || applier.configs[1].LLM.APIKey != "page-key-9999" {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	cleared, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited, APIKey: ptr("")})
	if err != nil || cleared.APIKey != KeyNone || applier.configs[2].LLM.APIKey != "" || len(store.rows[storage.SettingsSessionAnalysis].SecretEnc) != 0 {
		t.Fatalf("cleared = %+v, %v", cleared, err)
	}

	// Switching the stage off hands the runner no client.
	edited.LLM.Enabled = false
	if off, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited}); err != nil || off.Settings.LLM.Enabled || applier.models[3] != nil || query.modelName() != "" {
		t.Fatalf("off = %+v, %v, model %v", off, err, applier.models[3])
	}

	// Reset drops the saved section; the file applies again, key included.
	reset, err := service.Reset(ctx)
	if err != nil || reset.Source != SourceFile || reset.APIKey != KeyFile || reset.Settings.LLM.Model != "file-model" || len(store.rows) != 0 ||
		applier.configs[4].LLM.APIKey != "file-key-0001" || query.modelName() != "file-model" {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
}

func TestSettingsRejectWhatTheFileWouldReject(t *testing.T) {
	ctx := context.Background()
	service, store, applier, _ := settingsFixture(t)
	base := editableOf(fileSection())
	cases := map[string]func(*EditableSettings){
		"base_url":          func(edited *EditableSettings) { edited.LLM.BaseURL = "https://models.example.com/v1" }, // not local
		"base_url ":         func(edited *EditableSettings) { edited.LLM.BaseURL = "http://user:pw@127.0.0.1:1/v1" },
		"max_concurrency":   func(edited *EditableSettings) { edited.LLM.MaxConcurrency = 0 },
		"max_output_tokens": func(edited *EditableSettings) { edited.LLM.MaxOutputTokens = 50 },
		"context_tokens":    func(edited *EditableSettings) { edited.LLM.MaxOutputTokens = 12000 }, // pack + prefix + output > context
		"model":             func(edited *EditableSettings) { edited.LLM.Model = "  " },
		"structured_output": func(edited *EditableSettings) { edited.LLM.StructuredOutput = "xml" },
		"run_at":            func(edited *EditableSettings) { edited.RunAt = "25:00" },
		"l1_settle_hours":   func(edited *EditableSettings) { edited.L1SettleHours = -1 },
	}
	for field, change := range cases {
		edited := base
		change(&edited)
		_, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited})
		if !errors.Is(err, ErrInvalidSettings) || !strings.Contains(SettingsMessage(err), strings.TrimSpace(field)) {
			t.Errorf("%s: %v (%q)", field, err, SettingsMessage(err))
		}
	}
	if len(store.rows) != 0 || len(applier.configs) != 0 {
		t.Fatalf("a rejected change was saved or applied: %d rows, %d applies", len(store.rows), len(applier.configs))
	}
	if _, err := service.Update(ctx, SettingsUpdate{EditableSettings: base, APIKey: ptr("two\nlines")}); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("key with a line break: %v", err)
	}
	if SettingsMessage(errors.New("other")) != "" {
		t.Fatal("a foreign error has a settings message")
	}
	// The page never loosens the local-only guard; the file can.
	open := fileSection()
	open.LLM.AllowNonLocal = true
	loose, err := NewSettingsService(open, &settingsMemory{}, testCipher(t), &recordingApplier{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited := base
	edited.LLM.BaseURL = "https://models.example.com/v1"
	if view, err := loose.Update(ctx, SettingsUpdate{EditableSettings: edited}); err != nil || !view.FileOnly.AllowNonLocal {
		t.Fatalf("file allows non-local: %+v, %v", view, err)
	}
}

func TestLoadEffectiveConfigIgnoresAnUnusableSavedSection(t *testing.T) {
	ctx := context.Background()
	file := fileSection()
	cipher := testCipher(t)
	store := &settingsMemory{}
	if got := LoadEffectiveConfig(ctx, file, store, cipher, nil); got != file {
		t.Fatalf("nothing saved = %+v", got)
	}
	service, err := NewSettingsService(file, store, cipher, &recordingApplier{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited := editableOf(file)
	edited.LLM.Model, edited.LLM.MaxConcurrency = "page-model", 8
	if _, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited, APIKey: ptr("page-key")}); err != nil {
		t.Fatal(err)
	}
	// A restart reads the saved section back.
	effective := LoadEffectiveConfig(ctx, file, store, cipher, nil)
	if effective.LLM.Model != "page-model" || effective.LLM.MaxConcurrency != 8 || effective.LLM.APIKey != "page-key" || effective.Pack.MaxTokens != 6000 {
		t.Fatalf("effective = %+v", effective.LLM)
	}
	// The file changed so the saved values no longer fit the context budget.
	tighter := file
	tighter.Pack.MaxTokens = 14000
	if got := LoadEffectiveConfig(ctx, tighter, store, cipher, nil); got != tighter {
		t.Fatalf("an invalid saved section was applied: %+v", got.LLM)
	}
	// A key that cannot be decrypted, unknown fields, and a store error.
	row := store.rows[storage.SettingsSessionAnalysis]
	broken := row
	broken.SecretEnc = []byte("not a ciphertext")
	store.rows[storage.SettingsSessionAnalysis] = broken
	if got := LoadEffectiveConfig(ctx, file, store, cipher, nil); got != file {
		t.Fatalf("undecryptable key applied: %+v", got.LLM)
	}
	broken = row
	broken.Settings = `{"run_at":"02:00","unknown":1}`
	store.rows[storage.SettingsSessionAnalysis] = broken
	if got := LoadEffectiveConfig(ctx, file, store, cipher, nil); got != file {
		t.Fatalf("unknown saved field applied: %+v", got.LLM)
	}
	store.fail = errors.New("database unavailable")
	if got := LoadEffectiveConfig(ctx, file, store, cipher, nil); got != file {
		t.Fatalf("store error applied something: %+v", got.LLM)
	}
	// The service itself falls back the same way.
	if view, err := service.Get(ctx); err != nil || view.Source != SourceFile || view.Settings.LLM.Model != "file-model" {
		t.Fatalf("view on a broken store = %+v, %v", view, err)
	}
}

// namedModel is a scripted model with its own name and an optional gate that
// holds every call until it is closed.
type namedModel struct {
	*scriptedModel
	name    string
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (model *namedModel) Model() string { return model.name }

func (model *namedModel) Complete(ctx context.Context, messages []ChatMessage, schema map[string]any) (Completion, error) {
	if model.gate != nil {
		model.once.Do(func() { close(model.entered) })
		<-model.gate
	}
	return model.scriptedModel.Complete(ctx, messages, schema)
}

// A change saved while a run is in progress is picked up by the next run.
func TestRunnerAppliesSettingsBetweenRuns(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	seedAgentSession(store)
	settled := baseTime.Add(30 * time.Hour)
	first := &namedModel{scriptedModel: &scriptedModel{}, name: "model-a", gate: make(chan struct{}), entered: make(chan struct{})}
	runner := facetRunner(t, store, first, settled)
	key := analysisID(sessionK, bytes.Repeat([]byte{1}, 32))

	finished := make(chan storage.SessionAnalysisRun, 1)
	go func() {
		run, _ := runner.RunOnce(ctx, TriggerManual)
		finished <- run
	}()
	<-first.entered // the run is inside its model call
	second := &namedModel{scriptedModel: &scriptedModel{}, name: "model-b"}
	changed := runner.options.Config
	changed.LLM.MaxSessionsRun, changed.RunAt = 7, "04:15"
	if err := runner.Apply(changed, second); err != nil {
		t.Fatal(err)
	}
	if !runner.Running() {
		t.Fatal("the run ended before the change")
	}
	close(first.gate)
	if run := <-finished; run.L1OK != 1 || store.facets[key].Model != "model-a" || second.calls != 0 {
		t.Fatalf("the running run used the new settings: %+v model=%s calls=%d", run, store.facets[key].Model, second.calls)
	}
	// The next run has the new client and limits; the pack is due again
	// because its facet belongs to another model.
	run, err := runner.RunOnce(ctx, TriggerManual)
	if err != nil || run.L1Candidates != 1 || run.L1OK != 1 || store.facets[key].Model != "model-b" || second.calls != 1 ||
		runner.options.Config.LLM.MaxSessionsRun != 7 {
		t.Fatalf("next run = %+v model=%s calls=%d", run, store.facets[key].Model, second.calls)
	}
	// Switching the stage off: the next run calls no model.
	off := runner.options.Config
	off.LLM.Enabled = false
	if err := runner.Apply(off, nil); err != nil {
		t.Fatal(err)
	}
	if run, _ := runner.RunOnce(ctx, TriggerManual); run.L1Candidates != 0 || second.calls != 1 {
		t.Fatalf("run with the stage off = %+v calls=%d", run, second.calls)
	}
	if err := runner.Apply(config.SessionAnalysisConfig{RunAt: "nope"}, nil); err == nil {
		t.Fatal("an unparsable run time was applied")
	}
}

// A new daily run time reschedules the loop without waiting for the old one.
func TestRunnerReschedulesWhenTheRunTimeChanges(t *testing.T) {
	store := newMemoryStore()
	now := time.Date(2026, 11, 12, 10, 0, 59, 900_000_000, time.UTC)
	runner := facetRunner(t, store, nil, now)
	runner.options.LLM = nil
	if wait := runner.untilNextRun(); wait < 15*time.Hour {
		t.Fatalf("initial wait = %s", wait)
	}
	runner.Start(context.Background())
	defer runner.Close()
	changed := runner.options.Config
	changed.RunAt = "10:01"
	if err := runner.Apply(changed, nil); err != nil {
		t.Fatal(err)
	}
	if wait := runner.untilNextRun(); wait > time.Second {
		t.Fatalf("wait after the change = %s", wait)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		runs := len(store.runs)
		store.mu.Unlock()
		if runs > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the loop did not run at the new time")
}

func TestSettingsConnectionTest(t *testing.T) {
	ctx := context.Background()
	service, store, applier, _ := settingsFixture(t)
	var probed config.SessionAnalysisConfig
	service.probe = func(_ context.Context, candidate config.SessionAnalysisConfig) ProbeResult {
		probed = candidate
		return ProbeResult{OK: true, HTTPStatus: 200}
	}
	edited := editableOf(fileSection())
	edited.LLM.Enabled, edited.LLM.Model = false, "candidate-model"
	// The test checks the model fields even while the stage is off, uses the
	// key in use when none is given, and saves nothing.
	if result, err := service.Test(ctx, SettingsUpdate{EditableSettings: edited}); err != nil || !result.OK ||
		probed.LLM.Model != "candidate-model" || probed.LLM.APIKey != "file-key-0001" {
		t.Fatalf("test = %+v, %v, probed %+v", result, err, probed.LLM)
	}
	if len(store.rows) != 0 || len(applier.configs) != 0 {
		t.Fatal("a connection test saved or applied settings")
	}
	edited.LLM.Model = ""
	if _, err := service.Test(ctx, SettingsUpdate{EditableSettings: edited}); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("test without a model: %v", err)
	}

	// The real probe against a local endpoint: only how the call ended.
	answer, status := `{"ok": true}`, http.StatusOK
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		bodies = append(bodies, body)
		if status != http.StatusOK {
			writer.WriteHeader(status)
			return
		}
		encoded, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"finish_reason": "length", "message": map[string]any{"content": answer, "reasoning_content": "thinking…"}}},
			"usage":   map[string]any{"prompt_tokens": 20, "completion_tokens": 9},
		})
		_, _ = writer.Write(encoded)
	}))
	t.Cleanup(server.Close)
	candidate := fileSection()
	candidate.LLM.BaseURL = server.URL + "/v1"
	result := probeModel(ctx, candidate)
	if !result.OK || result.HTTPStatus != 200 || !result.ValidJSON || !result.Truncated || !result.Reasoned || result.InputTokens != 20 || result.OutputTokens != 9 {
		t.Fatalf("probe = %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "thinking") || strings.Contains(string(encoded), `\"ok\"`) {
		t.Fatalf("the probe result carries model output: %s", encoded)
	}
	// The probe sends a fixed synthetic prompt.
	messages, _ := bodies[0]["messages"].([]any)
	if len(messages) != 2 || messages[1].(map[string]any)["content"] != "ping" {
		t.Fatalf("probe messages = %v", messages)
	}
	answer = "not json"
	if result := probeModel(ctx, candidate); !result.OK || result.ValidJSON {
		t.Fatalf("non-JSON answer = %+v", result)
	}
	status = http.StatusUnauthorized
	if result := probeModel(ctx, candidate); result.OK || result.Error != "http_status" || result.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("401 = %+v", result)
	}
	server.Close()
	if result := probeModel(ctx, candidate); result.OK || result.Error != "unreachable" {
		t.Fatalf("closed endpoint = %+v", result)
	}
	candidate.LLM.BaseURL = "https://models.example.com/v1"
	if result := probeModel(ctx, candidate); result.OK || result.Error == "" {
		t.Fatalf("non-local endpoint = %+v", result)
	}
}
