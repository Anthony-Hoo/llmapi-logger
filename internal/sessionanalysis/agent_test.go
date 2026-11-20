package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
)

const agentTestKey = "agent-test-key-5150"

// loggedSettingsFixture is settingsFixture with the log captured and a key
// saved from the page, so a later write must keep it.
func loggedSettingsFixture(t *testing.T) (*SettingsService, *settingsMemory, *recordingApplier, *bytes.Buffer) {
	t.Helper()
	store, applier, logs := &settingsMemory{}, &recordingApplier{}, &bytes.Buffer{}
	query, err := NewQueryService(newMemoryStore(), nil, testCipher(t), "file-model")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSettingsService(fileSection(), store, testCipher(t), applier, query, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	initial, _ := service.Get(context.Background())
	if _, err := service.Update(context.Background(), SettingsUpdate{EditableSettings: initial.Settings, APIKey: ptr(agentTestKey)}); err != nil {
		t.Fatal(err)
	}
	return service, store, applier, logs
}

func intPtr(value int) *int { return &value }

func TestSettingsPatchChangesOneFieldAndKeepsTheKey(t *testing.T) {
	ctx := context.Background()
	service, store, applier, _ := loggedSettingsFixture(t)
	before, _ := service.Get(ctx)
	rowBefore := store.rows[storage.SettingsSessionAnalysis]

	patched, err := service.Patch(ctx, before.Version(), SettingsPatch{LLM: LLMPatch{MaxConcurrency: intPtr(3)}})
	if err != nil {
		t.Fatal(err)
	}
	want := before.Settings
	want.LLM.MaxConcurrency = 3
	if !reflect.DeepEqual(patched.Settings, want) || patched.APIKey != KeySaved || patched.Version() <= before.Version() {
		t.Fatalf("patched = %+v", patched)
	}
	// The key is kept exactly: same source, same plaintext handed to the runner.
	if last := applier.configs[len(applier.configs)-1]; last.LLM.APIKey != agentTestKey || last.LLM.MaxConcurrency != 3 {
		t.Fatalf("applied = %+v", last.LLM)
	}
	row := store.rows[storage.SettingsSessionAnalysis]
	if len(row.SecretEnc) == 0 || bytes.Equal(row.SecretEnc, rowBefore.SecretEnc) && row.Settings == rowBefore.Settings {
		t.Fatalf("row = %+v", row)
	}
	// llm.enabled false alone keeps the model fields.
	disabled, err := service.Patch(ctx, patched.Version(), SettingsPatch{LLM: LLMPatch{Enabled: boolPtr(false)}})
	if err != nil || disabled.Settings.LLM.Enabled || disabled.Settings.LLM.Model != before.Settings.LLM.Model || disabled.Settings.LLM.MaxConcurrency != 3 {
		t.Fatalf("disabled = %+v, %v", disabled, err)
	}
}

func boolPtr(value bool) *bool { return &value }

func TestSettingsPatchTrimsLikeTheForm(t *testing.T) {
	ctx := context.Background()
	service, _, _, _ := loggedSettingsFixture(t)
	before, _ := service.Get(ctx)
	diff, err := service.CheckPatch(ctx, before.Version(), SettingsPatch{RunAt: ptr(" 04:15 "), LLM: LLMPatch{Model: ptr("  other-model "), BaseURL: ptr(" http://127.0.0.1:9000/v1 ")}})
	if err != nil || diff.After.RunAt != "04:15" || diff.After.LLM.Model != "other-model" || diff.After.LLM.BaseURL != "http://127.0.0.1:9000/v1" {
		t.Fatalf("diff = %+v, %v", diff, err)
	}
	if want := []string{"run_at", "llm.base_url", "llm.model"}; !reflect.DeepEqual(diff.Changed, want) {
		t.Fatalf("changed = %v", diff.Changed)
	}
	// The web route trims the same three fields itself (overlay).
	edited := before.Settings
	edited.RunAt, edited.LLM.Model, edited.LLM.BaseURL = " 04:15 ", "  other-model ", " http://127.0.0.1:9000/v1 "
	web, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited})
	if err != nil || !reflect.DeepEqual(web.Settings, diff.After) {
		t.Fatalf("web = %+v, %v", web.Settings, err)
	}
}

func TestSettingsStaleVersionAndChecksChangeNothing(t *testing.T) {
	ctx := context.Background()
	service, store, applier, _ := loggedSettingsFixture(t)
	view, _ := service.Get(ctx)
	row, applied := store.rows[storage.SettingsSessionAnalysis], len(applier.configs)

	planned, err := service.CheckPatch(ctx, view.Version(), SettingsPatch{L1SettleHours: intPtr(12)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckReset(ctx, view.Version()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(store.rows[storage.SettingsSessionAnalysis], row) || len(applier.configs) != applied {
		t.Fatal("a check saved or applied")
	}
	for _, version := range []int64{0, view.Version() - 1, AnyVersion} {
		if _, err := service.Patch(ctx, version, SettingsPatch{L1SettleHours: intPtr(12)}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("patch at %d = %v", version, err)
		}
		if _, err := service.ResetIfVersion(ctx, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("reset at %d = %v", version, err)
		}
		if _, err := service.CheckPatch(ctx, version, SettingsPatch{}); !errors.Is(err, ErrVersionConflict) && version != AnyVersion {
			t.Fatalf("check at %d = %v", version, err)
		}
	}
	if !reflect.DeepEqual(store.rows[storage.SettingsSessionAnalysis], row) || len(applier.configs) != applied {
		t.Fatal("a refused write changed something")
	}
	patched, err := service.Patch(ctx, view.Version(), SettingsPatch{L1SettleHours: intPtr(12)})
	if err != nil || !reflect.DeepEqual(patched.Settings, planned.After) || planned.Version != view.Version() || planned.KeySource != KeySaved {
		t.Fatalf("patched %+v, planned %+v (%v)", patched.Settings, planned, err)
	}
	reset, err := service.ResetIfVersion(ctx, patched.Version())
	if err != nil || reset.Version() != 0 || len(store.rows) != 0 {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
	if again, err := service.Patch(ctx, 0, SettingsPatch{}); err != nil || again.Version() <= patched.Version() || again.APIKey != KeyFile {
		t.Fatalf("after reset = %+v, %v", again, err)
	}
}

func TestSettingsWebEditBetweenCheckAndPatchConflicts(t *testing.T) {
	ctx := context.Background()
	service, _, _, _ := loggedSettingsFixture(t)
	view, _ := service.Get(ctx)
	planned, err := service.CheckPatch(ctx, AnyVersion, SettingsPatch{L1SettleHours: intPtr(12)})
	if err != nil {
		t.Fatal(err)
	}
	// The pinned clock gives the web save the same reading as the fixture's
	// save; the version still moves.
	if saved, err := service.Update(ctx, SettingsUpdate{EditableSettings: view.Settings}); err != nil || saved.Version() == view.Version() {
		t.Fatalf("web save = %+v, %v", saved, err)
	}
	if _, err := service.Patch(ctx, planned.Version, SettingsPatch{L1SettleHours: intPtr(12)}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("patch after a web save = %v", err)
	}
}

func TestSetAPIKeyChangesOnlyTheKeyAndNeverShowsIt(t *testing.T) {
	ctx := context.Background()
	service, store, applier, logs := loggedSettingsFixture(t)
	before, _ := service.Get(ctx)
	const newKey = "rotated-key-8086"

	view, err := service.SetAPIKey(ctx, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Settings, before.Settings) || view.APIKey != KeySaved || view.Version() <= before.Version() {
		t.Fatalf("view = %+v", view)
	}
	if last := applier.configs[len(applier.configs)-1]; last.LLM.APIKey != newKey {
		t.Fatal("the runner did not get the new key")
	}
	cleared, err := service.ClearAPIKey(ctx)
	if err != nil || cleared.APIKey != KeyNone || !reflect.DeepEqual(cleared.Settings, before.Settings) {
		t.Fatalf("cleared = %+v, %v", cleared, err)
	}
	if last := applier.configs[len(applier.configs)-1]; last.LLM.APIKey != "" {
		t.Fatal("the cleared key is still sent")
	}
	_, emptyErr := service.SetAPIKey(ctx, "")
	var invalid *SettingsError
	if !errors.As(emptyErr, &invalid) || invalid.Field != "llm.api_key" {
		t.Fatalf("empty key = %v", emptyErr)
	}
	_, breakErr := service.SetAPIKey(ctx, "line\nbreak-"+newKey)
	if !errors.As(breakErr, &invalid) || invalid.Field != "llm.api_key" {
		t.Fatalf("key with a line break = %v", breakErr)
	}
	diff, _ := service.CheckPatch(ctx, AnyVersion, SettingsPatch{})
	for _, value := range []any{view, cleared, diff, emptyErr.Error(), breakErr.Error(), logs.String(), store.rows[storage.SettingsSessionAnalysis].Settings} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), newKey) || strings.Contains(string(encoded), agentTestKey) {
			t.Fatalf("the key leaked into %s", encoded)
		}
	}
	if !strings.Contains(logs.String(), "session analysis settings saved") {
		t.Fatal("the log was not captured")
	}
}

func TestSettingsPatchRejectsTheKeyField(t *testing.T) {
	var patch SettingsPatch
	decoder := json.NewDecoder(strings.NewReader(`{"llm":{"api_key":"x"}}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&patch) == nil {
		t.Fatal("api_key accepted in a patch")
	}
}

func TestSettingsErrorsNameTheField(t *testing.T) {
	ctx := context.Background()
	service, _, _, _ := loggedSettingsFixture(t)
	view, _ := service.Get(ctx)
	for _, test := range []struct {
		patch SettingsPatch
		field string
	}{
		{SettingsPatch{LLM: LLMPatch{MaxConcurrency: intPtr(99)}}, "llm.max_concurrency"},
		{SettingsPatch{RunAt: ptr("25:00")}, "run_at"},
		{SettingsPatch{L1SettleHours: intPtr(-1)}, "l1_settle_hours"},
		{SettingsPatch{LLM: LLMPatch{ContextTokens: intPtr(4096)}}, "llm.context_tokens"},
		{SettingsPatch{LLM: LLMPatch{StructuredOutput: ptr("xml")}}, "llm.structured_output"},
		{SettingsPatch{LLM: LLMPatch{BaseURL: ptr("http://8.8.8.8/v1")}}, "llm.base_url"},
		{SettingsPatch{LLM: LLMPatch{Model: ptr(" ")}}, "llm.model"},
		{SettingsPatch{LLM: LLMPatch{MaxSessionsRun: intPtr(0)}}, "llm.max_sessions_per_run"},
		{SettingsPatch{LLM: LLMPatch{MaxOutputTokens: intPtr(1)}}, "llm.max_output_tokens"},
	} {
		_, err := service.CheckPatch(ctx, view.Version(), test.patch)
		var invalid *SettingsError
		if !errors.As(err, &invalid) || invalid.Field != test.field || !errors.Is(err, ErrInvalidSettings) {
			t.Fatalf("%+v = %v (%+v)", test.patch, err, invalid)
		}
		// The web route fails with the same text.
		_, update, _ := service.preparePatch(ctx, AnyVersion, test.patch, false)
		if _, webErr := service.Update(ctx, update); webErr == nil || webErr.Error() != err.Error() || SettingsMessage(webErr) != invalid.Message {
			t.Fatalf("web = %v, agent = %v", webErr, err)
		}
	}
	if failure := settingsError("the model client rejected the address"); failure.Field != "llm.base_url" {
		t.Fatalf("address = %+v", failure)
	}
	if failure := settingsError("session_analysis.enabled requires insights.enabled"); failure.Field != "" {
		t.Fatalf("file-only = %+v", failure)
	}
}

func TestValidateCalibrationLabels(t *testing.T) {
	ctx := context.Background()
	query, err := NewQueryService(newMemoryStore(), nil, testCipher(t), "local-small")
	if err != nil {
		t.Fatal(err)
	}
	if !query.CalibrationAvailable() {
		t.Fatal("calibration should be available")
	}
	valid := CalibrationLabel{SessionID: strings.Repeat("ab", 32), TaskType: TaskTypes[0], Friction: []string{FrictionKinds[0]}}
	if err := ValidateCalibrationLabels([]CalibrationLabel{valid}); err != nil {
		t.Fatal(err)
	}
	many := make([]CalibrationLabel, 1001)
	for index := range many {
		many[index] = valid
	}
	for _, test := range []struct {
		labels []CalibrationLabel
		index  int
		field  string
	}{
		{nil, -1, "labels"},
		{many, -1, "labels"},
		{[]CalibrationLabel{valid, valid, {SessionID: "abc"}}, 2, "session_id"},
		{[]CalibrationLabel{{SessionID: strings.Repeat("zz", 32)}}, 0, "session_id"},
		{[]CalibrationLabel{valid, {SessionID: valid.SessionID, Outcome: "great"}}, 1, "outcome"},
		{[]CalibrationLabel{{SessionID: valid.SessionID, Friction: []string{"bad-friction"}}}, 0, "friction"},
	} {
		err := ValidateCalibrationLabels(test.labels)
		var labelErr *LabelError
		if !errors.As(err, &labelErr) || labelErr.Index != test.index || labelErr.Field != test.field {
			t.Fatalf("labels = %v (%+v)", err, labelErr)
		}
		// Calibrate refuses the same input with the same error text.
		if _, calibrateErr := query.Calibrate(ctx, test.labels); calibrateErr == nil || calibrateErr.Error() != err.Error() {
			t.Fatalf("Calibrate = %v, helper = %v", calibrateErr, err)
		}
	}
	query.SetModel("")
	if query.CalibrationAvailable() {
		t.Fatal("calibration available without a model")
	}
}

// A write never starts from the configuration file because the saved row
// could not be read: SetAPIKey, ClearAPIKey, Patch, ResetIfVersion and the
// web's Update refuse with ErrSettingsUnavailable and save nothing, while
// reads still fall back to the file. A saved row that was read but can no
// longer be used is the file-applies state and stays writable.
func TestWritesRefuseWhenTheSavedSectionCannotBeRead(t *testing.T) {
	ctx := context.Background()
	writes := map[string]func(*SettingsService, int64) error{
		"set key": func(service *SettingsService, _ int64) error {
			_, err := service.SetAPIKey(ctx, "rotated-key-0002")
			return err
		},
		"clear key": func(service *SettingsService, _ int64) error { _, err := service.ClearAPIKey(ctx); return err },
		"patch": func(service *SettingsService, version int64) error {
			_, err := service.Patch(ctx, version, SettingsPatch{RunAt: ptr("04:00")})
			return err
		},
		"reset": func(service *SettingsService, version int64) error {
			_, err := service.ResetIfVersion(ctx, version)
			return err
		},
		"update": func(service *SettingsService, _ int64) error {
			view, _ := service.Get(ctx)
			_, err := service.Update(ctx, SettingsUpdate{EditableSettings: view.Settings})
			return err
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			service, store, _, _ := settingsFixture(t)
			initial, _ := service.Get(ctx)
			edited := initial.Settings
			edited.RunAt, edited.LLM.Model, edited.LLM.MaxConcurrency = "03:30", "page-model", 4
			saved, err := service.Update(ctx, SettingsUpdate{EditableSettings: edited, APIKey: ptr("page-key-9999")})
			if err != nil {
				t.Fatal(err)
			}
			store.mu.Lock()
			before := store.rows[storage.SettingsSessionAnalysis]
			store.fail = errors.New("transient: connection reset")
			store.mu.Unlock()
			err = write(service, saved.UpdatedNS)
			if !errors.Is(err, ErrSettingsUnavailable) {
				t.Fatalf("write on an unreadable store = %v", err)
			}
			// Reads keep falling back to the file.
			if view, err := service.Get(ctx); err != nil || view.Source != SourceFile {
				t.Fatalf("read on an unreadable store = %+v, %v", view, err)
			}
			store.mu.Lock()
			store.fail = nil
			after := store.rows[storage.SettingsSessionAnalysis]
			store.mu.Unlock()
			if after.UpdatedAtNS != before.UpdatedAtNS || after.Settings != before.Settings || !bytes.Equal(after.SecretEnc, before.SecretEnc) {
				t.Fatal("a refused write changed the saved row")
			}
			view, _ := service.Get(ctx)
			if view.Settings.LLM.Model != "page-model" || view.APIKey != KeySaved || view.UpdatedNS != saved.UpdatedNS {
				t.Fatalf("saved section after the refused write = %+v", view)
			}
		})
	}

	// An unusable saved row is not a read failure: the file applies and a
	// key write starts from it.
	service, store, _, _ := settingsFixture(t)
	initial, _ := service.Get(ctx)
	if _, err := service.Update(ctx, SettingsUpdate{EditableSettings: initial.Settings, APIKey: ptr("page-key-9999")}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	broken := store.rows[storage.SettingsSessionAnalysis]
	broken.Settings = `{"run_at":"02:00","unknown":1}`
	store.rows[storage.SettingsSessionAnalysis] = broken
	store.mu.Unlock()
	if view, err := service.SetAPIKey(ctx, "rotated-key-0002"); err != nil || view.APIKey != KeySaved {
		t.Fatalf("key write over an unusable row = %+v, %v", view, err)
	}
}

// TestPatch sends the key in use only to the destination in effect; a
// typed key may go anywhere the settings allow.
func TestTestPatchKeepsTheKeyInUseAtTheAddressInEffect(t *testing.T) {
	ctx := context.Background()
	service, _, _, _ := settingsFixture(t)
	var probed []config.SessionAnalysisConfig
	service.probe = func(_ context.Context, candidate config.SessionAnalysisConfig) ProbeResult {
		probed = append(probed, candidate)
		return ProbeResult{OK: true}
	}
	moved := SettingsPatch{LLM: LLMPatch{BaseURL: ptr("http://10.9.9.9:8000/v1")}}
	_, err := service.TestPatch(ctx, moved, nil)
	var target *KeyTargetError
	if !errors.As(err, &target) || target.Field != "llm.base_url" || len(probed) != 0 {
		t.Fatalf("file key to another address = %v, %d probes", err, len(probed))
	}
	typed := "typed-key-0003"
	if _, err := service.TestPatch(ctx, moved, &typed); err != nil || len(probed) != 1 || probed[0].LLM.APIKey != typed || probed[0].LLM.BaseURL != "http://10.9.9.9:8000/v1" {
		t.Fatalf("typed key = %v %+v", err, probed)
	}
	view, _ := service.Get(ctx)
	same := SettingsPatch{LLM: LLMPatch{BaseURL: ptr("  " + view.Settings.LLM.BaseURL + " "), Model: ptr("other-model")}}
	if _, err := service.TestPatch(ctx, same, nil); err != nil || len(probed) != 2 || probed[1].LLM.APIKey != fileSection().LLM.APIKey {
		t.Fatalf("address in effect = %v %+v", err, probed)
	}
	if _, err := service.ClearAPIKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.TestPatch(ctx, moved, nil); err != nil || len(probed) != 3 || probed[2].LLM.APIKey != "" {
		t.Fatalf("no key in use = %v %+v", err, probed)
	}
	file := fileSection()
	other := file
	other.LLM.AllowNonLocal = !file.LLM.AllowNonLocal
	if TargetChange(file, other) != "llm.allow_non_local" || TargetChange(file, file) != "" {
		t.Fatal("TargetChange misses a destination field")
	}
}

// Contract section 0.1 item 133: a settings refusal says why (Reason), and
// for llm.structured_output which values it takes (Allowed). StructuredOutputs
// is the configuration validator's list: every value of it is accepted and
// anything else is refused with exactly that list.
func TestSettingsRefusalsCarryReasonAndAllowedValues(t *testing.T) {
	ctx := context.Background()
	service, _, _, _ := settingsFixture(t)
	for _, value := range StructuredOutputs {
		if _, err := service.CheckPatch(ctx, AnyVersion, SettingsPatch{LLM: LLMPatch{StructuredOutput: ptr(value)}}); err != nil {
			t.Fatalf("structured_output %q = %v", value, err)
		}
	}
	for _, test := range []struct {
		patch   SettingsPatch
		field   string
		reason  string
		allowed []string
	}{
		{SettingsPatch{LLM: LLMPatch{StructuredOutput: ptr("xml")}}, "llm.structured_output", ReasonNotAllowedValue, StructuredOutputs},
		{SettingsPatch{RunAt: ptr("7")}, "run_at", ReasonInvalidFormat, nil},
		{SettingsPatch{L1SettleHours: intPtr(1000)}, "l1_settle_hours", ReasonOutOfRange, nil},
		{SettingsPatch{LLM: LLMPatch{BaseURL: ptr("https://llm.example.com/v1")}}, "llm.base_url", ReasonNotLocalAddress, nil},
		{SettingsPatch{LLM: LLMPatch{Model: ptr(" ")}}, "llm.model", ReasonRequired, nil},
	} {
		_, err := service.CheckPatch(ctx, AnyVersion, test.patch)
		var refused *SettingsError
		if !errors.As(err, &refused) || refused.Field != test.field || refused.Reason != test.reason || strings.Join(refused.Allowed, ",") != strings.Join(test.allowed, ",") {
			t.Errorf("%+v = %+v", test.patch, refused)
		}
	}
	// Calibration labels: the reason, and a field's values.
	err := ValidateCalibrationLabels([]CalibrationLabel{{SessionID: strings.Repeat("a", 64), TaskType: "bugfix"}})
	var label *LabelError
	if !errors.As(err, &label) || label.Field != "task_type" || label.Reason != ReasonNotAllowedValue || strings.Join(label.Allowed, ",") != strings.Join(TaskTypes, ",") {
		t.Fatalf("label = %+v", label)
	}
}
