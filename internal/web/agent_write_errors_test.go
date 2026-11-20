package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

// A settings write refused because the saved section could not be read is a
// retryable upstream failure, not INTERNAL: nothing was written.
func TestSettingsReadFailureIsUpstreamUnavailable(t *testing.T) {
	err := fmt.Errorf("%w: %w", sessionanalysis.ErrSettingsUnavailable, errors.New("connection reset"))
	if failure := agentWriteFailure(err); failure.Code != agentapi.CodeUpstreamUnavailable || len(failure.Details) != 0 {
		t.Fatalf("failure = %+v", failure)
	}
}

// apply takes no body: a refusal raised while a plan runs never names field
// "body". A typed service error maps as it does when the plan is made; an
// unclassified one asks for a new plan.
func TestApplyFailuresNeverBlameTheBody(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("%w: the local model is not enabled", query.ErrInvalidQuery),
		orgreport.ErrInvalid,
	} {
		failure := agentApplyFailure(err)
		if failure.Code != agentapi.CodeInvalidArgument || failure.Details["field"] != nil || failure.Details["reason"] != "refused_at_apply" ||
			!strings.Contains(failure.Hint, "new plan") {
			t.Errorf("%v = %+v", err, failure)
		}
		// Plan creation keeps naming the body: there it is the input.
		if failure := agentWriteFailure(err); failure.Details["field"] != "body" {
			t.Errorf("plan-time %v = %+v", err, failure)
		}
	}
	typed := &sessionanalysis.SettingsError{Field: "llm.timeout_seconds", Message: "out of range"}
	if failure := agentApplyFailure(typed); failure.Details["field"] != "llm.timeout_seconds" {
		t.Errorf("typed = %+v", failure)
	}
}

// The calibration probe: planned while the model stage was on, applied after
// it was switched off. The apply answers what the plan step answers for the
// same state, with what to do next.
func TestCalibrationAppliedAfterTheModelStageWasSwitchedOff(t *testing.T) {
	fixture := newWriteFixture(t)
	labels := `[{"session_id":"` + analysisOwnID + `","task_type":"bug_fix","outcome":"achieved"}]`
	plan := fixture.plan(t, `{"op":"analysis.calibrate","args":{"labels":`+labels+`}}`)
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"llm.enabled": false}})
	applied := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite))
	planned := failure(t, fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.calibrate","args":{"labels":`+labels+`}}`, fixture.adminWrite))
	for _, body := range []agentapi.ErrorBody{applied, planned} {
		if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != "llm.enabled" || body.Details["reason"] != "model_stage_disabled" {
			t.Fatalf("calibration refusal = %+v", body)
		}
	}
	if !strings.Contains(applied.Hint, "new calibration plan") {
		t.Fatalf("apply hint = %q", applied.Hint)
	}
	rows := fixture.writeAudits()
	if last := rows[len(rows)-1]; last.ObjectKind != "analysis-calibration" || last.ErrorCode != string(agentapi.CodeInvalidArgument) {
		t.Fatalf("audit row = %+v", last)
	}
}

// Every op forced to fail at apply: none of the refusals names field body.
func TestEveryApplyRefusalNamesNoBody(t *testing.T) {
	fixture := newWriteFixture(t)
	created := fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "ua-rule",
		"set": map[string]any{"name": "rule", "enabled": true, "model_pattern": "^m", "user_agent_pattern": "^ua"}})
	stale := fixture.plan(t, map[string]any{"op": "config.set", "kind": "ua-rule", "id": created.ID, "set": map[string]any{"enabled": false}})
	removal := fixture.plan(t, map[string]any{"op": "config.remove", "kind": "ua-rule", "id": created.ID})
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "ua-rule", "id": created.ID, "set": map[string]any{"name": "renamed"}})
	fixture.trigger.running = true
	run := fixture.plan(t, `{"op":"analysis.run"}`)
	// Suggestion 43 exists when the plan is made and is gone when it is
	// applied.
	dismiss := fixture.plan(t, `{"op":"analysis.dismiss","args":{"suggestion_id":43}}`)
	fixture.suggestions.mu.Lock()
	delete(fixture.suggestions.open, 43)
	fixture.suggestions.mu.Unlock()
	settings := fixture.plan(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": "04:00"}})
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": "05:00"}})
	for name, test := range map[string]struct {
		planID string
		code   agentapi.Code
	}{
		"config.set":        {stale.PlanID, agentapi.CodeVersionConflict},
		"config.remove":     {removal.PlanID, agentapi.CodeVersionConflict},
		"analysis.run":      {run.PlanID, agentapi.CodeRunInProgress},
		"analysis.dismiss":  {dismiss.PlanID, agentapi.CodeNotFound},
		"analysis-settings": {settings.PlanID, agentapi.CodeVersionConflict},
	} {
		body := failure(t, fixture.facade(http.MethodPost, "/plans/"+test.planID+"/apply", nil, fixture.adminWrite))
		if body.Code != test.code || body.Details["field"] == "body" {
			t.Errorf("%s = %+v", name, body)
		}
	}
}

// Contract section 0.1 item 108: every CONFLICT of the write services
// carries details.reason (and details.field when there is one) and a hint
// with the next step and the read command that shows what is in the way.
func TestConflictsSayWhatToDo(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	check := func(name string, body agentapi.ErrorBody, reason, field, hint string) {
		t.Helper()
		if body.Code != agentapi.CodeConflict || body.Details["reason"] != reason || (field != "" && body.Details["field"] != field) ||
			!strings.Contains(body.Hint, hint) || !strings.Contains(body.Hint, "llmaudit config show --kind org") {
			t.Errorf("%s = %s %v %q", name, body.Code, body.Details, body.Hint)
		}
	}
	check("group with projects", failure(t, fixture.facade(http.MethodPost, "/plans",
		map[string]any{"op": "config.remove", "kind": "group", "id": ids.group}, fixture.adminWrite)),
		"has_projects", "", "llmaudit config remove --kind project")
	check("duplicate group name", failure(t, fixture.facade(http.MethodPost, "/plans",
		map[string]any{"op": "config.set", "kind": "group", "set": map[string]any{"name": "GROUP SEED", "enabled": true}}, fixture.adminWrite)),
		"duplicate", "name", "Choose another name")
	fixture.planAndApply(t, map[string]any{"op": "config.remove", "kind": "project", "id": ids.project})
	check("group with members", failure(t, fixture.facade(http.MethodPost, "/plans",
		map[string]any{"op": "config.remove", "kind": "group", "id": ids.group}, fixture.adminWrite)),
		"has_members", "", "llmaudit config remove --kind member")
	// A conflict the store reports without a typed reason (a constraint).
	stored := agentWriteFailure(fmt.Errorf("%w: org_groups_name_key", orgreport.ErrConflict))
	if stored.Code != agentapi.CodeConflict || stored.Details["reason"] != "constraint" || !strings.Contains(stored.Hint, "llmaudit config show --kind org") ||
		strings.Contains(stored.Message, "org_groups_name_key") {
		t.Errorf("store conflict = %+v", stored)
	}
}

// Contract section 0.1 item 128: while the saved weekly-report settings
// cannot be read (the reader failing, the writer working), the plan still
// shows the file's values (a read), but applying it is a retryable
// UPSTREAM_UNAVAILABLE that saves nothing, and the web page's PUT and DELETE
// answer 503 and save nothing. Before, the apply saved the configuration
// file's values over the administrator's settings.
func TestWeeklySettingsWritesRefuseWhenTheSavedRowCannotBeRead(t *testing.T) {
	fixture := newWriteFixture(t)
	saved := `{"idle_gap_seconds":45,"ranked_clients":["codex","opencode"],"max_concurrent_roots":4,"max_single_request_roots":50}`
	if put := fixture.web(http.MethodPut, orgReportsSettingsPath, saved); put.Code != http.StatusOK {
		t.Fatalf("web put = %d %s", put.Code, put.Body.String())
	}
	before := fixture.web(http.MethodGet, orgReportsSettingsPath, "").Body.String()
	fixture.orgRows.setFailLoad(errors.New("transient: reader pool exhausted"))
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "weekly-settings", "set": map[string]any{"idle_gap_seconds": 90}})
	applied := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite))
	if applied.Code != agentapi.CodeUpstreamUnavailable {
		t.Fatalf("apply during the read error = %+v", applied)
	}
	reset := fixture.plan(t, map[string]any{"op": "config.reset", "kind": "weekly-settings"})
	if body := failure(t, fixture.facade(http.MethodPost, "/plans/"+reset.PlanID+"/apply", nil, fixture.adminWrite)); body.Code != agentapi.CodeUpstreamUnavailable {
		t.Fatalf("reset apply during the read error = %+v", body)
	}
	for _, request := range [][2]string{{http.MethodPut, `{"idle_gap_seconds":90,"ranked_clients":["codex"],"max_concurrent_roots":4,"max_single_request_roots":50}`}, {http.MethodDelete, ""}} {
		response := fixture.web(request[0], orgReportsSettingsPath, request[1])
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "org_unavailable") {
			t.Fatalf("web %s during the read error = %d %s", request[0], response.Code, response.Body.String())
		}
	}
	fixture.orgRows.setFailLoad(nil)
	if after := fixture.web(http.MethodGet, orgReportsSettingsPath, "").Body.String(); after != before {
		t.Fatalf("saved settings changed by refused writes:\nbefore %s\nafter  %s", before, after)
	}
}

// Contract section 0.1 item 132: plan input has one spelling per field at
// any depth. Keys are matched with their case, so a key that names a field
// only without regard to case is an unknown field naming the key, and no
// JSON object of the input may repeat a key (the last one used to win).
func TestPlanInputIsDecodedExactly(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	project := func(rule string) string {
		return `{"op":"config.set","kind":"project","id":"` + ids.project + `","set":{"rules":[` + rule + `]}}`
	}
	label := func(body string) string { return `{"op":"analysis.calibrate","args":{"labels":[` + body + `]}}` }
	for _, test := range []struct {
		name, path, body, field, reason string
	}{
		{"rule field in another case", "/plans", project(`{"kind":"repo_name","pattern_untrusted":"a","Pattern":"b"}`), "rules[0].Pattern", "unknown_field"},
		{"rule kind in another case", "/plans", project(`{"Kind":"repo_name","pattern":"a"}`), "rules[0].Kind", "unknown_field"},
		{"label field in another case", "/plans", label(`{"session_id":"` + analysisOwnID + `","Task_type":"bug_fix"}`), "args.labels[0].Task_type", "unknown_field"},
		{"added rule in another case", "/plans", `{"op":"config.set","kind":"project","id":"` + ids.project + `","add":{"rules":[{"kind":"repo_name","PATTERN":"x"}]}}`, "rules[0].PATTERN", "unknown_field"},
		{"settings field in another case", "/plans", `{"op":"config.set","kind":"group","set":{"name":"a","Name":"b","enabled":true}}`, "Name", ""},
		{"duplicate set key", "/plans", `{"op":"config.set","kind":"group","set":{"name":"x","name":"y","enabled":true}}`, "set.name", "duplicate_key"},
		{"duplicate top-level key", "/plans", `{"op":"analysis.run","op":"analysis.run"}`, "op", "duplicate_key"},
		{"duplicate rule key", "/plans", project(`{"kind":"repo_name","pattern":"a","pattern":"b"}`), "set.rules[0].pattern", "duplicate_key"},
		{"duplicate label key", "/plans", label(`{"session_id":"` + analysisOwnID + `","task_type":"bug_fix","task_type":"feature"}`), "args.labels[0].task_type", "duplicate_key"},
		{"duplicate args key", "/plans", `{"op":"weekly.regenerate","args":{"week":"2026-11-02","week":"2026-10-26"}}`, "args.week", "duplicate_key"},
		{"duplicate test-model key", "/analysis/test-model", `{"set":{"llm.model":"a","llm.model":"b"}}`, "set.llm.model", "duplicate_key"},
		{"duplicate key-set key", "/config/analysis-settings/api-key", `{"api_key":"first-0007","api_key":"second-0008"}`, "api_key", "duplicate_key"},
	} {
		method := http.MethodPost
		if strings.HasSuffix(test.path, "api-key") {
			method = http.MethodPut
		}
		response := fixture.facade(method, test.path, test.body, fixture.adminWrite)
		body := failure(t, response)
		if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != test.field || (test.reason != "" && body.Details["reason"] != test.reason) {
			t.Errorf("%s = %s %v", test.name, body.Code, body.Details)
		}
		if strings.Contains(response.Body.String(), "second-0008") || strings.Contains(response.Body.String(), "first-0007") {
			t.Errorf("%s echoed a key value", test.name)
		}
	}
	// The exact spellings are accepted.
	fixture.plan(t, project(`{"kind":"repo_name","pattern_untrusted":"exact"}`))
}
