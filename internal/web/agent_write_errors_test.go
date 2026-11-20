package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
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
		// The field is the plan's id, the only input of apply (item 133).
		if failure.Code != agentapi.CodeInvalidArgument || failure.Details["field"] != "plan_id" || failure.Details["reason"] != "refused_at_apply" ||
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

// writeArgumentCase is one refused write input and what the refusal names.
type writeArgumentCase struct {
	name, method, path string
	body               any
	field, reason      string
	// allowed is the closed set the answer lists, nil when the field takes
	// none.
	allowed []string
}

// Contract section 0.1 item 133: every INVALID_ARGUMENT of the write side
// carries details.field and a stable details.reason, and details.allowed
// when the field takes a closed set. At least one bad value for every
// settable field of every plan operation, every args field, and the
// test-model and key endpoints.
func TestEveryWriteArgumentRefusalNamesFieldAndReason(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	week := orgTestWeek.Format("2006-01-02")
	set := func(kind, id string, values map[string]any) map[string]any {
		body := map[string]any{"op": "config.set", "kind": kind, "set": values}
		if id != "" {
			body["id"] = id
		}
		return body
	}
	plan := func(name string, body any, field, reason string, allowed ...string) writeArgumentCase {
		return writeArgumentCase{name: name, method: http.MethodPost, path: "/plans", body: body, field: field, reason: reason, allowed: allowed}
	}
	label := func(values map[string]any) map[string]any {
		values["session_id"] = analysisOwnID
		return map[string]any{"op": "analysis.calibrate", "args": map[string]any{"labels": []any{values}}}
	}
	ua := func(field string, value any) map[string]any {
		return set("ua-rule", ids.uaRule, map[string]any{field: value})
	}
	content := func(field string, value any) map[string]any {
		return set("content-rule", ids.contentRule, map[string]any{field: value})
	}
	analysis := func(field string, value any) map[string]any {
		return set("analysis-settings", "", map[string]any{field: value})
	}
	weekly := func(field string, value any) map[string]any {
		return set("weekly-settings", "", map[string]any{field: value})
	}
	cases := []writeArgumentCase{
		// The request itself.
		plan("unknown op", map[string]any{"op": "config.drop"}, "op", "not_allowed_value", agentapi.PlanOps...),
		plan("unknown top-level field", map[string]any{"op": "analysis.run", "extra": 1}, "extra", "unknown_field"),
		plan("field the op does not use", map[string]any{"op": "analysis.run", "kind": "group"}, "kind", "not_used"),
		plan("unknown kind", map[string]any{"op": "config.set", "kind": "rule", "set": map[string]any{"name": "x"}}, "kind", "not_allowed_value", agentapi.WriteKinds...),
		plan("kind not resettable", map[string]any{"op": "config.reset", "kind": "group"}, "kind", "not_allowed_value", "weekly-settings", "analysis-settings"),
		plan("bad id", ua("enabled", false), "", ""),
		plan("bad expected_version", map[string]any{"op": "config.remove", "kind": "ua-rule", "id": ids.uaRule, "expected_version": "v1"}, "expected_version", "invalid_format"),
		plan("unknown settable field", set("group", ids.group, map[string]any{"colour": "red"}), "colour", "unknown_field", agentapi.SettableFields["group"]...),
		plan("api key as a field", analysis("llm.api_key", "k"), "llm.api_key", "not_settable"),
		plan("null value", ua("name", nil), "name", "null_not_allowed"),
		plan("add to a kind without lists", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "add": map[string]any{"name": []string{"x"}}}, "name", "not_a_list_field"),
		// ua-rule
		plan("ua-rule name", ua("name", " "), "name", "empty"),
		plan("ua-rule enabled", ua("enabled", "yes"), "enabled", "wrong_type"),
		plan("ua-rule model_pattern", ua("model_pattern", "("), "model_pattern", "invalid_regexp"),
		plan("ua-rule user_agent_pattern", ua("user_agent_pattern", "("), "user_agent_pattern", "invalid_regexp"),
		// content-rule
		plan("content-rule name", content("name", " "), "name", "empty"),
		plan("content-rule enabled", content("enabled", 1), "enabled", "wrong_type"),
		plan("content-rule action", content("action", "allow"), "action", "invalid_value", contentpolicy.ActionBlock, contentpolicy.ActionDryRun),
		plan("content-rule model_pattern", content("model_pattern", "("), "model_pattern", "invalid_regexp"),
		plan("content-rule scan_scopes", content("scan_scopes", []string{"everything"}), "scan_scopes", "invalid_value", contentpolicy.AllScanScopes...),
		plan("content-rule keywords", content("keywords", []string{"a\nb"}), "keywords", "invalid_character"),
		// group
		plan("group name", set("group", ids.group, map[string]any{"name": " "}), "name", "empty"),
		plan("group enabled", set("group", ids.group, map[string]any{"enabled": "no"}), "enabled", "wrong_type"),
		// project
		plan("project name", set("project", ids.project, map[string]any{"name": " "}), "name", "empty"),
		plan("project group_id", set("project", ids.project, map[string]any{"group_id": 987654}), "group_id", "unknown_group"),
		plan("project enabled", set("project", ids.project, map[string]any{"enabled": "on"}), "enabled", "wrong_type"),
		plan("project rule kind", set("project", ids.project, map[string]any{"rules": []any{map[string]any{"kind": "regex", "pattern": "x"}}}), "rules[0].kind", "invalid_value",
			orgreport.RuleRepoURL, orgreport.RuleRepoName, orgreport.RulePathGlob, orgreport.RuleAgentProject),
		// member and principal
		plan("member group_id", set("member", "7", map[string]any{"group_id": "seven"}), "group_id", "wrong_type"),
		plan("member without group_id", map[string]any{"op": "config.set", "kind": "member", "id": "7", "set": map[string]any{}}, "set", "required"),
		plan("principal class", set("principal", "user:7", map[string]any{"class": "robot"}), "class", "invalid_value", orgreport.ClassHuman, orgreport.ClassService),
		plan("principal id", set("principal", "robot:7", map[string]any{"class": "human"}), "id", "invalid_format"),
		// weekly-settings
		plan("weekly idle_gap_seconds", weekly("idle_gap_seconds", 0), "idle_gap_seconds", "invalid_value"),
		plan("weekly ranked_clients", weekly("ranked_clients", []string{"unknown-client"}), "ranked_clients", "unknown_client", "claude-code", "codex", "opencode"),
		plan("weekly max_concurrent_roots", weekly("max_concurrent_roots", 0), "max_concurrent_roots", "invalid_value"),
		plan("weekly max_single_request_roots", weekly("max_single_request_roots", -1), "max_single_request_roots", "invalid_value"),
		// analysis-settings
		plan("analysis run_at", analysis("run_at", "25:00"), "run_at", "invalid_format"),
		plan("analysis l1_settle_hours", analysis("l1_settle_hours", 999), "l1_settle_hours", "out_of_range"),
		plan("analysis llm.enabled", analysis("llm.enabled", "true"), "llm.enabled", "wrong_type"),
		plan("analysis llm.base_url", analysis("llm.base_url", "ftp://127.0.0.1/v1"), "llm.base_url", "invalid_format"),
		plan("analysis llm.base_url not local", analysis("llm.base_url", "https://llm.example.com/v1"), "llm.base_url", "not_local_address"),
		plan("analysis llm.model", analysis("llm.model", " "), "llm.model", "required"),
		plan("analysis llm.structured_output", analysis("llm.structured_output", "xml"), "llm.structured_output", "not_allowed_value", sessionanalysis.StructuredOutputs...),
		plan("analysis llm.context_tokens", analysis("llm.context_tokens", 10), "llm.context_tokens", "out_of_range"),
		plan("analysis llm.disable_thinking", analysis("llm.disable_thinking", 1), "llm.disable_thinking", "wrong_type"),
		plan("analysis llm.max_output_tokens", analysis("llm.max_output_tokens", 1), "llm.max_output_tokens", "out_of_range"),
		plan("analysis llm.max_concurrency", analysis("llm.max_concurrency", 0), "llm.max_concurrency", "out_of_range"),
		plan("analysis llm.timeout_seconds", analysis("llm.timeout_seconds", 0), "llm.timeout_seconds", "out_of_range"),
		plan("analysis llm.max_sessions_per_run", analysis("llm.max_sessions_per_run", 0), "llm.max_sessions_per_run", "out_of_range"),
		// args
		plan("week missing", map[string]any{"op": "weekly.regenerate", "args": map[string]any{}}, "args.week", "required"),
		plan("week format", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "last"}}, "args.week", "invalid_format"),
		plan("week not ended", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": orgTestWeek.AddDate(0, 0, 14).Format("2006-01-02")}}, "args.week", "week_not_ended"),
		plan("suggestion_id", map[string]any{"op": "analysis.dismiss", "args": map[string]any{"suggestion_id": "42"}}, "args.suggestion_id", "invalid_format"),
		plan("unknown args field", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week, "group": 1}}, "args.group", "unknown_field"),
		plan("labels not a list", map[string]any{"op": "analysis.calibrate", "args": map[string]any{"labels": "x"}}, "args.labels", "wrong_type"),
		plan("labels empty", map[string]any{"op": "analysis.calibrate", "args": map[string]any{"labels": []any{}}}, "args.labels", "out_of_range"),
		plan("label session_id", map[string]any{"op": "analysis.calibrate", "args": map[string]any{"labels": []any{map[string]any{"session_id": "submitted-value-0009"}}}}, "args.labels[0].session_id", "invalid_format"),
		plan("label task_type", label(map[string]any{"task_type": "bugfix"}), "args.labels[0].task_type", "not_allowed_value", sessionanalysis.TaskTypes...),
		plan("label outcome", label(map[string]any{"outcome": "done"}), "args.labels[0].outcome", "not_allowed_value", sessionanalysis.Outcomes...),
		plan("label collaboration", label(map[string]any{"collaboration": "pair"}), "args.labels[0].collaboration", "not_allowed_value", sessionanalysis.Collaborations...),
		plan("label work_relevance", label(map[string]any{"work_relevance": "hobby"}), "args.labels[0].work_relevance", "not_allowed_value", sessionanalysis.WorkRelevances...),
		plan("label friction", label(map[string]any{"friction": []string{"slow"}}), "args.labels[0].friction", "not_allowed_value", sessionanalysis.FrictionKinds...),
		plan("label wrong type", label(map[string]any{"task_type": 3}), "args.labels[0]", "wrong_type"),
		// test-model and the key
		{name: "test-model unknown field", method: http.MethodPost, path: "/analysis/test-model", body: map[string]any{"bogus": 1}, field: "bogus", reason: "unknown_field"},
		{name: "test-model empty key", method: http.MethodPost, path: "/analysis/test-model", body: map[string]any{"api_key": ""}, field: "api_key", reason: "wrong_type"},
		{name: "test-model set field", method: http.MethodPost, path: "/analysis/test-model", body: map[string]any{"set": map[string]any{"llm.timeout_seconds": 0}}, field: "llm.timeout_seconds", reason: "out_of_range"},
		{name: "test-model unknown set field", method: http.MethodPost, path: "/analysis/test-model", body: map[string]any{"set": map[string]any{"llm.colour": 1}}, field: "llm.colour", reason: "unknown_field",
			allowed: agentapi.SettableFields["analysis-settings"]},
		{name: "test-model saved key elsewhere", method: http.MethodPost, path: "/analysis/test-model", body: map[string]any{"set": map[string]any{"llm.base_url": "http://127.0.0.1:9/v1"}}, field: "llm.base_url", reason: "saved_key_not_sent_to_unsaved_address"},
		{name: "key unknown field", method: http.MethodPut, path: "/config/analysis-settings/api-key", body: map[string]any{"key": "x"}, field: "key", reason: "unknown_field"},
		{name: "key empty", method: http.MethodPut, path: "/config/analysis-settings/api-key", body: map[string]any{"api_key": ""}, field: "api_key", reason: "required"},
		{name: "key wrong type", method: http.MethodPut, path: "/config/analysis-settings/api-key", body: map[string]any{"api_key": 5}, field: "api_key", reason: "wrong_type"},
		{name: "key body not JSON", method: http.MethodPut, path: "/config/analysis-settings/api-key", body: "{", field: "body", reason: "invalid_json"},
	}
	cases[5] = plan("bad id", set("ua-rule", "first", map[string]any{"enabled": false}), "id", "invalid_format")
	for _, test := range cases {
		response := fixture.facade(test.method, test.path, test.body, fixture.adminWrite)
		body := failure(t, response)
		// No refusal repeats a submitted value or a service's internal text.
		if text := response.Body.String(); strings.Contains(text, "submitted-value-0009") || strings.Contains(text, "invalid request") {
			t.Errorf("%s repeats input or internal text: %s", test.name, text)
		}
		if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != test.field || body.Details["reason"] != test.reason {
			t.Errorf("%s = %s %v %q", test.name, body.Code, body.Details, body.Message)
			continue
		}
		allowed, _ := body.Details["allowed"].([]any)
		if len(allowed) != len(test.allowed) {
			t.Errorf("%s allowed = %v, want %v", test.name, body.Details["allowed"], test.allowed)
			continue
		}
		for index, value := range test.allowed {
			if allowed[index] != value {
				t.Errorf("%s allowed = %v, want %v", test.name, allowed, test.allowed)
				break
			}
		}
	}
	// The token exchange's body.
	exchange := fixture.do(http.MethodPost, agentapi.PathPrefix+"/token", `{"code":`, agentCaller{}, agentapi.HeaderCLIVersion, agentapi.LatestVersion)
	if body := failure(t, exchange); body.Details["field"] != "body" || body.Details["reason"] != "invalid_json" {
		t.Errorf("exchange body = %v", body.Details)
	}
}
