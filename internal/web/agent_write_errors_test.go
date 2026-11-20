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
