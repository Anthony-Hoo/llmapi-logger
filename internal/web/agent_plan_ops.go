package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

// analysis.run, analysis.calibrate, analysis.dismiss and weekly.regenerate
// (contract section 4.5.1). None of them has a check-only twin in its
// service; the plan checks what the table of section 4.5.1 lists and the
// service decides the rest when the plan is applied.

func (handler *managementHandler) agentAnalysisRunner() (AgentAnalysisRunner, error) {
	if handler.sessionAnalysis == nil {
		return nil, &agentFailure{Code: agentapi.CodeModuleDisabled, Details: map[string]any{"module": agentModuleSessionAnalysis}}
	}
	runner, ok := handler.sessionAnalysis.(AgentAnalysisRunner)
	if !ok {
		return nil, errAgentUnavailable
	}
	return runner, nil
}

func quota(value agentaccess.Quota) *agentaccess.Quota { return &value }

func (handler *managementHandler) planAnalysisRun(ctx context.Context) (*agentPlan, error) {
	runner, err := handler.agentAnalysisRunner()
	if err != nil {
		return nil, err
	}
	state, err := runner.RunState(ctx)
	if err != nil {
		return nil, err
	}
	if !state.Available {
		return nil, &agentFailure{Code: agentapi.CodeUpstreamUnavailable, Message: "the session analysis runner is not available on this deployment"}
	}
	plan := newAgentPlan(agentapi.OpAnalysisRun, agentPlanTarget{Kind: "analysis-run"})
	plan.view.Extras["running"] = state.Running
	plan.view.Extras["last_run"] = agentRunSummaryOf(state.LastRun)
	plan.effect("Starts a session analysis run in the background; it returns at once. Follow it with `llmaudit analysis overview --since 1d`.")
	if state.Running {
		plan.effect("A run is in progress now: applying this plan fails with RUN_IN_PROGRESS unless that run has finished.")
	}
	plan.quota = quota(agentaccess.QuotaAnalysisRun)
	plan.verify = "llmaudit analysis overview --since 1d"
	plan.apply = func(context.Context) (agentApplied, error) {
		return agentApplied{}, handler.sessionAnalysis.TriggerRun()
	}
	return plan, nil
}

func (handler *managementHandler) planAnalysisCalibrate(request agentPlanRequest) (*agentPlan, error) {
	runner, err := handler.agentAnalysisRunner()
	if err != nil {
		return nil, err
	}
	var labels []sessionanalysis.CalibrationLabel
	var elements []json.RawMessage
	if err := json.Unmarshal(request.Args["labels"], &elements); err != nil || elements == nil {
		return nil, fieldFailure("args.labels", "args.labels must be a JSON array of labels")
	}
	for index, element := range elements {
		var label sessionanalysis.CalibrationLabel
		if err := strictDecode(element, &label); err != nil {
			return nil, fieldFailure("args.labels["+formatAgentID(int64(index))+"]", "a label has an unknown field or a value of the wrong type")
		}
		labels = append(labels, label)
	}
	if err := sessionanalysis.ValidateCalibrationLabels(labels); err != nil {
		return nil, err
	}
	if !runner.CalibrationAvailable() {
		return nil, calibrationUnavailable("")
	}
	plan := newAgentPlan(agentapi.OpAnalysisCalibrate, agentPlanTarget{Kind: "analysis-calibration"})
	plan.view.Extras["labels"] = len(labels)
	plan.effect("Compares these labels with the stored facets of the current model and saves the agreement per field; fields below the agreement bar are hidden from reports.")
	plan.verify = "llmaudit analysis overview --since 1d"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		// The model stage may have been switched off since the plan was made:
		// the refusal is the plan step's, with what to do next.
		const again = "The model stage was switched off after this plan was made. Enable it (`llmaudit config set --kind analysis-settings --set llm.enabled=true`), then make a new calibration plan."
		if !runner.CalibrationAvailable() {
			return agentApplied{}, calibrationUnavailable(again)
		}
		result, err := handler.sessionAnalysis.Calibrate(ctx, labels)
		if err != nil {
			if errors.Is(err, query.ErrInvalidQuery) && !runner.CalibrationAvailable() {
				return agentApplied{}, calibrationUnavailable(again)
			}
			return agentApplied{}, err
		}
		return agentApplied{Result: agentCalibration{PromptVersion: result.PromptVersion, Model: result.Model, Labels: result.Labels,
			Samples: result.Samples, Compared: copyCounts(result.Compared), Agreement: copyCounts(result.Agreement),
			HiddenFields: append([]string{}, result.HiddenFields...), CreatedAt: agentTime(result.CreatedNS)}}, nil
	}
	return plan, nil
}

// calibrationUnavailable is the refusal of a calibration while the model
// stage is off, at plan time and, with hint, at apply time.
func calibrationUnavailable(hint string) *agentFailure {
	return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "calibration needs the model stage: it is not enabled", Hint: hint,
		Details: map[string]any{"field": "llm.enabled", "reason": "model_stage_disabled"}}
}

func (handler *managementHandler) planAnalysisDismiss(request agentPlanRequest) (*agentPlan, error) {
	if _, err := handler.agentAnalysisRunner(); err != nil {
		return nil, err
	}
	// A JSON number only: json.Number would also take a numeric string.
	raw := bytes.TrimSpace(request.Args["suggestion_id"])
	var number json.Number
	if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &number) != nil {
		return nil, fieldFailure("args.suggestion_id", "args.suggestion_id must be a positive integer, written as a JSON number")
	}
	id, ok := parseAgentID(number.String(), false)
	if !ok || id <= 0 {
		return nil, fieldFailure("args.suggestion_id", "args.suggestion_id must be a positive integer, written as a JSON number")
	}
	plan := newAgentPlan(agentapi.OpAnalysisDismiss, agentPlanTarget{Kind: "analysis-suggestion", ID: formatAgentID(id)})
	plan.effect("Marks the suggestion dismissed in the weekly review. Only all-keys and project suggestions can be dismissed; the service decides when the plan is applied.")
	plan.verify = "llmaudit analysis report"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		err := handler.sessionAnalysis.DismissSuggestion(ctx, id)
		if err != nil && agentErrorCodeOf(err) == agentapi.CodeNotFound {
			return agentApplied{}, &agentFailure{Code: agentapi.CodeNotFound, Message: "no suggestion with this id can be dismissed",
				Hint: "List the open suggestions with `llmaudit analysis report`; only all-keys and project suggestions can be dismissed."}
		}
		return agentApplied{}, err
	}
	return plan, nil
}

// retentionEffect describes, for a week that starts before the retention
// window, what regenerating it does. The web route regenerates such a week
// too; the plan makes the loss visible before the user agrees. Retention
// deletes requests by their start time, and a regenerated snapshot is
// computed only from the requests still stored, so the requests of the week
// that started before the cutoff are missing from it. "" when the week is
// inside the window or nothing is ever deleted.
func (handler *managementHandler) retentionEffect(state orgreport.WeekState) string {
	if handler.retentionDays <= 0 {
		return ""
	}
	cutoff := handler.agent.Now().Add(-time.Duration(handler.retentionDays) * 24 * time.Hour)
	if state.StartNS >= cutoff.UnixNano() {
		return ""
	}
	days := strconv.Itoa(handler.retentionDays)
	lost := "the requests of this week that started before " + cutoff.UTC().Format(time.RFC3339) + " have been deleted"
	if state.EndNS <= cutoff.UnixNano() {
		lost = "every request of this week has been deleted"
	}
	text := "This week is older than the retention window (retention_days = " + days + "): " + lost +
		", so the new snapshot counts only the requests still stored"
	if state.Frozen {
		return text + " and replaces the frozen one; what the frozen snapshot counted for the deleted requests is lost and cannot be recovered."
	}
	return text + "."
}

type agentWeekState struct {
	Week        string  `json:"week"`
	StartAt     *string `json:"start_at"`
	EndAt       *string `json:"end_at"`
	Ended       bool    `json:"ended"`
	Frozen      bool    `json:"frozen"`
	FrozenAt    *string `json:"frozen_at"`
	GeneratedAt *string `json:"generated_at"`
}

func (handler *managementHandler) planWeeklyRegenerate(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	week, err := decodeString(request.Args["week"], "args.week")
	if err != nil {
		return nil, err
	}
	if failure := handler.agentWeekFailure(week, "args.week"); failure != nil {
		return nil, failure
	}
	state, err := org.WeekState(ctx, week)
	if errors.Is(err, orgreport.ErrInvalid) {
		return nil, fieldFailure("args.week", "args.week is not a report week")
	}
	if err != nil {
		return nil, err
	}
	if !state.Ended {
		return nil, &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "only an ended week can be regenerated",
			Details: map[string]any{"field": "args.week", "reason": "week_not_ended"}}
	}
	// The version is the stored state the plan shows (frozen, frozen_at,
	// generated_at): a freeze or regeneration in between is a conflict, not
	// a replacement of a snapshot the user never saw.
	version := state.Version()
	plan := newAgentPlan(agentapi.OpWeeklyRegenerate, agentPlanTarget{Kind: "weekly-report", ID: state.Week, Version: agentVersion(version)})
	plan.view.Extras["week"] = agentWeekState{Week: state.Week, StartAt: agentTime(state.StartNS), EndAt: agentTime(state.EndNS),
		Ended: state.Ended, Frozen: state.Frozen, FrozenAt: agentTime(state.FrozenAtNS), GeneratedAt: agentTime(state.GeneratedAtNS)}
	if state.Frozen {
		plan.effect("Replaces the frozen snapshot of this week with one computed from the current catalog and evidence.")
	} else {
		plan.effect("Freezes this week now with a snapshot computed from the current catalog and evidence.")
	}
	if effect := handler.retentionEffect(state); effect != "" {
		plan.effect(effect)
	}
	plan.quota = quota(agentaccess.QuotaRegenerate)
	plan.timeout = orgRegenerateTimeout
	plan.verify = "llmaudit weekly report --week " + state.Week
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		if err := org.RegenerateIfVersion(ctx, week, version); err != nil {
			return agentApplied{}, err
		}
		after, err := org.WeekState(ctx, week)
		if err != nil {
			// The week was regenerated; only its new version is unknown.
			return agentApplied{}, nil
		}
		return agentApplied{Version: agentVersion(after.Version())}, nil
	}
	return plan, nil
}
