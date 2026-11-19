package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/orgreport"
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
		return nil, &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "calibration needs the model stage: it is not enabled",
			Details: map[string]any{"field": "llm.enabled", "reason": "model_stage_disabled"}}
	}
	plan := newAgentPlan(agentapi.OpAnalysisCalibrate, agentPlanTarget{Kind: "analysis-calibration"})
	plan.view.Extras["labels"] = len(labels)
	plan.effect("Compares these labels with the stored facets of the current model and saves the agreement per field; fields below the agreement bar are hidden from reports.")
	plan.verify = "llmaudit analysis overview --since 1d"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		result, err := handler.sessionAnalysis.Calibrate(ctx, labels)
		if err != nil {
			return agentApplied{}, err
		}
		return agentApplied{Result: agentCalibration{PromptVersion: result.PromptVersion, Model: result.Model, Labels: result.Labels,
			Samples: result.Samples, Compared: copyCounts(result.Compared), Agreement: copyCounts(result.Agreement),
			HiddenFields: append([]string{}, result.HiddenFields...), CreatedAt: agentTime(result.CreatedNS)}}, nil
	}
	return plan, nil
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
	if handler.retentionDays > 0 {
		cutoff := handler.agent.Now().Add(-time.Duration(handler.retentionDays) * 24 * time.Hour)
		if state.StartNS < cutoff.UnixNano() {
			return nil, &agentFailure{Code: agentapi.CodeInvalidArgument,
				Message: "the week starts before the retention period: its evidence has been deleted, so regenerating it would lose data",
				Details: map[string]any{"field": "args.week", "reason": "past_retention", "retention_days": handler.retentionDays}}
		}
	}
	plan := newAgentPlan(agentapi.OpWeeklyRegenerate, agentPlanTarget{Kind: "weekly-report", ID: state.Week})
	plan.view.Extras["week"] = agentWeekState{Week: state.Week, StartAt: agentTime(state.StartNS), EndAt: agentTime(state.EndNS),
		Ended: state.Ended, Frozen: state.Frozen, FrozenAt: agentTime(state.FrozenAtNS), GeneratedAt: agentTime(state.GeneratedAtNS)}
	if state.Frozen {
		plan.effect("Replaces the frozen snapshot of this week with one computed from the current catalog and evidence.")
	} else {
		plan.effect("Freezes this week now with a snapshot computed from the current catalog and evidence.")
	}
	plan.quota = quota(agentaccess.QuotaRegenerate)
	plan.timeout = orgRegenerateTimeout
	plan.verify = "llmaudit weekly report --week " + state.Week
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		return agentApplied{}, handler.org.Regenerate(ctx, week)
	}
	return plan, nil
}
