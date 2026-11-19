package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
)

// Plans of the write facade (contract section 4.5.1). POST /plans validates
// a change completely through the services' check-only entry points and
// stores a closure that calls the versioned write entry with the version the
// check saw; POST /plans/{plan_id}/apply runs that closure once. Nothing in
// between is rebuilt from the plan's before/after: apply executes exactly
// the change that was checked, and the service refuses it with
// VERSION_CONFLICT when the object moved in between.

// agentWriteTimeout bounds one write, like the web routes' query timeout.
const agentWriteTimeout = queryTimeout

type agentPlanTarget struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

// agentPlanView is the plan object of the contract.
type agentPlanView struct {
	PlanID      string          `json:"plan_id"`
	ExpiresAt   string          `json:"expires_at"`
	Op          string          `json:"op"`
	Target      agentPlanTarget `json:"target"`
	Creates     bool            `json:"creates"`
	ChangedKeys []string        `json:"changed_keys"`
	Before      any             `json:"before"`
	After       any             `json:"after"`
	Effects     []string        `json:"effects"`
	Extras      map[string]any  `json:"extras"`
}

// agentApplied is what an executed plan reports.
type agentApplied struct {
	ID      string
	Version string
	Result  any
}

// agentPlan is a stored plan: its public view and how to execute it.
type agentPlan struct {
	view      agentPlanView
	untrusted bool
	// quota is a process-wide limit taken when the plan is executed.
	quota   *agentaccess.Quota
	timeout time.Duration
	apply   func(context.Context) (agentApplied, error)
	// verify is the read command that shows the result.
	verify string
}

func newAgentPlan(op string, target agentPlanTarget) *agentPlan {
	return &agentPlan{
		view:    agentPlanView{Op: op, Target: target, ChangedKeys: []string{}, Effects: []string{}, Extras: map[string]any{}},
		timeout: agentWriteTimeout,
	}
}

func (plan *agentPlan) effect(text string) { plan.view.Effects = append(plan.view.Effects, text) }

type agentApplyResult struct {
	Op      string          `json:"op"`
	Target  agentPlanTarget `json:"target"`
	Applied bool            `json:"applied"`
	ID      string          `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
}

// serveAgentPlanCreate is POST /plans. It changes nothing and writes no
// audit row (contract section 3.4).
func (handler *managementHandler) serveAgentPlanCreate(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentWriteFailure(writer, err)
		return
	}
	body, err := readAgentBody(writer, request, maxAgentPlanBodyBytes)
	if err != nil {
		handler.writeAgentWriteFailure(writer, err)
		return
	}
	planRequest, err := decodeAgentPlanRequest(body)
	if err != nil {
		handler.writeAgentWriteFailure(writer, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
	defer cancel()
	plan, err := handler.agentPlanFor(ctx, planRequest)
	if err != nil {
		handler.writeAgentWriteFailure(writer, err)
		return
	}
	stored, err := handler.agentPlans.Put(call.Identity.TokenID, plan)
	if err != nil {
		writeAgentServiceError(writer, err)
		return
	}
	plan.view.PlanID = stored.ID
	plan.view.ExpiresAt = stored.ExpiresAt.UTC().Format(time.RFC3339)
	envelope := agentapi.Success(plan.view)
	if plan.untrusted {
		envelope.Notice = agentapi.UntrustedNotice
	}
	envelope.NextActions = []string{"Show this plan to the user; after they agree, run `llmaudit apply " + stored.ID + "`."}
	writeAgentOK(writer, envelope)
}

func (handler *managementHandler) agentPlanFor(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	switch request.Op {
	case agentapi.OpConfigSet:
		return handler.planConfigSet(ctx, request)
	case agentapi.OpConfigRemove:
		return handler.planConfigRemove(ctx, request)
	case agentapi.OpConfigReset:
		return handler.planConfigReset(ctx, request)
	case agentapi.OpAnalysisRun:
		return handler.planAnalysisRun(ctx)
	case agentapi.OpAnalysisCalibrate:
		return handler.planAnalysisCalibrate(request)
	case agentapi.OpAnalysisDismiss:
		return handler.planAnalysisDismiss(request)
	case agentapi.OpWeeklyRegenerate:
		return handler.planWeeklyRegenerate(ctx, request)
	}
	return nil, fieldFailure("op", "unknown op")
}

// serveAgentPlanApply is POST /plans/{plan_id}/apply. The dispatcher has
// already re-checked the token, its tier and allow_write for this request;
// the plan is taken (and so spent) before it runs, and the service checks the
// version inside its own lock.
func (handler *managementHandler) serveAgentPlanApply(writer http.ResponseWriter, request *http.Request, call agentCall) {
	planID := call.Params["plan_id"]
	audit := agentaccess.WriteAudit{Event: agentaccess.EventWriteFailed, ObjectKind: "plan", ObjectID: planID, Outcome: agentaccess.OutcomeFailed}
	record := func(code agentapi.Code) {
		if code == "" {
			// The client went away; the outcome is unknown to it, and the
			// write itself is recorded only when it is known.
			code = agentapi.CodeTimeout
		}
		audit.ErrorCode = code
		handler.agent.RecordWrite(request.Context(), call.Identity, call.Meta, audit)
	}
	if _, err := agentCallParams(request, call); err != nil {
		record(handler.writeAgentWriteFailure(writer, err))
		return
	}
	if err := emptyAgentBody(writer, request); err != nil {
		record(handler.writeAgentWriteFailure(writer, err))
		return
	}
	stored, err := handler.agentPlans.Take(call.Identity.TokenID, planID)
	if err != nil {
		writeAgentServiceError(writer, err)
		record(agentaccess.CodeOf(err))
		return
	}
	plan := stored.Payload.(*agentPlan)
	audit.ObjectKind, audit.ObjectID = plan.view.Target.Kind, plan.view.Target.ID
	if plan.quota != nil {
		if err := handler.agent.Take(*plan.quota, call.Identity); err != nil {
			writeAgentServiceError(writer, err)
			record(agentaccess.CodeOf(err))
			return
		}
	}
	// The write must not be cut short by the client going away after the
	// service accepted it; the timeout still bounds it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), plan.timeout)
	defer cancel()
	applied, err := plan.apply(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = context.DeadlineExceeded
		}
		record(handler.writeAgentWriteFailure(writer, err))
		return
	}
	target := plan.view.Target
	if applied.ID != "" {
		target.ID = applied.ID
	}
	target.Version = applied.Version
	audit.Event, audit.Outcome, audit.ObjectID = agentaccess.EventWriteApplied, agentaccess.OutcomeOK, target.ID
	audit.ChangedKeys = plan.view.ChangedKeys
	handler.agent.RecordWrite(request.Context(), call.Identity, call.Meta, audit)
	result := agentApplyResult{Op: plan.view.Op, Target: target, Applied: true, Result: applied.Result}
	if plan.view.Creates {
		result.ID = target.ID
	}
	envelope := agentapi.Success(result)
	if plan.verify != "" {
		envelope.NextActions = []string{"Check the result with `" + plan.verify + "`."}
	}
	writeAgentOK(writer, envelope)
}

// emptyAgentBody refuses a request body on an endpoint that takes none (apply
// takes nothing but the plan id).
func emptyAgentBody(writer http.ResponseWriter, request *http.Request) error {
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1024))
	trimmed := bytes.TrimSpace(body)
	if err != nil || (len(trimmed) > 0 && string(trimmed) != "{}") {
		return fieldFailure("body", "apply takes no request body")
	}
	return nil
}
