package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"
)

// Error mapping of the write facade (contract sections 2.3 and 4.5). The
// services' typed errors carry a safe message, the offending field and a
// stable reason; the facade passes them on and never the error text of
// anything else.

// agentFailure is a fully described refusal.
type agentFailure struct {
	Code    agentapi.Code
	Message string
	Hint    string
	Details map[string]any
}

func (failure *agentFailure) Error() string { return "agent facade: " + string(failure.Code) }

func (failure *agentFailure) write(writer http.ResponseWriter) {
	writeAgentFailure(writer, failure.Code, failure.Message, failure.Hint, failure.Details)
}

// fieldFailure is an INVALID_ARGUMENT naming field.
func fieldFailure(field, message string) *agentFailure {
	return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: message, Details: map[string]any{"field": field}}
}

func validationFailure(code agentapi.Code, field, reason, message string) *agentFailure {
	details := map[string]any{}
	if field != "" {
		details["field"] = field
	}
	if reason != "" {
		details["reason"] = reason
	}
	return &agentFailure{Code: code, Message: message, Details: details}
}

// agentWriteFailure classifies an error of a write: typed service errors
// first, then the read facade's classification.
func agentWriteFailure(err error) *agentFailure {
	var failure *agentFailure
	if errors.As(err, &failure) {
		return failure
	}
	var (
		uaInvalid      *uaguard.ValidationError
		uaExists       *uaguard.AlreadyExistsError
		policyInvalid  *contentpolicy.ValidationError
		policyExists   *contentpolicy.AlreadyExistsError
		orgInvalid     *orgreport.ValidationError
		orgSettings    *orgreport.SettingsError
		analysisSet    *sessionanalysis.SettingsError
		calibrationBad *sessionanalysis.LabelError
		keyTarget      *sessionanalysis.KeyTargetError
		argument       agentArgError
	)
	switch {
	case errors.As(err, &argument):
		return fieldFailure(argument.field, "")
	case errors.Is(err, uaguard.ErrVersionConflict), errors.Is(err, contentpolicy.ErrVersionConflict),
		errors.Is(err, orgreport.ErrVersionConflict), errors.Is(err, sessionanalysis.ErrVersionConflict):
		return &agentFailure{Code: agentapi.CodeVersionConflict}
	case errors.As(err, &uaExists):
		return &agentFailure{Code: agentapi.CodeAlreadyExists, Details: map[string]any{"id": strconv.FormatInt(uaExists.ID, 10)}}
	case errors.As(err, &policyExists):
		return &agentFailure{Code: agentapi.CodeAlreadyExists, Details: map[string]any{"id": strconv.FormatInt(policyExists.ID, 10)}}
	case errors.As(err, &uaInvalid):
		return validationFailure(agentapi.CodeInvalidArgument, uaInvalid.Field, uaInvalid.Reason, uaInvalid.Message)
	case errors.As(err, &policyInvalid):
		return validationFailure(agentapi.CodeInvalidArgument, policyInvalid.Field, policyInvalid.Reason, policyInvalid.Message)
	case errors.As(err, &orgInvalid):
		code := agentapi.CodeInvalidArgument
		if orgInvalid.Conflict {
			code = agentapi.CodeConflict
		}
		return validationFailure(code, orgInvalid.Field, orgInvalid.Reason, orgInvalid.Message)
	case errors.As(err, &orgSettings):
		return validationFailure(agentapi.CodeInvalidArgument, orgSettings.Field, orgSettings.Reason, orgSettings.Message)
	case errors.Is(err, orgreport.ErrInvalidSettings):
		return validationFailure(agentapi.CodeInvalidArgument, "", "", orgreport.SettingsMessage(err))
	case errors.As(err, &analysisSet):
		return validationFailure(agentapi.CodeInvalidArgument, analysisSet.Field, "", analysisSet.Message)
	case errors.Is(err, sessionanalysis.ErrInvalidSettings):
		return validationFailure(agentapi.CodeInvalidArgument, "", "", sessionanalysis.SettingsMessage(err))
	case errors.As(err, &calibrationBad):
		field := "args.labels"
		if calibrationBad.Index >= 0 {
			field = fmt.Sprintf("args.labels[%d].%s", calibrationBad.Index, calibrationBad.Field)
		}
		return validationFailure(agentapi.CodeInvalidArgument, field, "", "invalid calibration label")
	case errors.Is(err, sessionanalysis.ErrRunInProgress):
		return &agentFailure{Code: agentapi.CodeRunInProgress}
	case errors.As(err, &keyTarget):
		return &agentFailure{Code: agentapi.CodeInvalidArgument,
			Message: "the API key in use is only sent to the model address in effect; " + keyTarget.Field + " differs from it",
			Hint: "Either save the address first with `llmaudit config set --kind analysis-settings --set " + keyTarget.Field + "=<value>` and " +
				"`llmaudit apply <plan-id>` (the plan shows the new address to the user), or ask the user to run " +
				"`llmaudit analysis test-model --set " + keyTarget.Field + "=<value> --prompt-key` in their own terminal and type a key for this test.",
			Details: map[string]any{"field": keyTarget.Field, "reason": "saved_key_not_sent_to_unsaved_address"}}
	case errors.Is(err, sessionanalysis.ErrSettingsUnavailable):
		// The saved section could not be read; nothing was written.
		return &agentFailure{Code: agentapi.CodeUpstreamUnavailable}
	}
	code := agentErrorCodeOf(err)
	if code == agentapi.CodeInvalidArgument {
		return &agentFailure{Code: code, Details: map[string]any{"field": "body"}}
	}
	return &agentFailure{Code: code}
}

// agentApplyFailure classifies an error a plan's execution returned. Typed
// service errors map exactly as when the plan was made, so the same refusal
// carries the same code, field and reason at both steps. apply takes no
// body, so an otherwise unclassified refusal never names field "body": it
// says the service refused the change when it was applied and asks for a
// new plan made from the current state.
func agentApplyFailure(err error) *agentFailure {
	failure := agentWriteFailure(err)
	if failure.Code == agentapi.CodeInvalidArgument && failure.Details["field"] == "body" {
		return &agentFailure{Code: agentapi.CodeInvalidArgument,
			Message: "the service refused the change when the plan was applied",
			Hint:    "Something the plan relied on has changed since it was made. Read the current state and make a new plan.",
			Details: map[string]any{"reason": "refused_at_apply"}}
	}
	return failure
}

// writeAgentApplyFailure is writeAgentWriteFailure for the error of a plan's
// execution (agentApplyFailure).
func (handler *managementHandler) writeAgentApplyFailure(writer http.ResponseWriter, err error) agentapi.Code {
	return handler.writeFailure(writer, err, agentApplyFailure)
}

// writeAgentWriteFailure answers a failed write and returns the code it
// wrote. A cancelled request writes nothing, as the web does.
func (handler *managementHandler) writeAgentWriteFailure(writer http.ResponseWriter, err error) agentapi.Code {
	return handler.writeFailure(writer, err, agentWriteFailure)
}

func (handler *managementHandler) writeFailure(writer http.ResponseWriter, err error, classify func(error) *agentFailure) agentapi.Code {
	if errors.Is(err, context.Canceled) {
		return ""
	}
	failure := classify(err)
	if failure.Code == agentapi.CodeInternal || failure.Code == agentapi.CodeUpstreamUnavailable {
		handler.logger.Warn("agent facade write failed", "error_code", string(failure.Code), "error_class", storage.ErrorClass(err))
	}
	failure.write(writer)
	return failure.Code
}
