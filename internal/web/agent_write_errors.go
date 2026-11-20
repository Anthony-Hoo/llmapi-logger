package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

// Reasons of the write facade's INVALID_ARGUMENT answers (contract section
// 0.1 item 133), beyond those of the read side (agent_params.go) and of the
// services' typed errors, which pass through unchanged. Every write-side
// INVALID_ARGUMENT carries details.field and details.reason, and
// details.allowed when the field takes a closed set of values.
const (
	reasonWrongType      = "wrong_type"
	reasonInvalidJSON    = "invalid_json"
	reasonTooLarge       = "too_large"
	reasonNotUsed        = "not_used"
	reasonNotSettable    = "not_settable"
	reasonNotAListField  = "not_a_list_field"
	reasonNullNotAllowed = "null_not_allowed"
	reasonReadOnly       = "read_only"
	reasonBothSpellings  = "both_spellings"
	reasonSetAndEdited   = "set_and_edited"
	reasonInvalidValue   = "invalid_value"
)

// fieldFailure is an INVALID_ARGUMENT naming field, with a reason.
func fieldFailure(field, reason, message string) *agentFailure {
	return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: message, Details: map[string]any{"field": field, "reason": reason}}
}

// allow adds details.allowed, the values the field accepts.
func (failure *agentFailure) allow(values []string) *agentFailure {
	if len(values) > 0 {
		if failure.Details == nil {
			failure.Details = map[string]any{}
		}
		failure.Details["allowed"] = append([]string{}, values...)
	}
	return failure
}

// principalClasses are the values of a principal's class.
var principalClasses = []string{orgreport.ClassHuman, orgreport.ClassService}

// projectRuleKinds are the kinds of a project rule.
var projectRuleKinds = []string{orgreport.RuleRepoURL, orgreport.RuleRepoName, orgreport.RulePathGlob, orgreport.RuleAgentProject}

// contentRuleActions are the actions of a keyword rule.
var contentRuleActions = []string{contentpolicy.ActionBlock, contentpolicy.ActionDryRun}

// closedSetOf returns the values a write field accepts when it takes a
// closed set, nil otherwise. field is the facade's field path; an element
// path ("rules[2].kind") names its list's element field.
func closedSetOf(field string) []string {
	if index := strings.LastIndex(field, "]."); index >= 0 {
		element := field[index+2:]
		if strings.HasPrefix(field, "rules[") && element == "kind" {
			return projectRuleKinds
		}
		if strings.HasPrefix(field, "args.labels[") {
			return sessionanalysis.LabelValues(element)
		}
		return nil
	}
	switch field {
	case "action":
		return contentRuleActions
	case "scan_scopes":
		return contentpolicy.AllScanScopes
	case "class":
		return principalClasses
	case "llm.structured_output":
		return sessionanalysis.StructuredOutputs
	}
	return nil
}

// withClosedSet adds details.allowed to a refused value of a closed-set
// field that does not list it yet.
func withClosedSet(failure *agentFailure) *agentFailure {
	if failure.Code != agentapi.CodeInvalidArgument || failure.Details["allowed"] != nil {
		return failure
	}
	switch failure.Details["reason"] {
	case reasonInvalidValue, reasonNotAllowedValue, reasonRequired:
		field, _ := failure.Details["field"].(string)
		return failure.allow(closedSetOf(field))
	}
	return failure
}

func validationFailure(code agentapi.Code, field, reason, message string) *agentFailure {
	details := map[string]any{}
	if field == "" && code == agentapi.CodeInvalidArgument {
		// A refused value the service names no field for (a rule's
		// timestamps): the change as a whole.
		field = "set"
	}
	if field != "" {
		details["field"] = field
	}
	if reason != "" {
		details["reason"] = reason
	}
	return withClosedSet(&agentFailure{Code: code, Message: message, Details: details})
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
		policyInvalid  *contentpolicy.ValidationError
		orgInvalid     *orgreport.ValidationError
		orgSettings    *orgreport.SettingsError
		analysisSet    *sessionanalysis.SettingsError
		calibrationBad *sessionanalysis.LabelError
		keyTarget      *sessionanalysis.KeyTargetError
		argument       agentArgError
	)
	switch {
	case errors.As(err, &argument):
		return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: argument.message, Details: argument.details()}
	case errors.Is(err, uaguard.ErrVersionConflict), errors.Is(err, contentpolicy.ErrVersionConflict),
		errors.Is(err, orgreport.ErrVersionConflict), errors.Is(err, sessionanalysis.ErrVersionConflict):
		return &agentFailure{Code: agentapi.CodeVersionConflict}
	case errors.As(err, &uaInvalid):
		return validationFailure(agentapi.CodeInvalidArgument, uaInvalid.Field, uaInvalid.Reason, uaInvalid.Message)
	case errors.As(err, &policyInvalid):
		return validationFailure(agentapi.CodeInvalidArgument, policyInvalid.Field, policyInvalid.Reason, policyInvalid.Message)
	case errors.As(err, &orgInvalid):
		if orgInvalid.Conflict {
			failure := validationFailure(agentapi.CodeConflict, orgInvalid.Field, orgInvalid.Reason, orgInvalid.Message)
			failure.Hint = orgConflictHint(orgInvalid.Object, orgInvalid.Reason)
			return failure
		}
		return validationFailure(agentapi.CodeInvalidArgument, orgInvalid.Field, orgInvalid.Reason, orgInvalid.Message)
	case errors.Is(err, orgreport.ErrConflict):
		// A conflict the store reported (a constraint), without a typed
		// reason: the catalog changed in a way the check could not see.
		failure := validationFailure(agentapi.CodeConflict, "", "constraint", "the change conflicts with the stored catalog")
		failure.Hint = orgConflictHint("", "constraint")
		return failure
	case errors.As(err, &orgSettings):
		return validationFailure(agentapi.CodeInvalidArgument, settingsField(orgSettings.Field), orgSettings.Reason, orgSettings.Message).allow(orgSettings.Allowed)
	case errors.Is(err, orgreport.ErrInvalidSettings):
		return validationFailure(agentapi.CodeInvalidArgument, "set", reasonInvalidValue, orgreport.SettingsMessage(err))
	case errors.As(err, &analysisSet):
		return validationFailure(agentapi.CodeInvalidArgument, settingsField(analysisSet.Field), analysisSet.Reason, analysisSet.Message).allow(analysisSet.Allowed)
	case errors.Is(err, sessionanalysis.ErrInvalidSettings):
		return validationFailure(agentapi.CodeInvalidArgument, "set", reasonInvalidValue, sessionanalysis.SettingsMessage(err))
	case errors.As(err, &calibrationBad):
		field := "args.labels"
		if calibrationBad.Index >= 0 {
			field = fmt.Sprintf("args.labels[%d].%s", calibrationBad.Index, calibrationBad.Field)
		}
		message := "invalid calibration label: " + calibrationBad.Error()
		if len(calibrationBad.Allowed) > 0 {
			message += "; " + calibrationBad.Field + " accepts " + strings.Join(calibrationBad.Allowed, ", ")
		}
		return validationFailure(agentapi.CodeInvalidArgument, field, calibrationBad.Reason, message).allow(calibrationBad.Allowed)
	case errors.Is(err, sessionanalysis.ErrRunInProgress):
		return &agentFailure{Code: agentapi.CodeRunInProgress}
	case errors.As(err, &keyTarget):
		return &agentFailure{Code: agentapi.CodeInvalidArgument,
			Message: "the API key in use is only sent to the model address in effect; " + keyTarget.Field + " differs from it",
			Hint: "Either save the address first with `llmaudit config set --kind analysis-settings --set " + keyTarget.Field + "=<value>` and " +
				"`llmaudit apply <plan-id>` (the plan shows the new address to the user), or ask the user to run " +
				"`llmaudit analysis test-model --set " + keyTarget.Field + "=<value> --prompt-key` in their own terminal and type a key for this test.",
			Details: map[string]any{"field": keyTarget.Field, "reason": "saved_key_not_sent_to_unsaved_address"}}
	case errors.Is(err, sessionanalysis.ErrSettingsUnavailable), errors.Is(err, orgreport.ErrSettingsUnavailable):
		// The saved section could not be read; nothing was written.
		return &agentFailure{Code: agentapi.CodeUpstreamUnavailable}
	}
	code := agentErrorCodeOf(err)
	if code == agentapi.CodeInvalidArgument {
		return &agentFailure{Code: code, Details: map[string]any{"field": "body", "reason": reasonRejectedByService}}
	}
	return &agentFailure{Code: code}
}

// settingsField is the field of a settings refusal; one that names no
// editable field (a value only the configuration file sets) is "set".
func settingsField(field string) string {
	if field == "" {
		return "set"
	}
	return field
}

// orgConflictHint is the next step for a CONFLICT of the org catalog. It
// names no other object's id (contract section 0.1 item 35): the read
// command lists them.
func orgConflictHint(object, reason string) string {
	const catalogList = "`llmaudit config show --kind org` lists the groups, projects and members with their group_id."
	switch reason {
	case orgreport.ReasonHasProjects:
		return "Move the group's projects to another group (`llmaudit config set --kind project --id <project-id> --set group_id=<other-group-id>`) " +
			"or remove them (`llmaudit config remove --kind project --id <project-id>`) first, then plan the removal again. " + catalogList
	case orgreport.ReasonHasMembers:
		return "Move the group's members to another group (`llmaudit config set --kind member --id <user-id> --set group_id=<other-group-id>`) " +
			"or remove them (`llmaudit config remove --kind member --id <user-id>`) first, then plan the removal again. " + catalogList
	case orgreport.ReasonDuplicate:
		switch object {
		case orgreport.ObjectGroup:
			return "Another project group has this name (names are compared without regard to case). Choose another name, or change the existing group with --id instead. " + catalogList
		case orgreport.ObjectProject:
			return "Another project in the same group (or another organisation-wide project) has this name, compared without regard to case. Choose another name, or change the existing project with --id instead. " + catalogList
		}
		return "Another entry of the catalog conflicts with this one. " + catalogList
	}
	return "The change conflicts with the catalog as it is stored now. Read it again with `llmaudit config show --kind org` and make a new plan."
}

// agentApplyFailure classifies an error a plan's execution returned. Typed
// service errors map exactly as when the plan was made, so the same refusal
// carries the same code, field and reason at both steps. apply takes no
// body, so an otherwise unclassified refusal never names field "body": it
// says the service refused the change when it was applied and asks for a
// new plan made from the current state; its field is the plan's id, the only
// input of apply.
func agentApplyFailure(err error) *agentFailure {
	failure := agentWriteFailure(err)
	if failure.Code == agentapi.CodeInvalidArgument && failure.Details["field"] == "body" {
		return &agentFailure{Code: agentapi.CodeInvalidArgument,
			Message: "the service refused the change when the plan was applied",
			Hint:    "Something the plan relied on has changed since it was made. Read the current state and make a new plan.",
			Details: map[string]any{"field": "plan_id", "reason": "refused_at_apply"}}
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
