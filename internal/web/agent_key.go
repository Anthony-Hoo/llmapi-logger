package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/sessionanalysis"
)

// The two writes that do not go through a plan (contract section 4.5.3):
// setting the analysis model's API key, and the connection test. A plan
// echoes its content back, so a key never goes into one; clearing the key
// carries no value and is a plan (config.clear-key, agent_plan_config.go). The key is
// read from the body into a string that goes to the service and nowhere
// else: no response, log line, audit row or error message contains it.

const agentKeyObject = "analysis-settings"

// agentTestModelBodyFields are the fields of the test-model body.
var agentTestModelBodyFields = []string{"set", "api_key"}

type agentKeySource struct {
	APIKey string `json:"api_key"`
}

func (handler *managementHandler) recordKeyWrite(request *http.Request, call agentCall, keys []string, code agentapi.Code) {
	audit := agentaccess.WriteAudit{Event: agentaccess.EventWriteApplied, ObjectKind: agentKeyObject, ChangedKeys: keys, Outcome: agentaccess.OutcomeOK}
	if code != "" {
		audit.Event, audit.Outcome, audit.ErrorCode, audit.ChangedKeys = agentaccess.EventWriteFailed, agentaccess.OutcomeFailed, code, keys
	}
	handler.agent.RecordWrite(request.Context(), call.Identity, call.Meta, audit)
}

// failKeyWrite answers a failed key or test request and records it.
func (handler *managementHandler) failKeyWrite(writer http.ResponseWriter, request *http.Request, call agentCall, keys []string, err error) {
	code := handler.writeAgentWriteFailure(writer, err)
	if code == "" {
		code = agentapi.CodeTimeout
	}
	handler.recordKeyWrite(request, call, keys, code)
}

// serveAgentAPIKeySet is PUT /config/analysis-settings/api-key, body
// {"api_key": "…"}. Every other setting stays as it is.
func (handler *managementHandler) serveAgentAPIKeySet(writer http.ResponseWriter, request *http.Request, call agentCall) {
	keys := []string{"api_key"}
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	body, err := readAgentBody(writer, request, maxAgentKeyBodyBytes)
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	members, err := decodeObject(body, "body")
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	var key string
	for name, raw := range members {
		if name != "api_key" {
			handler.failKeyWrite(writer, request, call, keys, fieldFailure(name, reasonUnknownField, "the only field is api_key"))
			return
		}
		if json.Unmarshal(raw, &key) != nil {
			handler.failKeyWrite(writer, request, call, keys, fieldFailure("api_key", reasonWrongType, "api_key must be a JSON string"))
			return
		}
	}
	if key == "" {
		handler.failKeyWrite(writer, request, call, keys, fieldFailure("api_key", reasonRequired, "api_key is required and must not be empty; clearing the key is a plan: llmaudit config set-key --kind analysis-settings --clear"))
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), agentWriteTimeout)
	defer cancel()
	view, err := settings.SetAPIKey(ctx, key)
	key = ""
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	handler.recordKeyWrite(request, call, keys, "")
	envelope := agentapi.Success(agentKeySource{APIKey: view.APIKey})
	envelope.NextActions = []string{"Test the model with the saved key: `llmaudit analysis test-model`."}
	writeAgentOK(writer, envelope)
}

// serveAgentTestModel is POST /analysis/test-model, body {set?, api_key?}:
// the saved settings with set merged in (not saved), probed with api_key or,
// without it, the key in use. It is the web form's "test connection".
func (handler *managementHandler) serveAgentTestModel(writer http.ResponseWriter, request *http.Request, call agentCall) {
	var keys []string
	// Every refusal below happens before any request leaves for the model:
	// it gives back the test quota's slot (contract section 0.1 item 131).
	// Its write_failed row is capped like a write_denied row
	// (QuotaDeniedAudit): a refusal that costs no test must not let a token
	// add audit rows at the request rate.
	refuse := func(err error) {
		handler.agent.Refund(call.WriteSlot)
		code := handler.writeAgentWriteFailure(writer, err)
		if code == "" {
			code = agentapi.CodeTimeout
		}
		if handler.agent.Take(agentaccess.QuotaDeniedAudit, call.Identity) == nil {
			handler.recordKeyWrite(request, call, keys, code)
		}
	}
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		refuse(err)
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		refuse(err)
		return
	}
	body, err := readAgentBody(writer, request, maxAgentKeyBodyBytes)
	if err != nil {
		refuse(err)
		return
	}
	members, err := decodeObject(body, "body")
	if err != nil {
		refuse(err)
		return
	}
	var set map[string]json.RawMessage
	var key *string
	for _, name := range sortedMemberKeys(members) {
		switch name {
		case "set":
			if set, err = decodeObject(members[name], "set"); err != nil {
				refuse(err)
				return
			}
		case "api_key":
			var value string
			if json.Unmarshal(members[name], &value) != nil || value == "" {
				refuse(fieldFailure("api_key", reasonWrongType, "api_key must be a non-empty JSON string"))
				return
			}
			key = &value
		default:
			refuse(fieldFailure(name, reasonUnknownField, "unknown field "+name+"; the fields are "+strings.Join(agentTestModelBodyFields, ", ")))
			return
		}
	}
	set, err = canonicalFields("analysis-settings", "set", set, agentapi.SettableFields["analysis-settings"])
	if err != nil {
		refuse(err)
		return
	}
	patch, err := analysisSettingsPatch(set)
	if err != nil {
		refuse(err)
		return
	}
	keys = sortedMemberKeys(set)
	if key != nil {
		keys = append(keys, "api_key")
	}
	checkCtx, cancel := context.WithTimeout(request.Context(), agentWriteTimeout)
	_, err = settings.CheckPatch(checkCtx, sessionanalysis.AnyVersion, patch)
	cancel()
	if err != nil {
		refuse(err)
		return
	}
	// The probe has its own timeout, as on the web route. Without a key typed
	// for this request the key in use goes only to the destination in effect:
	// TestPatch refuses any other before sending anything.
	result, err := settings.TestPatch(request.Context(), patch, key)
	key = nil
	if err != nil {
		refuse(err)
		return
	}
	record := true
	if result.Error == sessionanalysis.ProbeInvalidAddress {
		// The model client refused the address: nothing was sent, so the
		// test is given back and its row is capped as for a refusal.
		handler.agent.Refund(call.WriteSlot)
		record = handler.agent.Take(agentaccess.QuotaDeniedAudit, call.Identity) == nil
	}
	audit := agentaccess.WriteAudit{Event: agentaccess.EventWriteApplied, ObjectKind: agentKeyObject, ObjectID: "test-model", ChangedKeys: keys, Outcome: agentaccess.OutcomeOK}
	if !result.OK {
		audit.Event, audit.Outcome = agentaccess.EventWriteFailed, agentaccess.OutcomeFailed
	}
	if audit.ChangedKeys == nil {
		audit.ChangedKeys = []string{}
	}
	if record {
		handler.agent.RecordWrite(request.Context(), call.Identity, call.Meta, audit)
	}
	// Like every other command's result, the test's carries meta: the probe
	// itself is complete either way; state says whether it reached the model.
	meta := agentapi.Meta{State: "ok", Complete: true}
	if !result.OK {
		meta.State = "failed"
	}
	writeAgentOK(writer, agentapi.ReadSuccess(result, meta))
}
