package web

import (
	"context"
	"encoding/json"
	"net/http"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/sessionanalysis"
)

// The two writes that do not go through a plan (contract section 4.5.3):
// setting or clearing the analysis model's API key, and the connection test.
// A plan echoes its content back, so the key never goes into one. The key is
// read from the body into a string that goes to the service and nowhere
// else: no response, log line, audit row or error message contains it.

// maxAgentKeyBodyBytes bounds the key and test bodies like the web route.
const maxAgentKeyBodyBytes = maxSettingsBodyBytes

const agentKeyObject = "analysis-settings"

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
	if _, err := agentParams(request); err != nil {
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
			handler.failKeyWrite(writer, request, call, keys, fieldFailure(name, "the only field is api_key"))
			return
		}
		if json.Unmarshal(raw, &key) != nil {
			handler.failKeyWrite(writer, request, call, keys, fieldFailure("api_key", "api_key must be a JSON string"))
			return
		}
	}
	if key == "" {
		handler.failKeyWrite(writer, request, call, keys, fieldFailure("api_key", "api_key is required and must not be empty; clear the key with DELETE"))
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

// serveAgentAPIKeyClear is DELETE /config/analysis-settings/api-key. The key
// source is then none: the configuration file's key comes back only with a
// reset, as on the web page.
func (handler *managementHandler) serveAgentAPIKeyClear(writer http.ResponseWriter, request *http.Request, call agentCall) {
	keys := []string{"api_key"}
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	if _, err := agentParams(request); err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	if err := emptyAgentBody(writer, request); err != nil {
		handler.failKeyWrite(writer, request, call, keys, fieldFailure("body", "clearing the key takes no request body"))
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), agentWriteTimeout)
	defer cancel()
	view, err := settings.ClearAPIKey(ctx)
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	handler.recordKeyWrite(request, call, keys, "")
	writeAgentOK(writer, agentapi.Success(agentKeySource{APIKey: view.APIKey}))
}

// serveAgentTestModel is POST /analysis/test-model, body {set?, api_key?}:
// the saved settings with set merged in (not saved), probed with api_key or,
// without it, the key in use. It is the web form's "test connection".
func (handler *managementHandler) serveAgentTestModel(writer http.ResponseWriter, request *http.Request, call agentCall) {
	var keys []string
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	if _, err := agentParams(request); err != nil {
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
	var set map[string]json.RawMessage
	var key *string
	for _, name := range sortedMemberKeys(members) {
		switch name {
		case "set":
			if set, err = decodeObject(members[name], "set"); err != nil {
				handler.failKeyWrite(writer, request, call, keys, err)
				return
			}
		case "api_key":
			var value string
			if json.Unmarshal(members[name], &value) != nil || value == "" {
				handler.failKeyWrite(writer, request, call, keys, fieldFailure("api_key", "api_key must be a non-empty JSON string"))
				return
			}
			key = &value
		default:
			handler.failKeyWrite(writer, request, call, keys, fieldFailure(name, "unknown field "+name+"; the body is {set?, api_key?}"))
			return
		}
	}
	patch, err := analysisSettingsPatch(set)
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	keys = sortedMemberKeys(set)
	if key != nil {
		keys = append(keys, "api_key")
	}
	checkCtx, cancel := context.WithTimeout(request.Context(), agentWriteTimeout)
	diff, err := settings.CheckPatch(checkCtx, sessionanalysis.AnyVersion, patch)
	cancel()
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	// The probe has its own timeout, as on the web route.
	result, err := handler.sessionAnalysisSettings.Test(request.Context(), sessionanalysis.SettingsUpdate{EditableSettings: diff.After, APIKey: key})
	key = nil
	if err != nil {
		handler.failKeyWrite(writer, request, call, keys, err)
		return
	}
	audit := agentaccess.WriteAudit{Event: agentaccess.EventWriteApplied, ObjectKind: agentKeyObject, ObjectID: "test-model", ChangedKeys: keys, Outcome: agentaccess.OutcomeOK}
	if !result.OK {
		audit.Event, audit.Outcome = agentaccess.EventWriteFailed, agentaccess.OutcomeFailed
	}
	if audit.ChangedKeys == nil {
		audit.ChangedKeys = []string{}
	}
	handler.agent.RecordWrite(request.Context(), call.Identity, call.Meta, audit)
	writeAgentOK(writer, agentapi.Success(result))
}
