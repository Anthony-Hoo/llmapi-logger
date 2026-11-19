package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"llmapi-logger/internal/agentapi"
)

// The wire format of POST /plans (contract section 4.5.1, as the CLI sends
// it; section 0.1 records the details):
//
//	{"op": "config.set", "kind": "content-rule", "id": "12",
//	 "set": {"enabled": false, "llm.model": "…"},
//	 "add": {"keywords": ["…"]}, "remove": {"rules": [{"kind": "…", "pattern": "…"}]},
//	 "expected_version": "1763500000000000000",
//	 "args": {"week": "…", "suggestion_id": 42, "labels": […]}}
//
// id and expected_version are JSON strings, set keys are flat and dotted,
// add and remove map a list field to the elements to add or remove, and
// args.suggestion_id is a JSON number. Every key is checked here so an error
// names it; the values are then decoded strictly into the services' patch
// types, which do every value check.

// maxAgentPlanBodyBytes is the largest plan request: a calibration of 1000
// labels, like the web route.
const maxAgentPlanBodyBytes = 512 << 10

// agentPlanRequest is a decoded POST /plans body.
type agentPlanRequest struct {
	Op              string
	Kind            string
	ID              *string
	Set             map[string]json.RawMessage
	Add             map[string]json.RawMessage
	Remove          map[string]json.RawMessage
	ExpectedVersion *string
	Args            map[string]json.RawMessage
	present         map[string]bool
}

// planFields are the top-level keys each op uses.
var planFields = map[string][]string{
	agentapi.OpConfigSet:         {"kind", "id", "set", "add", "remove", "expected_version"},
	agentapi.OpConfigRemove:      {"kind", "id", "expected_version"},
	agentapi.OpConfigReset:       {"kind"},
	agentapi.OpConfigClearKey:    {"kind"},
	agentapi.OpAnalysisRun:       {},
	agentapi.OpAnalysisCalibrate: {"args"},
	agentapi.OpAnalysisDismiss:   {"args"},
	agentapi.OpWeeklyRegenerate:  {"args"},
}

// planArgs are the keys of args each op requires.
var planArgs = map[string][]string{
	agentapi.OpAnalysisCalibrate: {"labels"},
	agentapi.OpAnalysisDismiss:   {"suggestion_id"},
	agentapi.OpWeeklyRegenerate:  {"week"},
}

// readAgentBody reads a JSON body of at most limit bytes and checks that it
// is exactly one JSON value.
func readAgentBody(writer http.ResponseWriter, request *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fieldFailure("body", "the request body is too large")
		}
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return nil, fieldFailure("body", "the request body is not valid JSON")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fieldFailure("body", "the request body has data after the JSON value")
	}
	return body, nil
}

// decodeObject decodes one JSON object into raw members; field names it in
// an error.
func decodeObject(raw []byte, field string) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fieldFailure(field, field+" must be a JSON object")
	}
	return members, nil
}

func decodeString(raw json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fieldFailure(field, field+" must be a JSON string")
	}
	return value, nil
}

func decodeAgentPlanRequest(body []byte) (agentPlanRequest, error) {
	members, err := decodeObject(body, "body")
	if err != nil {
		return agentPlanRequest{}, err
	}
	request := agentPlanRequest{present: map[string]bool{}}
	for _, key := range sortedMemberKeys(members) {
		raw := members[key]
		request.present[key] = true
		switch key {
		case "op":
			if request.Op, err = decodeString(raw, key); err != nil {
				return request, err
			}
		case "kind":
			if request.Kind, err = decodeString(raw, key); err != nil {
				return request, err
			}
		case "id", "expected_version":
			value, err := decodeString(raw, key)
			if err != nil {
				return request, err
			}
			if key == "id" {
				request.ID = &value
			} else {
				request.ExpectedVersion = &value
			}
		case "set", "add", "remove", "args":
			object, err := decodeObject(raw, key)
			if err != nil {
				return request, err
			}
			switch key {
			case "set":
				request.Set = object
			case "add":
				request.Add = object
			case "remove":
				request.Remove = object
			case "args":
				request.Args = object
			}
		default:
			return request, fieldFailure(key, "unknown field "+strconv.Quote(key))
		}
	}
	allowed, ok := planFields[request.Op]
	if !ok {
		return request, fieldFailure("op", "op must be one of "+strings.Join(agentapi.PlanOps, ", "))
	}
	for key := range request.present {
		if key != "op" && !contains(allowed, key) {
			return request, fieldFailure(key, key+" is not used by "+request.Op)
		}
	}
	if args, needs := planArgs[request.Op]; needs {
		for key := range request.Args {
			if !contains(args, key) {
				return request, fieldFailure("args."+key, "unknown field args."+key)
			}
		}
		for _, key := range args {
			if _, ok := request.Args[key]; !ok {
				return request, fieldFailure("args."+key, "args."+key+" is required")
			}
		}
	}
	return request, nil
}

func sortedMemberKeys(members map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(members))
	for key := range members {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}

// agentExpectedVersion parses expected_version: a decimal string of ASCII
// digits. Absent means "the version when the plan is created" (any).
func agentExpectedVersion(request agentPlanRequest, any int64) (int64, error) {
	if request.ExpectedVersion == nil {
		return any, nil
	}
	version, ok := parseAgentID(*request.ExpectedVersion, false)
	if !ok {
		return 0, fieldFailure("expected_version", "expected_version must be a decimal version string as config show prints it")
	}
	return version, nil
}

// isKeyField reports the API key under any of its names.
func isKeyField(field string) bool {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "api_key", "llm.api_key":
		return true
	}
	return false
}

const keyFieldMessage = "api_key is not a settable field: the user sets it with `llmaudit config set-key --kind analysis-settings`"

// decodeAgentSet checks the keys of set against the kind's field list and
// decodes the values strictly into T, a service patch type whose JSON names
// are the web API's. A dotted key is a nested field ("llm.model" is
// {"llm": {"model": …}}). null is refused except where it is a value
// (allowNull), because a null pointer would mean "keep" and silently change
// nothing.
func decodeAgentSet[T any](kind string, set map[string]json.RawMessage, allowNull func(string) bool) (T, error) {
	var patch T
	fields := agentapi.SettableFields[kind]
	for _, key := range sortedMemberKeys(set) {
		if isKeyField(key) {
			return patch, fieldFailure(key, keyFieldMessage)
		}
		if !contains(fields, key) {
			return patch, fieldFailure(key, "unknown field "+strconv.Quote(key)+" for kind "+kind+"; settable: "+strings.Join(fields, ", "))
		}
		if bytes.Equal(bytes.TrimSpace(set[key]), []byte("null")) && (allowNull == nil || !allowNull(key)) {
			return patch, fieldFailure(key, key+" cannot be null")
		}
		var single T
		if err := strictDecode(nest(map[string]json.RawMessage{key: set[key]}), &single); err != nil {
			return patch, fieldFailure(key, key+" has a value of the wrong type")
		}
	}
	if err := strictDecode(nest(set), &patch); err != nil {
		return patch, fieldFailure("set", "set cannot be decoded")
	}
	return patch, nil
}

// decodeAgentListEdit checks the keys of an add or remove object against
// the kind's list fields and decodes it strictly into T.
func decodeAgentListEdit[T any](kind, name string, edit map[string]json.RawMessage) (T, error) {
	var out T
	lists := agentapi.ListFields[kind]
	for _, key := range sortedMemberKeys(edit) {
		if isKeyField(key) {
			return out, fieldFailure(key, keyFieldMessage)
		}
		if !contains(lists, key) {
			if len(lists) == 0 {
				return out, fieldFailure(key, kind+" has no list field; "+name+" cannot be used")
			}
			return out, fieldFailure(key, key+" is not a list field of "+kind+"; list fields: "+strings.Join(lists, ", "))
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(edit[key], &elements); err != nil || elements == nil {
			return out, fieldFailure(key, name+"."+key+" must be a JSON array")
		}
		var single T
		if err := strictDecode(map[string]any{key: edit[key]}, &single); err != nil {
			return out, fieldFailure(key, name+"."+key+" has an element of the wrong shape")
		}
	}
	if err := strictDecode(edit, &out); err != nil {
		return out, fieldFailure(name, name+" cannot be decoded")
	}
	return out, nil
}

// nest turns flat dotted keys into nested objects.
func nest(flat map[string]json.RawMessage) map[string]any {
	out := map[string]any{}
	for key, value := range flat {
		parts := strings.Split(key, ".")
		node := out
		for _, part := range parts[:len(parts)-1] {
			child, ok := node[part].(map[string]any)
			if !ok {
				child = map[string]any{}
				node[part] = child
			}
			node = child
		}
		node[parts[len(parts)-1]] = value
	}
	return out
}

func strictDecode(value any, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// checkListConflicts refuses a field named both in set and in add or remove.
func checkListConflicts(request agentPlanRequest) error {
	for _, edit := range []map[string]json.RawMessage{request.Add, request.Remove} {
		for key := range edit {
			if _, ok := request.Set[key]; ok {
				return fieldFailure(key, key+" cannot be both set and edited with add or remove")
			}
		}
	}
	return nil
}
