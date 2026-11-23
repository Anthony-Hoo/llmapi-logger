package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
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

// The request body limits of the facade, all of them stated here (contract
// section 0.1 item 163). Every endpoint whose method carries a body is in
// agentBodyLimits; the GET endpoints and logout do not read one.
const (
	// POST /token: {"code", "code_verifier"}.
	maxAgentTokenBodyBytes = 4 << 10
	// POST /plans: a calibration of 1000 labels, like the web route.
	maxAgentPlanBodyBytes = 512 << 10
	// POST /plans/{plan_id}/apply: nothing, or {}.
	maxAgentApplyBodyBytes = 1 << 10
	// PUT /config/analysis-settings/api-key and POST /analysis/test-model:
	// like the web route's settings body (16 KiB).
	maxAgentKeyBodyBytes = maxSettingsBodyBytes
	// POST /config/project-preview: like the web route (64 KiB).
	maxAgentPreviewBodyBytes = maxOrgBodyBytes
)

// agentBodyLimits maps every facade endpoint whose method carries a body to
// its limit; 0 is an endpoint that does not read its body.
var agentBodyLimits = map[string]int64{
	"token.exchange":            maxAgentTokenBodyBytes,
	"logout":                    0,
	agentapi.EndpointPlanCreate: maxAgentPlanBodyBytes,
	agentapi.EndpointPlanApply:  maxAgentApplyBodyBytes,
	agentapi.EndpointAPIKeySet:  maxAgentKeyBodyBytes,
	agentapi.EndpointTestModel:  maxAgentKeyBodyBytes,
	"config.project-preview":    maxAgentPreviewBodyBytes,
}

// The most JSON values a facade request body may hold, counting every
// object, array, string, number and literal and every object member (its
// key), all of them stated here (contract section 0.1 item 170). Each is
// about twice the largest legitimate body of the endpoint, worked out from
// the services' own limits; a body with more is refused before anything
// decodes it, so what the decoders below allocate is bounded by these
// numbers and not only by the size in bytes.
var (
	// A calibration label at its largest: the object, its six members (key
	// and value each) and every friction kind once.
	agentLabelValues = 1 + 2*6 + len(sessionanalysis.FrictionKinds)
	// POST /plans: the largest plan is a calibration of the most labels the
	// service accepts, inside {"op": …, "args": {"labels": […]}}.
	maxAgentPlanBodyValues = 2 * (7 + sessionanalysis.MaxCalibrationLabels*agentLabelValues)
	// POST /config/project-preview: the most rules of a project, each
	// {"kind": …, "pattern": …}, and week, group_id and project_id.
	maxAgentPreviewBodyValues = 2 * (10 + orgreport.MaxRulesPerProject*5)
	// POST /analysis/test-model: every settable field of the analysis
	// settings in set, and api_key.
	maxAgentTestModelBodyValues = 2 * (6 + 2*len(agentapi.SettableFields["analysis-settings"]))
	// POST /token ({"code", "code_verifier"}), PUT
	// /config/analysis-settings/api-key ({"api_key"}) and POST
	// /plans/{plan_id}/apply ({} or nothing) hold at most five values; 16
	// leaves room for a refusal that names the wrong key.
	maxAgentSmallBodyValues = 16
)

// agentBodyValueLimits maps every facade endpoint that reads its body to the
// most values it may hold, as agentBodyLimits does for bytes.
var agentBodyValueLimits = map[string]int{
	"token.exchange":            maxAgentSmallBodyValues,
	agentapi.EndpointPlanCreate: maxAgentPlanBodyValues,
	agentapi.EndpointPlanApply:  maxAgentSmallBodyValues,
	agentapi.EndpointAPIKeySet:  maxAgentSmallBodyValues,
	agentapi.EndpointTestModel:  maxAgentTestModelBodyValues,
	"config.project-preview":    maxAgentPreviewBodyValues,
}

// maxAgentBodyDecoders is how many bodies of plan creation, the project
// preview and the connection test the process decodes and checks at the
// same time (contract section 0.1 item 170); a request waits for a slot for
// at most agentBodyWait, and within its own context. Reads without a body
// do not take one.
const (
	maxAgentBodyDecoders = 4
	agentBodyWait        = 10 * time.Second
)

// acquireAgentBodySlot waits for one of the decoding slots. release gives
// it back and may be called more than once. A request that cannot start in
// time, or whose context ends while it waits, gets context.DeadlineExceeded:
// the facade's TIMEOUT.
func (handler *managementHandler) acquireAgentBodySlot(ctx context.Context) (func(), error) {
	slots := handler.agentBodySlots
	acquired := func() func() {
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }
	}
	select {
	case slots <- struct{}{}:
		return acquired(), nil
	default:
	}
	ctx, cancel := context.WithTimeout(ctx, agentBodyWait)
	defer cancel()
	select {
	case slots <- struct{}{}:
		return acquired(), nil
	case <-ctx.Done():
		return func() {}, context.DeadlineExceeded
	}
}

// maxAgentBodyDepth is the deepest nesting of objects and arrays a facade
// request body may have. The deepest legitimate input (a project rule in a
// plan's set, add or remove, a calibration label) has four levels; a deeper
// body is refused before any other check reads it, so the checks below
// never see more than this many levels.
const maxAgentBodyDepth = 32

const (
	reasonTooDeeplyNested = "too_deeply_nested"
	reasonTooManyValues   = "too_many_values"
	reasonTooMany         = "too_many"
)

// jsonDepth is the deepest nesting of objects and arrays in data (jsonShape).
func jsonDepth(data []byte) int {
	depth, _ := jsonShape(data)
	return depth
}

// jsonShape is the deepest nesting of objects and arrays in data and the
// number of JSON values in it, each object member's key counted as one
// more, counted in one pass without allocating; brackets and other
// characters inside strings do not count. It does not check that data is
// JSON.
func jsonShape(data []byte) (int, int) {
	depth, deepest, values := 0, 0, 0
	inString, escaped, inScalar := false, false, false
	for _, character := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == '"':
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString, inScalar = true, false
			values++
		case '{', '[':
			inScalar = false
			values++
			depth++
			if depth > deepest {
				deepest = depth
			}
		case '}', ']':
			inScalar = false
			depth--
		case ',', ':', ' ', '\t', '\n', '\r':
			inScalar = false
		default:
			// The first character of a number or a literal.
			if !inScalar {
				inScalar = true
				values++
			}
		}
	}
	return deepest, values
}

// checkAgentBodyShape refuses a body nested deeper than maxAgentBodyDepth
// and then one that holds more than maxValues values (jsonShape).
func checkAgentBodyShape(body []byte, maxValues int) error {
	depth, values := jsonShape(body)
	if depth > maxAgentBodyDepth {
		return fieldFailure("body", reasonTooDeeplyNested,
			"the request body nests objects and arrays more than "+strconv.Itoa(maxAgentBodyDepth)+" levels deep")
	}
	if values > maxValues {
		return fieldFailure("body", reasonTooManyValues,
			"the request body holds more than "+strconv.Itoa(maxValues)+" JSON values (object keys included) for this endpoint")
	}
	return nil
}

// The services' own limits on the length of each list field a plan or the
// project preview takes (contract section 0.1 item 170), checked on the raw
// array before any element is decoded: a longer list is refused, with the
// service's reason, without building anything per element. They apply to
// set, add and remove alike.
var agentListLimits = map[string]map[string]int{
	"project":         {"rules": orgreport.MaxRulesPerProject},
	"content-rule":    {"keywords": contentpolicy.MaxKeywords, "scan_scopes": len(contentpolicy.AllScanScopes)},
	"weekly-settings": {"ranked_clients": config.MaxOrgRankedClients},
}

// agentListNouns name a list's elements in the refusal.
var agentListNouns = map[string]string{"rules": "rules per project", "keywords": "keywords", "scan_scopes": "scan scopes", "ranked_clients": "ranked clients"}

// checkListLength refuses raw, the value of the list field key of kind, when
// it is an array of more elements than the service accepts. A value that is
// not an array is left to the decoder.
func checkListLength(kind, key string, raw json.RawMessage) error {
	limit, ok := agentListLimits[kind][key]
	if !ok {
		return nil
	}
	if length, isArray := jsonArrayLength(raw); isArray && length > limit {
		message := "at most " + strconv.Itoa(limit) + " " + agentListNouns[key] + " are allowed"
		if key == "rules" {
			message = "at most " + strconv.Itoa(limit) + " rules per project"
		}
		return fieldFailure(key, reasonTooMany, message)
	}
	return nil
}

// jsonArrayLength is the number of elements of the JSON array raw, counted
// in one pass without allocating; isArray is false when raw is not an
// array. raw must be valid JSON (the body has been checked).
func jsonArrayLength(raw []byte) (int, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '[' {
		return 0, false
	}
	count, depth, empty := 0, 0, true
	inString, escaped := false, false
	for _, character := range raw[1:] {
		if inString {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == '"':
				inString = false
			}
			continue
		}
		switch character {
		case ' ', '\t', '\n', '\r':
			continue
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				if !empty {
					count++
				}
				return count, true
			}
			depth--
		case ',':
			if depth == 0 {
				count++
			}
		}
		empty = false
	}
	return 0, false
}

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
// nests at most maxAgentBodyDepth levels, holds at most maxValues values and
// is exactly one JSON value in which no object repeats a key.
func readAgentBody(writer http.ResponseWriter, request *http.Request, limit int64, maxValues int) ([]byte, error) {
	body, err := readAgentBodyBytes(writer, request, limit, maxValues)
	if err != nil {
		return nil, err
	}
	return body, checkAgentBodyJSON(body)
}

// readAgentBodyBytes reads a body of at most limit bytes and checks its
// shape (checkAgentBodyShape) without decoding it.
func readAgentBodyBytes(writer http.ResponseWriter, request *http.Request, limit int64, maxValues int) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fieldFailure("body", reasonTooLarge, "the request body is too large")
		}
		return nil, err
	}
	if err := checkAgentBodyShape(body, maxValues); err != nil {
		return nil, err
	}
	return body, nil
}

// checkAgentBodyJSON checks that body is exactly one JSON value in which no
// object repeats a key.
func checkAgentBodyJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return fieldFailure("body", reasonInvalidJSON, "the request body is not valid JSON")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fieldFailure("body", reasonInvalidJSON, "the request body has data after the JSON value")
	}
	// Every object of the input, at any depth, names each key once: the
	// maps the input is read into would keep only the last.
	return checkDuplicateKeys(body)
}

// decodeObject decodes one JSON object into raw members; field names it in
// an error.
func decodeObject(raw []byte, field string) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fieldFailure(field, reasonWrongType, field+" must be a JSON object")
	}
	return members, nil
}

func decodeString(raw json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fieldFailure(field, reasonWrongType, field+" must be a JSON string")
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
			return request, fieldFailure(key, reasonUnknownField, "unknown field "+strconv.Quote(key))
		}
	}
	allowed, ok := planFields[request.Op]
	if !ok {
		return request, fieldFailure("op", reasonNotAllowedValue, "op must be one of "+strings.Join(agentapi.PlanOps, ", ")).allow(agentapi.PlanOps)
	}
	for key := range request.present {
		if key != "op" && !contains(allowed, key) {
			return request, fieldFailure(key, reasonNotUsed, key+" is not used by "+request.Op)
		}
	}
	if args, needs := planArgs[request.Op]; needs {
		for key := range request.Args {
			if !contains(args, key) {
				return request, fieldFailure("args."+key, reasonUnknownField, "unknown field args."+key)
			}
		}
		for _, key := range args {
			if _, ok := request.Args[key]; !ok {
				return request, fieldFailure("args."+key, reasonRequired, "args."+key+" is required")
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
		return 0, fieldFailure("expected_version", reasonInvalidFormat, "expected_version must be a decimal version string as config show prints it")
	}
	return version, nil
}

// isKeyField reports the API key under any of its names. The rule is shared
// with the command-line client, which refuses the same names before sending
// anything (contract section 0.1 item 177).
func isKeyField(field string) bool {
	return agentapi.IsKeyField(field)
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
			return patch, fieldFailure(key, reasonNotSettable, keyFieldMessage)
		}
		if !contains(fields, key) {
			return patch, fieldFailure(key, reasonUnknownField, "unknown field "+strconv.Quote(key)+" for kind "+kind+"; settable: "+strings.Join(fields, ", ")).allow(fields)
		}
		if bytes.Equal(bytes.TrimSpace(set[key]), []byte("null")) && (allowNull == nil || !allowNull(key)) {
			return patch, fieldFailure(key, reasonNullNotAllowed, key+" cannot be null")
		}
		var single T
		if err := strictDecode(nest(map[string]json.RawMessage{key: set[key]}), &single, ""); err != nil {
			return patch, strictFailure(err, fieldFailure(key, reasonWrongType, key+" has a value of the wrong type"))
		}
	}
	if err := strictDecode(nest(set), &patch, ""); err != nil {
		return patch, strictFailure(err, fieldFailure("set", reasonWrongType, "set cannot be decoded"))
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
			return out, fieldFailure(key, reasonNotSettable, keyFieldMessage)
		}
		if !contains(lists, key) {
			if len(lists) == 0 {
				return out, fieldFailure(key, reasonNotAListField, kind+" has no list field; "+name+" cannot be used")
			}
			return out, fieldFailure(key, reasonNotAListField, key+" is not a list field of "+kind+"; list fields: "+strings.Join(lists, ", ")).allow(lists)
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(edit[key], &elements); err != nil || elements == nil {
			return out, fieldFailure(key, reasonWrongType, name+"."+key+" must be a JSON array")
		}
		var single T
		if err := strictDecode(map[string]any{key: edit[key]}, &single, ""); err != nil {
			return out, strictFailure(err, fieldFailure(key, reasonWrongType, name+"."+key+" has an element of the wrong shape"))
		}
	}
	if err := strictDecode(edit, &out, ""); err != nil {
		return out, strictFailure(err, fieldFailure(name, reasonWrongType, name+" cannot be decoded"))
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

// strictDecode encodes value and decodes it into target: unknown fields,
// and keys that name a field only without regard to case, are refused. The
// latter is an *agentFailure naming the key under prefix; any other failure
// is the decoder's error, which the caller describes (strictFailure).
func strictDecode(value any, target any, prefix string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return readStrictJSON(encoded, target, prefix)
}

// strictFailure is the refusal of a strictDecode error: its own when it
// names a key, otherwise fallback.
func strictFailure(err error, fallback *agentFailure) *agentFailure {
	var failure *agentFailure
	if errors.As(err, &failure) {
		return failure
	}
	return fallback
}

// readOnlyFields are the fields of the read shape (config show, a plan's
// before/after and extras.deleted_object) that the server assigns: an input
// carrying one is refused with every such field named, so that a copy of a
// read object can be turned into input by deleting them.
var readOnlyFields = []string{"id", "version", "created_at", "updated_at", "user_id", "kind"}

// untrustedSuffix marks text fields in the read shape (contract section 0.1
// item 24). Input accepts "<field>_untrusted" as an alias of "<field>", so a
// read object (extras.deleted_object of a removal) can be given back as
// input.
const untrustedSuffix = "_untrusted"

// canonicalFields turns the keys of a set, add or remove object into the
// kind's field names: a "<field>_untrusted" alias becomes "<field>" (both at
// once is refused), project rule elements' "pattern_untrusted" becomes
// "pattern", and server-assigned read-only fields are refused, all of them
// named in one error. fields are the names the object may use.
func canonicalFields(kind, name string, members map[string]json.RawMessage, fields []string) (map[string]json.RawMessage, error) {
	if members == nil {
		return nil, nil
	}
	var readOnly []string
	for _, key := range sortedMemberKeys(members) {
		if contains(readOnlyFields, key) && !contains(fields, key) {
			readOnly = append(readOnly, key)
		}
	}
	if len(readOnly) > 0 {
		failure := fieldFailure(readOnly[0], reasonReadOnly, strings.Join(readOnly, ", ")+" "+pluralIs(len(readOnly))+" assigned by the server and cannot be "+
			"given; remove "+pluralIt(len(readOnly))+" from the input (a copy of a removed object is restored as a new object with a new id)")
		failure.Details["fields"] = readOnly
		return nil, failure
	}
	out := make(map[string]json.RawMessage, len(members))
	for _, key := range sortedMemberKeys(members) {
		canonical := key
		if base, ok := strings.CutSuffix(key, untrustedSuffix); ok && contains(fields, base) {
			canonical = base
			if _, both := members[base]; both {
				return nil, fieldFailure(base, reasonBothSpellings, base+" and "+key+" name the same field; give it once")
			}
		}
		value := members[key]
		if err := checkListLength(kind, canonical, value); err != nil {
			return nil, err
		}
		if kind == "project" && canonical == "rules" {
			renamed, err := canonicalProjectRules(name, value)
			if err != nil {
				return nil, err
			}
			value = renamed
		}
		out[canonical] = value
	}
	return out, nil
}

// canonicalProjectRules renames pattern_untrusted to pattern in the elements
// of a project's rules list; any other shape is left for the strict decoder.
func canonicalProjectRules(name string, raw json.RawMessage) (json.RawMessage, error) {
	var elements []json.RawMessage
	if json.Unmarshal(raw, &elements) != nil || elements == nil {
		return raw, nil
	}
	changed := false
	for index, element := range elements {
		var rule map[string]json.RawMessage
		if json.Unmarshal(element, &rule) != nil || rule == nil {
			continue
		}
		pattern, ok := rule["pattern"+untrustedSuffix]
		if !ok {
			continue
		}
		if _, both := rule["pattern"]; both {
			return nil, fieldFailure("rules["+strconv.Itoa(index)+"].pattern", reasonBothSpellings, "pattern and pattern_untrusted name the same field; give it once")
		}
		delete(rule, "pattern"+untrustedSuffix)
		rule["pattern"] = pattern
		encoded, err := json.Marshal(rule)
		if err != nil {
			return nil, fieldFailure(name, reasonWrongType, name+".rules cannot be decoded")
		}
		elements[index], changed = encoded, true
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(elements)
	if err != nil {
		return nil, fieldFailure(name, reasonWrongType, name+".rules cannot be decoded")
	}
	return encoded, nil
}

func pluralIs(count int) string {
	if count == 1 {
		return "is"
	}
	return "are"
}

func pluralIt(count int) string {
	if count == 1 {
		return "it"
	}
	return "them"
}

// canonicalPlanFields applies canonicalFields to set, add and remove of a
// config.set request.
func canonicalPlanFields(request *agentPlanRequest) error {
	var err error
	if request.Set, err = canonicalFields(request.Kind, "set", request.Set, agentapi.SettableFields[request.Kind]); err != nil {
		return err
	}
	if request.Add, err = canonicalFields(request.Kind, "add", request.Add, agentapi.ListFields[request.Kind]); err != nil {
		return err
	}
	request.Remove, err = canonicalFields(request.Kind, "remove", request.Remove, agentapi.ListFields[request.Kind])
	return err
}

// suppliedFields lists the fields set names, in the kind's field order: the
// changed keys of a create, which include a field set to its zero value.
func suppliedFields(kind string, set map[string]json.RawMessage) []string {
	supplied := []string{}
	for _, field := range agentapi.SettableFields[kind] {
		if _, ok := set[field]; ok {
			supplied = append(supplied, field)
		}
	}
	return supplied
}

// checkListConflicts refuses a field named both in set and in add or remove.
func checkListConflicts(request agentPlanRequest) error {
	for _, edit := range []map[string]json.RawMessage{request.Add, request.Remove} {
		for key := range edit {
			if _, ok := request.Set[key]; ok {
				return fieldFailure(key, reasonSetAndEdited, key+" cannot be both set and edited with add or remove")
			}
		}
	}
	return nil
}
