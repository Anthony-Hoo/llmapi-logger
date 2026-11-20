package web

import (
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// Request bodies of the facade (contract section 0.1 item 163): every
// endpoint that reads a body has a size limit, nesting deeper than
// maxAgentBodyDepth is refused before any other work, and the strict input
// checks cost memory linear in the body.

// bodyEndpoints are the facade endpoints that read a body, with the method
// and path the tests call.
var bodyEndpoints = []struct {
	id, method, path string
}{
	{"token.exchange", http.MethodPost, "/token"},
	{agentapi.EndpointPlanCreate, http.MethodPost, "/plans"},
	{agentapi.EndpointPlanApply, http.MethodPost, "/plans/pln_00000000000000000000000000000000/apply"},
	{agentapi.EndpointAPIKeySet, http.MethodPut, "/config/analysis-settings/api-key"},
	{agentapi.EndpointTestModel, http.MethodPost, "/analysis/test-model"},
	{"config.project-preview", http.MethodPost, "/config/project-preview"},
}

// TestAgentBodyLimitsCoverEveryBodyEndpoint checks that every registered
// endpoint whose method carries a body is listed in agentBodyLimits, and
// that every listed limit is positive except where the body is not read.
func TestAgentBodyLimitsCoverEveryBodyEndpoint(t *testing.T) {
	registry := agentapi.NewRegistry(agentapi.Endpoints)
	for _, endpoint := range registry.Endpoints() {
		if endpoint.Method == http.MethodGet || endpoint.Method == http.MethodHead {
			continue
		}
		limit, ok := agentBodyLimits[endpoint.ID]
		if !ok {
			t.Errorf("%s %s has no entry in agentBodyLimits", endpoint.Method, endpoint.Pattern)
			continue
		}
		if limit <= 0 && endpoint.ID != "logout" {
			t.Errorf("%s has no positive body limit: %d", endpoint.ID, limit)
		}
	}
	for _, endpoint := range bodyEndpoints {
		if agentBodyLimits[endpoint.id] <= 0 {
			t.Errorf("%s reads a body but has no limit", endpoint.id)
		}
	}
}

func deeplyNested(depth int) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

// TestAgentBodyTooDeeplyNestedIsRefusedFirst sends one level more than the
// limit to every endpoint that reads a body: each answers INVALID_ARGUMENT
// with reason too_deeply_nested, and one level less is not refused for its
// depth.
func TestAgentBodyTooDeeplyNestedIsRefusedFirst(t *testing.T) {
	fixture := newWriteFixture(t)
	tooDeep := `{"x":` + deeplyNested(maxAgentBodyDepth) + `}`
	deepest := `{"x":` + deeplyNested(maxAgentBodyDepth-1) + `}`
	for _, endpoint := range bodyEndpoints {
		token := fixture.adminWrite
		if endpoint.id == "config.project-preview" {
			token = fixture.adminRead
		}
		if endpoint.id == "token.exchange" {
			token = ""
		}
		refused := failure(t, fixture.facade(endpoint.method, endpoint.path, tooDeep, token))
		if refused.Code != agentapi.CodeInvalidArgument || refused.Details["reason"] != reasonTooDeeplyNested || refused.Details["field"] != "body" {
			t.Errorf("%s: %d levels = %+v", endpoint.id, maxAgentBodyDepth+1, refused)
		}
		if within := failure(t, fixture.facade(endpoint.method, endpoint.path, deepest, token)); within.Details["reason"] == reasonTooDeeplyNested {
			t.Errorf("%s: %d levels refused for its depth", endpoint.id, maxAgentBodyDepth)
		}
	}
	// A bracket inside a string is not a level.
	if depth := jsonDepth([]byte(`{"a":"[[[[{{{{\"[[["}`)); depth != 1 {
		t.Fatalf("depth of a string with brackets = %d", depth)
	}
	// A deep refused plan creates nothing and is not counted.
	plans := fixture.handler.agentPlans.Len()
	// More than the write quota of 60 per ten minutes.
	for index := 0; index < 70; index++ {
		if code := failure(t, fixture.facade(http.MethodPost, "/plans", tooDeep, fixture.adminWrite)).Code; code != agentapi.CodeInvalidArgument {
			t.Fatalf("request %d = %s", index, code)
		}
	}
	if fixture.handler.agentPlans.Len() != plans {
		t.Fatal("a refused body created a plan")
	}
}

// TestAgentBodyLegitimateDepthIsWellInsideTheLimit builds the deepest input
// each plan kind and each other body takes and checks it uses at most a
// quarter of the depth limit.
func TestAgentBodyLegitimateDepthIsWellInsideTheLimit(t *testing.T) {
	session := strings.Repeat("a", 64)
	bodies := map[string]string{
		"config.set project rules": `{"op":"config.set","kind":"project","id":"1","set":{"name":"p","group_id":null,"enabled":true,"rules":[{"kind":"repo_name","pattern":"x"}]},` +
			`"add":{"rules":[{"kind":"repo_name","pattern":"y"}]},"remove":{"rules":[{"kind":"repo_name","pattern":"x"}]},"expected_version":"1"}`,
		"config.set content-rule lists": `{"op":"config.set","kind":"content-rule","set":{"name":"c","scan_scopes":["system"],"keywords":["k"]}}`,
		"config.set settings":           `{"op":"config.set","kind":"weekly-settings","set":{"ranked_clients":["codex"]},"add":{"ranked_clients":["opencode"]}}`,
		"config.set analysis":           `{"op":"config.set","kind":"analysis-settings","set":{"llm.model":"m","llm.max_concurrency":2}}`,
		"config.remove":                 `{"op":"config.remove","kind":"group","id":"1","expected_version":"1"}`,
		"analysis.calibrate":            `{"op":"analysis.calibrate","args":{"labels":[{"session_id":"` + session + `","task_type":"bug_fix"}]}}`,
		"analysis.dismiss":              `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`,
		"weekly.regenerate":             `{"op":"weekly.regenerate","args":{"week":"2026-01-05"}}`,
		"test-model":                    `{"set":{"llm.model":"m"},"api_key":"k"}`,
		"set-key":                       `{"api_key":"k"}`,
		"project-preview":               `{"week":"2026-01-05","group_id":null,"rules":[{"kind":"repo_name","pattern":"x"}],"project_id":1}`,
		"token":                         `{"code":"c","code_verifier":"v"}`,
	}
	for name, body := range bodies {
		if depth := jsonDepth([]byte(body)); depth*4 > maxAgentBodyDepth {
			t.Errorf("%s needs depth %d, more than a quarter of the limit %d", name, depth, maxAgentBodyDepth)
		}
	}
}

// worstCaseBody fills limit bytes with prefix, nesting at the deepest
// allowed level and as many distinct keys as fit, then closes it.
func worstCaseBody(prefix, suffix string, depth, limit int) string {
	var builder strings.Builder
	builder.WriteString(prefix)
	opened := 0
	for ; opened < depth; opened++ {
		builder.WriteString(`{"a":`)
	}
	builder.WriteString(`{`)
	closing := strings.Repeat("}", opened+1) + suffix
	for index := 0; ; index++ {
		entry := `"k` + strconv.Itoa(index) + `":0`
		if index > 0 {
			entry = "," + entry
		}
		if builder.Len()+len(entry)+len(closing) > limit {
			break
		}
		builder.WriteString(entry)
	}
	builder.WriteString(closing)
	return builder.String()
}

// longKeyAboveElements fills limit bytes with prefix and as many array
// elements as fit, then closes it.
func longKeyAboveElements(prefix, suffix string, limit int) string {
	elements := (limit - len(prefix) - len(suffix) + 1) / 2
	return prefix + strings.TrimSuffix(strings.Repeat("0,", elements), ",") + suffix
}

// TestStrictKeyCheckAllocationIsLinear calls checkExactKeys directly with a
// long key above many valid map entries and array elements: every key is
// accepted, so the check walks all of them, and the path of a key that
// passes is never built.
func TestStrictKeyCheckAllocationIsLinear(t *testing.T) {
	const maxAllocationFactor = 64
	long := strings.Repeat("q", 30<<10)
	var builder strings.Builder
	builder.WriteString(`{"` + long + `":{`)
	for index := 0; index < 4000; index++ {
		if index > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(`"k` + strconv.Itoa(index) + `":[0,0,0,0]`)
	}
	builder.WriteString(`}}`)
	data := []byte(builder.String())
	var err error
	allocated := allocatedBy(func() { err = checkExactKeys(data, reflect.TypeOf(map[string]map[string][]int{}), "set") })
	t.Logf("checkExactKeys, 30 KB key above 4000 keys: %d bytes, %d KiB allocated (%.1fx)", len(data), allocated>>10, float64(allocated)/float64(len(data)))
	if err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
	if allocated > uint64(maxAllocationFactor*len(data)) {
		t.Errorf("%d bytes allocated for %d bytes of input, more than %dx", allocated, len(data), maxAllocationFactor)
	}
	// The refusal still names the full path.
	refused := checkExactKeys([]byte(`{"a":{"b":[0,{"Kind":1}]}}`), reflect.TypeOf(map[string]map[string][]any{}), "set")
	if refused != nil {
		t.Fatalf("an any element refused: %v", refused)
	}
	type rule struct {
		Kind string `json:"kind"`
	}
	failure, ok := checkExactKeys([]byte(`{"a":{"b":[{"kind":"x"},{"Kind":"y"}]}}`), reflect.TypeOf(map[string]map[string][]rule{}), "set").(*agentFailure)
	if !ok || failure.Details["field"] != "set.a.b[1].Kind" {
		t.Fatalf("refusal = %+v", failure)
	}
	duplicate, ok := checkDuplicateKeys([]byte(`{"a":[{"b":1},{"c":{"d":1,"d":2}}]}`)).(*agentFailure)
	if !ok || duplicate.Details["field"] != "a[1].c.d" {
		t.Fatalf("duplicate = %+v", duplicate)
	}
}

// allocatedBy returns the bytes allocated while fn runs, the least of
// three runs.
func allocatedBy(fn func()) uint64 {
	least := ^uint64(0)
	for run := 0; run < 3; run++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated < least {
			least = allocated
		}
	}
	return least
}

// TestAgentBodyCheckAllocationIsLinear measures what one refused request
// allocates for the worst bodies at each size limit: the deepest nesting the
// limit allows with as many keys as fit, and the shapes that cost the most
// before (a deep array value, an object nested level by level). Each must
// stay within maxAllocationFactor times the body size: what remains is the
// cost per key of decoding into Go maps, which the web route pays too (the
// log gives its figure for the preview bodies). Before the depth limit the
// 9990 nested arrays cost about 8000 times the body.
func TestAgentBodyCheckAllocationIsLinear(t *testing.T) {
	const maxAllocationFactor = 64
	fixture := newWriteFixture(t)
	previewLimit := int(agentBodyLimits["config.project-preview"])
	planLimit := int(agentBodyLimits[agentapi.EndpointPlanCreate])
	keyLimit := int(agentBodyLimits[agentapi.EndpointTestModel])
	cases := []struct {
		name, method, path, body, token string
	}{
		{"preview, deepest allowed + keys", http.MethodPost, "/config/project-preview",
			worstCaseBody(`{"rules":[{"kind":"repo_name","pattern":`, `}]}`, maxAgentBodyDepth-4, previewLimit), fixture.adminRead},
		{"preview, rule nested to the limit", http.MethodPost, "/config/project-preview",
			worstCaseBody(`{"rules":[`, `]}`, maxAgentBodyDepth-3, previewLimit), fixture.adminRead},
		{"preview, 9990 nested arrays", http.MethodPost, "/config/project-preview",
			`{"rules":[{"kind":"repo_name","pattern":` + deeplyNested(9990) + `}]}`, fixture.adminRead},
		{"plan, deepest allowed + keys", http.MethodPost, "/plans",
			worstCaseBody(`{"op":"config.set","kind":"project","set":{"name":"deep","group_id":null,"enabled":true,"rules":[`, `]}}`, maxAgentBodyDepth-5, planLimit), fixture.adminWrite},
		{"plan, keys of set", http.MethodPost, "/plans",
			worstCaseBody(`{"op":"config.set","kind":"group","set":`, `}`, 0, planLimit), fixture.adminWrite},
		{"test-model, deepest allowed + keys", http.MethodPost, "/analysis/test-model",
			worstCaseBody(`{"set":{"llm.model":`, `}}`, maxAgentBodyDepth-3, keyLimit), fixture.adminWrite},
		{"test-model, 8000 nested arrays", http.MethodPost, "/analysis/test-model",
			`{"set":{"llm.model":` + deeplyNested(8000) + `}}`, fixture.adminWrite},
		// A long key above many keys or elements: a check that built the path
		// of every key would copy the long key once per child.
		{"preview, 30 KB key above keys", http.MethodPost, "/config/project-preview",
			worstCaseBody(`{"rules":[{"`+strings.Repeat("p", 30<<10)+`":`, `}]}`, 0, previewLimit), fixture.adminRead},
		{"test-model, 8 KB key above elements", http.MethodPost, "/analysis/test-model",
			longKeyAboveElements(`{"set":{"`+strings.Repeat("m", 8<<10)+`":[`, `]}}`, keyLimit), fixture.adminWrite},
	}
	for _, test := range cases {
		var code agentapi.Code
		allocated := allocatedBy(func() {
			code = failure(t, fixture.facade(test.method, test.path, test.body, test.token)).Code
		})
		t.Logf("%-38s %7d bytes: %s, %d KiB allocated (%.1fx)", test.name, len(test.body), code, allocated>>10, float64(allocated)/float64(len(test.body)))
		if code != agentapi.CodeInvalidArgument {
			t.Errorf("%s = %s", test.name, code)
		}
		if test.path == "/config/project-preview" {
			web := allocatedBy(func() { fixture.web(http.MethodPost, "/api/v1/org/projects/preview", test.body) })
			t.Logf("%-38s the web route: %d KiB allocated (%.1fx)", "", web>>10, float64(web)/float64(len(test.body)))
		}
		if allocated > uint64(maxAllocationFactor*len(test.body)) {
			t.Errorf("%s: %d bytes allocated for a %d-byte body, more than %dx", test.name, allocated, len(test.body), maxAllocationFactor)
		}
	}
}
