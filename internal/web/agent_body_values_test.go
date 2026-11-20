package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
)

// The value limits, the services' list limits and the bound on bodies
// decoded at once (contract section 0.1 item 170).

// TestJSONShapeCountsEveryValueAndKey counts objects, arrays, strings,
// numbers, literals and keys, and nothing inside a string.
func TestJSONShapeCountsEveryValueAndKey(t *testing.T) {
	for body, want := range map[string][2]int{
		`{}`:                                     {1, 1},
		`[1, -2.5e3, true, false, null]`:         {1, 6},
		`{"a":[1,"x",true,null,{}]}`:             {3, 8},
		`{"a":"[{\"b\":1}]","c":{"d":"}"}}`:      {2, 7},
		` [ "\\" , 0 ] `:                         {1, 3},
		`{"k":` + deeplyNested(5) + `}`:          {6, 7},
		`"` + strings.Repeat("{[,:0", 100) + `"`: {0, 1},
	} {
		depth, values := jsonShape([]byte(body))
		if depth != want[0] || values != want[1] {
			t.Errorf("jsonShape(%s) = depth %d, %d values; want %d, %d", body, depth, values, want[0], want[1])
		}
	}
	for raw, want := range map[string]int{`[]`: 0, ` [ ] `: 0, `[{}]`: 1, `[[1,2],{"a":[3,4]},"x,y"]`: 3, `["\"]",0]`: 2} {
		if length, isArray := jsonArrayLength([]byte(raw)); !isArray || length != want {
			t.Errorf("jsonArrayLength(%s) = %d, %v; want %d", raw, length, isArray, want)
		}
	}
	if _, isArray := jsonArrayLength([]byte(`{"a":[1]}`)); isArray {
		t.Error("an object counted as an array")
	}
}

// valueBody is a body of exactly values values: {"x":[0,0,…]}.
func valueBody(values int) string {
	return `{"x":[` + strings.TrimSuffix(strings.Repeat("0,", values-3), ",") + `]}`
}

// TestAgentBodyValueLimitIsCheckedBeforeDecoding: every endpoint that reads
// a body has a value limit; one value more than it is refused with
// too_many_values before anything decodes the body, the limit itself is
// not, and refused plans take no write quota.
func TestAgentBodyValueLimitIsCheckedBeforeDecoding(t *testing.T) {
	fixture := newWriteFixture(t)
	for _, endpoint := range bodyEndpoints {
		limit, ok := agentBodyValueLimits[endpoint.id]
		if !ok || limit <= 0 {
			t.Errorf("%s has no value limit", endpoint.id)
			continue
		}
		if len(valueBody(limit+1)) > int(agentBodyLimits[endpoint.id]) {
			t.Errorf("%s: %d values do not fit in its %d bytes", endpoint.id, limit+1, agentBodyLimits[endpoint.id])
		}
		token := fixture.adminWrite
		switch endpoint.id {
		case "config.project-preview":
			token = fixture.adminRead
		case "token.exchange":
			token = ""
		}
		refused := failure(t, fixture.facade(endpoint.method, endpoint.path, valueBody(limit+1), token))
		if refused.Code != agentapi.CodeInvalidArgument || refused.Details["field"] != "body" || refused.Details["reason"] != reasonTooManyValues ||
			!strings.Contains(refused.Message, strconv.Itoa(limit)) {
			t.Errorf("%s: %d values = %+v", endpoint.id, limit+1, refused)
		}
		if within := failure(t, fixture.facade(endpoint.method, endpoint.path, valueBody(limit), token)); within.Details["reason"] == reasonTooManyValues {
			t.Errorf("%s: %d values refused for their number", endpoint.id, limit)
		}
	}
	plans := fixture.handler.agentPlans.Len()
	for index := 0; index < 70; index++ {
		if code := failure(t, fixture.facade(http.MethodPost, "/plans", valueBody(maxAgentPlanBodyValues+1), fixture.adminWrite)).Code; code != agentapi.CodeInvalidArgument {
			t.Fatalf("request %d = %s", index, code)
		}
	}
	if fixture.handler.agentPlans.Len() != plans {
		t.Fatal("a refused body created a plan")
	}
	fixture.plan(t, `{"op":"analysis.run"}`)
}

// list is n copies of element as a JSON array.
func list(element string, n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(element+",", n), ",") + "]"
}

// TestAgentListLimitsComeBeforeTheElements: a list one element longer than
// the service accepts is refused with the service's field and reason before
// any element is decoded, so elements that would be refused one by one
// (empty objects) are never looked at; set, add and remove alike.
func TestAgentListLimitsComeBeforeTheElements(t *testing.T) {
	fixture := newWriteFixture(t)
	cases := []struct {
		name, body, field, reason string
	}{
		{"labels", `{"op":"analysis.calibrate","args":{"labels":` + list(`{}`, sessionanalysis.MaxCalibrationLabels+1) + `}}`, "args.labels", sessionanalysis.ReasonOutOfRange},
		{"set.rules", `{"op":"config.set","kind":"project","set":{"name":"p","group_id":null,"enabled":true,"rules":` + list(`{}`, orgreport.MaxRulesPerProject+1) + `}}`, "rules", orgreport.ReasonTooMany},
		{"add.rules", `{"op":"config.set","kind":"project","id":"1","add":{"rules":` + list(`{}`, orgreport.MaxRulesPerProject+1) + `}}`, "rules", orgreport.ReasonTooMany},
		{"remove.keywords", `{"op":"config.set","kind":"content-rule","id":"1","remove":{"keywords":` + list(`{}`, contentpolicy.MaxKeywords+1) + `}}`, "keywords", contentpolicy.ReasonTooMany},
		{"set.keywords", `{"op":"config.set","kind":"content-rule","set":{"name":"c","keywords":` + list(`{}`, contentpolicy.MaxKeywords+1) + `}}`, "keywords", contentpolicy.ReasonTooMany},
		{"set.scan_scopes", `{"op":"config.set","kind":"content-rule","set":{"name":"c","scan_scopes":` + list(`{}`, len(contentpolicy.AllScanScopes)+1) + `}}`, "scan_scopes", contentpolicy.ReasonTooMany},
		{"add.ranked_clients", `{"op":"config.set","kind":"weekly-settings","add":{"ranked_clients":` + list(`{}`, config.MaxOrgRankedClients+1) + `}}`, "ranked_clients", orgreport.ReasonTooMany},
	}
	for _, test := range cases {
		refused := failure(t, fixture.facade(http.MethodPost, "/plans", test.body, fixture.adminWrite))
		if refused.Code != agentapi.CodeInvalidArgument || refused.Details["field"] != test.field || refused.Details["reason"] != test.reason {
			t.Errorf("%s: %+v", test.name, refused)
		}
	}
	preview := `{"week":"2026-01-05","group_id":null,"project_id":1,"rules":` + list(`{}`, orgreport.MaxRulesPerProject+1) + `}`
	if refused := failure(t, fixture.facade(http.MethodPost, "/config/project-preview", preview, fixture.adminRead)); refused.Details["field"] != "rules" ||
		refused.Details["reason"] != orgreport.ReasonTooMany || refused.Message != "at most 32 rules per project" {
		t.Errorf("preview: %+v", refused)
	}
	// The service gives the same answer to the same number of rules it
	// decodes: what the early check says is what the service would say.
	rules := list(`{"kind":"repo_name","pattern":"p"}`, orgreport.MaxRulesPerProject+1)
	early := failure(t, fixture.facade(http.MethodPost, "/plans", `{"op":"config.set","kind":"project","set":{"name":"p","group_id":null,"enabled":true,"rules":`+rules+`}}`, fixture.adminWrite))
	_, err := orgreport.CompileRules(make([]orgreport.Rule, orgreport.MaxRulesPerProject+1))
	service := agentWriteFailure(err)
	if early.Details["field"] != service.Details["field"] || early.Details["reason"] != service.Details["reason"] || early.Message != service.Message {
		t.Errorf("early %+v, service %+v", early, service)
	}
}

// fillValues is prefix, then as many copies of element as keep the body at
// most maxValues values and maxBytes bytes, then suffix.
func fillValues(prefix, element, suffix string, maxValues, maxBytes int) string {
	_, base := jsonShape([]byte(prefix + suffix))
	_, each := jsonShape([]byte(element))
	count := min((maxValues-base)/each, (maxBytes-len(prefix)-len(suffix)+1)/(len(element)+1))
	return prefix + strings.TrimSuffix(strings.Repeat(element+",", count), ",") + suffix
}

// costliestLabel is a label every part of which is decoded: a session id
// and as many (unknown) friction values as keep 1000 such labels within the
// plan's value limit, so all of them are decoded before the service refuses
// the first friction value.
func costliestLabels() string {
	session := strings.Repeat("a", 64)
	friction := (maxAgentPlanBodyValues-7)/sessionanalysis.MaxCalibrationLabels - 5
	label := `{"session_id":"` + session + `","friction":` + list(`"x"`, friction) + `}`
	return `{"op":"analysis.calibrate","args":{"labels":` + list(label, sessionanalysis.MaxCalibrationLabels) + `}}`
}

// TestAgentBodyCostIsBoundedAtTheValueLimits: the costly shapes filled up to
// each endpoint's value limit (not its byte limit, which the value limit
// cuts first), and 1000 labels that are decoded one by one, each allocate
// at most 32 MiB for a plan and 4 MiB for the smaller bodies; 30 of the
// costliest plans at once raise the heap in use by less than 150 MiB.
func TestAgentBodyCostIsBoundedAtTheValueLimits(t *testing.T) {
	fixture := newWriteFixture(t)
	worst := map[string]uint64{}
	for _, endpoint := range costlyBodyEndpoints() {
		limit := maxAgentPlanBodyValues
		switch endpoint.path {
		case "/config/project-preview":
			limit = maxAgentPreviewBodyValues
		case "/analysis/test-model":
			limit = maxAgentTestModelBodyValues
		}
		for shape, element := range costlyBodyShapes {
			body := fillValues(endpoint.prefix, element, endpoint.suffix, limit, endpoint.limit)
			var refused agentapi.ErrorBody
			allocated := allocatedBy(func() {
				refused = failure(t, fixture.facade(endpoint.method, endpoint.path, body, endpoint.token(fixture)))
			})
			t.Logf("%-24s %-22s %7d bytes: %s %v %v, %6d KiB allocated", endpoint.name, shape, len(body), refused.Code, refused.Details["field"], refused.Details["reason"], allocated>>10)
			if refused.Code != agentapi.CodeInvalidArgument || refused.Details["reason"] == reasonTooManyValues {
				t.Errorf("%s, %s: %+v", endpoint.name, shape, refused)
			}
			if allocated > uint64(endpoint.maxMiB)<<20 {
				t.Errorf("%s, %s: %d MiB allocated, more than %d MiB", endpoint.name, shape, allocated>>20, endpoint.maxMiB)
			}
			worst[endpoint.name] = max(worst[endpoint.name], allocated)
		}
	}
	labels := costliestLabels()
	var refused agentapi.ErrorBody
	allocated := allocatedBy(func() { refused = failure(t, fixture.facade(http.MethodPost, "/plans", labels, fixture.adminWrite)) })
	t.Logf("1000 labels decoded one by one, %d bytes: %s %v %v, %d KiB allocated", len(labels), refused.Code, refused.Details["field"], refused.Details["reason"], allocated>>10)
	if refused.Details["field"] != "args.labels[0].friction" || allocated > 32<<20 {
		t.Errorf("1000 labels: %+v, %d MiB allocated", refused, allocated>>20)
	}
	for name, most := range worst {
		t.Logf("most allocated by one request, %s: %d KiB", name, most>>10)
	}
	above, codes := concurrentPeak(t, fixture, labels)
	t.Logf("30 x the 1000 labels at once: the heap in use rose %d MiB; answers %v", above>>20, codes)
	if !peakAnswersDidTheWork(codes) || above > 150<<20 {
		t.Errorf("30 at once: answers %v, heap rose %d MiB", codes, above>>20)
	}
}

// TestAgentLargestLegitimateBodiesAreAccepted: the largest input of each
// plan kind the web page can save that needs no stored object, and of the
// preview and the connection test, passes every body check and is accepted.
// The kinds that change an existing object (member, principal, removals,
// resets, clearing the key) take only scalars, far inside every limit.
func TestAgentLargestLegitimateBodiesAreAccepted(t *testing.T) {
	fixture := newWriteFixture(t)
	var labels []string
	for index := 0; index < sessionanalysis.MaxCalibrationLabels; index++ {
		labels = append(labels, fmt.Sprintf(`{"session_id":"%064x","task_type":"%s","outcome":"%s","collaboration":"%s","work_relevance":"%s","friction":["%s"]}`,
			index, sessionanalysis.TaskTypes[0], sessionanalysis.Outcomes[0], sessionanalysis.Collaborations[0], sessionanalysis.WorkRelevances[0],
			strings.Join(sessionanalysis.FrictionKinds, `","`)))
	}
	rule := func(index int) string { return fmt.Sprintf(`{"kind":"repo_name","pattern":"repo-%02d"}`, index) }
	var rules, keywords []string
	for index := 0; index < orgreport.MaxRulesPerProject; index++ {
		rules = append(rules, rule(index))
	}
	for index := 0; index < contentpolicy.MaxKeywords; index++ {
		keywords = append(keywords, strconv.Quote(fmt.Sprintf("keyword-%03d", index)))
	}
	// Ranked clients come from the deployment's client vocabulary (the
	// fixture's has three); config.MaxOrgRankedClients of them fit the
	// value limit many times over, as the list limit test shows.
	clients := []string{`"claude-code"`, `"codex"`, `"opencode"`}
	scopes := `["` + strings.Join(contentpolicy.AllScanScopes, `","`) + `"]`
	plans := map[string]string{
		"calibration of the most labels": `{"op":"analysis.calibrate","args":{"labels":[` + strings.Join(labels, ",") + `]}}`,
		"project of the most rules":      `{"op":"config.set","kind":"project","set":{"name":"largest","group_id":null,"enabled":true,"rules":[` + strings.Join(rules, ",") + `]}}`,
		"content rule of the most keywords and every scope": `{"op":"config.set","kind":"content-rule","set":{"name":"largest","enabled":true,"action":"dry_run","model_pattern":"^gpt-.*$",` +
			`"scan_scopes":` + scopes + `,"keywords":[` + strings.Join(keywords, ",") + `]}}`,
		"weekly settings of the most ranked clients": `{"op":"config.set","kind":"weekly-settings","set":{"ranked_clients":[` + strings.Join(clients, ",") + `]}}`,
		"ua rule of every field":                     `{"op":"config.set","kind":"ua-rule","set":{"name":"largest","enabled":true,"model_pattern":"^m","user_agent_pattern":"^ua"}}`,
		"group of every field":                       `{"op":"config.set","kind":"group","set":{"name":"largest","enabled":true}}`,
		"analysis run":                               `{"op":"analysis.run"}`,
		"dismissal":                                  `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`,
		"regeneration":                               `{"op":"weekly.regenerate","args":{"week":"2026-11-02"}}`,
		"analysis settings of every field": `{"op":"config.set","kind":"analysis-settings","set":{"run_at":"03:00","l1_settle_hours":12,"llm.enabled":true,` +
			`"llm.base_url":"` + fixture.model.URL + `/v1","llm.model":"m","llm.structured_output":"json_schema","llm.context_tokens":16384,"llm.disable_thinking":true,` +
			`"llm.max_output_tokens":1500,"llm.max_concurrency":2,"llm.timeout_seconds":30,"llm.max_sessions_per_run":300}}`,
	}
	for name, body := range plans {
		_, values := jsonShape([]byte(body))
		response := fixture.facade(http.MethodPost, "/plans", body, fixture.adminWrite)
		t.Logf("%-50s %7d bytes, %6d values: %d", name, len(body), values, response.Code)
		if response.Code != http.StatusOK {
			t.Errorf("%s: %d %s", name, response.Code, response.Body.String())
		}
		if values*2 > maxAgentPlanBodyValues+16 {
			t.Errorf("%s holds %d values, more than half the limit %d", name, values, maxAgentPlanBodyValues)
		}
	}
	preview := `{"group_id":null,"project_id":0,"rules":[` + strings.Join(rules, ",") + `]}`
	if _, values := jsonShape([]byte(preview)); values*2 > maxAgentPreviewBodyValues {
		t.Errorf("the largest preview holds %d values, more than half the limit %d", values, maxAgentPreviewBodyValues)
	}
	if response := fixture.facade(http.MethodPost, "/config/project-preview", preview, fixture.adminRead); response.Code != http.StatusOK {
		t.Errorf("preview of the most rules: %d %s", response.Code, response.Body.String())
	}
	testModel := `{"set":{"run_at":"03:00","l1_settle_hours":12,"llm.enabled":true,"llm.base_url":"` + fixture.model.URL + `/v1","llm.model":"m",` +
		`"llm.structured_output":"json_schema","llm.context_tokens":16384,"llm.disable_thinking":true,"llm.max_output_tokens":1500,` +
		`"llm.max_concurrency":2,"llm.timeout_seconds":30,"llm.max_sessions_per_run":300},"api_key":"test-key-0001"}`
	if _, values := jsonShape([]byte(testModel)); values*2 > maxAgentTestModelBodyValues {
		t.Errorf("the largest test-model body holds %d values, more than half the limit %d", values, maxAgentTestModelBodyValues)
	}
	if response := fixture.facade(http.MethodPost, "/analysis/test-model", testModel, fixture.adminWrite); response.Code != http.StatusOK {
		t.Errorf("test-model with every field: %d %s", response.Code, response.Body.String())
	}
}

// TestAgentBodyDecodingIsBounded: with every decoding slot taken, a plan,
// a preview and a connection test wait; one whose deadline passes first is
// refused with TIMEOUT and gives its write slot back, a read without a body
// is answered at once, and a waiting request starts as soon as a slot is
// given back.
func TestAgentBodyDecodingIsBounded(t *testing.T) {
	fixture := newWriteFixture(t)
	slots := fixture.handler.agentBodySlots
	for index := 0; index < maxAgentBodyDecoders; index++ {
		slots <- struct{}{}
	}
	call := func(ctx context.Context, method, path, body, token string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, agentapi.PathPrefix+path, strings.NewReader(body)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set(agentapi.HeaderCLIVersion, agentapi.LatestVersion)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		return response
	}
	for _, request := range []struct {
		path, body, token string
		rounds            int
	}{
		// More plans and tests than the quotas leave room for with the ones
		// made below (60 writes, 12 tests per ten minutes): a request that
		// never started gives its slot back.
		{"/plans", `{"op":"analysis.run"}`, fixture.adminWrite, 40},
		{"/config/project-preview", `{"group_id":null,"project_id":0,"rules":[{"kind":"repo_name","pattern":"x"}]}`, fixture.adminRead, 3},
		{"/analysis/test-model", `{"set":{"llm.model":"m"}}`, fixture.adminWrite, 13},
	} {
		for round := 0; round < request.rounds; round++ {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			started := time.Now()
			refused := failure(t, call(ctx, http.MethodPost, request.path, request.body, request.token))
			cancel()
			if refused.Code != agentapi.CodeTimeout || time.Since(started) > agentBodyWait/2 {
				t.Fatalf("%s while every slot is taken: %+v after %v", request.path, refused, time.Since(started))
			}
		}
	}
	if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.adminRead); response.Code != http.StatusOK {
		t.Fatalf("a read while every slot is taken: %d", response.Code)
	}
	done := make(chan int, 1)
	go func() {
		done <- call(context.Background(), http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite).Code
	}()
	select {
	case code := <-done:
		t.Fatalf("a plan started while every slot was taken: %d", code)
	case <-time.After(100 * time.Millisecond):
	}
	<-slots
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("the waiting plan: %d", code)
		}
	case <-time.After(agentBodyWait):
		t.Fatal("the waiting plan did not start when a slot was given back")
	}
	if len(slots) != maxAgentBodyDecoders-1 {
		t.Fatalf("%d slots taken after the plan, want %d", len(slots), maxAgentBodyDecoders-1)
	}
	// Refused requests gave their write and test slots back.
	for index := 0; index < maxAgentBodyDecoders-1; index++ {
		<-slots
	}
	for index := 0; index < agentaccess.MaxPlansPerToken-1; index++ {
		if response := fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite); response.Code != http.StatusOK {
			t.Fatalf("plan %d after the timeouts: %d %s", index, response.Code, response.Body.String())
		}
	}
	if response := fixture.facade(http.MethodPost, "/analysis/test-model", `{"set":{"llm.model":"m"}}`, fixture.adminWrite); response.Code != http.StatusOK {
		t.Fatalf("a test after the timeouts: %d %s", response.Code, response.Body.String())
	}
}
