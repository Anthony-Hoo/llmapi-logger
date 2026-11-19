package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// writeCells are the five write endpoints with a body that is harmless for
// the token that passes the gates.
var writeCells = []struct {
	method, path, body string
	audited            bool
}{
	{http.MethodPost, "/plans", `{"op":"analysis.run"}`, false},
	{http.MethodPost, "/plans/pln_unknown/apply", ``, true},
	{http.MethodPut, "/config/analysis-settings/api-key", `{}`, true},
	{http.MethodDelete, "/config/analysis-settings/api-key", ``, true},
	{http.MethodPost, "/analysis/test-model", `{"bogus":1}`, true},
}

var gateCodes = map[agentapi.Code]bool{
	agentapi.CodeFeatureDisabled: true, agentapi.CodeUnauthenticated: true, agentapi.CodeForbiddenRole: true,
	agentapi.CodeReadOnlyToken: true, agentapi.CodeWriteDisabled: true, agentapi.CodeRateLimited: true,
}

// Plan section 12: every write endpoint against an administrator read token,
// an administrator write token, a developer token, allow_write off and the
// feature off.
func TestAgentWriteRejectionMatrix(t *testing.T) {
	on := newWriteFixture(t)
	off := newWriteFixtureWith(t, writeFixtureOptions{allowWrite: false})
	disabled, err := NewHandler(Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range writeCells {
		for _, row := range []struct {
			name    string
			fixture *writeFixture
			token   string
			want    agentapi.Code
		}{
			{"admin read", on, on.adminRead, agentapi.CodeReadOnlyToken},
			{"developer", on, on.developer, agentapi.CodeForbiddenRole},
			{"allow_write off", off, off.adminWrite, agentapi.CodeWriteDisabled},
		} {
			response := row.fixture.facade(cell.method, cell.path, cell.body, row.token)
			if got := failure(t, response).Code; got != row.want {
				t.Errorf("%s %s %s = %s, want %s", row.name, cell.method, cell.path, got, row.want)
			}
		}
		response := on.facade(cell.method, cell.path, cell.body, on.adminWrite)
		decoded := decodeAgent(t, response)
		if !decoded.OK && gateCodes[decoded.Error.Code] {
			t.Errorf("admin write %s %s stopped at the gate: %s", cell.method, cell.path, decoded.Error.Code)
		}
		recorder := disabledRequest(disabled, cell.method, agentapi.PathPrefix+cell.path, cell.body, on.adminWrite)
		if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), string(agentapi.CodeFeatureDisabled)) {
			t.Errorf("feature off %s %s = %d %s", cell.method, cell.path, recorder.Code, recorder.Body.String())
		}
	}
	// write_denied rows: one per refused apply, key change and test, none for
	// plan creation; the developer's carry its role.
	denied := map[string]int{}
	for _, row := range on.writeAudits() {
		if row.Event != "write_denied" {
			continue
		}
		if row.Outcome != storage.AgentOutcomeDenied || row.ErrorCode == "" || row.TokenID == nil {
			t.Errorf("denied row = %+v", row)
		}
		denied[row.Role+" "+row.ErrorCode]++
	}
	if denied["admin READ_ONLY_TOKEN"] != 4 || denied["developer FORBIDDEN_ROLE"] != 4 {
		t.Errorf("write_denied rows = %v", denied)
	}
	offDenied := 0
	for _, row := range off.writeAudits() {
		if row.Event == "write_denied" && row.ErrorCode == string(agentapi.CodeWriteDisabled) {
			offDenied++
		}
	}
	if offDenied != 4 {
		t.Errorf("allow_write off rows = %d", offDenied)
	}
}

func disabledRequest(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(recorder, request)
	return recorder
}

// Section 1 of the plan: the key enters only through the key endpoint and
// test-model, and appears in no response, log line, audit row or plan.
func TestAgentModelKeyNeverLeaks(t *testing.T) {
	fixture := newWriteFixture(t)
	before := fixture.show(t, "analysis-settings")
	var outputs []string
	collect := func(response *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		outputs = append(outputs, response.Body.String())
		return response
	}

	set := collect(fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, fixture.adminWrite))
	if set.Code != http.StatusOK || !strings.Contains(set.Body.String(), `"api_key":"saved"`) {
		t.Fatalf("set key = %d %s", set.Code, set.Body.String())
	}
	afterSet := fixture.show(t, "analysis-settings")
	if !jsonEqual(afterSet["settings"], before["settings"]) || afterSet["api_key"] != "saved" || afterSet["version"] == before["version"] {
		t.Fatalf("setting the key changed other settings or no version:\n%v\n%v", afterSet, before)
	}

	probe := collect(fixture.facade(http.MethodPost, "/analysis/test-model",
		map[string]any{"set": map[string]any{"llm.model": "probe-model"}, "api_key": plantedModelKey + "-unsaved"}, fixture.adminWrite))
	if probe.Code != http.StatusOK || !fixture.model.sawKey(plantedModelKey+"-unsaved") {
		t.Fatalf("test-model = %d %s (model saw the key: %v)", probe.Code, probe.Body.String(), fixture.model.sawKey(plantedModelKey+"-unsaved"))
	}
	if now := fixture.show(t, "analysis-settings"); !jsonEqual(now, afterSet) {
		t.Fatalf("test-model saved something")
	}
	// The saved key is used when none is given.
	if probe := collect(fixture.facade(http.MethodPost, "/analysis/test-model", `{}`, fixture.adminWrite)); probe.Code != http.StatusOK || !fixture.model.sawKey(plantedModelKey) {
		t.Fatalf("test-model with the saved key = %d", probe.Code)
	}

	// Refusals that carry the key do not repeat it.
	for _, body := range []string{
		`{"key":"` + plantedModelKey + `"}`,
		`{"api_key":"` + plantedModelKey + `","extra":1}`,
		`{"api_key":"` + plantedModelKey + `"`,
		`{"api_key":"` + plantedModelKey + `"} {}`,
		`{"api_key":"` + plantedModelKey + strings.Repeat("x", maxAgentKeyBodyBytes) + `"}`,
	} {
		response := collect(fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", body, fixture.adminWrite))
		if response.Code != http.StatusBadRequest {
			t.Errorf("bad key body = %d", response.Code)
		}
	}
	collect(fixture.facade(http.MethodPost, "/analysis/test-model", `{"api_key":"`+plantedModelKey+`","set":{"llm.timeout_seconds":0}}`, fixture.adminWrite))
	collect(fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"api_key": plantedModelKey}}, fixture.adminWrite))

	clear := collect(fixture.facade(http.MethodDelete, "/config/analysis-settings/api-key", nil, fixture.adminWrite))
	if clear.Code != http.StatusOK || !strings.Contains(clear.Body.String(), `"api_key":"none"`) {
		t.Fatalf("clear key = %d %s", clear.Code, clear.Body.String())
	}
	afterClear := fixture.show(t, "analysis-settings")
	if !jsonEqual(afterClear["settings"], before["settings"]) || afterClear["api_key"] != "none" {
		t.Fatalf("clearing the key changed other settings: %v", afterClear)
	}

	everything := strings.Join(outputs, "\n") + fixture.logs.String()
	for _, row := range fixture.store.Audit() {
		encoded, _ := json.Marshal(row)
		everything += string(encoded)
	}
	for _, rows := range fixture.settingRows.rows {
		if strings.Contains(rows.Settings, plantedModelKey) {
			t.Fatal("the key is stored in plain text")
		}
	}
	if strings.Contains(everything, plantedModelKey) {
		t.Fatal("the key appears in a response, a log line or an audit row")
	}
	keyRows := 0
	for _, row := range fixture.writeAudits() {
		if row.ObjectKind == "analysis-settings" && row.ChangedKeys == `["api_key"]` && row.Event == "write_applied" {
			keyRows++
		}
	}
	if keyRows != 2 {
		t.Fatalf("key audit rows = %d", keyRows)
	}
}

func jsonEqual(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

// Contract section 3.4: an apply writes one row with the changed key names
// and no value; a failed apply writes write_failed with the code.
func TestAgentWriteAuditRows(t *testing.T) {
	fixture := newWriteFixture(t)
	const secretName = "planted-rule-name-0077"
	created := fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "ua-rule",
		"set": map[string]any{"name": secretName, "enabled": true, "model_pattern": "^planted-model$", "user_agent_pattern": "^planted-ua$"}})
	stale := fixture.plan(t, map[string]any{"op": "config.set", "kind": "ua-rule", "id": created.ID, "set": map[string]any{"enabled": false}})
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "ua-rule", "id": created.ID, "set": map[string]any{"name": secretName + "-2"}})
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+stale.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("stale = %s", code)
	}
	rows := fixture.writeAudits()
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	createRow, renameRow, failedRow := rows[0], rows[1], rows[2]
	if createRow.Event != "write_applied" || createRow.Outcome != "ok" || createRow.ObjectKind != "ua-rule" || createRow.ObjectID != created.ID ||
		createRow.ChangedKeys != `["name","enabled","model_pattern","user_agent_pattern"]` || createRow.Command != "config.set" || createRow.Role != "admin" {
		t.Errorf("create row = %+v", createRow)
	}
	if renameRow.ChangedKeys != `["name"]` {
		t.Errorf("rename row = %+v", renameRow)
	}
	if failedRow.Event != "write_failed" || failedRow.Outcome != "failed" || failedRow.ErrorCode != "VERSION_CONFLICT" || failedRow.ObjectID != created.ID {
		t.Errorf("failed row = %+v", failedRow)
	}
	for _, row := range rows {
		encoded, _ := json.Marshal(row)
		if strings.Contains(string(encoded), "planted") {
			t.Fatalf("an audit row holds a value: %s", encoded)
		}
	}
}

// Contract section 7, on the injected clock.
func TestAgentRateLimits(t *testing.T) {
	t.Run("reads", func(t *testing.T) {
		fixture := newWriteFixture(t)
		for index := 0; index < 120; index++ {
			if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.adminRead); response.Code != http.StatusOK {
				t.Fatalf("read %d = %d", index, response.Code)
			}
		}
		limited := fixture.facade(http.MethodGet, "/whoami", nil, fixture.adminRead)
		if failure(t, limited).Code != agentapi.CodeRateLimited || limited.Header().Get("Retry-After") != "60" {
			t.Fatalf("121st read = %d %s", limited.Code, limited.Header().Get("Retry-After"))
		}
		if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.developer); response.Code != http.StatusOK {
			t.Fatal("the limit is per token")
		}
		if response := fixture.facade(http.MethodPost, "/logout", nil, fixture.adminRead); response.Code != http.StatusOK {
			t.Fatal("logout must not be limited")
		}
	})
	t.Run("reads reopen", func(t *testing.T) {
		fixture := newWriteFixture(t)
		for index := 0; index < 120; index++ {
			fixture.facade(http.MethodGet, "/whoami", nil, fixture.adminRead)
		}
		fixture.clock.Advance(time.Minute)
		if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.adminRead); response.Code != http.StatusOK {
			t.Fatalf("after the window = %d", response.Code)
		}
	})
	t.Run("pack and facet", func(t *testing.T) {
		fixture := newWriteFixture(t)
		for index := 0; index < 20; index++ {
			path := "/analysis/sessions/" + analysisOwnID + "/facet"
			if index%2 == 0 {
				path = "/analysis/sessions/" + analysisOwnID + "/pack"
			}
			if response := fixture.facade(http.MethodGet, path, nil, fixture.developer); response.Code == http.StatusTooManyRequests {
				t.Fatalf("sensitive read %d limited", index)
			}
		}
		if code := failure(t, fixture.facade(http.MethodGet, "/analysis/sessions/"+analysisOwnID+"/pack", nil, fixture.developer)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("21st sensitive read = %s", code)
		}
		if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.developer); response.Code != http.StatusOK {
			t.Fatal("ordinary reads are not held by the sensitive limit")
		}
	})
	t.Run("writes", func(t *testing.T) {
		fixture := newWriteFixture(t)
		for index := 0; index < 60; index++ {
			if response := fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite); response.Code != http.StatusOK {
				t.Fatalf("plan %d = %d %s", index, response.Code, response.Body.String())
			}
		}
		limited := fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite)
		if failure(t, limited).Code != agentapi.CodeRateLimited || limited.Header().Get("Retry-After") != "600" {
			t.Fatalf("61st write = %s", limited.Header().Get("Retry-After"))
		}
	})
	t.Run("test-model", func(t *testing.T) {
		fixture := newWriteFixture(t)
		for index := 0; index < 12; index++ {
			fixture.facade(http.MethodPost, "/analysis/test-model", `{"bogus":1}`, fixture.adminWrite)
		}
		limited := fixture.facade(http.MethodPost, "/analysis/test-model", `{}`, fixture.adminWrite)
		if failure(t, limited).Code != agentapi.CodeRateLimited || limited.Header().Get("Retry-After") != "3600" {
			t.Fatalf("13th test = %s", limited.Header().Get("Retry-After"))
		}
	})
	t.Run("analysis run is global", func(t *testing.T) {
		fixture := newWriteFixture(t)
		first, second := fixture.plan(t, `{"op":"analysis.run"}`), fixture.plan(t, `{"op":"analysis.run"}`)
		fixture.apply(t, first.PlanID)
		if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+second.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("second run = %s", code)
		}
		fixture.clock.Advance(10 * time.Minute)
		fixture.planAndApply(t, `{"op":"analysis.run"}`)
		if fixture.trigger.triggered != 2 {
			t.Fatalf("triggered %d", fixture.trigger.triggered)
		}
	})
	t.Run("regenerate", func(t *testing.T) {
		fixture := newWriteFixture(t)
		body := map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": orgTestWeek.Format("2006-01-02")}}
		for index := 0; index < 6; index++ {
			fixture.planAndApply(t, body)
		}
		if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+fixture.plan(t, body).PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("7th regenerate = %s", code)
		}
		if fixture.snapshots.saves != 6 {
			t.Fatalf("snapshots saved %d", fixture.snapshots.saves)
		}
	})
}

// Contract section 4.5.1, the four operations without a check-only twin.
func TestAgentOperationPlans(t *testing.T) {
	fixture := newWriteFixture(t)
	run := fixture.plan(t, `{"op":"analysis.run"}`)
	if run.Extras["running"] != false || run.Target.Kind != "analysis-run" {
		t.Fatalf("run plan = %+v", run)
	}
	fixture.trigger.running = true
	busy := fixture.plan(t, `{"op":"analysis.run"}`)
	if busy.Extras["running"] != true {
		t.Fatalf("busy plan = %+v", busy)
	}
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+busy.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeRunInProgress {
		t.Fatalf("busy apply = %s", code)
	}
	fixture.trigger.running = false

	for _, test := range []struct {
		week, reason string
	}{
		{orgTestWeek.AddDate(0, 0, 7).Format("2006-01-02"), "week_not_ended"},
		{orgTestWeek.AddDate(0, 0, -56).Format("2006-01-02"), "past_retention"},
	} {
		body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": test.week}}, fixture.adminWrite))
		if body.Code != agentapi.CodeInvalidArgument || body.Details["reason"] != test.reason || body.Details["field"] != "args.week" {
			t.Errorf("regenerate %s = %s %v", test.week, body.Code, body.Details)
		}
	}
	notMonday := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-04"}}, fixture.adminWrite))
	if notMonday.Details["week_start"] != "monday" || !strings.Contains(notMonday.Hint, "2026-11-02") {
		t.Errorf("not a week start = %+v", notMonday)
	}
	regenerate := fixture.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-02"}})
	week, _ := regenerate.Extras["week"].(map[string]any)
	if week["ended"] != true || week["frozen"] != false || regenerate.Target.ID != "2026-11-02" {
		t.Fatalf("regenerate plan = %+v", regenerate)
	}
	fixture.apply(t, regenerate.PlanID)
	again := fixture.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-02"}})
	if week, _ := again.Extras["week"].(map[string]any); week["frozen"] != true || week["frozen_at"] == nil {
		t.Fatalf("frozen state = %+v", again.Extras)
	}

	badLabel := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "analysis.calibrate",
		"args": map[string]any{"labels": []any{map[string]any{"session_id": "nothex", "task_type": "bugfix"}}}}, fixture.adminWrite))
	if badLabel.Code != agentapi.CodeInvalidArgument || badLabel.Details["field"] != "args.labels[0].session_id" {
		t.Errorf("bad label = %s %v", badLabel.Code, badLabel.Details)
	}
	if body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "analysis.calibrate",
		"args": map[string]any{"labels": []any{}}}, fixture.adminWrite)); body.Details["field"] != "args.labels" {
		t.Errorf("no labels = %v", body.Details)
	}
	calibrate := fixture.planAndApply(t, map[string]any{"op": "analysis.calibrate",
		"args": map[string]any{"labels": []any{map[string]any{"session_id": analysisOwnID, "task_type": "bug_fix"}}}})
	if !strings.Contains(string(calibrate.Result), `"labels":1`) {
		t.Fatalf("calibration result = %s", calibrate.Result)
	}
	dismiss := fixture.plan(t, `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`)
	if dismiss.Target.ID != "42" {
		t.Fatalf("dismiss plan = %+v", dismiss)
	}
	if body := failure(t, fixture.facade(http.MethodPost, "/plans/"+dismiss.PlanID+"/apply", nil, fixture.adminWrite)); body.Code != agentapi.CodeNotFound {
		t.Fatalf("dismiss unknown = %s", body.Code)
	}
}

// The administrator's change list (contract section 3.2).
func TestAgentChangesEndpoint(t *testing.T) {
	fixture := newWriteFixture(t)
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "group", "set": map[string]any{"name": "changes", "enabled": true}})
	fixture.facade(http.MethodPost, "/plans/pln_missing/apply", nil, fixture.adminRead)
	response := fixture.web(http.MethodGet, "/api/v1/agent-access/changes?limit=10", "")
	if response.Code != http.StatusOK {
		t.Fatalf("changes = %d %s", response.Code, response.Body.String())
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Items) != 2 {
		t.Fatalf("changes body = %s", response.Body.String())
	}
	denied, applied := list.Items[0], list.Items[1]
	if denied["event"] != "write_denied" || denied["error_code"] != "READ_ONLY_TOKEN" || denied["object_kind"] != "plan" {
		t.Errorf("denied = %v", denied)
	}
	if applied["event"] != "write_applied" || applied["outcome"] != "ok" || applied["object_kind"] != "group" ||
		!jsonEqual(applied["changed_keys"], []string{"name", "enabled"}) || applied["token_id"] == nil {
		t.Errorf("applied = %v", applied)
	}
	if _, err := time.Parse(time.RFC3339, applied["at"].(string)); err != nil {
		t.Errorf("at = %v", applied["at"])
	}
	// Token issuance and other non-write events are not changes.
	for _, item := range list.Items {
		if !strings.HasPrefix(item["event"].(string), "write_") {
			t.Errorf("non-write row %v", item)
		}
	}
	developer := fixture.do(http.MethodGet, "/api/v1/agent-access/changes", "", agentCaller{cookie: developerSignIn(t, fixture.handler)})
	if developer.Code != http.StatusForbidden {
		t.Fatalf("developer changes = %d", developer.Code)
	}
	for _, query := range []string{"?limit=0", "?limit=201", "?limit=x", "?since=1d", "?limit=1&limit=2"} {
		if response := fixture.web(http.MethodGet, "/api/v1/agent-access/changes"+query, ""); response.Code != http.StatusBadRequest {
			t.Errorf("changes%s = %d", query, response.Code)
		}
	}
	if response := fixture.web(http.MethodPost, "/api/v1/agent-access/changes", ""); response.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST changes = %d", response.Code)
	}
}
