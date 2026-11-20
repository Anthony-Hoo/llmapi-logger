package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
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
	// write_denied rows: one per refused apply, key setting and test, none
	// for plan creation (clearing the key is a plan); the developer's carry
	// its role.
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
	if denied["admin READ_ONLY_TOKEN"] != 3 || denied["developer FORBIDDEN_ROLE"] != 3 {
		t.Errorf("write_denied rows = %v", denied)
	}
	offDenied := 0
	for _, row := range off.writeAudits() {
		if row.Event == "write_denied" && row.ErrorCode == string(agentapi.CodeWriteDisabled) {
			offDenied++
		}
	}
	if offDenied != 3 {
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

// plantedUnsavedKey is the key test-model is given for one probe; it shares
// nothing with plantedModelKey.
const plantedUnsavedKey = "probe-only-credential-7731"

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
		map[string]any{"set": map[string]any{"llm.model": "probe-model"}, "api_key": plantedUnsavedKey}, fixture.adminWrite))
	if probe.Code != http.StatusOK || !fixture.model.sawKey(plantedUnsavedKey) || fixture.model.sawKey(plantedModelKey) {
		t.Fatalf("test-model = %d %s (model saw the unsaved key: %v)", probe.Code, probe.Body.String(), fixture.model.sawKey(plantedUnsavedKey))
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

	clearPlan := collect(fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.clear-key", "kind": "analysis-settings"}, fixture.adminWrite))
	if clearPlan.Code != http.StatusOK {
		t.Fatalf("clear key plan = %d %s", clearPlan.Code, clearPlan.Body.String())
	}
	var plan planResponse
	_ = json.Unmarshal(decodeAgent(t, clearPlan).Data, &plan)
	collect(fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite))
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
	if strings.Contains(everything, plantedModelKey) || strings.Contains(everything, plantedUnsavedKey) {
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

// The key in use (saved or from the configuration file) never goes with a
// connection test to an address that is not the one in effect: the agent
// could choose that address. The test is refused before anything is sent;
// with a key typed for this request, or with no key in use, it runs.
func TestAgentTestModelKeepsTheKeyAtTheAddressInEffect(t *testing.T) {
	fixture := newWriteFixture(t)
	if response := fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, fixture.adminWrite); response.Code != http.StatusOK {
		t.Fatalf("set key = %d %s", response.Code, response.Body.String())
	}
	elsewhere := newModelServer(t)
	refused := failure(t, fixture.facade(http.MethodPost, "/analysis/test-model",
		map[string]any{"set": map[string]any{"llm.base_url": elsewhere.URL + "/v1"}}, fixture.adminWrite))
	if refused.Code != agentapi.CodeInvalidArgument || refused.Details["field"] != "llm.base_url" ||
		refused.Details["reason"] != "saved_key_not_sent_to_unsaved_address" ||
		!strings.Contains(refused.Hint, "llmaudit config set --kind analysis-settings") || !strings.Contains(refused.Hint, "llmaudit apply") ||
		!strings.Contains(refused.Hint, "--prompt-key") {
		t.Fatalf("test-model to another address = %+v", refused)
	}
	if len(elsewhere.authorization) != 0 || fixture.model.sawKey(plantedModelKey) {
		t.Fatal("a request was sent")
	}
	rows := fixture.writeAudits()
	if last := rows[len(rows)-1]; last.Event != "write_failed" || last.ErrorCode != string(agentapi.CodeInvalidArgument) || last.ChangedKeys != `["llm.base_url"]` {
		t.Fatalf("audit row = %+v", last)
	}

	// The address in effect, or another field, keeps the key in use.
	if response := fixture.facade(http.MethodPost, "/analysis/test-model", map[string]any{"set": map[string]any{
		"llm.base_url": " " + fixture.model.URL + "/v1 ", "llm.model": "other-model"}}, fixture.adminWrite); response.Code != http.StatusOK || !fixture.model.sawKey(plantedModelKey) {
		t.Fatalf("test-model at the address in effect = %d %s", response.Code, response.Body.String())
	}
	// A key typed for this request may go to the unsaved address, alone.
	if response := fixture.facade(http.MethodPost, "/analysis/test-model", map[string]any{"set": map[string]any{"llm.base_url": elsewhere.URL + "/v1"},
		"api_key": plantedUnsavedKey}, fixture.adminWrite); response.Code != http.StatusOK || !elsewhere.sawKey(plantedUnsavedKey) || elsewhere.sawKey(plantedModelKey) {
		t.Fatalf("test-model with a typed key = %d %s", response.Code, response.Body.String())
	}

	// The configuration file's key is held back the same way.
	fresh := newWriteFixture(t)
	other := newModelServer(t)
	if code := failure(t, fresh.facade(http.MethodPost, "/analysis/test-model", map[string]any{"set": map[string]any{"llm.base_url": other.URL + "/v1"}}, fresh.adminWrite)).Code; code != agentapi.CodeInvalidArgument ||
		len(other.authorization) != 0 {
		t.Fatalf("file key to another address = %s, %d requests", code, len(other.authorization))
	}
	// With no key in use there is nothing to hold back.
	if _, err := fresh.settings.ClearAPIKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if response := fresh.facade(http.MethodPost, "/analysis/test-model", map[string]any{"set": map[string]any{"llm.base_url": other.URL + "/v1"}}, fresh.adminWrite); response.Code != http.StatusOK || len(other.authorization) != 1 {
		t.Fatalf("test-model without a key = %d %s", response.Code, response.Body.String())
	}

	// The web form's test is unchanged: an administrator in a browser may
	// test the address typed in the form with the key in use.
	webTarget := newModelServer(t)
	body := fixture.webSettingsBody(t, func(settings map[string]any) {
		settings["llm"].(map[string]any)["base_url"] = webTarget.URL + "/v1"
	})
	if response := fixture.web(http.MethodPost, "/api/v1/settings/session-analysis/test", body); response.Code != http.StatusOK || !webTarget.sawKey(plantedModelKey) {
		t.Fatalf("web test = %d %s", response.Code, response.Body.String())
	}

	// A plan that moves the address while a key is in use says the key goes
	// there from then on.
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"llm.base_url": elsewhere.URL + "/v1"}})
	if !strings.Contains(strings.Join(plan.Effects, "\n"), "API key in use (saved key) will be sent to the new address") {
		t.Fatalf("plan effects = %v", plan.Effects)
	}
	model := fixture.plan(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"llm.model": "other-model"}})
	if strings.Contains(strings.Join(model.Effects, "\n"), "API key") {
		t.Fatalf("a model change claims the key moves: %v", model.Effects)
	}
}

// Clearing the model key loses a value the agent cannot restore, so it is a
// plan like every other change; apply executes it. Setting a key stays a
// terminal-only write without a plan.
func TestAgentClearingTheKeyIsAPlan(t *testing.T) {
	fixture := newWriteFixture(t)
	if response := fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, fixture.adminWrite); response.Code != http.StatusOK {
		t.Fatalf("set key = %d", response.Code)
	}
	// The old one-step endpoint is gone.
	if code := failure(t, fixture.facade(http.MethodDelete, "/config/analysis-settings/api-key", nil, fixture.adminWrite)).Code; code != agentapi.CodeNotFound {
		t.Fatalf("DELETE api-key = %s", code)
	}
	body := map[string]any{"op": "config.clear-key", "kind": "analysis-settings"}
	if code := failure(t, fixture.facade(http.MethodPost, "/plans", body, fixture.adminRead)).Code; code != agentapi.CodeReadOnlyToken {
		t.Fatalf("read token = %s", code)
	}
	for _, bad := range []map[string]any{{"op": "config.clear-key"}, {"op": "config.clear-key", "kind": "weekly-settings"}, {"op": "config.clear-key", "kind": "analysis-settings", "set": map[string]any{}}} {
		if code := failure(t, fixture.facade(http.MethodPost, "/plans", bad, fixture.adminWrite)).Code; code != agentapi.CodeInvalidArgument {
			t.Errorf("%v = %s", bad, code)
		}
	}
	plan := fixture.plan(t, body)
	effects := strings.Join(plan.Effects, "\n")
	if plan.Op != "config.clear-key" || plan.Target.Kind != "analysis-settings" || plan.Target.Version == "0" || !jsonEqual(plan.ChangedKeys, []string{"api_key"}) ||
		!jsonEqual(plan.Extras["api_key"], map[string]string{"before": "saved", "after": "none"}) ||
		!strings.Contains(effects, "Only the user can set a key again") || !strings.Contains(effects, "llmaudit config set-key --kind analysis-settings") {
		t.Fatalf("plan = %+v", plan)
	}
	if shown := fixture.show(t, "analysis-settings"); shown["api_key"] != "saved" {
		t.Fatal("creating the plan cleared the key")
	}
	applied := fixture.apply(t, plan.PlanID)
	if shown := fixture.show(t, "analysis-settings"); shown["api_key"] != "none" || applied.Target.Version == plan.Target.Version {
		t.Fatalf("after apply = %v, %+v", shown, applied)
	}
	rows := fixture.writeAudits()
	if last := rows[len(rows)-1]; last.Event != "write_applied" || last.ObjectKind != "analysis-settings" || last.ChangedKeys != `["api_key"]` {
		t.Fatalf("audit row = %+v", last)
	}
	// With no key in use there is nothing to clear: no plan (contract
	// section 0.1 item 106; it used to be a plan that changed nothing but the
	// version).
	nothing := failure(t, fixture.facade(http.MethodPost, "/plans", body, fixture.adminWrite))
	if nothing.Code != agentapi.CodeInvalidArgument || nothing.Details["reason"] != "nothing_to_clear" || nothing.Details["field"] != "api_key" {
		t.Fatalf("clear without a key = %s %v", nothing.Code, nothing.Details)
	}
	// A change in between is a conflict.
	if response := fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, fixture.adminWrite); response.Code != http.StatusOK {
		t.Fatalf("set key again = %d", response.Code)
	}
	stale := fixture.plan(t, body)
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": "04:00"}})
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+stale.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("stale clear = %s", code)
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
	// A failed apply records what it attempted, like an applied one.
	if failedRow.Event != "write_failed" || failedRow.Outcome != "failed" || failedRow.ErrorCode != "VERSION_CONFLICT" || failedRow.ObjectID != created.ID ||
		failedRow.ObjectKind != "ua-rule" || failedRow.ChangedKeys != `["enabled"]` {
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
	t.Run("a refused pack keeps the read slot", func(t *testing.T) {
		fixture := newWriteFixture(t)
		path := "/analysis/sessions/" + analysisOwnID + "/pack"
		refused := 0
		// 20 packs pass and take 20 read slots; the next 100 are refused by the
		// sensitive limit and must take none.
		for index := 0; index < 120; index++ {
			if fixture.facade(http.MethodGet, path, nil, fixture.developer).Code == http.StatusTooManyRequests {
				refused++
			}
		}
		if refused != 100 {
			t.Fatalf("refused packs = %d, want 100", refused)
		}
		for index := 0; index < 100; index++ {
			if response := fixture.facade(http.MethodGet, "/whoami", nil, fixture.developer); response.Code != http.StatusOK {
				t.Fatalf("read %d after refused packs = %d %s", index, response.Code, response.Body.String())
			}
		}
		if code := failure(t, fixture.facade(http.MethodGet, "/whoami", nil, fixture.developer)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("121st counted read = %s", code)
		}
	})
	t.Run("writes", func(t *testing.T) {
		fixture := newWriteFixture(t)
		// Plan creations and applies share the write quota. Half of the 60 are
		// applies of an unknown plan, since one token holds at most
		// agentaccess.MaxPlansPerToken live plans.
		for index := 0; index < 30; index++ {
			if response := fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite); response.Code != http.StatusOK {
				t.Fatalf("plan %d = %d %s", index, response.Code, response.Body.String())
			}
			if code := failure(t, fixture.facade(http.MethodPost, "/plans/pln_AAAAAAAAAAAAAAAAAAAAAA/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodePlanNotFound {
				t.Fatalf("apply %d = %s", index, code)
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
	t.Run("a run that did not start keeps the run quota", func(t *testing.T) {
		fixture := newWriteFixture(t)
		fixture.trigger.running = true
		busy := fixture.plan(t, `{"op":"analysis.run"}`)
		if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+busy.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeRunInProgress {
			t.Fatalf("busy apply = %s", code)
		}
		fixture.trigger.running = false
		fixture.planAndApply(t, `{"op":"analysis.run"}`)
		if fixture.trigger.triggered != 1 {
			t.Fatalf("triggered %d", fixture.trigger.triggered)
		}
		if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+fixture.plan(t, `{"op":"analysis.run"}`).PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("run after a started run = %s", code)
		}
		// The refusal came after the plan was taken: its row names the target.
		rows := fixture.writeAudits()
		if last := rows[len(rows)-1]; last.Event != "write_failed" || last.ErrorCode != string(agentapi.CodeRateLimited) ||
			last.ObjectKind != "analysis-run" || last.ChangedKeys != "[]" {
			t.Fatalf("rate-limited row = %+v", last)
		}
	})
	t.Run("concurrent runs against a limit of one", func(t *testing.T) {
		fixture := newWriteFixture(t)
		first, second := fixture.plan(t, `{"op":"analysis.run"}`), fixture.plan(t, `{"op":"analysis.run"}`)
		var wait sync.WaitGroup
		codes := make([]int, 2)
		for index, id := range []string{first.PlanID, second.PlanID} {
			wait.Add(1)
			go func() {
				defer wait.Done()
				codes[index] = fixture.facade(http.MethodPost, "/plans/"+id+"/apply", nil, fixture.adminWrite).Code
			}()
		}
		wait.Wait()
		if fixture.trigger.triggered != 1 || codes[0]+codes[1] != http.StatusOK+http.StatusTooManyRequests {
			t.Fatalf("codes = %v, triggered = %d", codes, fixture.trigger.triggered)
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

// Contract section 0.1 item 101: an apply of a weekly regeneration that is
// blocked behind a long snapshot write (here the web route's regeneration of
// another week) gives up at its own deadline with TIMEOUT, writes nothing and
// gives its slot of the global regeneration quota back.
func TestAgentRegenerateBlockedBehindAFreezeTimesOutAndRefunds(t *testing.T) {
	fixture := newWriteFixture(t)
	fixture.snapshots.hold, fixture.snapshots.entered = make(chan struct{}), make(chan struct{}, 1)
	other := orgTestWeek.AddDate(0, 0, -7).Format("2006-01-02")
	webDone := make(chan int, 1)
	go func() {
		webDone <- fixture.web(http.MethodPost, "/api/v1/org/weekly/regenerate?week="+other, "").Code
	}()
	<-fixture.snapshots.entered

	fixture.handler.regenerateTimeout = 50 * time.Millisecond
	week := orgTestWeek.Format("2006-01-02")
	plan := fixture.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week}})
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeTimeout {
		t.Fatalf("blocked apply = %s", code)
	}
	fixture.snapshots.mu.Lock()
	_, written := fixture.snapshots.snapshots[week]
	fixture.snapshots.mu.Unlock()
	if written {
		t.Fatal("the timed-out regeneration wrote a snapshot")
	}
	// The slot came back: the whole quota of six is still free.
	for index := 0; index < 6; index++ {
		if _, err := fixture.service.TakeSlot(agentaccess.QuotaRegenerate, agentaccess.Identity{}); err != nil {
			t.Fatalf("regeneration slot %d after the timed-out apply = %v", index+1, err)
		}
	}
	if _, err := fixture.service.TakeSlot(agentaccess.QuotaRegenerate, agentaccess.Identity{}); agentaccess.CodeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("seventh slot = %v", err)
	}
	close(fixture.snapshots.hold)
	if code := <-webDone; code != http.StatusNoContent {
		t.Fatalf("web regeneration = %d", code)
	}
	rows := fixture.writeAudits()
	if last := rows[len(rows)-1]; last.Event != agentaccess.EventWriteFailed || last.ErrorCode != string(agentapi.CodeTimeout) {
		t.Fatalf("audit row = %+v", last)
	}
}

// Contract section 0.1 item 102: a refused plan request (validation, not
// found, conflict, the per-token plan cap) consumes neither the write quota
// nor a place under the per-token plan cap; only created plans do.
func TestRefusedPlanRequestsDoNotConsumeWriteLimits(t *testing.T) {
	fixture := newWriteFixture(t)
	refused := []any{
		`{"op":"no.such.op"}`,
		map[string]any{"op": "config.set", "kind": "ua-rule", "id": "999", "set": map[string]any{"enabled": false}},
		map[string]any{"op": "config.remove", "kind": "content-rule", "id": "999"},
		map[string]any{"op": "config.set", "kind": "ua-rule", "set": map[string]any{"name": "x"}},
	}
	for index := 0; index < 100; index++ {
		response := fixture.facade(http.MethodPost, "/plans", refused[index%len(refused)], fixture.adminWrite)
		if code := failure(t, response).Code; code == agentapi.CodeRateLimited {
			t.Fatalf("refused request %d was rate limited", index)
		}
	}
	for index := 0; index < agentaccess.MaxPlansPerToken; index++ {
		fixture.plan(t, `{"op":"analysis.run"}`)
	}
	// The per-token cap refuses the next plan; that refusal is not counted.
	for index := 0; index < 5; index++ {
		if code := failure(t, fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.run"}`, fixture.adminWrite)).Code; code != agentapi.CodeRateLimited {
			t.Fatalf("plan beyond the per-token cap = %s", code)
		}
	}
	identity, err := fixture.service.Authenticate(context.Background(), "Bearer "+fixture.adminWrite, "192.0.2.77")
	if err != nil {
		t.Fatal(err)
	}
	left := 0
	for ; left < 100; left++ {
		if _, err := fixture.service.TakeSlot(agentaccess.QuotaWrite, identity); err != nil {
			break
		}
	}
	if left != 60-agentaccess.MaxPlansPerToken {
		t.Fatalf("write quota left after %d created plans = %d", agentaccess.MaxPlansPerToken, left)
	}
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

	// A week older than the retention window is not refused (the web route
	// regenerates it too): TestAgentRegenerateBeyondRetentionMatchesTheWeb.
	for _, test := range []struct {
		week, reason string
	}{
		{orgTestWeek.AddDate(0, 0, 7).Format("2006-01-02"), "week_not_ended"},
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
	fixture.apply(t, dismiss.PlanID)
	if !jsonEqual(fixture.suggestions.dismissed, []int64{42}) {
		t.Fatalf("dismissed = %v", fixture.suggestions.dismissed)
	}
	// Contract section 0.1 item 105: a suggestion that does not exist gets no
	// plan; the refusal is the one apply would give.
	if body := failure(t, fixture.facade(http.MethodPost, "/plans", `{"op":"analysis.dismiss","args":{"suggestion_id":99}}`, fixture.adminWrite)); body.Code != agentapi.CodeNotFound || !strings.Contains(body.Hint, "llmaudit analysis report") {
		t.Fatalf("dismiss unknown = %s %s", body.Code, body.Hint)
	}
	// A dismissed suggestion still exists: dismissing it again is planned and
	// succeeds, as on the web route.
	redismiss := fixture.plan(t, `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`)
	fixture.apply(t, redismiss.PlanID)
	for _, effect := range append(dismiss.Effects, redismiss.Effects...) {
		if strings.Contains(effect, "decides") {
			t.Fatalf("effect defers to the service: %q", effect)
		}
	}
}

// Parity: the web route regenerates a week older than the retention window,
// so the agent does too; the plan says what regenerating it loses.
func TestAgentRegenerateBeyondRetentionMatchesTheWeb(t *testing.T) {
	fixture := newWriteFixture(t)
	week := orgTestWeek.Format("2006-01-02")
	inside := fixture.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week}})
	if strings.Contains(strings.Join(inside.Effects, "\n"), "retention") {
		t.Fatalf("a week inside the window mentions retention: %v", inside.Effects)
	}
	// The test week is now about 50 days old, retention is 30 days.
	fixture.clock.Advance(40 * 24 * time.Hour)
	fixture.adminWrite = agentaccesstest.IssueAdmin(t, fixture.service, agentapi.TierWrite).Token
	if web := fixture.web(http.MethodPost, "/api/v1/org/weekly/regenerate?week="+week, ""); web.Code != http.StatusNoContent {
		t.Fatalf("web = %d", web.Code)
	}
	old := fixture.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week}})
	effects := strings.Join(old.Effects, "\n")
	if !strings.Contains(effects, "older than the retention window (retention_days = 30)") || !strings.Contains(effects, "every request of this week has been deleted") ||
		!strings.Contains(effects, "cannot be recovered") {
		t.Fatalf("effects = %v", old.Effects)
	}
	fixture.apply(t, old.PlanID)

	// A week that only began before the cutoff loses only its first days.
	partial := newWriteFixture(t)
	partial.clock.Advance(23 * 24 * time.Hour) // the cutoff falls inside the test week
	partial.adminWrite = agentaccesstest.IssueAdmin(t, partial.service, agentapi.TierWrite).Token
	plan := partial.plan(t, map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week}})
	if effects := strings.Join(plan.Effects, "\n"); !strings.Contains(effects, "that started before") || strings.Contains(effects, "cannot be recovered") {
		t.Fatalf("partial effects = %v", plan.Effects)
	}
}

// A regenerate plan replaces only the week state it showed: a freeze or a
// regeneration in between, from the web page here, is a VERSION_CONFLICT,
// and the conflict does not spend the regenerate quota.
func TestAgentRegenerateRefusesAStateItDidNotShow(t *testing.T) {
	fixture := newWriteFixture(t)
	week := orgTestWeek.Format("2006-01-02")
	body := map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": week}}
	plan := fixture.plan(t, body)
	if shown := plan.Extras["week"].(map[string]any); shown["frozen"] != false || plan.Target.Version != "0" {
		t.Fatalf("plan = %+v", plan)
	}
	if web := fixture.web(http.MethodPost, "/api/v1/org/weekly/regenerate?week="+week, ""); web.Code != http.StatusNoContent {
		t.Fatalf("web = %d", web.Code)
	}
	saves := fixture.snapshots.saves
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("stale plan = %s", code)
	}
	if fixture.snapshots.saves != saves {
		t.Fatal("a stale plan replaced the snapshot")
	}
	// Even at the same clock reading a new regeneration is a new version.
	fresh := fixture.plan(t, body)
	if fixture.web(http.MethodPost, "/api/v1/org/weekly/regenerate?week="+week, "").Code != http.StatusNoContent {
		t.Fatal("web regenerate")
	}
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+fresh.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("plan before a second web regeneration = %s", code)
	}
	// Conflicts gave their quota slots back: six regenerations still run.
	for index := 0; index < 6; index++ {
		applied := fixture.planAndApply(t, body)
		if applied.Target.Version == "" || applied.Target.Version == "0" {
			t.Fatalf("applied = %+v", applied)
		}
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

// write_denied rows are bounded per token and never carry path text a
// client chose (section 0.1).
func TestAgentDeniedRowsAreBounded(t *testing.T) {
	fixture := newWriteFixture(t)
	for index := 0; index < 75; index++ {
		response := fixture.facade(http.MethodPost, "/plans/"+`<script>`+strconv.Itoa(index)+"/apply", nil, fixture.developer)
		if code := failure(t, response).Code; code != agentapi.CodeForbiddenRole {
			t.Fatalf("developer apply %d = %s", index, code)
		}
	}
	rows := fixture.writeAudits()
	if len(rows) != 60 {
		t.Fatalf("denied rows = %d, want the cap of 60", len(rows))
	}
	for _, row := range rows {
		if row.ObjectID != "" || row.Event != "write_denied" {
			t.Fatalf("row = %+v", row)
		}
	}
	// Another token keeps its own allowance; a plan id of the right shape is
	// recorded as it is.
	planID := fixture.plan(t, `{"op":"analysis.run"}`).PlanID
	fixture.facade(http.MethodPost, "/plans/"+planID+"/apply", nil, fixture.adminRead)
	rows = fixture.writeAudits()
	if last := rows[len(rows)-1]; last.ObjectID != planID || last.ErrorCode != string(agentapi.CodeReadOnlyToken) {
		t.Fatalf("read token row = %+v", last)
	}
}

// Optional modules that are off answer MODULE_DISABLED for their writes, as
// for their reads; the rules, which are always there, still work.
func TestAgentWritesOfDisabledModules(t *testing.T) {
	fixture := newWriteFixtureWith(t, writeFixtureOptions{allowWrite: true, noModules: true})
	for _, test := range []struct {
		method, path string
		body         any
		module       string
	}{
		{http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "group", "set": map[string]any{"name": "g", "enabled": true}}, "org_reports"},
		{http.MethodPost, "/plans", map[string]any{"op": "config.reset", "kind": "weekly-settings"}, "org_reports"},
		{http.MethodPost, "/plans", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-02"}}, "org_reports"},
		{http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": "03:00"}}, "session_analysis"},
		{http.MethodPost, "/plans", `{"op":"analysis.run"}`, "session_analysis"},
		{http.MethodPost, "/plans", `{"op":"analysis.dismiss","args":{"suggestion_id":1}}`, "session_analysis"},
		{http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, "session_analysis"},
		{http.MethodPost, "/plans", map[string]any{"op": "config.clear-key", "kind": "analysis-settings"}, "session_analysis"},
		{http.MethodPost, "/analysis/test-model", `{}`, "session_analysis"},
	} {
		body := failure(t, fixture.facade(test.method, test.path, test.body, fixture.adminWrite))
		if body.Code != agentapi.CodeModuleDisabled || body.Details["module"] != test.module {
			t.Errorf("%s %s %v = %s %v", test.method, test.path, test.body, body.Code, body.Details)
		}
	}
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "ua-rule",
		"set": map[string]any{"name": "still", "enabled": true, "model_pattern": "^a", "user_agent_pattern": "^b"}})
}

// Contract section 0.1 item 106: a reset or clear-key plan says one true
// thing for the state it shows. A section with nothing saved has nothing to
// reset and no plan; a saved section whose values equal the file's is reset
// with a single sentence that says only the source (and the key) change; a
// clear of a key that comes from the file says the section becomes saved.
func TestResetAndClearKeyPlansSayOneTrueThing(t *testing.T) {
	fixture := newWriteFixture(t)
	for _, kind := range []string{"weekly-settings", "analysis-settings"} {
		body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.reset", "kind": kind}, fixture.adminWrite))
		if body.Code != agentapi.CodeInvalidArgument || body.Details["reason"] != "nothing_saved" || body.Details["field"] != "kind" {
			t.Fatalf("reset of %s with nothing saved = %s %v", kind, body.Code, body.Details)
		}
	}

	// The file has a key: clearing it is a real change that saves the section.
	clear := fixture.plan(t, map[string]any{"op": "config.clear-key", "kind": "analysis-settings"})
	if !jsonEqual(clear.Extras["api_key"], map[string]string{"before": "file", "after": "none"}) ||
		!strings.Contains(strings.Join(clear.Effects, "\n"), "the source becomes saved") {
		t.Fatalf("clear of the file key = %+v", clear)
	}

	// Save the file's own values: the saved section equals the file.
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": "02:00"}})
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "weekly-settings", "set": map[string]any{"idle_gap_seconds": 180}})
	for _, kind := range []string{"weekly-settings", "analysis-settings"} {
		plan := fixture.plan(t, map[string]any{"op": "config.reset", "kind": kind})
		effects := strings.Join(plan.Effects, "\n")
		if strings.Contains(effects, effectNoChange) || !strings.Contains(effects, "no setting value changes") || strings.Count(effects, "Drops the saved settings") != 1 {
			t.Fatalf("%s reset of values equal to the file = %v", kind, plan.Effects)
		}
		fixture.apply(t, plan.PlanID)
		if shown := fixture.show(t, kind); shown["version"] != "0" {
			t.Fatalf("%s after reset = %v", kind, shown)
		}
	}

	// Saved values that differ: the reset says they change back.
	fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "weekly-settings", "set": map[string]any{"idle_gap_seconds": 60}})
	plan := fixture.plan(t, map[string]any{"op": "config.reset", "kind": "weekly-settings"})
	effects := strings.Join(plan.Effects, "\n")
	if !jsonEqual(plan.ChangedKeys, []string{"idle_gap_seconds"}) || strings.Contains(effects, "no setting value changes") || strings.Contains(effects, effectNoChange) {
		t.Fatalf("reset of changed values = %+v", plan)
	}
}

// Contract section 0.1 item 107: every plan of an operation that cannot be
// undone through this interface says so; a removal says that an object made
// again from the copy gets a new id.
func TestIrreversiblePlansSaySo(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	for name, body := range map[string]any{
		"analysis.run":         `{"op":"analysis.run"}`,
		"analysis.calibrate":   map[string]any{"op": "analysis.calibrate", "args": map[string]any{"labels": []any{map[string]any{"session_id": analysisOwnID, "task_type": "bug_fix"}}}},
		"analysis.dismiss":     `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`,
		"weekly.regenerate":    map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": orgTestWeek.Format("2006-01-02")}},
		"config.remove rule":   map[string]any{"op": "config.remove", "kind": "ua-rule", "id": ids.uaRule},
		"config.remove group":  map[string]any{"op": "config.remove", "kind": "group", "id": ids.otherGroup},
		"config.remove member": map[string]any{"op": "config.remove", "kind": "member", "id": "7"},
		"config.clear-key":     map[string]any{"op": "config.clear-key", "kind": "analysis-settings"},
	} {
		plan := fixture.plan(t, body)
		effects := strings.Join(plan.Effects, "\n")
		if !strings.Contains(effects, effectIrreversible) {
			t.Errorf("%s plan does not say it cannot be undone: %v", name, plan.Effects)
		}
		if strings.HasPrefix(name, "config.remove") && name != "config.remove member" && !strings.Contains(effects, "new id") {
			t.Errorf("%s plan does not say a restored object gets a new id: %v", name, plan.Effects)
		}
	}
	// A change that can be undone with another change does not claim it.
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "ua-rule", "id": ids.uaRule, "set": map[string]any{"enabled": false}})
	if strings.Contains(strings.Join(plan.Effects, "\n"), effectIrreversible) {
		t.Fatalf("a reversible change claims it cannot be undone: %v", plan.Effects)
	}
}

// Contract section 0.1 item 110: the connection test's result carries meta
// like every other command's; state says whether the probe reached the model.
func TestTestModelResultCarriesMeta(t *testing.T) {
	fixture := newWriteFixture(t)
	response := fixture.facade(http.MethodPost, "/analysis/test-model", map[string]any{}, fixture.adminWrite)
	decoded := decodeAgent(t, response)
	if response.Code != http.StatusOK || decoded.Meta == nil || decoded.Meta.State != "ok" || !decoded.Meta.Complete ||
		!strings.Contains(response.Body.String(), `"incomplete_reason":""`) {
		t.Fatalf("test-model = %d %s", response.Code, response.Body.String())
	}
	// A probe that runs and fails is still a complete result, state failed.
	fixture.model.Close()
	response = fixture.facade(http.MethodPost, "/analysis/test-model", map[string]any{}, fixture.adminWrite)
	decoded = decodeAgent(t, response)
	if response.Code != http.StatusOK || decoded.Meta == nil || decoded.Meta.State != "failed" || !decoded.Meta.Complete {
		t.Fatalf("failed probe = %d %s", response.Code, response.Body.String())
	}
	// A read-tier administrator token is refused: the test spends the
	// model's quota and can send the key in use, so it needs the write tier.
	if code := failure(t, fixture.facade(http.MethodPost, "/analysis/test-model", map[string]any{}, fixture.adminRead)).Code; code != agentapi.CodeReadOnlyToken {
		t.Fatalf("read token = %s", code)
	}
}
