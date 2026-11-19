package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Parity of the writes (plan section 12, contract section 4.6): every write
// route of the web, performed through the facade on one fixture and through
// the web route with the equivalent full body on an identical fixture, leaves
// the same stored state. The state compared is everything the configuration
// reads show, with versions and times removed; ids are compared too, because
// both fixtures allocate them in the same order.

// configState is every configurable object of a fixture, normalised.
func (fixture *writeFixture) configState(t *testing.T) map[string]any {
	t.Helper()
	state := map[string]any{}
	for _, kind := range []string{"ua-rule", "content-rule", "org", "weekly-settings", "analysis-settings"} {
		state[kind] = stripVolatile(fixture.show(t, kind))
	}
	// Each fixture has its own model server; its address is not a difference.
	encoded, _ := json.Marshal(state)
	var normalised map[string]any
	_ = json.Unmarshal([]byte(strings.ReplaceAll(string(encoded), fixture.model.URL, "http://model.invalid")), &normalised)
	return normalised
}

func stripVolatile(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, inner := range typed {
			switch key {
			case "version", "updated_at", "created_at":
				continue
			}
			out[key] = stripVolatile(inner)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, inner := range typed {
			out[index] = stripVolatile(inner)
		}
		return out
	}
	return value
}

// webSettingsBody is the full PUT body of the analysis settings the web form
// would submit, from the values in use with change applied.
func (fixture *writeFixture) webSettingsBody(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	response := fixture.web(http.MethodGet, "/api/v1/settings/session-analysis", "")
	var view struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	change(view.Settings)
	encoded, _ := json.Marshal(view.Settings)
	return string(encoded)
}

func TestAgentWritesMatchTheWebRoutes(t *testing.T) {
	facade, web := newWriteFixture(t), newWriteFixture(t)
	idsFacade, idsWeb := facade.seed(t), web.seed(t)
	if idsFacade != idsWeb {
		t.Fatalf("the fixtures diverged: %+v %+v", idsFacade, idsWeb)
	}
	ids := idsFacade
	const contentBody = `{"name":"content seed","enabled":true,"action":"block","model_pattern":"gpt-*","scan_scopes":["system","latest_user"],"keywords":["alpha","beta","gamma"]}`
	steps := []struct {
		name               string
		plan               any
		method, path, body string
	}{
		{"ua create", map[string]any{"op": "config.set", "kind": "ua-rule", "set": map[string]any{"name": "ua new", "enabled": true, "model_pattern": "^m", "user_agent_pattern": " ^ua "}},
			http.MethodPost, "/api/v1/user-agent-rules", `{"name":"ua new","enabled":true,"model_pattern":"^m","user_agent_pattern":" ^ua "}`},
		{"ua update", map[string]any{"op": "config.set", "kind": "ua-rule", "id": ids.uaRule, "set": map[string]any{"enabled": false}},
			http.MethodPut, "/api/v1/user-agent-rules/" + ids.uaRule, `{"name":"ua seed","enabled":false,"model_pattern":"^gpt-","user_agent_pattern":"^curl/"}`},
		{"ua delete", map[string]any{"op": "config.remove", "kind": "ua-rule", "id": ids.uaRule},
			http.MethodDelete, "/api/v1/user-agent-rules/" + ids.uaRule, ``},
		{"content create", map[string]any{"op": "config.set", "kind": "content-rule", "set": map[string]any{"name": "content new", "enabled": true, "action": "dry_run",
			"model_pattern": "", "scan_scopes": []string{"system", "latest_user", "user_history", "assistant", "tool_calls", "tool_results", "tool_definitions"}, "keywords": []string{"k1", "K1", "k2"}}},
			http.MethodPost, "/api/v1/content-policy-rules", `{"name":"content new","enabled":true,"action":"dry_run","model_pattern":"","scan_scopes":["system","latest_user","user_history","assistant","tool_calls","tool_results","tool_definitions"],"keywords":["k1","K1","k2"]}`},
		{"content update", map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule, "add": map[string]any{"keywords": []string{"gamma"}}},
			http.MethodPut, "/api/v1/content-policy-rules/" + ids.contentRule, contentBody},
		{"content delete", map[string]any{"op": "config.remove", "kind": "content-rule", "id": ids.contentRule},
			http.MethodDelete, "/api/v1/content-policy-rules/" + ids.contentRule, ``},
		{"group create", map[string]any{"op": "config.set", "kind": "group", "set": map[string]any{"name": "group new", "enabled": false}},
			http.MethodPost, "/api/v1/org/groups", `{"name":"group new","enabled":false}`},
		{"group update", map[string]any{"op": "config.set", "kind": "group", "id": ids.otherGroup, "set": map[string]any{"name": "group renamed"}},
			http.MethodPut, "/api/v1/org/groups/" + ids.otherGroup, `{"name":"group renamed","enabled":true}`},
		{"project create", map[string]any{"op": "config.set", "kind": "project", "set": map[string]any{"name": "project new", "group_id": nil, "enabled": true,
			"rules": []any{map[string]any{"kind": "path_glob", "pattern": "/home/*/demo"}}}},
			http.MethodPost, "/api/v1/org/projects", `{"name":"project new","group_id":null,"enabled":true,"rules":[{"kind":"path_glob","pattern":"/home/*/demo"}]}`},
		{"project update", map[string]any{"op": "config.set", "kind": "project", "id": ids.project, "set": map[string]any{"name": "project renamed"}},
			http.MethodPut, "/api/v1/org/projects/" + ids.project, `{"name":"project renamed","group_id":` + ids.group + `,"enabled":true,"rules":[{"kind":"repo_name","pattern":"demo"}]}`},
		{"member put", map[string]any{"op": "config.set", "kind": "member", "id": "8", "set": map[string]any{"group_id": json.Number(ids.otherGroup)}},
			http.MethodPut, "/api/v1/org/members/8", `{"group_id":` + ids.otherGroup + `}`},
		{"member delete", map[string]any{"op": "config.remove", "kind": "member", "id": "7"},
			http.MethodDelete, "/api/v1/org/members/7", ``},
		{"principal put", map[string]any{"op": "config.set", "kind": "principal", "id": "token:70", "set": map[string]any{"class": "service"}},
			http.MethodPut, "/api/v1/org/principals/token/70", `{"class":"service"}`},
		{"principal delete", map[string]any{"op": "config.remove", "kind": "principal", "id": "user:7"},
			http.MethodDelete, "/api/v1/org/principals/user/7", ``},
		{"project delete", map[string]any{"op": "config.remove", "kind": "project", "id": ids.project},
			http.MethodDelete, "/api/v1/org/projects/" + ids.project, ``},
		{"group delete", map[string]any{"op": "config.remove", "kind": "group", "id": ids.group},
			http.MethodDelete, "/api/v1/org/groups/" + ids.group, ``},
		{"weekly settings put", map[string]any{"op": "config.set", "kind": "weekly-settings", "set": map[string]any{"idle_gap_seconds": 90, "ranked_clients": []string{"opencode", "codex"}}},
			http.MethodPut, "/api/v1/settings/org-reports", `{"idle_gap_seconds":90,"ranked_clients":["codex","opencode"],"max_concurrent_roots":10,"max_single_request_roots":200}`},
		{"weekly settings delete", map[string]any{"op": "config.reset", "kind": "weekly-settings"},
			http.MethodDelete, "/api/v1/settings/org-reports", ``},
	}
	for _, step := range steps {
		facade.planAndApply(t, step.plan)
		if response := web.web(step.method, step.path, step.body); response.Code >= 300 {
			t.Fatalf("%s via web = %d %s", step.name, response.Code, response.Body.String())
		}
		if got, want := facade.configState(t), web.configState(t); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: facade and web differ:\nfacade %v\nweb    %v", step.name, got, want)
		}
	}

	// The analysis settings: the web form submits the whole section.
	facade.planAndApply(t, map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"run_at": " 04:15 ", "llm.max_concurrency": 2}})
	body := web.webSettingsBody(t, func(settings map[string]any) {
		settings["run_at"] = "04:15"
		settings["llm"].(map[string]any)["max_concurrency"] = 2
	})
	if response := web.web(http.MethodPut, "/api/v1/settings/session-analysis", body); response.Code != http.StatusOK {
		t.Fatalf("analysis settings via web = %d %s", response.Code, response.Body.String())
	}
	if got, want := facade.configState(t), web.configState(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("analysis settings differ:\nfacade %v\nweb    %v", got, want)
	}
	facade.planAndApply(t, map[string]any{"op": "config.reset", "kind": "analysis-settings"})
	if response := web.web(http.MethodDelete, "/api/v1/settings/session-analysis", ""); response.Code != http.StatusOK {
		t.Fatalf("analysis reset via web = %d", response.Code)
	}
	if got, want := facade.configState(t), web.configState(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("analysis reset differs:\nfacade %v\nweb    %v", got, want)
	}

	// The key alone, as the web form with only the key field filled in.
	facade.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, facade.adminWrite)
	body = web.webSettingsBody(t, func(settings map[string]any) { settings["api_key"] = plantedModelKey })
	if response := web.web(http.MethodPut, "/api/v1/settings/session-analysis", body); response.Code != http.StatusOK {
		t.Fatalf("key via web = %d", response.Code)
	}
	if got, want := facade.configState(t), web.configState(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("setting the key differs:\nfacade %v\nweb    %v", got, want)
	}

	// The operations: a run, a regeneration and a calibration.
	facade.planAndApply(t, `{"op":"analysis.run"}`)
	if response := web.web(http.MethodPost, "/api/v1/session-analysis/run", ""); response.Code != http.StatusAccepted {
		t.Fatalf("run via web = %d", response.Code)
	}
	if facade.trigger.triggered != 1 || web.trigger.triggered != 1 {
		t.Fatalf("runs: %d %d", facade.trigger.triggered, web.trigger.triggered)
	}
	facade.planAndApply(t, `{"op":"weekly.regenerate","args":{"week":"2026-11-02"}}`)
	if response := web.web(http.MethodPost, "/api/v1/org/weekly/regenerate?week=2026-11-02", ""); response.Code != http.StatusNoContent {
		t.Fatalf("regenerate via web = %d", response.Code)
	}
	gotSnapshot, wantSnapshot := facade.snapshots.snapshots["2026-11-02"], web.snapshots.snapshots["2026-11-02"]
	if !reflect.DeepEqual(gotSnapshot.Result, wantSnapshot.Result) || !reflect.DeepEqual(gotSnapshot.ProjectNames, wantSnapshot.ProjectNames) {
		t.Fatalf("snapshots differ:\n%+v\n%+v", gotSnapshot, wantSnapshot)
	}
	labels := `[{"session_id":"` + analysisOwnID + `","task_type":"bug_fix","outcome":"achieved"}]`
	applied := facade.planAndApply(t, `{"op":"analysis.calibrate","args":{"labels":`+labels+`}}`)
	response := web.web(http.MethodPost, "/api/v1/session-analysis/calibration", `{"labels":`+labels+`}`)
	var viaWeb, viaFacade map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &viaWeb)
	_ = json.Unmarshal(applied.Result, &viaFacade)
	if response.Code != http.StatusOK || viaWeb["labels"] != viaFacade["labels"] || viaWeb["samples"] != viaFacade["samples"] ||
		!jsonEqual(viaWeb["agreement"], viaFacade["agreement"]) || !jsonEqual(viaWeb["compared"], viaFacade["compared"]) {
		t.Fatalf("calibration differs: web %d %v, facade %v", response.Code, viaWeb, viaFacade)
	}

	// Dismissing a suggestion.
	facade.planAndApply(t, `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`)
	if response := web.web(http.MethodPost, "/api/v1/session-analysis/suggestions/42/dismiss", ""); response.Code != http.StatusOK {
		t.Fatalf("dismiss via web = %d", response.Code)
	}
	if !reflect.DeepEqual(facade.suggestions.dismissed, web.suggestions.dismissed) || len(web.suggestions.dismissed) != 1 {
		t.Fatalf("dismissed: facade %v, web %v", facade.suggestions.dismissed, web.suggestions.dismissed)
	}

	// The connection test with an unsaved model and key: the same probe, and
	// nothing saved on either side.
	before := facade.configState(t)
	probe := facade.facade(http.MethodPost, "/analysis/test-model", map[string]any{"set": map[string]any{"llm.model": "probe-model"}, "api_key": plantedUnsavedKey}, facade.adminWrite)
	body = web.webSettingsBody(t, func(settings map[string]any) {
		settings["llm"].(map[string]any)["model"] = "probe-model"
		settings["api_key"] = plantedUnsavedKey
	})
	webProbe := web.web(http.MethodPost, "/api/v1/settings/session-analysis/test", body)
	var facadeResult, webResult map[string]any
	_ = json.Unmarshal(decodeAgent(t, probe).Data, &facadeResult)
	_ = json.Unmarshal(webProbe.Body.Bytes(), &webResult)
	delete(facadeResult, "latency_ms")
	delete(webResult, "latency_ms")
	if probe.Code != http.StatusOK || webProbe.Code != http.StatusOK || !reflect.DeepEqual(facadeResult, webResult) ||
		!facade.model.sawKey(plantedUnsavedKey) || !web.model.sawKey(plantedUnsavedKey) {
		t.Fatalf("test-model differs: facade %d %v, web %d %v", probe.Code, facadeResult, webProbe.Code, webResult)
	}
	if after := facade.configState(t); !reflect.DeepEqual(after, before) {
		t.Fatal("test-model saved something")
	}
}
