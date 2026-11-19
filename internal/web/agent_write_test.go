package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Tests of the write facade (contract section 4.5, plan section 12).

// createContentRule makes one rule through the web route and returns its id.
func (fixture *writeFixture) createContentRule(t *testing.T, name string) string {
	t.Helper()
	response := fixture.web(http.MethodPost, "/api/v1/content-policy-rules",
		`{"name":"`+name+`","enabled":true,"action":"block","model_pattern":"gpt-*","scan_scopes":["system","latest_user"],"keywords":["alpha","beta"]}`)
	if response.Code != http.StatusCreated && response.Code != http.StatusOK {
		t.Fatalf("web create = %d %s", response.Code, response.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &created)
	return strconv.FormatInt(created.ID, 10)
}

// item finds the object with id in a config show list.
func item(t *testing.T, data map[string]any, list, idKey, id string) map[string]any {
	t.Helper()
	items, _ := data[list].([]any)
	for _, entry := range items {
		object := entry.(map[string]any)
		if formatJSONID(object[idKey]) == id {
			return object
		}
	}
	return nil
}

func formatJSONID(value any) string {
	switch typed := value.(type) {
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case string:
		return typed
	}
	return ""
}

// withoutVolatile drops what a write changes besides the fields: the version
// and the update time.
func withoutVolatile(object map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range object {
		if key == "version" || key == "updated_at" {
			continue
		}
		out[key] = value
	}
	return out
}

func TestAgentPlanApplyLifecycle(t *testing.T) {
	fixture := newWriteFixture(t)
	id := fixture.createContentRule(t, "lifecycle")
	before := item(t, fixture.show(t, "content-rule"), "items", "id", id)

	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": id, "set": map[string]any{"enabled": false}})
	if plan.Target.Kind != "content-rule" || plan.Target.ID != id || plan.Target.Version != before["version"] ||
		!reflect.DeepEqual(plan.ChangedKeys, []string{"enabled"}) || plan.Creates || len(plan.Effects) == 0 {
		t.Fatalf("plan = %+v", plan)
	}
	// Creating a plan changes nothing and audits nothing.
	if now := item(t, fixture.show(t, "content-rule"), "items", "id", id); !reflect.DeepEqual(now, before) {
		t.Fatalf("plan changed the rule: %v", now)
	}
	if rows := fixture.writeAudits(); len(rows) != 0 {
		t.Fatalf("plan creation audited: %+v", rows)
	}
	// A plan of another token is not found, and asking does not spend it.
	other := issueAgentAdmin(t, fixture.agentEnv, agentapi.TierWrite)
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, other)).Code; code != agentapi.CodePlanNotFound {
		t.Fatalf("foreign apply = %s", code)
	}
	applied := fixture.apply(t, plan.PlanID)
	after := item(t, fixture.show(t, "content-rule"), "items", "id", id)
	if after["enabled"] != false || applied.Target.Version != after["version"] || applied.Target.Version == before["version"] {
		t.Fatalf("after = %v, applied %+v", after, applied)
	}
	// Exactly the planned change: every other field is as it was.
	expected := withoutVolatile(before)
	expected["enabled"] = false
	if !reflect.DeepEqual(withoutVolatile(after), expected) {
		t.Fatalf("apply changed more than planned:\n%v\n%v", withoutVolatile(after), expected)
	}
	// A plan runs once.
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodePlanNotFound {
		t.Fatalf("second apply = %s", code)
	}

	// A change through the web route between plan and apply wins.
	stale := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": id, "set": map[string]any{"name": "renamed"}})
	if response := fixture.web(http.MethodPut, "/api/v1/content-policy-rules/"+id,
		`{"name":"lifecycle","enabled":true,"action":"block","model_pattern":"gpt-*","scan_scopes":["system","latest_user"],"keywords":["alpha","beta"]}`); response.Code != http.StatusOK {
		t.Fatalf("web update = %d %s", response.Code, response.Body.String())
	}
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+stale.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("stale apply = %s", code)
	}
	if now := item(t, fixture.show(t, "content-rule"), "items", "id", id); now["name_untrusted"] != "lifecycle" {
		t.Fatalf("a conflicting apply wrote: %v", now)
	}
	// An explicit expected_version that is already stale is refused at plan time.
	if code := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "content-rule", "id": id,
		"set": map[string]any{"enabled": false}, "expected_version": before["version"]}, fixture.adminWrite)).Code; code != agentapi.CodeVersionConflict {
		t.Fatalf("stale expected_version = %s", code)
	}

	// Plans expire after ten minutes.
	expiring := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": id, "set": map[string]any{"enabled": false}})
	fixture.clock.Advance(agentaccess.PlanLifetime)
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+expiring.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodePlanExpired {
		t.Fatalf("expired apply = %s", code)
	}

	// The token is checked again at apply: a revoked token is refused.
	revoked := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": id, "set": map[string]any{"enabled": false}})
	for _, token := range fixture.store.Tokens() {
		if token.Tier == storage.AgentTierWrite {
			fixture.store.Mutate(token.ID, func(row *storage.AgentToken) { now := fixture.clock.Now().UnixNano(); row.RevokedAtNS = &now })
		}
	}
	if code := failure(t, fixture.facade(http.MethodPost, "/plans/"+revoked.PlanID+"/apply", nil, fixture.adminWrite)).Code; code != agentapi.CodeTokenRevoked {
		t.Fatalf("revoked apply = %s", code)
	}
}

func TestAgentApplyRefusedWhenWritesAreTurnedOff(t *testing.T) {
	fixture := newWriteFixture(t)
	id := fixture.createContentRule(t, "switch")
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": id, "set": map[string]any{"enabled": false}})
	// The deployment switch goes off (a restart with allow_write: false keeps
	// the token valid); the plan store is the handler's and survives here.
	fixture.handler.agent = fixture.serviceWith(t, false)
	response := fixture.facade(http.MethodPost, "/plans/"+plan.PlanID+"/apply", nil, fixture.adminWrite)
	if code := failure(t, response).Code; code != agentapi.CodeWriteDisabled {
		t.Fatalf("apply with writes off = %s", code)
	}
	if now := item(t, fixture.show(t, "content-rule"), "items", "id", id); now["enabled"] != true {
		t.Fatalf("a refused apply wrote: %v", now)
	}
}
