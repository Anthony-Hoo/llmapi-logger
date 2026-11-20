package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// webCreate posts body to path through the web route and returns the id of
// the created object.
func (fixture *writeFixture) webCreate(t *testing.T, method, path, body string) string {
	t.Helper()
	response := fixture.web(method, path, body)
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("web %s %s = %d %s", method, path, response.Code, response.Body.String())
	}
	var created struct {
		ID json.Number `json:"id"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &created)
	return created.ID.String()
}

// seedCatalog creates one object of every kind through the web routes.
type seeded struct {
	uaRule, contentRule, group, otherGroup, project string
}

func (fixture *writeFixture) seed(t *testing.T) seeded {
	t.Helper()
	var ids seeded
	ids.uaRule = fixture.webCreate(t, http.MethodPost, "/api/v1/user-agent-rules",
		`{"name":"ua seed","enabled":true,"model_pattern":"^gpt-","user_agent_pattern":"^curl/"}`)
	ids.contentRule = fixture.createContentRule(t, "content seed")
	ids.group = fixture.webCreate(t, http.MethodPost, "/api/v1/org/groups", `{"name":"group seed","enabled":true}`)
	ids.otherGroup = fixture.webCreate(t, http.MethodPost, "/api/v1/org/groups", `{"name":"group other","enabled":true}`)
	ids.project = fixture.webCreate(t, http.MethodPost, "/api/v1/org/projects",
		`{"name":"project seed","group_id":`+ids.group+`,"enabled":true,"rules":[{"kind":"repo_name","pattern":"demo"}]}`)
	if response := fixture.web(http.MethodPut, "/api/v1/org/members/7", `{"group_id":`+ids.group+`}`); response.Code != http.StatusOK {
		t.Fatalf("member = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.web(http.MethodPut, "/api/v1/org/principals/user/7", `{"class":"service"}`); response.Code != http.StatusOK {
		t.Fatalf("principal = %d %s", response.Code, response.Body.String())
	}
	return ids
}

// objectOf reads one object of kind as config show returns it.
func (fixture *writeFixture) objectOf(t *testing.T, kind, id string) map[string]any {
	t.Helper()
	switch kind {
	case "ua-rule", "content-rule":
		return item(t, fixture.show(t, kind), "items", "id", id)
	case "group":
		return item(t, fixture.show(t, "org"), "groups", "id", id)
	case "project":
		return item(t, fixture.show(t, "org"), "projects", "id", id)
	case "member":
		return item(t, fixture.show(t, "org"), "members", "user_id", id)
	case "principal":
		kindName, raw, _ := strings.Cut(id, ":")
		for _, entry := range fixture.show(t, "org")["principals"].([]any) {
			object := entry.(map[string]any)
			if object["kind"] == kindName && formatJSONID(object["id"]) == raw {
				return object
			}
		}
		return nil
	default:
		return fixture.show(t, kind)["settings"].(map[string]any)
	}
}

// Plan section 12: a config.set of one field changes that field and nothing
// else, for every kind, end to end through the facade.
func TestAgentSetChangesOnlyTheGivenField(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	otherGroup, _ := strconv.ParseInt(ids.otherGroup, 10, 64)
	cases := []struct {
		kind, id string
		set      map[string]any
		// field and value as config show writes them
		field string
		want  any
	}{
		{"ua-rule", ids.uaRule, map[string]any{"enabled": false}, "enabled", false},
		{"content-rule", ids.contentRule, map[string]any{"enabled": false}, "enabled", false},
		{"group", ids.group, map[string]any{"enabled": false}, "enabled", false},
		{"project", ids.project, map[string]any{"enabled": false}, "enabled", false},
		{"member", "7", map[string]any{"group_id": otherGroup}, "group_id", float64(otherGroup)},
		{"principal", "user:7", map[string]any{"class": "human"}, "class", "human"},
		{"weekly-settings", "", map[string]any{"idle_gap_seconds": 60}, "idle_gap_seconds", float64(60)},
		{"analysis-settings", "", map[string]any{"llm.enabled": false}, "llm", nil},
	}
	for _, test := range cases {
		before := fixture.objectOf(t, test.kind, test.id)
		if before == nil {
			t.Fatalf("%s %s was not seeded", test.kind, test.id)
		}
		body := map[string]any{"op": "config.set", "kind": test.kind, "set": test.set}
		if test.id != "" {
			body["id"] = test.id
		}
		plan := fixture.plan(t, body)
		wantKeys := []string{test.field}
		if test.kind == "analysis-settings" {
			wantKeys = []string{"llm.enabled"}
		}
		if !reflect.DeepEqual(plan.ChangedKeys, wantKeys) {
			t.Errorf("%s changed_keys = %v", test.kind, plan.ChangedKeys)
		}
		fixture.apply(t, plan.PlanID)
		after := fixture.objectOf(t, test.kind, test.id)
		expected := withoutVolatile(before)
		if test.kind == "analysis-settings" {
			llm := map[string]any{}
			for key, value := range before["llm"].(map[string]any) {
				llm[key] = value
			}
			llm["enabled"] = false
			expected["llm"] = llm
		} else {
			expected[test.field] = test.want
		}
		if !reflect.DeepEqual(withoutVolatile(after), expected) {
			t.Errorf("%s: set of one field changed more:\nafter    %v\nexpected %v", test.kind, withoutVolatile(after), expected)
		}
	}
}

// Contract section 4.5.2: creating requires the fields of the table, with no
// form default for enabled or action, and a rule name taken refuses with the
// existing id.
func TestAgentCreateRequiresTheContractFields(t *testing.T) {
	fixture := newWriteFixture(t)
	cases := []struct {
		kind  string
		set   map[string]any
		field string
	}{
		{"ua-rule", map[string]any{"name": "n", "model_pattern": "^a", "user_agent_pattern": "^b"}, "enabled"},
		{"content-rule", map[string]any{"name": "n", "enabled": true, "keywords": []string{"k"}}, "action"},
		{"content-rule", map[string]any{"name": "n", "action": "block", "keywords": []string{"k"}}, "enabled"},
		{"group", map[string]any{"name": "n"}, "enabled"},
		{"project", map[string]any{"name": "n", "group_id": nil, "rules": []any{}}, "enabled"},
		{"project", map[string]any{"name": "n", "enabled": true, "rules": []any{}}, "group_id"},
	}
	for _, test := range cases {
		response := fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": test.kind, "set": test.set}, fixture.adminWrite)
		body := failure(t, response)
		if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != test.field {
			t.Errorf("%s create without %s = %s %v", test.kind, test.field, body.Code, body.Details)
		}
	}
	// A content rule created with every required field and no scan_scopes
	// scans all seven scopes, like the web form's default.
	created := fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": "content-rule",
		"set": map[string]any{"name": " padded ", "enabled": true, "action": "dry_run", "keywords": []string{"k"}}})
	rule := item(t, fixture.show(t, "content-rule"), "items", "id", created.ID)
	if created.ID == "" || rule["name_untrusted"] != "padded" || len(rule["scan_scopes"].([]any)) != 7 || rule["action"] != "dry_run" {
		t.Fatalf("created = %+v rule %v", created, rule)
	}
	// A duplicate name is accepted, as the web route accepts it; the plan
	// names the rule that already has it before the user agrees, and the
	// create makes a second rule with an id of its own.
	for _, kind := range []string{"ua-rule", "content-rule"} {
		set := map[string]any{"name": "padded", "enabled": true, "action": "block", "keywords": []string{"x"}}
		existing := created.ID
		if kind == "ua-rule" {
			set = map[string]any{"name": "dup", "enabled": true, "model_pattern": "^a", "user_agent_pattern": "^b"}
			existing = fixture.planAndApply(t, map[string]any{"op": "config.set", "kind": kind, "set": set}).ID
		}
		plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": kind, "set": set})
		if !jsonEqual(plan.Extras["same_name"], []string{existing}) || !strings.Contains(strings.Join(plan.Effects, "\n"), "already exists (id "+existing+")") {
			t.Errorf("%s duplicate plan = %v %v", kind, plan.Extras, plan.Effects)
		}
		second := fixture.apply(t, plan.PlanID)
		if second.ID == "" || second.ID == existing {
			t.Errorf("%s duplicate create = %+v", kind, second)
		}
	}
	unique := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule",
		"set": map[string]any{"name": "unique", "enabled": true, "action": "block", "keywords": []string{"x"}}})
	if _, ok := unique.Extras["same_name"]; ok {
		t.Errorf("unique name plan = %v", unique.Extras)
	}
}

// Contract section 4.5.2: unknown fields, the key, a field both set and
// edited and the other shape errors are INVALID_ARGUMENT naming the field,
// before anything is checked against data.
func TestAgentPlanRequestErrorsNameTheField(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	cases := []struct {
		name  string
		body  any
		field string
	}{
		{"unknown top-level", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "set": map[string]any{"enabled": true}, "colour": 1}, "colour"},
		{"unknown op", map[string]any{"op": "config.drop"}, "op"},
		{"unknown kind", map[string]any{"op": "config.set", "kind": "rule", "set": map[string]any{"enabled": true}}, "kind"},
		{"unknown set field", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "set": map[string]any{"colour": "red"}}, "colour"},
		{"api_key in set", map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"api_key": plantedModelKey}}, "api_key"},
		{"llm.api_key in set", map[string]any{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"llm.api_key": plantedModelKey}}, "llm.api_key"},
		{"set and add", map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule,
			"set": map[string]any{"keywords": []string{"a"}}, "add": map[string]any{"keywords": []string{"b"}}}, "keywords"},
		{"add when creating", map[string]any{"op": "config.set", "kind": "content-rule",
			"set": map[string]any{"name": "x", "enabled": true, "action": "block", "keywords": []string{"a"}}, "add": map[string]any{"scan_scopes": []string{"system"}}}, "add"},
		{"add to a scalar", map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule, "add": map[string]any{"name": []string{"b"}}}, "name"},
		{"null", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "set": map[string]any{"enabled": nil}}, "enabled"},
		{"wrong type", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "set": map[string]any{"enabled": "no"}}, "enabled"},
		{"numeric id", map[string]any{"op": "config.set", "kind": "group", "id": 3, "set": map[string]any{"enabled": true}}, "id"},
		{"bad id", map[string]any{"op": "config.set", "kind": "group", "id": "x3", "set": map[string]any{"enabled": true}}, "id"},
		{"bad version", map[string]any{"op": "config.set", "kind": "group", "id": ids.group, "set": map[string]any{"enabled": true}, "expected_version": "v1"}, "expected_version"},
		{"nothing to change", map[string]any{"op": "config.set", "kind": "group", "id": ids.group}, "set"},
		{"field of another op", map[string]any{"op": "config.remove", "kind": "group", "id": ids.group, "set": map[string]any{"enabled": true}}, "set"},
		{"settings with an id", map[string]any{"op": "config.set", "kind": "weekly-settings", "id": "1", "set": map[string]any{"idle_gap_seconds": 60}}, "id"},
		{"member without id", map[string]any{"op": "config.set", "kind": "member", "set": map[string]any{"group_id": 1}}, "id"},
		{"remove settings", map[string]any{"op": "config.remove", "kind": "weekly-settings", "id": "1"}, "kind"},
		{"reset a rule", map[string]any{"op": "config.reset", "kind": "ua-rule"}, "kind"},
		{"string suggestion", map[string]any{"op": "analysis.dismiss", "args": map[string]any{"suggestion_id": "4"}}, "args.suggestion_id"},
		{"missing week", map[string]any{"op": "weekly.regenerate", "args": map[string]any{}}, "args.week"},
		{"unknown arg", map[string]any{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-02", "force": true}}, "args.force"},
		{"run with args", map[string]any{"op": "analysis.run", "args": map[string]any{}}, "args"},
		{"not an object", `[1]`, "body"},
		{"trailing data", `{"op":"analysis.run"} {}`, "body"},
	}
	for _, test := range cases {
		response := fixture.facade(http.MethodPost, "/plans", test.body, fixture.adminWrite)
		body := failure(t, response)
		if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != test.field {
			t.Errorf("%s = %s %v (%s)", test.name, body.Code, body.Details, body.Message)
		}
		if strings.Contains(response.Body.String(), plantedModelKey) {
			t.Errorf("%s echoes the key: %s", test.name, response.Body.String())
		}
	}
	if fixture.handler.agentPlans.Len() != 0 {
		t.Fatal("a refused plan was stored")
	}
}

// Contract section 4.5.2 merge rules through the facade: list elements are
// added and removed, adding a present one changes nothing, removing an absent
// one is refused, project rules compare by kind and normalised pattern.
func TestAgentListEdits(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule,
		"add": map[string]any{"keywords": []string{"gamma", " ALPHA "}}, "remove": map[string]any{"keywords": []string{"beta"}}})
	fixture.apply(t, plan.PlanID)
	rule := item(t, fixture.show(t, "content-rule"), "items", "id", ids.contentRule)
	if got := rule["keywords_untrusted"]; !reflect.DeepEqual(got, []any{"alpha", "gamma"}) {
		t.Fatalf("keywords = %v", got)
	}
	body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule,
		"remove": map[string]any{"keywords": []string{"absent"}}}, fixture.adminWrite))
	if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != "keywords" || body.Details["reason"] != "not_present" {
		t.Fatalf("remove absent = %s %v", body.Code, body.Details)
	}
	project := fixture.plan(t, map[string]any{"op": "config.set", "kind": "project", "id": ids.project,
		"add": map[string]any{"rules": []any{map[string]any{"kind": "repo_url", "pattern": "git.example.com/team/demo"}, map[string]any{"kind": "repo_name", "pattern": " demo "}}}})
	if !reflect.DeepEqual(project.ChangedKeys, []string{"rules"}) || project.Extras["preview"] == nil {
		t.Fatalf("project plan = %+v", project)
	}
	fixture.apply(t, project.PlanID)
	rules := item(t, fixture.show(t, "org"), "projects", "id", ids.project)["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %v", rules)
	}
	weekly := fixture.plan(t, map[string]any{"op": "config.set", "kind": "weekly-settings", "add": map[string]any{"ranked_clients": []string{"opencode"}}})
	fixture.apply(t, weekly.PlanID)
	if clients := fixture.show(t, "weekly-settings")["settings"].(map[string]any)["ranked_clients"]; !reflect.DeepEqual(clients, []any{"codex", "opencode"}) {
		t.Fatalf("ranked clients = %v", clients)
	}
	if body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "weekly-settings",
		"add": map[string]any{"ranked_clients": []string{"no-such-client"}}}, fixture.adminWrite)); body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != "ranked_clients" {
		t.Fatalf("unknown client = %s %v", body.Code, body.Details)
	}
}

// Contract section 4.5.1: a removal carries the deleted object, and a group
// with projects cannot be removed (CONFLICT, as on the web).
func TestAgentRemove(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.remove", "kind": "group", "id": ids.group}, fixture.adminWrite))
	if body.Code != agentapi.CodeConflict {
		t.Fatalf("remove a group with projects = %s %v", body.Code, body.Details)
	}
	for _, kind := range []string{"ua-rule", "content-rule", "project", "member", "principal"} {
		id := map[string]string{"ua-rule": ids.uaRule, "content-rule": ids.contentRule, "project": ids.project, "member": "7", "principal": "user:7"}[kind]
		before := fixture.objectOf(t, kind, id)
		plan := fixture.plan(t, map[string]any{"op": "config.remove", "kind": kind, "id": id})
		var deleted map[string]any
		encoded, _ := json.Marshal(plan.Extras["deleted_object"])
		_ = json.Unmarshal(encoded, &deleted)
		if !reflect.DeepEqual(deleted, before) || plan.Target.Version != before["version"] || string(plan.After) != "null" {
			t.Fatalf("%s removal plan = %+v (before %v)", kind, plan, before)
		}
		fixture.apply(t, plan.PlanID)
		if fixture.objectOf(t, kind, id) != nil {
			t.Fatalf("%s %s still there", kind, id)
		}
	}
}

// Contract section 0.1 item 103: changed_keys of a create plan lists every
// field the caller supplied, a field set to its zero value included, in the
// kind's field order; a field the caller left out and that takes a default
// is shown only in after.
func TestCreatePlanChangedKeysListEverySuppliedField(t *testing.T) {
	fixture := newWriteFixture(t)
	ua := fixture.plan(t, map[string]any{"op": "config.set", "kind": "ua-rule", "set": map[string]any{
		"name": "off rule", "enabled": false, "model_pattern": ".*", "user_agent_pattern": "^curl/"}})
	if want := []string{"name", "enabled", "model_pattern", "user_agent_pattern"}; !reflect.DeepEqual(ua.ChangedKeys, want) {
		t.Fatalf("ua-rule create changed_keys = %v, want %v", ua.ChangedKeys, want)
	}
	content := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "set": map[string]any{
		"name": "off policy", "enabled": false, "action": "dry_run", "keywords": []string{"alpha"}}})
	if want := []string{"name", "enabled", "action", "keywords"}; !reflect.DeepEqual(content.ChangedKeys, want) {
		t.Fatalf("content-rule create changed_keys = %v, want %v", content.ChangedKeys, want)
	}
	var after map[string]any
	_ = json.Unmarshal(content.After, &after)
	if scopes, _ := after["scan_scopes"].([]any); len(scopes) != 7 || after["enabled"] != false {
		t.Fatalf("content-rule create after = %v", after)
	}
	group := fixture.plan(t, map[string]any{"op": "config.set", "kind": "group", "set": map[string]any{"name": "off group", "enabled": false}})
	if want := []string{"name", "enabled"}; !reflect.DeepEqual(group.ChangedKeys, want) {
		t.Fatalf("group create changed_keys = %v", group.ChangedKeys)
	}
	project := fixture.plan(t, map[string]any{"op": "config.set", "kind": "project", "set": map[string]any{
		"name": "off project", "group_id": nil, "enabled": false, "rules": []any{}}})
	if want := []string{"name", "group_id", "enabled", "rules"}; !reflect.DeepEqual(project.ChangedKeys, want) {
		t.Fatalf("project create changed_keys = %v", project.ChangedKeys)
	}
}

// Contract section 0.1 item 104: for every removable kind, the object a
// removal plan shows in extras.deleted_object can be given back as input once
// the server-assigned fields are deleted (the _untrusted names are accepted
// as aliases), and the object it creates has every caller-settable field of
// the original. Given as it is, the copy is refused with every read-only
// field named.
func TestRemovedObjectsCanBeRecreatedFromTheirDeletedCopy(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	for _, test := range []struct{ kind, id string }{
		{"ua-rule", ids.uaRule}, {"content-rule", ids.contentRule}, {"group", ids.otherGroup},
		{"project", ids.project}, {"member", "7"}, {"principal", "user:7"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			original := fixture.objectOf(t, test.kind, test.id)
			removal := fixture.plan(t, map[string]any{"op": "config.remove", "kind": test.kind, "id": test.id})
			fixture.apply(t, removal.PlanID)
			deleted, _ := removal.Extras["deleted_object"].(map[string]any)
			if deleted == nil {
				t.Fatalf("no deleted_object: %+v", removal.Extras)
			}

			request := map[string]any{"op": "config.set", "kind": test.kind}
			switch test.kind {
			case "member":
				request["id"] = formatJSONID(deleted["user_id"])
			case "principal":
				request["id"] = deleted["kind"].(string) + ":" + formatJSONID(deleted["id"])
			}
			request["set"] = deleted
			refused := failure(t, fixture.facade(http.MethodPost, "/plans", request, fixture.adminWrite))
			var readOnly []any
			for _, field := range readOnlyFields {
				if _, ok := deleted[field]; ok && !contains(agentapi.SettableFields[test.kind], field) {
					readOnly = append(readOnly, field)
				}
			}
			if refused.Code != agentapi.CodeInvalidArgument || refused.Details["reason"] != "read_only" || len(readOnly) == 0 {
				t.Fatalf("copy given as it is = %s %v", refused.Code, refused.Details)
			}
			named, _ := refused.Details["fields"].([]any)
			if len(named) != len(readOnly) {
				t.Fatalf("read-only fields named = %v, want all of %v", named, readOnly)
			}
			for _, field := range readOnly {
				if !strings.Contains(refused.Message, field.(string)) {
					t.Fatalf("message %q does not name %s", refused.Message, field)
				}
			}

			set := map[string]any{}
			for key, value := range deleted {
				if !contains(readOnlyFields, key) || contains(agentapi.SettableFields[test.kind], key) {
					set[key] = value
				}
			}
			request["set"] = set
			applied := fixture.planAndApply(t, request)
			newID := test.id
			switch test.kind {
			case "member", "principal":
			default:
				// The server assigns the id of the new object; PostgreSQL never
				// reuses one, the SQLite test store may reuse the highest.
				if applied.ID == "" {
					t.Fatalf("restored %s has no id", test.kind)
				}
				newID = applied.ID
			}
			restored := fixture.objectOf(t, test.kind, newID)
			if restored == nil {
				t.Fatalf("restored %s %s not found", test.kind, newID)
			}
			for _, field := range agentapi.SettableFields[test.kind] {
				name := field
				if _, ok := original[field+untrustedSuffix]; ok {
					name = field + untrustedSuffix
				}
				if _, ok := original[name]; !ok {
					t.Fatalf("%s has no field %s in the read shape: %v", test.kind, field, original)
				}
				if !reflect.DeepEqual(original[name], restored[name]) {
					t.Fatalf("%s.%s = %v, restored %v", test.kind, name, original[name], restored[name])
				}
			}
		})
	}
}

// Contract section 0.1 item 104: a field and its _untrusted alias at once
// is refused, in set and inside a project rule.
func TestUntrustedAliasesCannotDuplicateAField(t *testing.T) {
	fixture := newWriteFixture(t)
	body := failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "group",
		"set": map[string]any{"name": "a", "name_untrusted": "b", "enabled": true}}, fixture.adminWrite))
	if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != "name" {
		t.Fatalf("name twice = %s %v", body.Code, body.Details)
	}
	body = failure(t, fixture.facade(http.MethodPost, "/plans", map[string]any{"op": "config.set", "kind": "project",
		"set": map[string]any{"name": "p", "group_id": nil, "enabled": true,
			"rules": []any{map[string]any{"kind": "repo_name", "pattern": "a", "pattern_untrusted": "b"}}}}, fixture.adminWrite))
	if body.Code != agentapi.CodeInvalidArgument || body.Details["field"] != "rules[0].pattern" {
		t.Fatalf("pattern twice = %s %v", body.Code, body.Details)
	}
	// The alias works in --add as well.
	ids := fixture.seed(t)
	plan := fixture.plan(t, map[string]any{"op": "config.set", "kind": "content-rule", "id": ids.contentRule,
		"add": map[string]any{"keywords_untrusted": []string{"gamma"}}})
	if !reflect.DeepEqual(plan.ChangedKeys, []string{"keywords"}) {
		t.Fatalf("alias in add changed_keys = %v", plan.ChangedKeys)
	}
}
