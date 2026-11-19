package agentcli

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

const sessionHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type commandCase struct {
	name   string
	args   []string
	method string
	path   string // relative to agentapi.PathPrefix, as sent (escaped)
	query  url.Values
	body   string // expected JSON body; "" means no body
	// errorCodes are the server codes this command's test also exercises.
	errorCodes []agentapi.Code
}

var readErrors = []agentapi.Code{agentapi.CodeUnauthenticated, agentapi.CodeForbiddenRole, agentapi.CodeInvalidArgument, agentapi.CodeNotFound, agentapi.CodeModuleDisabled, agentapi.CodeRateLimited}

var planErrors = []agentapi.Code{agentapi.CodeReadOnlyToken, agentapi.CodeWriteDisabled, agentapi.CodeInvalidArgument, agentapi.CodeAlreadyExists, agentapi.CodeVersionConflict}

func commandCases(t *testing.T) []commandCase {
	dir := t.TempDir()
	labels := writeFile(t, filepath.Join(dir, "labels.json"), `[{"session_id":"`+sessionHex+`","outcome":"ok"}]`)
	wrapped := writeFile(t, filepath.Join(dir, "wrapped.json"), `{"labels":[{"session_id":"`+sessionHex+`"}]}`)
	patch := writeFile(t, filepath.Join(dir, "patch.json"), `{"name":"from-file","model_pattern":"^a\\d+$"}`)
	tz := url.Values{"tz_offset_min": {"480"}}
	return []commandCase{
		{name: "whoami", args: []string{"whoami"}, method: "GET", path: "/whoami", errorCodes: []agentapi.Code{agentapi.CodeUnauthenticated, agentapi.CodeTokenExpired, agentapi.CodeTokenRevoked, agentapi.CodeRoleUnavailable, agentapi.CodeFeatureDisabled}},
		{name: "requests list", args: []string{"requests", "list", "--since", "2h", "--from", "2026-01-01", "--to", "2026-01-02", "--model", "m1", "--status", "5xx", "--user-agent", "ua x", "--path", "/v1/chat/completions", "--protocol", "openai", "--conversation", "conv_1", "--no-collapse", "--limit", "20", "--cursor", "c1", "--user-id", "1", "--username", "u1", "--token-id", "2", "--token-name", "t1"},
			method: "GET", path: "/requests", query: url.Values{"since": {"2h"}, "from": {"2026-01-01"}, "to": {"2026-01-02"}, "model": {"m1"}, "status": {"5xx"}, "user_agent": {"ua x"}, "path": {"/v1/chat/completions"}, "protocol": {"openai"}, "conversation": {"conv_1"}, "collapse": {"false"}, "limit": {"20"}, "cursor": {"c1"}, "user_id": {"1"}, "username": {"u1"}, "token_id": {"2"}, "token_name": {"t1"}},
			errorCodes: readErrors},
		{name: "requests list minimal", args: []string{"requests", "list"}, method: "GET", path: "/requests"},
		{name: "requests list state filters", args: []string{"requests", "list", "--forward-status", "rejected", "--blocked-by", "content_policy", "--block-code", "body_too_large", "--capture-status", "partial", "--upstream-error-class", "cyber_policy"},
			method: "GET", path: "/requests", query: url.Values{"forward_status": {"rejected"}, "blocked_by": {"content_policy"}, "block_code": {"body_too_large"}, "capture_status": {"partial"}, "upstream_error_class": {"cyber_policy"}}},
		{name: "requests get", args: []string{"requests", "get", "123", "--headers", "all"}, method: "GET", path: "/requests/123", query: url.Values{"headers": {"all"}}, errorCodes: []agentapi.Code{agentapi.CodeNotFound, agentapi.CodeNotReady}},
		{name: "requests get escaped", args: []string{"requests", "get", "a/b"}, method: "GET", path: "/requests/a%2Fb"},
		{name: "usage overview", args: []string{"usage", "overview", "--since", "7d", "--group-by", "model"}, method: "GET", path: "/usage/overview", query: url.Values{"since": {"7d"}, "group_by": {"model"}, "tz_offset_min": {"480"}}, errorCodes: readErrors},
		{name: "usage overview negative offset", args: []string{"usage", "overview", "--from", "2026-01-01", "--to", "2026-01-31", "--tz-offset-min", "-60"}, method: "GET", path: "/usage/overview", query: url.Values{"from": {"2026-01-01"}, "to": {"2026-01-31"}, "tz_offset_min": {"-60"}}},
		{name: "usage overview default offset", args: []string{"usage", "overview"}, method: "GET", path: "/usage/overview", query: tz},
		{name: "usage sessions", args: []string{"usage", "sessions", "--since", "1d", "--sort", "tokens", "--limit", "5", "--cursor", "c"}, method: "GET", path: "/usage/sessions", query: url.Values{"since": {"1d"}, "sort": {"tokens"}, "limit": {"5"}, "cursor": {"c"}}, errorCodes: readErrors},
		{name: "usage sessions range", args: []string{"usage", "sessions", "--from", "2026-01-01", "--to", "2026-01-31"}, method: "GET", path: "/usage/sessions", query: url.Values{"from": {"2026-01-01"}, "to": {"2026-01-31"}}},
		{name: "usage trend", args: []string{"usage", "trend", "ses_1"}, method: "GET", path: "/usage/sessions/ses_1/trend", errorCodes: []agentapi.Code{agentapi.CodeNotFound}},
		{name: "usage tree", args: []string{"usage", "tree", "0123456789abcdef01234567"}, method: "GET", path: "/usage/trees/0123456789abcdef01234567", errorCodes: []agentapi.Code{agentapi.CodeNotFound}},
		{name: "usage composition", args: []string{"usage", "composition", "9"}, method: "GET", path: "/requests/9/composition", errorCodes: []agentapi.Code{agentapi.CodeNotFound}},
		{name: "weekly me", args: []string{"weekly", "me"}, method: "GET", path: "/weekly/me", errorCodes: []agentapi.Code{agentapi.CodeModuleDisabled}},
		{name: "weekly report", args: []string{"weekly", "report", "--week", "2026-01-05", "--group-id", "0", "--metric", "cost"}, method: "GET", path: "/weekly/report", query: url.Values{"week": {"2026-01-05"}, "group_id": {"0"}, "metric": {"cost"}}, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole, agentapi.CodeInvalidArgument}},
		{name: "weekly trend", args: []string{"weekly", "trend", "--weeks", "4", "--group-id", "2"}, method: "GET", path: "/weekly/trend", query: url.Values{"weeks": {"4"}, "group_id": {"2"}}, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole}},
		{name: "weekly project negative id", args: []string{"weekly", "project", "-1", "--week", "2026-01-05"}, method: "GET", path: "/weekly/projects/-1", query: url.Values{"week": {"2026-01-05"}}, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole, agentapi.CodeNotFound}},
		{name: "weekly unattributed", args: []string{"weekly", "unattributed", "--week", "2026-01-05", "--limit", "10"}, method: "GET", path: "/weekly/unattributed", query: url.Values{"week": {"2026-01-05"}, "limit": {"10"}}, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole}},
		{name: "weekly regenerate", args: []string{"weekly", "regenerate", "--week", "2026-01-05"}, method: "POST", path: "/plans", body: `{"op":"weekly.regenerate","args":{"week":"2026-01-05"}}`, errorCodes: planErrors},
		{name: "analysis overview", args: []string{"analysis", "overview", "--since", "7d", "--user-id", "3"}, method: "GET", path: "/analysis/overview", query: url.Values{"since": {"7d"}, "user_id": {"3"}}, errorCodes: readErrors},
		{name: "analysis users", args: []string{"analysis", "users", "--from", "2026-01-01", "--to", "2026-01-31"}, method: "GET", path: "/analysis/users", query: url.Values{"from": {"2026-01-01"}, "to": {"2026-01-31"}}, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole}},
		{name: "analysis sessions", args: []string{"analysis", "sessions", "--since", "7d", "--kind", "agent", "--flags", "a,b", "--limit", "10", "--cursor", "c", "--user-id", "4"}, method: "GET", path: "/analysis/sessions", query: url.Values{"since": {"7d"}, "kind": {"agent"}, "flags": {"a,b"}, "limit": {"10"}, "cursor": {"c"}, "user_id": {"4"}}, errorCodes: readErrors},
		{name: "analysis sessions range", args: []string{"analysis", "sessions", "--from", "2026-01-01", "--to", "2026-01-31"}, method: "GET", path: "/analysis/sessions", query: url.Values{"from": {"2026-01-01"}, "to": {"2026-01-31"}}},
		{name: "analysis session facet", args: []string{"analysis", "session", sessionHex, "--facet"}, method: "GET", path: "/analysis/sessions/" + sessionHex + "/facet", errorCodes: []agentapi.Code{agentapi.CodeNotFound, agentapi.CodeRateLimited}},
		{name: "analysis report", args: []string{"analysis", "report", "--week", "previous", "--project-id", "5"}, method: "GET", path: "/analysis/report", query: url.Values{"week": {"previous"}, "project_id": {"5"}}, errorCodes: readErrors},
		{name: "analysis report user and group", args: []string{"analysis", "report", "--user-id", "6", "--group-id", "7"}, method: "GET", path: "/analysis/report", query: url.Values{"user_id": {"6"}, "group_id": {"7"}}},
		{name: "analysis run", args: []string{"analysis", "run"}, method: "POST", path: "/plans", body: `{"op":"analysis.run"}`, errorCodes: planErrors},
		{name: "analysis calibrate array", args: []string{"analysis", "calibrate", "--file", labels}, method: "POST", path: "/plans", body: `{"op":"analysis.calibrate","args":{"labels":[{"session_id":"` + sessionHex + `","outcome":"ok"}]}}`, errorCodes: planErrors},
		{name: "analysis calibrate wrapped", args: []string{"analysis", "calibrate", "--file", wrapped}, method: "POST", path: "/plans", body: `{"op":"analysis.calibrate","args":{"labels":[{"session_id":"` + sessionHex + `"}]}}`},
		{name: "analysis dismiss", args: []string{"analysis", "dismiss", "42"}, method: "POST", path: "/plans", body: `{"op":"analysis.dismiss","args":{"suggestion_id":42}}`, errorCodes: planErrors},
		{name: "analysis test-model", args: []string{"analysis", "test-model", "--set", "llm.model=example-model", "--set", "llm.enabled=true", "--set", "llm.max_concurrency=2"}, method: "POST", path: "/analysis/test-model", body: `{"set":{"llm.enabled":true,"llm.max_concurrency":2,"llm.model":"example-model"}}`, errorCodes: []agentapi.Code{agentapi.CodeReadOnlyToken, agentapi.CodeRateLimited}},
		{name: "analysis test-model saved", args: []string{"analysis", "test-model"}, method: "POST", path: "/analysis/test-model", body: `{}`},
		{name: "config show ua-rule", args: []string{"config", "show", "--kind", "ua-rule"}, method: "GET", path: "/config/ua-rule", errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole}},
		{name: "config show content-rule", args: []string{"config", "show", "--kind", "content-rule"}, method: "GET", path: "/config/content-rule"},
		{name: "config show org", args: []string{"config", "show", "--kind", "org"}, method: "GET", path: "/config/org"},
		{name: "config show weekly-settings", args: []string{"config", "show", "--kind", "weekly-settings"}, method: "GET", path: "/config/weekly-settings"},
		{name: "config show analysis-settings", args: []string{"config", "show", "--kind", "analysis-settings"}, method: "GET", path: "/config/analysis-settings"},
		{name: "config preview-project", args: []string{"config", "preview-project", "--group-id", "2", "--rule", "repo:example-repo", "--rule", "path:a:b", "--week", "2026-01-05", "--project-id", "7"}, method: "POST", path: "/config/project-preview",
			body: `{"group_id":2,"project_id":7,"rules":[{"kind":"repo","pattern":"example-repo"},{"kind":"path","pattern":"a:b"}],"week":"2026-01-05"}`, errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole, agentapi.CodeInvalidArgument}},
		{name: "config preview-project unified", args: []string{"config", "preview-project", "--group-id", "null"}, method: "POST", path: "/config/project-preview", body: `{"group_id":null,"rules":[]}`},
		{name: "config set", args: []string{"config", "set", "--kind", "content-rule", "--id", "12", "--set", "enabled=false", "--set", "name=first", "--set-json", `keywords=["a","b"]`, "--patch-file", patch, "--set", "name=last", "--set", "count=007", "--set", "ratio=1.5", "--set", "note=null", "--add", "scan_scopes=tool_result", "--add", "rules=repo:x:y", "--remove", "keywords=old", "--if-version", "1763500000000000000"},
			method: "POST", path: "/plans",
			body:       `{"add":{"rules":[{"kind":"repo","pattern":"x:y"}],"scan_scopes":["tool_result"]},"expected_version":"1763500000000000000","id":"12","kind":"content-rule","op":"config.set","remove":{"keywords":["old"]},"set":{"count":"007","enabled":false,"keywords":["a","b"],"model_pattern":"^a\\d+$","name":"last","note":null,"ratio":1.5}}`,
			errorCodes: planErrors},
		{name: "config set patch file wins when later", args: []string{"config", "set", "--kind", "content-rule", "--set", "name=first", "--patch-file", patch}, method: "POST", path: "/plans", body: `{"kind":"content-rule","op":"config.set","set":{"model_pattern":"^a\\d+$","name":"from-file"}}`},
		{name: "config remove", args: []string{"config", "remove", "--kind", "ua-rule", "--id", "3", "--if-version", "5"}, method: "POST", path: "/plans", body: `{"op":"config.remove","kind":"ua-rule","id":"3","expected_version":"5"}`, errorCodes: append(planErrors, agentapi.CodeConflict)},
		{name: "config reset", args: []string{"config", "reset", "--kind", "weekly-settings"}, method: "POST", path: "/plans", body: `{"op":"config.reset","kind":"weekly-settings"}`, errorCodes: planErrors},
		{name: "config set-key clear", args: []string{"config", "set-key", "--kind", "analysis-settings", "--clear"}, method: "DELETE", path: "/config/analysis-settings/api-key", errorCodes: []agentapi.Code{agentapi.CodeReadOnlyToken, agentapi.CodeWriteDisabled}},
		{name: "callers list", args: []string{"callers", "list"}, method: "GET", path: "/callers", errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole, agentapi.CodeUpstreamUnavailable}},
		{name: "status", args: []string{"status"}, method: "GET", path: "/status", errorCodes: []agentapi.Code{agentapi.CodeForbiddenRole}},
		{name: "apply", args: []string{"apply", "pln_abc"}, method: "POST", path: "/plans/pln_abc/apply", errorCodes: []agentapi.Code{agentapi.CodePlanNotFound, agentapi.CodePlanExpired, agentapi.CodeVersionConflict, agentapi.CodeRunInProgress, agentapi.CodeWriteDisabled}},
	}
}

func jsonEqual(t *testing.T, got []byte, want string) bool {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(got, &left); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(want), &right); err != nil {
		t.Fatalf("bad expected JSON %s", want)
	}
	return reflect.DeepEqual(left, right)
}

func TestEveryCommandSendsTheContractRequest(t *testing.T) {
	server := newFakeServer(t, nil)
	for _, testCase := range commandCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.saveLogin(server.URL)
			server.setResponder(nil)
			server.reset()
			if exit := h.run(testCase.args...); exit != 0 {
				t.Fatalf("exit %d, stderr %q", exit, h.stderr.String())
			}
			h.success()
			if h.stderr.Len() != 0 {
				t.Fatalf("stderr not empty on success: %q", h.stderr.String())
			}
			requests := server.recorded()
			if len(requests) != 1 {
				t.Fatalf("got %d requests", len(requests))
			}
			request := requests[0]
			if request.Method != testCase.method || request.Path != agentapi.PathPrefix+testCase.path {
				t.Fatalf("got %s %s, want %s %s", request.Method, request.Path, testCase.method, agentapi.PathPrefix+testCase.path)
			}
			wantQuery := testCase.query
			if wantQuery == nil {
				wantQuery = url.Values{}
			}
			gotQuery := url.Values(request.Query)
			if !reflect.DeepEqual(gotQuery, wantQuery) {
				t.Fatalf("query %v, want %v", gotQuery, wantQuery)
			}
			if testCase.body == "" {
				if len(request.Body) != 0 {
					t.Fatalf("unexpected body %s", request.Body)
				}
			} else if !jsonEqual(t, request.Body, testCase.body) {
				t.Fatalf("body %s, want %s", request.Body, testCase.body)
			}
			spec, _, err := findCommand(allCommands(), testCase.args)
			if err != nil {
				t.Fatal(err)
			}
			if got := request.Header.Get("Authorization"); got != "Bearer "+testToken {
				t.Fatalf("authorization header %q", got)
			}
			if got := request.Header.Get(agentapi.HeaderCLIVersion); got != Version {
				t.Fatalf("version header %q", got)
			}
			if got := request.Header.Get(agentapi.HeaderCommand); got != spec.header() {
				t.Fatalf("command header %q, want %q", got, spec.header())
			}

			for _, code := range testCase.errorCodes {
				server.setResponder(failWith(code))
				exit := h.run(testCase.args...)
				h.expectFailure(exit, code, agentapi.ExitCode(code))
			}
		})
	}
}

// TestCommandHeaderIsRecordable: the server records the command header only
// when it looks like requests.list (contract 0.1 #14).
func TestCommandHeaderIsRecordable(t *testing.T) {
	for _, spec := range allCommands() {
		header := spec.header()
		if len(header) > 64 || strings.Trim(header, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" {
			t.Errorf("command header %q is not recordable", header)
		}
	}
}

// TestRoutesCoverEveryCommand: every command has a route, every route is
// exercised by the command cases or a dedicated test, and the routes the
// server already registers match its registry.
func TestRoutesCoverEveryCommand(t *testing.T) {
	routes := Routes()
	byCommand := map[string][]Route{}
	for _, route := range routes {
		byCommand[route.Command] = append(byCommand[route.Command], route)
		if !strings.HasPrefix(route.Path, "/") || strings.HasPrefix(route.Path, agentapi.PathPrefix) {
			t.Errorf("route path %q must be relative to the prefix", route.Path)
		}
	}
	for _, spec := range allCommands() {
		if len(byCommand[spec.name()]) == 0 {
			t.Errorf("command %q has no route", spec.name())
		}
	}
	if len(allCommands()) != 36 {
		t.Errorf("got %d commands, the contract (sections 6.2 and 6.3) has 36", len(allCommands()))
	}

	exercised := map[string]bool{}
	for _, testCase := range commandCases(t) {
		spec, _, err := findCommand(allCommands(), testCase.args)
		if err != nil {
			t.Fatal(err)
		}
		exercised[spec.name()+" "+testCase.method+" "+templateOf(spec, testCase.method, testCase.path)] = true
	}
	// Covered by dedicated tests: login, logout, version, export, set-key PUT, pack.
	for _, extra := range []string{
		"login POST /token", "logout POST /logout", "version GET /whoami",
		"requests export GET /requests/{id}/export/{what}", "config set-key PUT /config/analysis-settings/api-key",
		"analysis session GET /analysis/sessions/{id}/pack",
	} {
		exercised[extra] = true
	}
	for _, route := range routes {
		if !exercised[route.Command+" "+route.Method+" "+route.Path] {
			t.Errorf("route %s %s of %q is not exercised by any test", route.Method, route.Path, route.Command)
		}
	}

	registry := agentapi.NewRegistry(agentapi.Endpoints)
	for _, route := range routes {
		switch route.Path {
		case "/token", "/whoami", "/logout":
			if _, _, ok := registry.Match(route.Method, agentapi.PathPrefix+route.Path); !ok {
				t.Errorf("route %s %s is not in the server registry", route.Method, route.Path)
			}
		}
	}

	want := map[string]Route{
		"login":          {Command: "login", Method: "POST", Path: "/token", Body: []string{"code", "code_verifier"}},
		"config set":     {Command: "config set", Method: "POST", Path: "/plans", Body: []string{"add", "expected_version", "id", "kind", "op", "remove", "set"}},
		"apply":          {Command: "apply", Method: "POST", Path: "/plans/{plan_id}/apply"},
		"weekly project": {Command: "weekly project", Method: "GET", Path: "/weekly/projects/{id}", Query: []string{"week"}},
	}
	for name, expected := range want {
		if got := byCommand[name][0]; !reflect.DeepEqual(got, expected) {
			t.Errorf("route of %q = %+v, want %+v", name, got, expected)
		}
	}
	setKey := byCommand["config set-key"]
	if len(setKey) != 2 || setKey[0].Method != "PUT" || !reflect.DeepEqual(setKey[0].Body, []string{"api_key"}) || setKey[1].Method != "DELETE" || setKey[1].Body != nil {
		t.Errorf("set-key routes = %+v", setKey)
	}
}

// templateOf maps a sent path back to the route template of the command.
func templateOf(spec *commandSpec, method, sent string) string {
	sentSegments := strings.Split(sent, "/")
	for _, route := range spec.Routes {
		if route.Method != method {
			continue
		}
		segments := strings.Split(route.Path, "/")
		if len(segments) != len(sentSegments) {
			continue
		}
		match := true
		for index, segment := range segments {
			if !strings.HasPrefix(segment, "{") && segment != sentSegments[index] {
				match = false
			}
		}
		if match {
			return route.Path
		}
	}
	return sent
}
