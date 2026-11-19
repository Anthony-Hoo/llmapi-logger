package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"
)

// readCall is one sample call of a read endpoint and the web route(s) it is
// equivalent to (contract section 4.8).
type readCall struct {
	id, method, path, body string
	web                    []string
}

const previewBody = `{"week":"2026-11-02","group_id":null,"rules":[{"kind":"repo_name","pattern":"demo"}],"project_id":0}`

func readCalls() []readCall {
	sa := "/api/v1/session-analysis/"
	return []readCall{
		{id: "requests.list", method: http.MethodGet, path: "/requests?collapse=false", web: []string{"/api/v1/audits"}},
		{id: "requests.get", method: http.MethodGet, path: "/requests/own-1?headers=all", web: []string{"/api/v1/audits/own-1"}},
		{id: "requests.export", method: http.MethodGet, path: "/requests/own-1/export/headers", web: []string{"/api/v1/audits/own-1"}},
		{id: "usage.composition", method: http.MethodGet, path: "/requests/own-1/composition", web: []string{"/api/v1/audits/own-1/composition"}},
		{id: "usage.overview", method: http.MethodGet, path: "/usage/overview?" + fixtureWindow, web: []string{"/api/v1/insights/overview?" + fixtureWindowNS}},
		{id: "usage.sessions", method: http.MethodGet, path: "/usage/sessions?" + fixtureWindow, web: []string{"/api/v1/insights/sessions?" + fixtureWindowNS}},
		{id: "usage.trend", method: http.MethodGet, path: "/usage/sessions/" + apiSessionShared + "/trend", web: []string{"/api/v1/insights/sessions/" + apiSessionShared + "/trend"}},
		{id: "usage.tree", method: http.MethodGet, path: "/usage/trees/" + apiTreeOwn, web: []string{"/api/v1/insights/agent-trees/" + apiTreeOwn}},
		{id: "weekly.me", method: http.MethodGet, path: "/weekly/me", web: []string{"/api/v1/org/me/weekly"}},
		{id: "weekly.report", method: http.MethodGet, path: "/weekly/report", web: []string{"/api/v1/org/weekly"}},
		{id: "weekly.trend", method: http.MethodGet, path: "/weekly/trend?weeks=2", web: []string{"/api/v1/org/weekly/trend?weeks=2"}},
		{id: "weekly.project", method: http.MethodGet, path: "/weekly/projects/-1", web: []string{"/api/v1/org/projects/-1/weekly"}},
		{id: "weekly.unattributed", method: http.MethodGet, path: "/weekly/unattributed", web: []string{"/api/v1/org/unattributed"}},
		{id: "analysis.overview", method: http.MethodGet, path: "/analysis/overview?" + fixtureWindow, web: []string{sa + "overview?" + fixtureWindowNS}},
		{id: "analysis.users", method: http.MethodGet, path: "/analysis/users?" + fixtureWindow, web: []string{sa + "users?" + fixtureWindowNS}},
		{id: "analysis.sessions", method: http.MethodGet, path: "/analysis/sessions?" + fixtureWindow, web: []string{sa + "sessions?" + fixtureWindowNS}},
		{id: "analysis.pack", method: http.MethodGet, path: "/analysis/sessions/" + analysisOwnID + "/pack", web: []string{sa + "sessions/" + analysisOwnID + "/pack"}},
		{id: "analysis.facet", method: http.MethodGet, path: "/analysis/sessions/" + analysisOwnID + "/facet", web: []string{sa + "sessions/" + analysisOwnID + "/facet"}},
		{id: "analysis.report", method: http.MethodGet, path: "/analysis/report", web: []string{sa + "report"}},
		{id: "config.show", method: http.MethodGet, path: "/config/org", web: []string{"/api/v1/org/catalog", "/api/v1/org/settings"}},
		{id: "config.show", method: http.MethodGet, path: "/config/ua-rule", web: []string{"/api/v1/user-agent-rules"}},
		{id: "config.show", method: http.MethodGet, path: "/config/content-rule", web: []string{"/api/v1/content-policy-rules"}},
		{id: "config.show", method: http.MethodGet, path: "/config/weekly-settings", web: []string{"/api/v1/settings/org-reports"}},
		{id: "config.show", method: http.MethodGet, path: "/config/analysis-settings", web: []string{"/api/v1/settings/session-analysis"}},
		{id: "config.project-preview", method: http.MethodPost, path: "/config/project-preview", body: previewBody, web: []string{"/api/v1/org/projects/preview"}},
		{id: "callers.list", method: http.MethodGet, path: "/callers", web: []string{"/api/v1/newapi/callers"}},
		{id: "status", method: http.MethodGet, path: "/status", web: []string{"/healthz", "/readyz"}},
	}
}

// facadeOutcome is "" for a 200 and the envelope's code otherwise.
func facadeOutcome(t *testing.T, response *httptest.ResponseRecorder) agentapi.Code {
	t.Helper()
	if response.Code == http.StatusOK {
		return ""
	}
	return agentErrorCode(t, response)
}

func endpointByID(id string) agentapi.Endpoint {
	for _, endpoint := range agentapi.Endpoints {
		if endpoint.ID == id {
			return endpoint
		}
	}
	return agentapi.Endpoint{}
}

func TestEveryReadEndpointHasASampleCall(t *testing.T) {
	covered := map[string]bool{}
	for _, call := range readCalls() {
		covered[call.id] = true
		if endpoint := endpointByID(call.id); endpoint.ID == "" || endpoint.Method != call.method {
			t.Errorf("sample %s does not match the registry", call.id)
		}
	}
	for _, endpoint := range agentapi.ReadEndpoints {
		if !covered[endpoint.ID] {
			t.Errorf("read endpoint %s has no sample call", endpoint.ID)
		}
	}
}

// Plan section 12: every read endpoint against an admin read token, an admin
// write token, a developer token, the write switch off (reads are not
// affected) and the whole feature off.
func TestAgentReadRejectionMatrix(t *testing.T) {
	disabled := newDeveloperHandler(t, Options{Developer: developerOptions(t, agentTestIdentity, nil)})
	for _, allowWrite := range []bool{true, false} {
		fixture := newReadFixtureWrites(t, allowWrite)
		for _, call := range readCalls() {
			endpoint := endpointByID(call.id)
			for kind, token := range map[string]string{"admin read": fixture.adminRead, "admin write": fixture.adminWrite, "developer": fixture.developer} {
				want := agentapi.Code("")
				if kind == "developer" && endpoint.Access == agentapi.AccessAdmin {
					want = agentapi.CodeForbiddenRole
				}
				if got := facadeOutcome(t, fixture.facade(call.method, call.path, call.body, token)); got != want {
					t.Errorf("allow_write=%v %s %s %s = %q, want %q", allowWrite, kind, call.method, call.path, got, want)
				}
			}
			off := agentEnv{handler: disabled}
			response := off.do(call.method, agentapi.PathPrefix+call.path, call.body, agentCaller{bearer: fixture.adminRead})
			if got := agentErrorCode(t, response); got != agentapi.CodeFeatureDisabled {
				t.Errorf("feature off %s = %s", call.path, got)
			}
		}
	}
}

// Optional modules that are off answer MODULE_DISABLED, never an empty
// result; the facade stays up for everything else.
func TestAgentReadModuleDisabled(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.handler.insights = nil
	fixture.handler.org = nil
	fixture.handler.sessionAnalysis = nil
	fixture.handler.sessionAnalysisSettings = nil
	for _, call := range readCalls() {
		module := strings.HasPrefix(call.id, "usage.") || strings.HasPrefix(call.id, "weekly.") || strings.HasPrefix(call.id, "analysis.") ||
			call.id == "config.project-preview" ||
			strings.HasSuffix(call.path, "/org") || strings.HasSuffix(call.path, "-settings")
		want := agentapi.Code("")
		if module {
			want = agentapi.CodeModuleDisabled
		}
		if got := facadeOutcome(t, fixture.facade(call.method, call.path, call.body, fixture.adminRead)); got != want {
			t.Errorf("%s = %q, want %q", call.path, got, want)
		}
	}
}

// --- parity -------------------------------------------------------------

// corpus is every scalar value of a web response, as text, plus the
// canonical float form of every value that is a number.
type corpus map[string]bool

func (values corpus) add(raw []byte) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if decoder.Decode(&decoded) != nil {
		return
	}
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case json.Number:
			values.addText(typed.String())
		case string:
			values.addText(typed)
		}
	}
	walk(decoded)
}

func (values corpus) addText(text string) {
	values[text] = true
	if number, err := strconv.ParseFloat(text, 64); err == nil {
		values[strconv.FormatFloat(number, 'g', -1, 64)] = true
	}
}

func (values corpus) hasNumber(number float64) bool {
	return values[strconv.FormatFloat(number, 'g', -1, 64)] || values[strconv.FormatInt(int64(number), 10)]
}

func (values corpus) containsSubstring(text string) bool {
	for value := range values {
		if strings.Contains(value, text) {
			return true
		}
	}
	return false
}

// derivedKeys are facade fields computed from web fields rather than copied:
// the unified state and status folds, the masking marker, opaque cursors.
var derivedKeys = map[string]bool{
	"state": true, "parse": true, "capture": true, "value_omitted": true, "headers_scope": true,
	"next_cursor": true, "incomplete_reason": true, "version": true,
}

// derivable reports whether one facade value can be read off the web corpus.
func derivable(web corpus, path []string, key string, value any) bool {
	switch typed := value.(type) {
	case nil, bool:
		return true
	case json.Number:
		number, _ := typed.Float64()
		if number == 0 || web.hasNumber(number) {
			return true
		}
		for _, segment := range path {
			if segment == "request_uri" {
				// lengths of the pieces of the web's request_uri
				return true
			}
		}
		switch {
		case strings.HasSuffix(key, "_seconds"):
			return web.hasNumber(math.Round(number * 1e9))
		case strings.HasSuffix(key, "_ms"):
			return web.hasNumber(math.Round(number * 1e6))
		}
		return false
	case string:
		if typed == "" || web[typed] || derivedKeys[key] {
			return true
		}
		if strings.HasSuffix(key, "_at") {
			at, err := time.Parse(time.RFC3339Nano, typed)
			return err == nil && web[strconv.FormatInt(at.UnixNano(), 10)]
		}
		// The Request-URI is split into path and parameters; each piece
		// must be part of the web's request_uri.
		for _, segment := range path {
			if segment == "request_uri" {
				return web.containsSubstring(typed)
			}
		}
		return false
	}
	return false
}

// assertDerivable checks every scalar of facade data against the web corpus.
func assertDerivable(t *testing.T, label string, web corpus, data json.RawMessage) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("%s: data does not decode: %v", label, err)
	}
	var walk func(path []string, key string, value any)
	walk = func(path []string, key string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for childKey, child := range typed {
				walk(append(path, childKey), childKey, child)
			}
		case []any:
			for _, child := range typed {
				walk(path, key, child)
			}
		default:
			if !derivable(web, path, key, typed) {
				t.Errorf("%s: %s = %v is not in the web response", label, strings.Join(path, "."), typed)
			}
		}
	}
	walk(nil, "", decoded)
}

func collectIDs(raw []byte, key string) []string {
	var decoded any
	_ = json.Unmarshal(raw, &decoded)
	var ids []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for childKey, child := range typed {
				if text, ok := child.(string); ok && childKey == key {
					ids = append(ids, text)
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(decoded)
	sort.Strings(ids)
	return ids
}

// Plan section 12, parity: on one shared fixture, for every read endpoint and
// both identities, every scalar value the facade returns (string or non-zero
// number, after converting _at times back to nanoseconds, _seconds and _ms
// back to nanoseconds) occurs in what the same identity gets from the
// equivalent web routes, every audit_id and session_id the facade lists is
// one the web lists, and the facade fails exactly when the web does. Fields
// computed from web fields (derivedKeys) are exempt from the value check.
func TestAgentReadParity(t *testing.T) {
	fixture := newReadFixture(t)
	identities := []struct {
		name   string
		token  string
		cookie *http.Cookie
		role   agentapi.Role
	}{
		{"admin", fixture.adminRead, fixture.adminWeb, agentapi.RoleAdmin},
		{"developer", fixture.developer, fixture.developerWeb, agentapi.RoleDeveloper},
	}
	for _, identity := range identities {
		for _, call := range readCalls() {
			label := identity.name + " " + call.path
			web := corpus{}
			webOK, webForbidden := true, false
			var webBodies [][]byte
			for _, path := range call.web {
				response := fixture.web(call.method, path, call.body, identity.cookie)
				webOK = webOK && response.Code == http.StatusOK
				webForbidden = webForbidden || response.Code == http.StatusForbidden
				web.add(response.Body.Bytes())
				webBodies = append(webBodies, response.Body.Bytes())
			}
			response := fixture.facade(call.method, call.path, call.body, identity.token)
			// The registry's access column agrees with the web: a route the
			// web refuses this identity is FORBIDDEN_ROLE, and only such a one.
			if facadeForbidden := facadeOutcome(t, response) == agentapi.CodeForbiddenRole; facadeForbidden != webForbidden {
				t.Errorf("%s: facade forbidden=%v, web forbidden=%v", label, facadeForbidden, webForbidden)
			}
			if (response.Code == http.StatusOK) != webOK {
				t.Errorf("%s: facade %d, web ok=%v", label, response.Code, webOK)
				continue
			}
			if !webOK {
				continue
			}
			data := response.Body.Bytes()
			if call.id != "requests.export" {
				data = decodeAgent(t, response).Data
			}
			assertDerivable(t, label, web, data)
			for _, key := range []string{"audit_id", "session_id"} {
				webIDs := map[string]bool{}
				for _, body := range webBodies {
					for _, id := range collectIDs(body, key) {
						webIDs[id] = true
					}
				}
				facadeIDs := map[string]bool{}
				for _, id := range collectIDs(data, key) {
					facadeIDs[id] = true
					if !webIDs[id] {
						t.Errorf("%s: facade lists %s %s the web does not", label, key, id)
					}
				}
				// ... and no fewer: the same query lists the same records.
				for id := range webIDs {
					if !facadeIDs[id] {
						t.Errorf("%s: web lists %s %s the facade does not", label, key, id)
					}
				}
			}
		}
	}
	// The exports against their own web routes.
	exports := map[string]string{
		"conversation": "/api/v1/audits/own-1", "request": "/api/v1/audits/own-1/reconstructed/request",
		"response": "/api/v1/audits/own-1/reconstructed/response", "timeline-request": "/api/v1/audits/own-1/timeline/request",
		"timeline-response": "/api/v1/audits/own-1/timeline/response",
	}
	for _, identity := range identities {
		for what, path := range exports {
			web := corpus{}
			web.add(fixture.web(http.MethodGet, path, "", identity.cookie).Body.Bytes())
			response := fixture.facade(http.MethodGet, "/requests/own-1/export/"+what, "", identity.token)
			if response.Code != http.StatusOK {
				t.Fatalf("%s export %s = %d", identity.name, what, response.Code)
			}
			assertDerivable(t, identity.name+" export "+what, web, response.Body.Bytes())
		}
		for _, side := range []string{"request", "response"} {
			web := fixture.web(http.MethodGet, "/api/v1/audits/own-1/raw/"+side, "", identity.cookie)
			facade := fixture.facade(http.MethodGet, "/requests/own-1/export/raw-"+side, "", identity.token)
			if facade.Code != http.StatusOK || !bytes.Equal(web.Body.Bytes(), facade.Body.Bytes()) {
				t.Fatalf("%s raw %s differs: %q %q", identity.name, side, web.Body.String(), facade.Body.String())
			}
			for _, name := range []string{"X-Audit-Complete", "X-Audit-Stored-Length", "X-Audit-Observed-Length", "X-Audit-Missing-Chunks", "X-Audit-SHA256"} {
				if web.Header().Get(name) != facade.Header().Get(name) {
					t.Errorf("raw %s header %s differs", side, name)
				}
			}
		}
	}
}

// --- D-rules --------------------------------------------------------------

func readData(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	var data map[string]any
	if err := json.Unmarshal(decodeAgent(t, response).Data, &data); err != nil {
		t.Fatalf("data = %s", response.Body.String())
	}
	return data
}

func listedAuditIDs(t *testing.T, response *httptest.ResponseRecorder) []string {
	t.Helper()
	data := readData(t, response)
	ids := []string{}
	for _, item := range data["items"].([]any) {
		ids = append(ids, item.(map[string]any)["audit_id"].(string))
	}
	sort.Strings(ids)
	return ids
}

func TestAgentDRules(t *testing.T) {
	fixture := newReadFixture(t)

	t.Run("D1 a developer reads its own key's records, by fingerprint or token id", func(t *testing.T) {
		got := listedAuditIDs(t, fixture.facade(http.MethodGet, "/requests?collapse=false", "", fixture.developer))
		if want := []string{"own-1", "token-only", "too-large-own"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("developer list = %v, want %v", got, want)
		}
		if got := listedAuditIDs(t, fixture.facade(http.MethodGet, "/requests?collapse=false", "", fixture.adminRead)); len(got) != 5 {
			t.Fatalf("admin list = %v", got)
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/requests/token-only", "", fixture.developer)); code != "" {
			t.Fatalf("token-id match = %s", code)
		}
	})

	t.Run("D2 locally blocked records are hidden except body_too_large", func(t *testing.T) {
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/requests/blocked-own", "", fixture.developer)); code != agentapi.CodeNotFound {
			t.Fatalf("blocked = %s", code)
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/requests/too-large-own", "", fixture.developer)); code != "" {
			t.Fatalf("body_too_large = %s", code)
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/requests/blocked-own", "", fixture.adminRead)); code != "" {
			t.Fatalf("admin blocked = %s", code)
		}
	})

	t.Run("D3 another key's record and a missing one look the same", func(t *testing.T) {
		foreign := fixture.facade(http.MethodGet, "/requests/foreign", "", fixture.developer)
		missing := fixture.facade(http.MethodGet, "/requests/does-not-exist", "", fixture.developer)
		if foreign.Code != http.StatusNotFound || !bytes.Equal(foreign.Body.Bytes(), missing.Body.Bytes()) {
			t.Fatalf("foreign %d %s / missing %s", foreign.Code, foreign.Body.String(), missing.Body.String())
		}
	})

	t.Run("D4 caller filters are refused for a developer before any read", func(t *testing.T) {
		before := fixture.audits.listCalls
		for _, key := range []string{"user_id=8", "username=x", "token_id=99", "token_name=x", "username="} {
			response := fixture.facade(http.MethodGet, "/requests?"+key, "", fixture.developer)
			decoded := decodeAgent(t, response)
			field := strings.SplitN(key, "=", 2)[0]
			if response.Code != http.StatusBadRequest || decoded.Error == nil || decoded.Error.Code != agentapi.CodeInvalidArgument || decoded.Error.Details["field"] != field {
				t.Fatalf("developer %s = %d %s", key, response.Code, response.Body.String())
			}
		}
		if fixture.audits.listCalls != before {
			t.Fatal("a refused filter reached the service")
		}
		if got := listedAuditIDs(t, fixture.facade(http.MethodGet, "/requests?user_id=8&collapse=false", "", fixture.adminRead)); !reflect.DeepEqual(got, []string{"foreign"}) {
			t.Fatalf("admin user filter = %v", got)
		}
	})

	t.Run("D5 no caller or token grouping and no session caller for a developer", func(t *testing.T) {
		for _, group := range []string{"caller", "token"} {
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/usage/overview?group_by="+group+"&"+fixtureWindow, "", fixture.developer)); code != agentapi.CodeInvalidArgument {
				t.Fatalf("developer group_by=%s = %s", group, code)
			}
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/usage/overview?group_by="+group+"&"+fixtureWindow, "", fixture.adminRead)); code != "" {
				t.Fatalf("admin group_by=%s = %s", group, code)
			}
		}
		callers := func(token string) int {
			count := 0
			for _, item := range readData(t, fixture.facade(http.MethodGet, "/usage/sessions?"+fixtureWindow, "", token))["items"].([]any) {
				if item.(map[string]any)["caller"] != nil {
					count++
				}
			}
			return count
		}
		if callers(fixture.developer) != 0 || callers(fixture.adminRead) == 0 {
			t.Fatalf("session callers: developer %d, admin %d", callers(fixture.developer), callers(fixture.adminRead))
		}
	})

	t.Run("D6 an out-of-scope parent is a placeholder", func(t *testing.T) {
		parent := strings.Repeat("12", 12)
		visible := func(token string) map[string]bool {
			nodes := map[string]bool{}
			for _, node := range readData(t, fixture.facade(http.MethodGet, "/usage/trees/"+apiTreeOwn, "", token))["nodes"].([]any) {
				typed := node.(map[string]any)
				nodes[typed["node_id"].(string)] = typed["visible"].(bool)
			}
			return nodes
		}
		developer, admin := visible(fixture.developer), visible(fixture.adminRead)
		if shown, ok := developer[parent]; !ok || shown {
			t.Fatalf("developer tree = %v", developer)
		}
		if !admin[parent] {
			t.Fatalf("admin tree = %v", admin)
		}
	})

	t.Run("D7 my week is the developer's own NewAPI user and empty for an administrator", func(t *testing.T) {
		developer := readData(t, fixture.facade(http.MethodGet, "/weekly/me", "", fixture.developer))
		row, _ := developer["row"].(map[string]any)
		if row == nil || row["user_id"] != float64(agentTestIdentity.UserID) {
			t.Fatalf("developer week = %v", developer)
		}
		response := fixture.facade(http.MethodGet, "/weekly/me", "", fixture.adminRead)
		decoded := decodeAgent(t, response)
		if admin := readData(t, response); admin["row"] != nil || decoded.Meta == nil || !decoded.Meta.Complete || len(decoded.NextActions) == 0 {
			t.Fatalf("admin week = %s", response.Body.String())
		}
	})

	t.Run("D8 selectors, the user listing and user ids are administrator-only", func(t *testing.T) {
		for _, path := range []string{
			"/analysis/overview?user_id=8&" + fixtureWindow, "/analysis/sessions?user_id=8&" + fixtureWindow,
			"/analysis/report?user_id=8", "/analysis/report?project_id=3", "/analysis/report?group_id=1", "/analysis/users?" + fixtureWindow,
		} {
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, path, "", fixture.developer)); code != agentapi.CodeForbiddenRole {
				t.Fatalf("developer %s = %s", path, code)
			}
		}
		// The value is validated before the role, as on the web.
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/analysis/report?user_id=x", "", fixture.developer)); code != agentapi.CodeInvalidArgument {
			t.Fatalf("developer bad selector = %s", code)
		}
		userIDs := func(token string) int {
			count := 0
			for _, item := range readData(t, fixture.facade(http.MethodGet, "/analysis/sessions?"+fixtureWindow, "", token))["items"].([]any) {
				if _, ok := item.(map[string]any)["user_id"]; ok {
					count++
				}
			}
			return count
		}
		if userIDs(fixture.developer) != 0 || userIDs(fixture.adminRead) != 2 {
			t.Fatalf("user ids: developer %d admin %d", userIDs(fixture.developer), userIDs(fixture.adminRead))
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/analysis/overview?user_id=8&"+fixtureWindow, "", fixture.adminRead)); code != "" {
			t.Fatalf("admin user selector = %s", code)
		}
	})

	t.Run("D9 work_relevance is the developer's own and empty for an administrator", func(t *testing.T) {
		path := "/analysis/sessions/" + analysisOwnID + "/facet"
		if got := readData(t, fixture.facade(http.MethodGet, path, "", fixture.developer))["work_relevance"]; got != "work" {
			t.Fatalf("developer work_relevance = %v", got)
		}
		admin := readData(t, fixture.facade(http.MethodGet, path, "", fixture.adminRead))
		if admin["work_relevance"] != "" || admin["items"].([]any)[0].(map[string]any)["work_relevance"] != nil {
			t.Fatalf("admin facet = %v", admin)
		}
	})

	t.Run("D10 run state, model and calibration are returned to both", func(t *testing.T) {
		fixture.analysis.run = &storage.SessionAnalysisRun{StartedAtNS: fixtureBase.UnixNano(), FinishedAtNS: fixtureBase.UnixNano() + 1, Trigger: "manual", SkipReasons: "{}"}
		defer func() { fixture.analysis.run = nil }()
		for _, token := range []string{fixture.developer, fixture.adminRead} {
			response := fixture.facade(http.MethodGet, "/analysis/overview?"+fixtureWindow, "", token)
			data := readData(t, response)
			if data["last_run"] == nil || data["model"] != "local-model" || data["running"] != false {
				t.Fatalf("overview = %s", response.Body.String())
			}
			if _, ok := data["calibration"]; !ok {
				t.Fatalf("overview lacks calibration: %s", response.Body.String())
			}
		}
	})

	t.Run("D11 every pack and facet read is logged and withheld when the log fails", func(t *testing.T) {
		for _, resource := range []string{"pack", "facet"} {
			path := "/analysis/sessions/" + analysisOwnID + "/" + resource
			views, audits := fixture.analysis.viewCount(), len(fixture.store.Audit())
			data := readData(t, fixture.facade(http.MethodGet, path, "", fixture.developer))
			if data["view_logged"] != true || fixture.analysis.viewCount() != views+1 {
				t.Fatalf("%s view log = %d -> %d", resource, views, fixture.analysis.viewCount())
			}
			entries := fixture.store.Audit()
			last := entries[len(entries)-1]
			if len(entries) != audits+1 || last.Event != agentaccess.EventSensitiveRead || last.ObjectID != analysisOwnID ||
				last.Outcome != storage.AgentOutcomeOK || last.TokenID == nil {
				t.Fatalf("%s audit = %+v", resource, entries)
			}
			fixture.analysis.failViews = true
			response := fixture.facade(http.MethodGet, path, "", fixture.developer)
			fixture.analysis.failViews = false
			if code := facadeOutcome(t, response); code != agentapi.CodeUpstreamUnavailable || strings.Contains(response.Body.String(), "fix the build") ||
				strings.Contains(response.Body.String(), "[pack]") {
				t.Fatalf("%s with a failing view log = %s %s", resource, code, response.Body.String())
			}
		}
	})

	t.Run("D12 configuration, directories, health and writes are administrator-only", func(t *testing.T) {
		for _, path := range []string{"/config/ua-rule", "/config/content-rule", "/config/org", "/config/weekly-settings", "/config/analysis-settings", "/callers", "/status",
			"/weekly/report", "/weekly/trend", "/weekly/projects/-1", "/weekly/unattributed"} {
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, path, "", fixture.developer)); code != agentapi.CodeForbiddenRole {
				t.Fatalf("developer %s = %s", path, code)
			}
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodPost, "/config/project-preview", previewBody, fixture.developer)); code != agentapi.CodeForbiddenRole {
			t.Fatalf("developer preview = %s", code)
		}
	})
}

// Every audit sub-resource and export refuses another key's record exactly
// as a missing one (plan section 12).
func TestAgentDeveloperCannotReadAnotherKeysRecordAnywhere(t *testing.T) {
	fixture := newReadFixture(t)
	paths := []string{"", "/composition"}
	for _, what := range agentapi.ExportKinds {
		paths = append(paths, "/export/"+what)
	}
	for _, suffix := range paths {
		for _, id := range []string{"foreign", "blocked-own"} {
			foreign := fixture.facade(http.MethodGet, "/requests/"+id+suffix, "", fixture.developer)
			missing := fixture.facade(http.MethodGet, "/requests/missing-record"+suffix, "", fixture.developer)
			if foreign.Code != http.StatusNotFound || !bytes.Equal(foreign.Body.Bytes(), missing.Body.Bytes()) ||
				strings.Contains(foreign.Body.String(), id) {
				t.Errorf("%s%s = %d %s (missing: %s)", id, suffix, foreign.Code, foreign.Body.String(), missing.Body.String())
			}
		}
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/requests/foreign"+suffix, "", fixture.adminRead)); code != "" &&
			!(suffix == "/composition" && code == agentapi.CodeNotFound) {
			t.Errorf("admin foreign%s = %s", suffix, code)
		}
	}
}

// --- credentials ----------------------------------------------------------

func TestAgentCredentialValuesNeverLeave(t *testing.T) {
	fixture := newReadFixture(t)
	var bodies []string
	collect := func(response *httptest.ResponseRecorder) {
		bodies = append(bodies, response.Body.String())
	}
	for _, token := range []string{fixture.adminRead, fixture.developer} {
		for _, call := range readCalls() {
			collect(fixture.facade(call.method, call.path, call.body, token))
		}
		for _, what := range agentapi.ExportKinds {
			collect(fixture.facade(http.MethodGet, "/requests/own-1/export/"+what, "", token))
		}
		collect(fixture.facade(http.MethodGet, "/requests/own-1", "", token))
	}
	for _, body := range bodies {
		for _, secret := range plantedCredentials {
			if strings.Contains(body, secret) {
				t.Fatalf("credential %q leaked: %s", secret, body)
			}
		}
	}
	// The identifying headers do come through, in the detail and the export.
	headers := fixture.facade(http.MethodGet, "/requests/own-1/export/headers", "", fixture.developer).Body.String()
	detail := fixture.facade(http.MethodGet, "/requests/own-1?headers=all", "", fixture.developer).Body.String()
	for _, value := range plantedVisible {
		if !strings.Contains(headers, value) || !strings.Contains(detail, value) {
			t.Errorf("visible value %q missing", value)
		}
	}
	// Masked entries keep their name and length.
	var exported struct {
		Headers []agentHeader `json:"headers"`
	}
	if err := json.Unmarshal([]byte(headers), &exported); err != nil {
		t.Fatal(err)
	}
	masked := 0
	for _, header := range exported.Headers {
		if header.ValueOmitted == agentapi.OmittedCredential {
			masked++
			if header.ValueUntrusted != nil || header.Length == 0 {
				t.Errorf("masked header %+v", header)
			}
		}
	}
	if masked != 4 {
		t.Fatalf("masked headers = %d, want 4", masked)
	}
	var uri struct {
		RequestURI agentRequestURI `json:"request_uri"`
	}
	_ = json.Unmarshal(decodeAgent(t, fixture.facade(http.MethodGet, "/requests/own-1", "", fixture.developer)).Data, &uri)
	if len(uri.RequestURI.Query) != 2 || uri.RequestURI.Query[0].Name != "key" || uri.RequestURI.Query[0].ValueOmitted != agentapi.OmittedCredential ||
		uri.RequestURI.Query[0].Length != len(plantedQueryKey) || *uri.RequestURI.Query[1].ValueUntrusted != "sse" {
		t.Fatalf("request_uri = %+v", uri.RequestURI)
	}
}

func TestAgentRequestURIFailsClosed(t *testing.T) {
	parsed := agentRequestURIOf("/v1/x?key=%zz" + plantedQueryKey + "&ok=1&%zzname=v")
	encoded, _ := json.Marshal(parsed)
	if strings.Contains(string(encoded), plantedQueryKey) || !parsed.QueryUnparsed || parsed.Path != "/v1/x" {
		t.Fatalf("unparsable query = %s", encoded)
	}
	if empty := agentRequestURIOf("/v1/x"); len(empty.Query) != 0 || empty.Path != "/v1/x" {
		t.Fatalf("no query = %+v", empty)
	}
}

// --- states and completeness ----------------------------------------------

func TestAgentAuditStateTable(t *testing.T) {
	code := func(value int) *int { return &value }
	rows := []struct {
		forward string
		status  *int
		want    string
	}{
		{storage.ForwardInProgress, nil, "running"},
		{storage.ForwardCompleted, code(100), "succeeded"},
		{storage.ForwardCompleted, code(399), "succeeded"},
		{storage.ForwardCompleted, code(400), "failed"},
		{storage.ForwardCompleted, code(599), "failed"},
		{storage.ForwardCompleted, nil, "failed"},
		{storage.ForwardRejected, code(403), "blocked"},
		{storage.ForwardClientCancelled, nil, "cancelled"},
		{storage.ForwardNewAPIError, code(200), "failed"},
		{storage.ForwardProxyError, nil, "failed"},
		{storage.ForwardInterrupted, nil, "failed"},
	}
	for _, row := range rows {
		if got := auditState(row.forward, row.status); got != row.want {
			t.Errorf("%s %v = %s, want %s", row.forward, row.status, got, row.want)
		}
	}
	for stored, want := range map[string]string{storage.ParsePending: "pending", storage.ParseProcessing: "pending", storage.ParseOK: "ok",
		storage.ParsePartial: "partial", storage.ParseError: "error", storage.ParseSkipped: "skipped"} {
		if got := auditParse(stored); got != want {
			t.Errorf("parse %s = %s", stored, got)
		}
	}
	for stored, want := range map[string]string{storage.CapturePending: "pending", storage.CaptureComplete: "complete", storage.CapturePartial: "partial",
		storage.CaptureFailed: "failed", storage.CaptureChunkMissing: "chunk_missing"} {
		if got := auditCapture(stored); got != want {
			t.Errorf("capture %s = %s", stored, got)
		}
	}
	base := query.AuditSummary{ForwardStatus: storage.ForwardCompleted, StatusCode: code(200), ParseStatus: storage.ParseOK, CaptureStatus: storage.CaptureComplete}
	completeness := []struct {
		change func(*query.AuditSummary)
		reason string
	}{
		{func(*query.AuditSummary) {}, ""},
		{func(summary *query.AuditSummary) { summary.ForwardStatus = storage.ForwardInProgress }, "in_progress"},
		{func(summary *query.AuditSummary) { summary.ParseStatus = storage.ParsePending }, "parse_pending"},
		{func(summary *query.AuditSummary) { summary.ParseStatus = storage.ParseProcessing }, "parse_pending"},
		{func(summary *query.AuditSummary) { summary.CaptureStatus = storage.CapturePartial }, "capture_incomplete"},
		{func(summary *query.AuditSummary) { summary.CaptureStatus = storage.CaptureChunkMissing }, "capture_incomplete"},
		{func(summary *query.AuditSummary) { summary.CaptureStatus = storage.CapturePending }, "capture_incomplete"},
	}
	for _, row := range completeness {
		summary := base
		row.change(&summary)
		meta := auditDetailMeta(summary)
		if meta.Complete != (row.reason == "") || meta.IncompleteReason != row.reason {
			t.Errorf("%+v = %+v, want %q", summary, meta, row.reason)
		}
	}
	// caller_final and billing_final.
	pending := query.AuditSummary{CallerStatus: storage.CallerPending}
	if agentAuditItemOf(pending).CallerFinal || !agentAuditItemOf(query.AuditSummary{CallerStatus: storage.CallerResolved}).CallerFinal {
		t.Fatal("caller_final")
	}
	for state, want := range map[string]bool{storage.BillingUnchecked: false, storage.BillingBilled: true, storage.BillingUnbilled: true} {
		if got := agentAuditDetailOf(query.Detail{TokenLink: &query.TokenLink{BillingState: state}}, false).BillingFinal; got != want {
			t.Errorf("billing_final %s = %v", state, got)
		}
	}
	if !agentAuditDetailOf(query.Detail{}, false).BillingFinal {
		t.Error("billing_final without a token link")
	}
	// Through the facade: meta of a detail and of a list item.
	fixture := newReadFixture(t)
	decoded := decodeAgent(t, fixture.facade(http.MethodGet, "/requests/blocked-own", "", fixture.adminRead))
	if decoded.Meta == nil || decoded.Meta.State != "blocked" || !decoded.Meta.Complete || decoded.Notice != agentapi.UntrustedNotice {
		t.Fatalf("detail meta = %+v", decoded)
	}
}

func TestAgentAnalysisAndReportCompleteness(t *testing.T) {
	overview := func(response sessionanalysis.OverviewResponse) agentapi.Meta { return analysisRunMeta(response) }
	rows := []struct {
		response sessionanalysis.OverviewResponse
		state    string
		reason   string
	}{
		{sessionanalysis.OverviewResponse{Running: true}, "running", ""},
		{sessionanalysis.OverviewResponse{}, "never_run", ""},
		{sessionanalysis.OverviewResponse{LastRun: &sessionanalysis.RunSummary{Error: "llm_unreachable"}}, "failed", ""},
		{sessionanalysis.OverviewResponse{LastRun: &sessionanalysis.RunSummary{}}, "succeeded", ""},
		{sessionanalysis.OverviewResponse{LastRun: &sessionanalysis.RunSummary{FacetsError: 1}}, "succeeded", "facets_incomplete"},
		{sessionanalysis.OverviewResponse{LastRun: &sessionanalysis.RunSummary{FacetsBad: 1}}, "succeeded", "facets_incomplete"},
	}
	for _, row := range rows {
		meta := overview(row.response)
		if meta.State != row.state || meta.IncompleteReason != row.reason || meta.Complete != (row.reason == "") {
			t.Errorf("%+v = %+v", row.response, meta)
		}
	}
	if meta := truncatedMeta(true); meta.Complete || meta.IncompleteReason != "truncated" {
		t.Errorf("truncated = %+v", meta)
	}
	// weekly report: meta.complete follows the report, final follows frozen.
	report := agentWeeklyReportOf(orgreport.WeeklyReport{Frozen: true, Complete: false})
	if !report.Final || report.Complete {
		t.Errorf("weekly = %+v", report)
	}
}

// pagedQuery answers List with a fixed page.
type pagedQuery struct {
	fakeQuery
	page query.Page
}

func (queries *pagedQuery) List(context.Context, query.Filter, query.Cursor, int) (query.Page, error) {
	return queries.page, nil
}

// The completeness rules of contract sections 4.1 and 4.3, row by row,
// through the facade where the fixture can produce the case.
func TestAgentReadCompletenessRows(t *testing.T) {
	fixture := newReadFixture(t)
	meta := func(path string) (*agentapi.Meta, agentapi.Response) {
		t.Helper()
		response := fixture.facade(http.MethodGet, path, "", fixture.adminRead)
		decoded := decodeAgent(t, response)
		if response.Code != http.StatusOK || decoded.Meta == nil {
			t.Fatalf("%s = %d %s", path, response.Code, response.Body.String())
		}
		return decoded.Meta, decoded
	}

	// Session analysis report: not computed, below the contributor minimum.
	if got, _ := meta("/analysis/report"); !got.Complete {
		t.Fatalf("report = %+v", got)
	}
	stats := fixture.reports.stats
	fixture.reports.stats = nil
	if got, _ := meta("/analysis/report"); got.Complete || got.IncompleteReason != "not_computed" {
		t.Fatalf("report without stats = %+v", got)
	}
	fixture.reports.stats = &sessionanalysis.WeeklyStats{Limited: true}
	if got, _ := meta("/analysis/report"); got.Complete || got.IncompleteReason != "below_contributor_minimum" {
		t.Fatalf("limited report = %+v", got)
	}
	fixture.reports.stats = stats

	// Weekly report: complete follows the report.
	if got := weeklyReportMeta(orgreport.WeeklyReport{Complete: false}); got.Complete || got.IncompleteReason != "evidence_pending" {
		t.Fatalf("weekly incomplete = %+v", got)
	}
	if got := weeklyReportMeta(orgreport.WeeklyReport{Complete: true}); !got.Complete || got.IncompleteReason != "" {
		t.Fatalf("weekly complete = %+v", got)
	}

	// status: not_ready is a 200 with complete=false.
	fixture.handler.readiness = func(context.Context) ReadyStatus {
		return ReadyStatus{Status: "not_ready", Database: "unavailable", EncryptionKey: "ok", ParserQueue: 3}
	}
	if got, decoded := meta("/status"); got.Complete || got.IncompleteReason != "not_ready" || got.State != "not_ready" ||
		!strings.Contains(string(decoded.Data), `"parser_queue":3`) {
		t.Fatalf("not ready = %+v %s", got, decoded.Data)
	}
	fixture.handler.readiness = nil
	if got, _ := meta("/status"); !got.Complete || got.State != "healthy" {
		t.Fatalf("ready = %+v", got)
	}

	// version on every modifiable object: the last modification time, "0"
	// for a settings section that was never saved.
	_, rules := meta("/config/content-rule")
	if !strings.Contains(string(rules.Data), `"version":"9"`) {
		t.Fatalf("content rule = %s", rules.Data)
	}
	_, settings := meta("/config/analysis-settings")
	if !strings.Contains(string(settings.Data), `"version":"0"`) {
		t.Fatalf("analysis settings = %s", settings.Data)
	}

	// collapse_applied is honest: any row filter or conversation turns it off.
	for path, want := range map[string]bool{
		"/requests": true, "/requests?collapse=false": false, "/requests?model=gpt-test": false, "/requests?conversation=conv-x": false,
	} {
		if got := readData(t, fixture.facade(http.MethodGet, path, "", fixture.adminRead))["collapse_applied"]; got != want {
			t.Errorf("%s collapse_applied = %v", path, got)
		}
	}

	// Usage overview: coverage is unknown, billing completeness is explicit.
	if got, decoded := meta("/usage/overview?" + fixtureWindow); !got.Complete || !strings.Contains(string(decoded.Data), `"coverage_unknown":true`) ||
		len(decoded.NextActions) == 0 {
		t.Fatalf("overview = %+v %v", got, decoded.NextActions)
	}
	if overview := agentUsageOverviewOf(insights.OverviewResponse{Totals: insights.UsageTotals{Requests: 2, BilledRequests: 2}}); !overview.BillingComplete || !overview.CoverageUnknown {
		t.Fatalf("billed overview = %+v", overview)
	}
	if overview := agentUsageOverviewOf(insights.OverviewResponse{Totals: insights.UsageTotals{Requests: 2, BilledRequests: 1, UnbilledRequests: 1}}); overview.BillingComplete {
		t.Fatalf("unbilled overview = %+v", overview)
	}

	// My week explains an empty row by its cause.
	if _, decoded := meta("/weekly/me"); len(decoded.NextActions) != 1 || decoded.NextActions[0] != agentWeeklyMeAdmin {
		t.Fatalf("admin week actions = %v", decoded.NextActions)
	}
	if weeklyMeAction(principal{Role: roleDeveloper}) != agentWeeklyMeUnknown ||
		weeklyMeAction(principal{Role: roleDeveloper, Identity: developerIdentity{UserID: 7}}) != agentWeeklyMeIdle {
		t.Fatal("developer week actions")
	}

	// An empty page that still has a next page says so.
	env := newAgentEnv(t, agentEnvOptions{})
	paged := &pagedQuery{page: query.Page{Items: []query.AuditSummary{}, NextCursor: &query.Cursor{BeforeStartedAtNS: 5, BeforeID: "a"}}}
	env.handler.query = paged
	token := issueAgentAdmin(t, env, agentapi.TierRead)
	decoded := decodeAgent(t, env.do(http.MethodGet, agentapi.PathPrefix+"/requests?user_agent=codex", "", agentCaller{bearer: token}))
	if len(decoded.NextActions) != 1 || decoded.NextActions[0] != agentEmptyPageAction || !strings.Contains(string(decoded.Data), `"next_cursor":"`) {
		t.Fatalf("empty page = %+v %s", decoded.NextActions, decoded.Data)
	}
	paged.page = query.Page{Items: []query.AuditSummary{{AuditID: "a"}}}
	if decoded := decodeAgent(t, env.do(http.MethodGet, agentapi.PathPrefix+"/requests", "", agentCaller{bearer: token})); len(decoded.NextActions) != 0 ||
		!strings.Contains(string(decoded.Data), `"next_cursor":""`) {
		t.Fatalf("last page = %+v %s", decoded.NextActions, decoded.Data)
	}
}

// --- errors -----------------------------------------------------------------

type failingQuery struct {
	fakeQuery
	err error
}

func (queries *failingQuery) List(context.Context, query.Filter, query.Cursor, int) (query.Page, error) {
	return query.Page{}, queries.err
}

// The web's catch-all 503 is split, and no error text is ever written.
func TestAgentErrorClassesAreSplitWithoutText(t *testing.T) {
	const sentinel = "SENTINEL-DRIVER-TEXT"
	cases := map[agentapi.Code]error{
		agentapi.CodeUpstreamUnavailable: fmt.Errorf("query: list: %w (%s)", storage.ErrClosed, sentinel),
		agentapi.CodeTimeout:             fmt.Errorf("query: list: %w (%s)", context.DeadlineExceeded, sentinel),
		agentapi.CodeInternal:            errors.New(sentinel),
		agentapi.CodeInvalidArgument:     fmt.Errorf("%w: %s", query.ErrInvalidQuery, sentinel),
		agentapi.CodeEvidenceUnavailable: fmt.Errorf("%w: %s", query.ErrIntegrity, sentinel),
		agentapi.CodeNotReady:            fmt.Errorf("%w: %s", query.ErrNotReady, sentinel),
		agentapi.CodeNotRetained:         fmt.Errorf("%w: %s", query.ErrNotRetained, sentinel),
	}
	for want, err := range cases {
		env := newAgentEnv(t, agentEnvOptions{})
		env.handler.query = &failingQuery{err: err}
		token := issueAgentAdmin(t, env, agentapi.TierRead)
		response := env.do(http.MethodGet, agentapi.PathPrefix+"/requests", "", agentCaller{bearer: token})
		if got := agentErrorCode(t, response); got != want || strings.Contains(response.Body.String(), sentinel) || strings.Contains(env.logs.String(), sentinel) {
			t.Errorf("%v = %s %s", err, got, response.Body.String())
		}
	}
	for err, want := range map[error]agentapi.Code{
		orgreport.ErrUnavailable: agentapi.CodeUpstreamUnavailable, contentpolicy.ErrUnavailable: agentapi.CodeUpstreamUnavailable,
		orgreport.ErrConflict: agentapi.CodeConflict, uaguard.ErrNotFound: agentapi.CodeNotFound, query.ErrNoTurnGraph: agentapi.CodeNotReady,
	} {
		if got := agentErrorCodeOf(err); got != want {
			t.Errorf("%v = %s", err, got)
		}
	}
}

type testSQLState string

func (state testSQLState) Error() string    { return "sqlstate " + string(state) }
func (state testSQLState) SQLState() string { return string(state) }

// Database conditions that pass on their own are retryable, never INTERNAL;
// a constraint or syntax error still is INTERNAL.
func TestAgentTransientDatabaseErrorsAreUpstreamUnavailable(t *testing.T) {
	for state, want := range map[string]agentapi.Code{
		"57014": agentapi.CodeUpstreamUnavailable, // statement timeout or cancel
		"53300": agentapi.CodeUpstreamUnavailable, // too many connections
		"57P01": agentapi.CodeUpstreamUnavailable, // admin shutdown
		"57P02": agentapi.CodeUpstreamUnavailable, // crash shutdown
		"57P03": agentapi.CodeUpstreamUnavailable, // cannot connect now
		"08006": agentapi.CodeUpstreamUnavailable, // connection failure
		"08001": agentapi.CodeUpstreamUnavailable,
		"40P01": agentapi.CodeUpstreamUnavailable, // deadlock
		"40001": agentapi.CodeUpstreamUnavailable, // serialization failure
		"55P03": agentapi.CodeUpstreamUnavailable, // lock not available
		"23505": agentapi.CodeInternal,
		"42601": agentapi.CodeInternal,
	} {
		if got := agentErrorCodeOf(fmt.Errorf("query: list: %w", testSQLState(state))); got != want {
			t.Errorf("SQLSTATE %s = %s, want %s", state, got, want)
		}
	}
	// A deadline still wins over the database's own report of it.
	if got := agentErrorCodeOf(errors.Join(context.DeadlineExceeded, testSQLState("57014"))); got != agentapi.CodeTimeout {
		t.Errorf("deadline with 57014 = %s", got)
	}
}

// --- parameters -------------------------------------------------------------

func TestAgentReadParameters(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	parse := func(query string) (agentRange, error) {
		values, _ := urlValues(query)
		return parseAgentRange(values, now)
	}
	if _, err := parse("since=2h&from=2026-10-01"); err == nil {
		t.Error("since with from was accepted")
	}
	if got, err := parse("from=2026-10-01&to=2026-10-01"); err != nil || *got.FromNS != time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixNano() ||
		*got.ToNS != time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).UnixNano() {
		t.Errorf("date range = %+v %v", got, err)
	}
	if got, err := parse("since=7d"); err != nil || *got.FromNS != now.Add(-7*24*time.Hour).UnixNano() || got.ToNS != nil {
		t.Errorf("since = %+v %v", got, err)
	}
	if got, err := parse("since=1h&to=2026-10-10T06:00:00Z"); err != nil || *got.FromNS != time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC).UnixNano() {
		t.Errorf("since before to = %+v %v", got, err)
	}
	for _, bad := range []string{"since=0d", "since=-1h", "since=1y", "since=+1h", "from=yesterday", "to=2026-13-01", "from=2026-10-02&to=2026-10-01"} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	// Cursors are opaque and bound to their list.
	wrapped := wrapAgentCursor(agentCursorAudits, "1:a")
	if inner, err := unwrapAgentCursor(agentCursorAudits, wrapped); err != nil || inner != "1:a" {
		t.Errorf("cursor round trip = %q %v", inner, err)
	}
	for _, bad := range []string{wrapAgentCursor(agentCursorUsageSessions, "x"), "not-base64!", base64.RawURLEncoding.EncodeToString([]byte("c0|audits|1:a"))} {
		if _, err := unwrapAgentCursor(agentCursorAudits, bad); err == nil {
			t.Errorf("cursor %q accepted", bad)
		}
	}

	fixture := newReadFixture(t)
	// Paging through the audit list with the wrapped cursor reaches every
	// record exactly once.
	seen := []string{}
	cursor := ""
	for range 10 {
		path := "/requests?limit=2&collapse=false"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		data := readData(t, fixture.facade(http.MethodGet, path, "", fixture.adminRead))
		for _, item := range data["items"].([]any) {
			seen = append(seen, item.(map[string]any)["audit_id"].(string))
		}
		cursor = data["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paged ids = %v", seen)
	}
	for _, path := range []string{"/requests?bogus=1", "/requests?limit=0", "/requests?limit=201", "/requests?status=600", "/requests?status=abc",
		"/requests?cursor=" + wrapAgentCursor(agentCursorUsageSessions, "x"), "/requests?collapse=maybe", "/requests?limit=1&limit=2",
		"/requests?capture_status=chunk_missing", "/requests/own-1?headers=some", "/requests/own-1/export/everything",
		"/usage/overview?tz_offset_min=900", "/analysis/overview", "/analysis/report?week=next", "/weekly/report?week=2026-11-03",
		"/config/everything", "/weekly/trend?weeks=13"} {
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, path, "", fixture.adminRead)); code != agentapi.CodeInvalidArgument {
			t.Errorf("%s = %s", path, code)
		}
	}
	// A week that is not a week start names the configured first day and the
	// nearest legal date.
	decoded := decodeAgent(t, fixture.facade(http.MethodGet, "/weekly/report?week=2026-11-04", "", fixture.adminRead))
	if decoded.Error.Details["week_start"] != "monday" || !strings.Contains(decoded.Error.Hint, "2026-11-02") {
		t.Fatalf("week error = %+v", decoded.Error)
	}
	// Times are RFC 3339 and no nanosecond field is left.
	body := fixture.facade(http.MethodGet, "/requests/own-1?headers=all", "", fixture.adminRead).Body.String()
	if strings.Contains(body, "_ns\"") || !strings.Contains(body, `"started_at":"2026-10-10T12:00:00Z"`) || !strings.Contains(body, `"ttft_ms":250`) {
		t.Fatalf("detail = %s", body)
	}
}

func urlValues(raw string) (map[string][]string, error) {
	request := httptest.NewRequest(http.MethodGet, "/x?"+raw, nil)
	return request.URL.Query(), nil
}

// --- field whitelists -------------------------------------------------------

// jsonFields lists the JSON names of a struct type, flattening embedded
// structs.
func jsonFields(typ reflect.Type) []string {
	var names []string
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.Anonymous && tag == "" {
			names = append(names, jsonFields(field.Type)...)
			continue
		}
		if tag == "-" || !field.IsExported() {
			continue
		}
		if tag == "" {
			tag = field.Name
		}
		names = append(names, tag)
	}
	return names
}

// Every field of a service response type is carried by its facade type,
// under its own name or a convention rename (_untrusted, _ns to _at or
// _seconds) or an explicit one, or is listed as deliberately dropped; and no
// facade type has a nanosecond field. A field added to a service type fails
// here until the facade decides about it.
func TestAgentFacadeTypesCoverTheServiceTypes(t *testing.T) {
	pairs := []struct {
		service, facade any
		renamed         map[string]string
		dropped         []string
	}{
		{query.AuditSummary{}, agentAuditItem{}, map[string]string{"ttft_ns": "ttft_ms", "parse_status": "parse", "capture_status": "capture",
			"newapi_user_id": "caller", "username": "caller", "display_name": "caller", "newapi_token_id": "caller", "token_name": "caller"}, nil},
		{query.Detail{}, agentAuditDetail{}, map[string]string{"audit": "audit_id", "parsed_result": "parsed", "token_link": "billing",
			"conversation": "conversation_summary"}, nil},
		{query.Stage{}, agentStage{}, nil, nil},
		{query.Header{}, agentHeader{}, map[string]string{"value_length": "length", "value": "value_untrusted"}, nil},
		{query.Body{}, agentBody{}, nil, nil},
		{query.ParsedResult{}, agentParsed{}, nil, nil},
		{query.Turn{}, agentTurn{}, nil, nil},
		{query.TokenLink{}, agentBilling{}, map[string]string{"newapi_user_id": "user_id", "newapi_token_id": "token_id"}, nil},
		{query.StreamTimeline{}, agentTimeline{}, nil, nil},
		{query.TimelinePoint{}, agentTimelinePoint{}, map[string]string{"at_ns": "observed_at"}, nil},
		{insights.UsageTotals{}, agentUsageTotals{}, nil, nil},
		{insights.CategoryValues{}, agentCategoryValues{}, nil, nil},
		{insights.Usage{}, agentUsage{}, nil, nil},
		{insights.OverviewResponse{}, agentUsageOverview{}, map[string]string{"from_ns": "from_at", "to_ns": "to_at"}, nil},
		{insights.GroupUsage{}, agentGroupUsage{}, nil, nil},
		{insights.SessionCard{}, agentSessionCard{}, map[string]string{"first_ns": "first_at", "last_ns": "last_at"}, nil},
		{insights.SessionCaller{}, agentSessionCaller{}, nil, nil},
		{insights.SessionsResponse{}, agentUsageSessions{}, nil, nil},
		{insights.TrendStep{}, agentTrendStep{}, nil, nil},
		{insights.TrendResponse{}, agentTrend{}, nil, nil},
		{insights.TreeNode{}, agentTreeNode{}, map[string]string{"first_ns": "first_at", "last_ns": "last_at"}, nil},
		{insights.TreeResponse{}, agentTree{}, nil, nil},
		{insights.CompositionResponse{}, agentComposition{}, nil, nil},
		{insights.CompositionItem{}, agentCompositionItem{}, nil, nil},
		{insights.ToolDef{}, agentToolDef{}, nil, nil},
		{insights.FileOp{}, agentFileOp{}, nil, nil},
		{insights.AgentIdentity{}, agentAgentIdentity{}, map[string]string{"root_id": "root_id_untrusted", "node_id": "node_id_untrusted", "parent_id": "parent_id_untrusted"}, nil},
		{insights.CompositionDiff{}, agentCompositionDiff{}, nil, nil},
		{orgreport.UserRow{}, agentUserRow{}, map[string]string{"daily_active_ns": "daily_active_seconds"}, nil},
		{orgreport.RankedUser{}, agentRankedUser{}, map[string]string{"daily_active_ns": "daily_active_seconds"}, nil},
		{orgreport.ProjectCell{}, agentProjectCell{}, nil, nil},
		{orgreport.ServiceRow{}, agentServiceRow{}, nil, nil},
		{orgreport.Tokens{}, agentTokens{}, nil, nil},
		{orgreport.Flag{}, agentFlag{}, nil, nil},
		{orgreport.ProjectRef{}, agentProjectRef{}, nil, nil},
		{orgreport.SelfReport{}, agentSelfReport{}, nil, nil},
		{orgreport.WeeklyReport{}, agentWeeklyReport{}, nil, nil},
		{orgreport.TrendWeek{}, agentTrendWeek{}, nil, nil},
		{orgreport.TrendReport{}, agentWeeklyTrend{}, nil, nil},
		{orgreport.ProjectReport{}, agentProjectReport{}, nil, nil},
		{orgreport.UnattributedEntry{}, agentUnattributedEntry{}, nil, nil},
		{orgreport.Rule{}, agentDraftRule{}, nil, nil},
		{orgreport.Group{}, agentOrgGroup{}, nil, nil},
		{orgreport.Project{}, agentOrgProject{}, nil, nil},
		{orgreport.Member{}, agentOrgMember{}, nil, nil},
		{orgreport.Principal{}, agentOrgPrincipal{}, nil, nil},
		{orgreport.CatalogView{}, agentOrgConfig{}, nil, nil},
		{orgreport.PublicSettings{}, agentOrgConfig{}, map[string]string{"idle_gap_seconds": "settings", "ranked_clients": "settings",
			"max_concurrent_roots": "settings", "max_single_request_roots": "settings"}, nil},
		{orgreport.SettingsView{}, agentWeeklySettings{}, map[string]string{"updated_ns": "updated_at"}, nil},
		{orgreport.EditableSettings{}, agentWeeklySettingsValues{}, nil, nil},
		{orgreport.PreviewResult{}, agentPreview{}, nil, nil},
		{sessionanalysis.SignalTotals{}, agentSignalTotals{}, nil, nil},
		{sessionanalysis.RunSummary{}, agentRunSummary{}, map[string]string{"started_ns": "started_at", "finished_ns": "finished_at"}, nil},
		{sessionanalysis.CalibrationResult{}, agentCalibration{}, map[string]string{"created_ns": "created_at"}, nil},
		{sessionanalysis.OverviewResponse{}, agentAnalysisOverview{}, map[string]string{"from_ns": "from_at", "to_ns": "to_at"}, nil},
		{sessionanalysis.SessionItem{}, agentAnalysisSession{}, map[string]string{"first_ns": "first_at", "last_ns": "last_at"}, nil},
		{sessionanalysis.UserTotalsItem{}, agentUserTotals{}, map[string]string{"last_ns": "last_at"}, nil},
		{sessionanalysis.PackResponse{}, agentPack{}, map[string]string{"built_ns": "built_at"}, nil},
		{sessionanalysis.FacetResponse{}, agentFacet{}, map[string]string{"created_ns": "created_at"}, nil},
		{sessionanalysis.DigestFacetItem{}, agentFacetItem{}, nil, nil},
		{sessionanalysis.EvidenceRef{}, agentEvidenceRef{}, nil, nil},
		{sessionanalysis.WeeklyStats{}, agentWeeklyStats{}, nil, nil},
		{sessionanalysis.SuggestionItem{}, agentSuggestion{}, map[string]string{"first_seen_ns": "first_seen_at", "last_seen_ns": "last_seen_at"}, nil},
		{sessionanalysis.ReportResponse{}, agentAnalysisReport{}, map[string]string{"computed_ns": "computed_at", "scope_name": "scope_name_untrusted"}, nil},
		{sessionanalysis.ScopeOption{}, agentScopeOption{}, nil, nil},
		{sessionanalysis.SettingsView{}, agentAnalysisSettings{}, map[string]string{"updated_ns": "updated_at"}, nil},
		{sessionanalysis.EditableSettings{}, agentAnalysisSettingsValues{}, nil, nil},
		{sessionanalysis.EditableLLM{}, agentLLMSettings{}, nil, nil},
		{sessionanalysis.FileOnlySettings{}, agentFileOnlySettings{}, nil, nil},
		{uaguard.Rule{}, agentUARule{}, nil, nil},
		{contentpolicy.Rule{}, agentContentRule{}, nil, nil},
		{newapi.User{}, agentCallerEntry{}, nil, nil},
		{ReadyStatus{}, agentReady{}, nil, nil},
	}
	for _, pair := range pairs {
		serviceType, facadeType := reflect.TypeOf(pair.service), reflect.TypeOf(pair.facade)
		facadeFields := map[string]bool{}
		for _, name := range jsonFields(facadeType) {
			facadeFields[name] = true
			if strings.HasSuffix(name, "_ns") {
				t.Errorf("%s has a nanosecond field %s", facadeType, name)
			}
		}
		dropped := map[string]bool{}
		for _, name := range pair.dropped {
			dropped[name] = true
		}
		for _, name := range jsonFields(serviceType) {
			base := strings.TrimSuffix(name, "_ns")
			candidates := []string{name, name + "_untrusted", base + "_at", base + "_seconds", pair.renamed[name]}
			if strings.HasSuffix(base, "_at") && base != name {
				candidates = append(candidates, base)
			}
			found := dropped[name]
			for _, candidate := range candidates {
				found = found || candidate != "" && facadeFields[candidate]
			}
			if !found {
				t.Errorf("%s.%s has no counterpart in %s", serviceType, name, facadeType)
			}
		}
	}
}
