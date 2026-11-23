package web

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// badArgument is one refused value of one parameter of one read endpoint.
type badArgument struct {
	endpoint string
	method   string
	path     string
	body     string
	field    string
	reason   string
	// developer sends the call with the developer token instead of the
	// administrator read token.
	developer bool
}

// sinceWindow is a valid required range for the session analysis reads.
const sinceWindow = "since=7d"

// badArguments lists, for every read endpoint in the registry, at least one
// refused value of each of its parameters (query parameters, path segments
// and body fields), every pair of arguments that exclude each other, and an
// unknown parameter.
func badArguments() []badArgument {
	get := func(endpoint, path, field, reason string) badArgument {
		return badArgument{endpoint: endpoint, method: http.MethodGet, path: path, field: field, reason: reason}
	}
	preview := func(body, field, reason string) badArgument {
		return badArgument{endpoint: "config.project-preview", method: http.MethodPost, path: "/config/project-preview", body: body, field: field, reason: reason}
	}
	var cases []badArgument
	// The unified time range of every endpoint that takes one.
	for endpoint, path := range map[string]string{
		"requests.list": "/requests?", "usage.overview": "/usage/overview?", "usage.sessions": "/usage/sessions?",
		"analysis.overview": "/analysis/overview?", "analysis.users": "/analysis/users?", "analysis.sessions": "/analysis/sessions?",
	} {
		cases = append(cases,
			get(endpoint, path+"from=yesterday", "from", reasonInvalidFormat),
			get(endpoint, path+"since=7d&to=2026-02-30", "to", reasonInvalidFormat),
			get(endpoint, path+"since=7x", "since", reasonInvalidFormat),
			get(endpoint, path+"since=1d&from=2026-01-01", "since", reasonConflict),
			get(endpoint, path+"from=2026-01-02&to=2026-01-01", "from", reasonEmptyRange),
		)
	}
	for endpoint, path := range map[string]string{
		"usage.overview": "/usage/overview?", "usage.sessions": "/usage/sessions?",
		"analysis.overview": "/analysis/overview?", "analysis.users": "/analysis/users?", "analysis.sessions": "/analysis/sessions?",
	} {
		cases = append(cases, get(endpoint, path+"since=500d", "since", reasonRangeTooLong),
			get(endpoint, path+"from=2024-01-01&to=2026-01-01", "from", reasonRangeTooLong))
	}
	for _, path := range []string{"/analysis/overview", "/analysis/users", "/analysis/sessions"} {
		cases = append(cases, get(endpointOf(path), path+"?to=2026-01-01", "since", reasonRequired))
	}
	cases = append(cases,
		// requests.list
		get("requests.list", "/requests?cursor=bogus", "cursor", reasonInvalidCursor),
		get("requests.list", "/requests?limit=201", "limit", reasonOutOfRange),
		get("requests.list", "/requests?limit=1&limit=2", "limit", reasonRepeatedParameter),
		get("requests.list", "/requests?protocol=+openai", "protocol", reasonInvalidFormat),
		get("requests.list", "/requests?path=v1", "path", reasonInvalidFormat),
		get("requests.list", "/requests?model=%20x", "model", reasonInvalidFormat),
		get("requests.list", "/requests?user_agent=%20x", "user_agent", reasonInvalidFormat),
		get("requests.list", "/requests?status=bogus", "status", reasonInvalidFormat),
		get("requests.list", "/requests?forward_status=bogus", "forward_status", reasonNotAllowedValue),
		get("requests.list", "/requests?blocked_by=%20x", "blocked_by", reasonInvalidFormat),
		get("requests.list", "/requests?block_code=Bad", "block_code", reasonInvalidFormat),
		get("requests.list", "/requests?capture_status=chunk_missing", "capture_status", reasonNotAllowedValue),
		get("requests.list", "/requests?upstream_error_class=Bad", "upstream_error_class", reasonInvalidFormat),
		get("requests.list", "/requests?conversation=%20x", "conversation", reasonInvalidFormat),
		get("requests.list", "/requests?collapse=maybe", "collapse", reasonNotAllowedValue),
		get("requests.list", "/requests?user_id=0", "user_id", reasonInvalidFormat),
		get("requests.list", "/requests?username=%20x", "username", reasonInvalidFormat),
		get("requests.list", "/requests?token_id=-1", "token_id", reasonInvalidFormat),
		get("requests.list", "/requests?token_name=%20x", "token_name", reasonInvalidFormat),
		get("requests.list", "/requests?zz_unknown=1", "zz_unknown", reasonUnknownParameter),
		// requests.get, requests.export, usage.composition
		get("requests.get", "/requests/a%20b", "id", reasonInvalidFormat),
		get("requests.get", "/requests/own-1?headers=some", "headers", reasonNotAllowedValue),
		get("requests.export", "/requests/a%20b/export/headers", "id", reasonInvalidFormat),
		get("requests.export", "/requests/own-1/export/bogus", "what", reasonNotAllowedValue),
		get("usage.composition", "/requests/a%20b/composition", "id", reasonInvalidFormat),
		// usage
		get("usage.overview", "/usage/overview?group_by=bogus", "group_by", reasonNotAllowedValue),
		get("usage.overview", "/usage/overview?tz_offset_min=900", "tz_offset_min", reasonOutOfRange),
		get("usage.sessions", "/usage/sessions?sort=bogus", "sort", reasonNotAllowedValue),
		get("usage.sessions", "/usage/sessions?cursor=bogus", "cursor", reasonInvalidCursor),
		get("usage.sessions", "/usage/sessions?limit=101", "limit", reasonOutOfRange),
		get("usage.trend", "/usage/sessions/ses_123/trend", "id", reasonInvalidFormat),
		get("usage.tree", "/usage/trees/xyz", "id", reasonInvalidFormat),
		// weekly
		get("weekly.me", "/weekly/me?week=2026-11-02", "week", reasonUnknownParameter),
		get("weekly.report", "/weekly/report?week=2026-13-01", "week", reasonInvalidFormat),
		get("weekly.report", "/weekly/report?week=2026-11-04", "week", reasonNotWeekStart),
		get("weekly.report", "/weekly/report?group_id=x", "group_id", reasonInvalidFormat),
		get("weekly.report", "/weekly/report?metric=bogus", "metric", reasonNotAllowedValue),
		get("weekly.trend", "/weekly/trend?weeks=13", "weeks", reasonOutOfRange),
		get("weekly.trend", "/weekly/trend?group_id=-1", "group_id", reasonInvalidFormat),
		get("weekly.project", "/weekly/projects/abc", "id", reasonInvalidFormat),
		get("weekly.project", "/weekly/projects/-1?week=2026-11-04", "week", reasonNotWeekStart),
		get("weekly.unattributed", "/weekly/unattributed?week=11/02/2026", "week", reasonInvalidFormat),
		get("weekly.unattributed", "/weekly/unattributed?limit=201", "limit", reasonOutOfRange),
		// analysis
		get("analysis.overview", "/analysis/overview?"+sinceWindow+"&user_id=0", "user_id", reasonInvalidFormat),
		get("analysis.sessions", "/analysis/sessions?"+sinceWindow+"&kind=foo", "kind", reasonNotAllowedValue),
		get("analysis.sessions", "/analysis/sessions?"+sinceWindow+"&flags=loop,bogus", "flags", reasonNotAllowedValue),
		get("analysis.sessions", "/analysis/sessions?"+sinceWindow+"&cursor=bogus", "cursor", reasonInvalidCursor),
		get("analysis.sessions", "/analysis/sessions?"+sinceWindow+"&limit=201", "limit", reasonOutOfRange),
		get("analysis.sessions", "/analysis/sessions?"+sinceWindow+"&user_id=x", "user_id", reasonInvalidFormat),
		get("analysis.pack", "/analysis/sessions/abc/pack", "id", reasonInvalidFormat),
		get("analysis.facet", "/analysis/sessions/abc/facet", "id", reasonInvalidFormat),
		get("analysis.report", "/analysis/report?week=last", "week", reasonNotAllowedValue),
		get("analysis.report", "/analysis/report?user_id=0", "user_id", reasonInvalidFormat),
		get("analysis.report", "/analysis/report?project_id=x", "project_id", reasonInvalidFormat),
		get("analysis.report", "/analysis/report?group_id=0", "group_id", reasonInvalidFormat),
		get("analysis.report", "/analysis/report?project_id=1&group_id=1", "group_id", reasonConflict),
		get("analysis.report", "/analysis/report?user_id=1&project_id=1", "project_id", reasonConflict),
		get("analysis.report", "/analysis/report?user_id=1&group_id=1", "group_id", reasonConflict),
		// configuration and directories
		get("config.show", "/config/bogus", "kind", reasonNotAllowedValue),
		get("callers.list", "/callers?zz_unknown=1", "zz_unknown", reasonUnknownParameter),
		get("status", "/status?zz_unknown=1", "zz_unknown", reasonUnknownParameter),
		preview(`{"week":"2026-11-02","rules":[{"kind":"repo_name","pattern":"demo"}],"zz":1}`, "zz", reasonUnknownParameter),
		preview(`{"week":"2026-11-04","rules":[{"kind":"repo_name","pattern":"demo"}]}`, "week", reasonNotWeekStart),
		preview(`{"week":7,"rules":[{"kind":"repo_name","pattern":"demo"}]}`, "week", reasonInvalidFormat),
		preview(`{"group_id":"x","rules":[{"kind":"repo_name","pattern":"demo"}]}`, "group_id", reasonInvalidFormat),
		preview(`{"project_id":-1,"rules":[{"kind":"repo_name","pattern":"demo"}]}`, "project_id", reasonInvalidFormat),
		preview(`{"group_id":null,"rules":[]}`, "rules", reasonRequired),
		preview(`{"rules":[{"kind":"repo_name","pattern":""}]}`, "rules[0].pattern", "empty"),
		preview(`{"rules":"repo_name:demo"}`, "rules", reasonInvalidFormat),
		preview(`[`, "body", reasonInvalidFormat),
	)
	// Arguments a developer token may not use: refused as arguments, after
	// their value was checked.
	for _, test := range []struct{ path, field string }{
		{"/requests?user_id=8", "user_id"}, {"/requests?username=x", "username"}, {"/requests?token_id=99", "token_id"},
		{"/requests?token_name=x", "token_name"}, {"/requests?username=", "username"},
		{"/usage/overview?group_by=caller", "group_by"}, {"/usage/overview?group_by=token", "group_by"},
		{"/analysis/overview?since=7d&user_id=8", "user_id"}, {"/analysis/sessions?since=7d&user_id=8", "user_id"},
		{"/analysis/report?user_id=8", "user_id"}, {"/analysis/report?project_id=1", "project_id"}, {"/analysis/report?group_id=1", "group_id"},
	} {
		argument := get(endpointOf(test.path), test.path, test.field, reasonAdministratorOnly)
		argument.developer = true
		cases = append(cases, argument)
	}
	return cases
}

// endpointOf resolves a facade path to its registry ID.
func endpointOf(path string) string {
	route, _, _ := strings.Cut(path, "?")
	endpoint, _, ok := agentapi.NewRegistry(agentapi.Endpoints).Match(http.MethodGet, agentapi.PathPrefix+route)
	if !ok {
		return ""
	}
	return endpoint.ID
}

// endpointParameters is every parameter of a read endpoint: its query
// parameters, its path segments and its body fields.
func endpointParameters(endpoint agentapi.Endpoint) map[string]bool {
	parameters := map[string]bool{}
	for _, name := range agentQueryParams[endpoint.ID] {
		parameters[name] = true
	}
	for _, segment := range strings.Split(endpoint.Pattern, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			parameters[segment[1:len(segment)-1]] = true
		}
	}
	for _, name := range agentBodyFields()[endpoint.ID] {
		parameters[name] = true
	}
	return parameters
}

// parameterOf is the parameter a field names: rules[0].pattern names rules.
func parameterOf(field string) string {
	if cut := strings.IndexAny(field, "[."); cut > 0 {
		return field[:cut]
	}
	return field
}

func TestAgentEveryInvalidArgumentNamesFieldAndReason(t *testing.T) {
	fixture := newReadFixture(t)
	covered := map[string]map[string]bool{}
	for _, test := range badArguments() {
		endpoint := endpointByID(test.endpoint)
		if endpoint.ID == "" {
			t.Fatalf("case for unknown endpoint %q", test.endpoint)
		}
		token := fixture.adminRead
		if test.developer {
			token = fixture.developer
		}
		response := fixture.facade(test.method, test.path, test.body, token)
		decoded := decodeAgent(t, response)
		label := test.method + " " + test.path + " " + test.body
		if response.Code != http.StatusBadRequest || decoded.Error == nil || decoded.Error.Code != agentapi.CodeInvalidArgument {
			t.Errorf("%s = %d %s", label, response.Code, response.Body.String())
			continue
		}
		field, _ := decoded.Error.Details["field"].(string)
		reason, _ := decoded.Error.Details["reason"].(string)
		if field != test.field || reason != test.reason {
			t.Errorf("%s: field %q reason %q, want %q %q (%s)", label, field, reason, test.field, test.reason, response.Body.String())
		}
		parameters := endpointParameters(endpoint)
		if reason != reasonUnknownParameter && field != "body" && !parameters[parameterOf(field)] {
			t.Errorf("%s: field %q is not a parameter of %s", label, field, endpoint.ID)
		}
		if message := decoded.Error.Message; message == "" || message == "invalid argument" {
			t.Errorf("%s: message %q says nothing a reader can act on", label, message)
		}
		if reason == reasonConflict {
			other, _ := decoded.Error.Details["conflicts_with"].(string)
			if !parameters[other] || other == field || !strings.Contains(test.path, other+"=") {
				t.Errorf("%s: conflicts_with %q does not name the other given argument", label, other)
			}
		}
		if covered[endpoint.ID] == nil {
			covered[endpoint.ID] = map[string]bool{}
		}
		covered[endpoint.ID][parameterOf(field)] = true
	}
	for _, endpoint := range agentapi.ReadEndpoints {
		var missing []string
		for parameter := range endpointParameters(endpoint) {
			if !covered[endpoint.ID][parameter] {
				missing = append(missing, parameter)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: no refused value tested for %v", endpoint.ID, missing)
		}
		if len(endpointParameters(endpoint)) == 0 && len(covered[endpoint.ID]) == 0 {
			t.Errorf("%s takes no parameter: an unknown parameter must be tested", endpoint.ID)
		}
	}
}

// Every pair of arguments that exclude each other is refused naming both.
func TestAgentExclusiveArgumentsNameBoth(t *testing.T) {
	fixture := newReadFixture(t)
	pairs := []struct{ path, field, other string }{
		{"/analysis/report?project_id=1&group_id=1", "group_id", "project_id"},
		{"/analysis/report?group_id=1&project_id=1", "group_id", "project_id"},
		{"/analysis/report?user_id=1&project_id=1", "project_id", "user_id"},
		{"/analysis/report?user_id=1&group_id=1", "group_id", "user_id"},
	}
	for _, path := range []string{"/requests", "/usage/overview", "/usage/sessions", "/analysis/overview", "/analysis/users", "/analysis/sessions"} {
		pairs = append(pairs, struct{ path, field, other string }{path + "?since=1d&from=2026-01-01", "since", "from"})
	}
	for _, pair := range pairs {
		body := decodeAgent(t, fixture.facade(http.MethodGet, pair.path, "", fixture.adminRead))
		if body.Error == nil || body.Error.Details["field"] != pair.field || body.Error.Details["conflicts_with"] != pair.other ||
			!strings.Contains(body.Error.Message, "`"+pair.field+"`") || !strings.Contains(body.Error.Message, "`"+pair.other+"`") {
			t.Errorf("%s = %+v", pair.path, body.Error)
		}
	}
}

// A cursor belongs to the query and the identity of the page that returned
// it: the next page of the same query (a relative range included, and a
// different page size) is accepted; another filter, another identity or
// another list is refused with cursor_query_mismatch, so pages of two
// queries are never mixed.
func TestAgentCursorsAreBoundToTheirQuery(t *testing.T) {
	fixture := newReadFixture(t)
	nextCursor := func(path, token string) string {
		t.Helper()
		cursor, _ := readData(t, fixture.facade(http.MethodGet, path, "", token))["next_cursor"].(string)
		if cursor == "" {
			t.Fatalf("%s returned no next_cursor", path)
		}
		return cursor
	}
	reason := func(path, token string) string {
		t.Helper()
		response := fixture.facade(http.MethodGet, path, "", token)
		if response.Code == http.StatusOK {
			return ""
		}
		body := decodeAgent(t, response)
		if body.Error == nil || body.Error.Details["field"] != "cursor" {
			t.Fatalf("%s = %s", path, response.Body.String())
		}
		reason, _ := body.Error.Details["reason"].(string)
		return reason
	}
	for _, list := range []struct {
		first, same, other string
		token, otherToken  string
	}{
		{"/requests?since=3650d&collapse=false&limit=2", "/requests?since=3650d&collapse=false&limit=3", "/requests?since=3650d&collapse=false&limit=2&status=error",
			fixture.adminRead, fixture.developer},
		{"/usage/sessions?" + fixtureWindow + "&limit=1", "/usage/sessions?" + fixtureWindow + "&limit=2", "/usage/sessions?" + fixtureWindow + "&limit=1&sort=tokens",
			fixture.adminRead, fixture.developer},
		{"/analysis/sessions?" + fixtureWindow + "&limit=1", "/analysis/sessions?" + fixtureWindow + "&limit=1", "/analysis/sessions?" + fixtureWindow + "&limit=1&kind=chat",
			fixture.adminRead, fixture.developer},
	} {
		cursor := nextCursor(list.first, list.token)
		if got := reason(list.same+"&cursor="+cursor, list.token); got != "" {
			t.Errorf("%s: the next page of the same query = %s", list.first, got)
		}
		if got := reason(list.other+"&cursor="+cursor, list.token); got != reasonCursorMismatch {
			t.Errorf("%s: another filter = %q", list.other, got)
		}
		if got := reason(list.first+"&cursor="+cursor, list.otherToken); got != reasonCursorMismatch {
			t.Errorf("%s: another identity = %q", list.first, got)
		}
	}
	// A cursor of another list is not a cursor of this one at all.
	cursor := nextCursor("/usage/sessions?"+fixtureWindow+"&limit=1", fixture.adminRead)
	if got := reason("/requests?cursor="+cursor, fixture.adminRead); got != reasonInvalidCursor {
		t.Errorf("a usage cursor on the audit list = %q", got)
	}
}

// An id of a group, project or user that does not exist is answered as the
// web route answers it (an empty result for the preview and the review, not
// an error), and next_actions says nothing was found, so zeros are not read
// as data. A known id has no such line.
func TestAgentUnknownObjectsAreNamedNotCounted(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.reports.stats = nil
	actions := func(method, path, body string) []string {
		t.Helper()
		response := fixture.facade(method, path, body, fixture.adminRead)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s = %s", path, body, response.Body.String())
		}
		return decodeAgent(t, response).NextActions
	}
	mentions := func(actions []string, text string) bool {
		for _, action := range actions {
			if strings.Contains(action, text) {
				return true
			}
		}
		return false
	}
	rules := `"rules":[{"kind":"repo_name","pattern":"demo"}]`
	for _, test := range []struct{ body, text string }{
		{`{"group_id":99,` + rules + `}`, "No project group with id 99"},
		{`{"project_id":7,` + rules + `}`, "No project with id 7"},
	} {
		if got := actions(http.MethodPost, "/config/project-preview", test.body); !mentions(got, test.text) {
			t.Errorf("preview %s: next_actions %v", test.body, got)
		}
		if web := fixture.web(http.MethodPost, "/api/v1/org/projects/preview", test.body, fixture.adminWeb); web.Code != http.StatusOK {
			t.Errorf("web preview %s = %d, the facade must answer the same way", test.body, web.Code)
		}
	}
	if got := actions(http.MethodPost, "/config/project-preview", `{"group_id":0,`+rules+`}`); len(got) != 0 {
		t.Errorf("ungrouped preview: next_actions %v", got)
	}
	if got := actions(http.MethodGet, "/analysis/report?project_id=99", ""); !mentions(got, "No project with id 99") {
		t.Errorf("report of an unknown project: next_actions %v", got)
	}
	if got := actions(http.MethodGet, "/analysis/report?user_id=99", ""); !mentions(got, "NewAPI user 99") {
		t.Errorf("report of an unknown user: next_actions %v", got)
	}
}

// The anonymous download refuses a query parameter with field and reason as
// well.
func TestAgentDownloadParameterErrorNamesFieldAndReason(t *testing.T) {
	fixture := newReadFixture(t)
	body := decodeAgent(t, fixture.facade(http.MethodGet, "/dl/signature/manifest.json?zz=1", "", ""))
	if body.Error == nil || body.Error.Code != agentapi.CodeInvalidArgument || body.Error.Details["field"] != "zz" ||
		body.Error.Details["reason"] != reasonUnknownParameter || body.Error.Message == "invalid argument" {
		t.Fatalf("download with a parameter = %+v", body.Error)
	}
}

// The sensitive_read row cleans the client-reported command and version like
// every other token event: a client cannot record the reserved "web" or
// arbitrary text (contract section 0.1 item 176).
func TestAgentSensitiveReadAuditCleansCommandAndVersion(t *testing.T) {
	fixture := newReadFixture(t)
	for _, resource := range []string{"pack", "facet"} {
		path := agentapi.PathPrefix + "/analysis/sessions/" + analysisOwnID + "/" + resource
		readData(t, fixture.do(http.MethodGet, path, "", agentCaller{bearer: fixture.developer},
			// The suffix after "-" passes the client-version gate but is not a
			// plausible version string.
			agentapi.HeaderCommand, "web", agentapi.HeaderCLIVersion, agentapi.LatestVersion+"-<script> x"))
		entries := fixture.store.Audit()
		last := entries[len(entries)-1]
		if last.Event != agentaccess.EventSensitiveRead || last.Command != agentaccess.CommandUnknown || last.CLIVersion != "" {
			t.Fatalf("%s audit row with a reserved command = %+v", resource, last)
		}
		readData(t, fixture.do(http.MethodGet, path, "", agentCaller{bearer: fixture.developer},
			agentapi.HeaderCommand, "analysis."+resource, agentapi.HeaderCLIVersion, agentapi.LatestVersion))
		entries = fixture.store.Audit()
		last = entries[len(entries)-1]
		if last.Event != agentaccess.EventSensitiveRead || last.Command != "analysis."+resource || last.CLIVersion != agentapi.LatestVersion ||
			last.ObjectID != analysisOwnID || last.TokenID == nil || last.Outcome != storage.AgentOutcomeOK {
			t.Fatalf("%s audit row with a valid command = %+v", resource, last)
		}
	}
}

// A pack or facet read refused for its id still writes the failed
// sensitive_read row (contract section 0.1 item 28).
func TestAgentRefusedSessionIDIsAuditedAsAFailedSensitiveRead(t *testing.T) {
	fixture := newReadFixture(t)
	for _, resource := range []string{"pack", "facet"} {
		before := len(fixture.store.Audit())
		if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/analysis/sessions/abc/"+resource, "", fixture.developer)); code != agentapi.CodeInvalidArgument {
			t.Fatalf("%s with a bad id = %s", resource, code)
		}
		entries := fixture.store.Audit()
		if len(entries) != before+1 {
			t.Fatalf("%s: %d audit rows written, want 1", resource, len(entries)-before)
		}
		last := entries[len(entries)-1]
		if last.Event != agentaccess.EventSensitiveRead || last.Outcome != storage.AgentOutcomeFailed || last.ErrorCode != string(agentapi.CodeInvalidArgument) {
			t.Fatalf("%s audit row = %+v", resource, last)
		}
	}
}
