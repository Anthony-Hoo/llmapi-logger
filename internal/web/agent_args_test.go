package web

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
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
		get("requests.list", "/requests?protocol=foo", "protocol", reasonNotAllowedValue),
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
