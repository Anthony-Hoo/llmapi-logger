package web

import (
	"net/http"
	"net/url"

	"llmapi-logger/internal/agentapi"
)

// agentQueryParams is, per facade endpoint, every query parameter its
// handler reads (contract sections 4.3–4.5; anything else is refused with
// INVALID_ARGUMENT, section 0.1 item 20). Handlers check their query through
// agentCallParams, so this table is what the server accepts, and the
// alignment test compares it with what the CLI can send.
var agentQueryParams = map[string][]string{
	"token.exchange": {},
	"whoami":         {},
	"logout":         {},

	// The signed download takes no parameter: the link is the whole request.
	agentapi.EndpointDownload: {},

	"requests.list": {"from", "to", "since", "cursor", "limit", "protocol", "path", "model", "user_agent",
		"status", "forward_status", "blocked_by", "block_code", "capture_status", "upstream_error_class", "conversation", "collapse",
		"user_id", "username", "token_id", "token_name"},
	"requests.get":    {"headers"},
	"requests.export": {},

	"usage.composition": {},
	"usage.overview":    {"from", "to", "since", "group_by", "tz_offset_min"},
	"usage.sessions":    {"from", "to", "since", "sort", "cursor", "limit"},
	"usage.trend":       {},
	"usage.tree":        {},

	"weekly.me":           {},
	"weekly.report":       {"week", "group_id", "metric"},
	"weekly.trend":        {"weeks", "group_id"},
	"weekly.project":      {"week"},
	"weekly.unattributed": {"week", "limit"},

	"analysis.overview": {"from", "to", "since", "user_id"},
	"analysis.users":    {"from", "to", "since"},
	"analysis.sessions": {"from", "to", "since", "kind", "flags", "cursor", "limit", "user_id"},
	"analysis.pack":     {},
	"analysis.facet":    {},
	"analysis.report":   {"week", "user_id", "project_id", "group_id"},

	"config.show":            {},
	"config.project-preview": {},
	"callers.list":           {},
	"status":                 {},

	"plans.create":         {},
	"plans.apply":          {},
	"config.api-key.set":   {},
	"config.api-key.clear": {},
	"analysis.test-model":  {},
}

// agentCallParams checks the query string of call against its endpoint's
// row of agentQueryParams. An endpoint without a row accepts no parameter.
func agentCallParams(request *http.Request, call agentCall) (url.Values, error) {
	return agentParams(request, agentQueryParams[call.Endpoint.ID]...)
}

// agentBodyFields is, per facade endpoint that takes a JSON body, its
// top-level fields and the fields of nested objects the CLI fills ("args.week").
// The plan fields come from the decoder's own tables; the alignment test
// checks the CLI against this.
func agentBodyFields() map[string][]string {
	plan := []string{"op"}
	for _, fields := range planFields {
		for _, field := range fields {
			// args is a container; its members are listed as args.<name>.
			if field != "args" && !contains(plan, field) {
				plan = append(plan, field)
			}
		}
	}
	for _, args := range planArgs {
		for _, arg := range args {
			plan = append(plan, "args."+arg)
		}
	}
	return map[string][]string{
		"token.exchange":         agentTokenBodyFields,
		"config.project-preview": {"week", "group_id", "rules", "project_id"},
		"plans.create":           plan,
		"config.api-key.set":     {"api_key"},
		"analysis.test-model":    agentTestModelBodyFields,
	}
}
