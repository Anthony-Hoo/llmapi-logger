package agentapi

// The web route table of contract section 4.8 as data. Every management
// route of the web UI is either mapped onto facade endpoints here or listed
// in WebRouteExceptions; a test in internal/web probes every row against the
// real handler and scans the handler source for routes this table lacks.

// planCommandSet is the command of every config.set row.
const planCommandSet = "config set"

// WebRoute maps one method and path of the management API onto the facade.
// Path segments written {name} stand for one value.
type WebRoute struct {
	Method string
	Path   string
	// Endpoints are the facade endpoint IDs that cover the route.
	Endpoints []string
	// Op is the plan operation of a write route (contract section 4.5.1).
	Op string
	// Commands are the llmaudit commands that reach the endpoints.
	Commands []string
	// Pending marks a row whose endpoints belong to a later phase and are not
	// registered yet. A test refuses a pending row whose endpoints all exist.
	// Since phase 4 no row is pending.
	Pending bool
}

// WebRouteException is a management route with no command, and why.
type WebRouteException struct {
	Method string
	Path   string
	Reason string
}

var planEndpoints = []string{EndpointPlanCreate, EndpointPlanApply}

func planRoute(method, path, op string, commands ...string) WebRoute {
	return WebRoute{Method: method, Path: path, Endpoints: planEndpoints, Op: op, Commands: commands}
}

// WebRoutes is the table of contract section 4.8, one row per method.
var WebRoutes = []WebRoute{
	{Method: "GET", Path: "/api/v1/audits", Endpoints: []string{"requests.list"}, Commands: []string{"requests list"}},
	{Method: "GET", Path: "/api/v1/audits/{id}", Endpoints: []string{"requests.get", "requests.export"}, Commands: []string{"requests get", "requests export"}},
	{Method: "GET", Path: "/api/v1/audits/{id}/raw/{side}", Endpoints: []string{"requests.export"}, Commands: []string{"requests export"}},
	{Method: "GET", Path: "/api/v1/audits/{id}/reconstructed/{side}", Endpoints: []string{"requests.export"}, Commands: []string{"requests export"}},
	{Method: "GET", Path: "/api/v1/audits/{id}/timeline/{side}", Endpoints: []string{"requests.export"}, Commands: []string{"requests export"}},
	{Method: "GET", Path: "/api/v1/audits/{id}/composition", Endpoints: []string{"usage.composition"}, Commands: []string{"usage composition"}},

	{Method: "GET", Path: "/api/v1/insights/overview", Endpoints: []string{"usage.overview"}, Commands: []string{"usage overview"}},
	{Method: "GET", Path: "/api/v1/insights/sessions", Endpoints: []string{"usage.sessions"}, Commands: []string{"usage sessions"}},
	{Method: "GET", Path: "/api/v1/insights/sessions/{id}/trend", Endpoints: []string{"usage.trend"}, Commands: []string{"usage trend"}},
	{Method: "GET", Path: "/api/v1/insights/agent-trees/{id}", Endpoints: []string{"usage.tree"}, Commands: []string{"usage tree"}},

	{Method: "GET", Path: "/api/v1/org/me/weekly", Endpoints: []string{"weekly.me"}, Commands: []string{"weekly me"}},
	{Method: "GET", Path: "/api/v1/org/weekly", Endpoints: []string{"weekly.report"}, Commands: []string{"weekly report"}},
	{Method: "GET", Path: "/api/v1/org/weekly/trend", Endpoints: []string{"weekly.trend"}, Commands: []string{"weekly trend"}},
	{Method: "GET", Path: "/api/v1/org/projects/{id}/weekly", Endpoints: []string{"weekly.project"}, Commands: []string{"weekly project"}},
	{Method: "GET", Path: "/api/v1/org/unattributed", Endpoints: []string{"weekly.unattributed"}, Commands: []string{"weekly unattributed"}},
	planRoute("POST", "/api/v1/org/weekly/regenerate", "weekly.regenerate", "weekly regenerate", "apply"),
	{Method: "GET", Path: "/api/v1/org/settings", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind org"}},
	{Method: "GET", Path: "/api/v1/org/catalog", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind org"}},
	planRoute("POST", "/api/v1/org/groups", "config.set", planCommandSet, "apply"),
	planRoute("PUT", "/api/v1/org/groups/{id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/org/groups/{id}", "config.remove", "config remove", "apply"),
	planRoute("POST", "/api/v1/org/projects", "config.set", planCommandSet, "apply"),
	planRoute("PUT", "/api/v1/org/projects/{id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/org/projects/{id}", "config.remove", "config remove", "apply"),
	{Method: "POST", Path: "/api/v1/org/projects/preview", Endpoints: []string{"config.project-preview"}, Commands: []string{"config preview-project"}},
	planRoute("PUT", "/api/v1/org/members/{user_id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/org/members/{user_id}", "config.remove", "config remove", "apply"),
	planRoute("PUT", "/api/v1/org/principals/{kind}/{id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/org/principals/{kind}/{id}", "config.remove", "config remove", "apply"),

	{Method: "GET", Path: "/api/v1/session-analysis/overview", Endpoints: []string{"analysis.overview"}, Commands: []string{"analysis overview"}},
	{Method: "GET", Path: "/api/v1/session-analysis/users", Endpoints: []string{"analysis.users"}, Commands: []string{"analysis users"}},
	{Method: "GET", Path: "/api/v1/session-analysis/sessions", Endpoints: []string{"analysis.sessions"}, Commands: []string{"analysis sessions"}},
	{Method: "GET", Path: "/api/v1/session-analysis/sessions/{id}/pack", Endpoints: []string{"analysis.pack"}, Commands: []string{"analysis session"}},
	{Method: "GET", Path: "/api/v1/session-analysis/sessions/{id}/facet", Endpoints: []string{"analysis.facet"}, Commands: []string{"analysis session"}},
	{Method: "GET", Path: "/api/v1/session-analysis/report", Endpoints: []string{"analysis.report"}, Commands: []string{"analysis report"}},
	planRoute("POST", "/api/v1/session-analysis/run", "analysis.run", "analysis run", "apply"),
	planRoute("POST", "/api/v1/session-analysis/calibration", "analysis.calibrate", "analysis calibrate", "apply"),
	planRoute("POST", "/api/v1/session-analysis/suggestions/{id}/dismiss", "analysis.dismiss", "analysis dismiss", "apply"),

	{Method: "GET", Path: "/api/v1/user-agent-rules", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind ua-rule"}},
	planRoute("POST", "/api/v1/user-agent-rules", "config.set", planCommandSet, "apply"),
	planRoute("PUT", "/api/v1/user-agent-rules/{id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/user-agent-rules/{id}", "config.remove", "config remove", "apply"),
	{Method: "GET", Path: "/api/v1/content-policy-rules", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind content-rule"}},
	planRoute("POST", "/api/v1/content-policy-rules", "config.set", planCommandSet, "apply"),
	planRoute("PUT", "/api/v1/content-policy-rules/{id}", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/content-policy-rules/{id}", "config.remove", "config remove", "apply"),

	{Method: "GET", Path: "/api/v1/settings/org-reports", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind weekly-settings"}},
	planRoute("PUT", "/api/v1/settings/org-reports", "config.set", planCommandSet, "apply"),
	planRoute("DELETE", "/api/v1/settings/org-reports", "config.reset", "config reset", "apply"),
	{Method: "GET", Path: "/api/v1/settings/session-analysis", Endpoints: []string{"config.show"}, Commands: []string{"config show --kind analysis-settings"}},
	{Method: "PUT", Path: "/api/v1/settings/session-analysis", Endpoints: []string{EndpointPlanCreate, EndpointPlanApply, EndpointAPIKeySet, EndpointAPIKeyClear},
		Op: OpConfigSet, Commands: []string{planCommandSet, "config set-key", "apply"}},
	planRoute("DELETE", "/api/v1/settings/session-analysis", "config.reset", "config reset", "apply"),
	{Method: "POST", Path: "/api/v1/settings/session-analysis/test", Endpoints: []string{EndpointTestModel}, Commands: []string{"analysis test-model"}},

	{Method: "GET", Path: "/api/v1/newapi/callers", Endpoints: []string{"callers.list"}, Commands: []string{"callers list"}},
	{Method: "GET", Path: "/healthz", Endpoints: []string{"status"}, Commands: []string{"status"}},
	{Method: "GET", Path: "/readyz", Endpoints: []string{"status"}, Commands: []string{"status"}},
}

// WebRouteExceptions are the management routes with no command.
var WebRouteExceptions = []WebRouteException{
	{Method: "GET", Path: "/api/v1/session", Reason: "web sign-in state; the CLI has whoami"},
	{Method: "POST", Path: "/api/v1/session", Reason: "web sign-in; the CLI has login"},
	{Method: "DELETE", Path: "/api/v1/session", Reason: "web sign-out; the CLI has logout"},
	{Method: "GET", Path: "/", Reason: "redirect to the static UI"},
	{Method: "GET", Path: "/ui", Reason: "static UI"},
	{Method: "GET", Path: "/ui/{path}", Reason: "static UI"},
	{Method: "POST", Path: "/api/v1/agent-access/authorizations", Reason: "agent access pages of the web UI (this module)"},
	{Method: "GET", Path: "/api/v1/agent-access/tokens", Reason: "agent access pages of the web UI (this module)"},
	{Method: "DELETE", Path: "/api/v1/agent-access/tokens/{id}", Reason: "agent access pages of the web UI (this module)"},
	{Method: "GET", Path: "/api/v1/agent-access/changes", Reason: "agent access pages of the web UI (this module): recent agent changes, administrators only"},
	{Method: "POST", Path: "/api/v1/agent-access/install-links", Reason: "agent access pages of the web UI (this module): the install prompt with its signed download link"},
}

// FacadeOnlyEndpoints are facade endpoints with no web route of their own:
// the CLI's sign-in, identity and sign-out, and the signed package download
// the install prompt fetches.
var FacadeOnlyEndpoints = []string{"token.exchange", "whoami", "logout", EndpointDownload}
