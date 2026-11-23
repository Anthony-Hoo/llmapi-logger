package agentapi

// ReadEndpoints are the read facade of phase 2 (contract sections 4.3 and
// 4.4). Every one is read tier; Access follows the contract's tables.
var ReadEndpoints = []Endpoint{
	// Audit records (4.3.1).
	{ID: "requests.list", Method: "GET", Pattern: "/requests", Access: AccessAny, Tier: TierRead},
	{ID: "requests.get", Method: "GET", Pattern: "/requests/{id}", Access: AccessAny, Tier: TierRead},
	{ID: "requests.export", Method: "GET", Pattern: "/requests/{id}/export/{what}", Access: AccessAny, Tier: TierRead},
	// Usage insights (4.3.3).
	{ID: "usage.composition", Method: "GET", Pattern: "/requests/{id}/composition", Access: AccessAny, Tier: TierRead},
	{ID: "usage.overview", Method: "GET", Pattern: "/usage/overview", Access: AccessAny, Tier: TierRead},
	{ID: "usage.sessions", Method: "GET", Pattern: "/usage/sessions", Access: AccessAny, Tier: TierRead},
	{ID: "usage.trend", Method: "GET", Pattern: "/usage/sessions/{id}/trend", Access: AccessAny, Tier: TierRead},
	{ID: "usage.tree", Method: "GET", Pattern: "/usage/trees/{id}", Access: AccessAny, Tier: TierRead},
	// Weekly project reports (4.3.4).
	{ID: "weekly.me", Method: "GET", Pattern: "/weekly/me", Access: AccessAny, Tier: TierRead},
	{ID: "weekly.report", Method: "GET", Pattern: "/weekly/report", Access: AccessAdmin, Tier: TierRead},
	{ID: "weekly.trend", Method: "GET", Pattern: "/weekly/trend", Access: AccessAdmin, Tier: TierRead},
	{ID: "weekly.project", Method: "GET", Pattern: "/weekly/projects/{id}", Access: AccessAdmin, Tier: TierRead},
	{ID: "weekly.unattributed", Method: "GET", Pattern: "/weekly/unattributed", Access: AccessAdmin, Tier: TierRead},
	// Session analysis (4.3.5).
	{ID: "analysis.overview", Method: "GET", Pattern: "/analysis/overview", Access: AccessAny, Tier: TierRead},
	{ID: "analysis.users", Method: "GET", Pattern: "/analysis/users", Access: AccessAdmin, Tier: TierRead},
	{ID: "analysis.sessions", Method: "GET", Pattern: "/analysis/sessions", Access: AccessAny, Tier: TierRead},
	{ID: "analysis.pack", Method: "GET", Pattern: "/analysis/sessions/{id}/pack", Access: AccessAny, Tier: TierRead},
	{ID: "analysis.facet", Method: "GET", Pattern: "/analysis/sessions/{id}/facet", Access: AccessAny, Tier: TierRead},
	{ID: "analysis.report", Method: "GET", Pattern: "/analysis/report", Access: AccessAny, Tier: TierRead},
	// Configuration and directories, read only (4.3.6), and the project
	// preview, which persists nothing (4.4).
	{ID: "config.show", Method: "GET", Pattern: "/config/{kind}", Access: AccessAdmin, Tier: TierRead},
	{ID: "config.project-preview", Method: "POST", Pattern: "/config/project-preview", Access: AccessAdmin, Tier: TierRead},
	{ID: "callers.list", Method: "GET", Pattern: "/callers", Access: AccessAdmin, Tier: TierRead},
	{ID: "status", Method: "GET", Pattern: "/status", Access: AccessAdmin, Tier: TierRead},
}

// ConfigKinds are the {kind} values of GET /config/{kind}.
var ConfigKinds = []string{"ua-rule", "content-rule", "org", "weekly-settings", "analysis-settings"}

// ExportKinds are the {what} values of GET /requests/{id}/export/{what}.
var ExportKinds = []string{
	"conversation", "headers", "request", "response",
	"raw-request", "raw-response", "timeline-request", "timeline-response",
}
