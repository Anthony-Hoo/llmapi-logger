package agentapi

// WriteEndpoints are the write facade of phase 4 (contract section 4.5).
// Every one is administrator-only and write tier; the dispatcher also requires
// agent_access.allow_write before the handler runs.
var WriteEndpoints = []Endpoint{
	{ID: EndpointPlanCreate, Method: "POST", Pattern: "/plans", Access: AccessAdmin, Tier: TierWrite},
	{ID: EndpointPlanApply, Method: "POST", Pattern: "/plans/{plan_id}/apply", Access: AccessAdmin, Tier: TierWrite},
	{ID: EndpointAPIKeySet, Method: "PUT", Pattern: "/config/analysis-settings/api-key", Access: AccessAdmin, Tier: TierWrite},
	{ID: EndpointAPIKeyClear, Method: "DELETE", Pattern: "/config/analysis-settings/api-key", Access: AccessAdmin, Tier: TierWrite},
	{ID: EndpointTestModel, Method: "POST", Pattern: "/analysis/test-model", Access: AccessAdmin, Tier: TierWrite},
}

// IDs of the write endpoints.
const (
	EndpointPlanCreate  = "plans.create"
	EndpointPlanApply   = "plans.apply"
	EndpointAPIKeySet   = "config.api-key.set"
	EndpointAPIKeyClear = "config.api-key.clear"
	EndpointTestModel   = "analysis.test-model"
)

// Plan operations (contract section 4.5.1).
const (
	OpConfigSet         = "config.set"
	OpConfigRemove      = "config.remove"
	OpConfigReset       = "config.reset"
	OpAnalysisRun       = "analysis.run"
	OpAnalysisCalibrate = "analysis.calibrate"
	OpAnalysisDismiss   = "analysis.dismiss"
	OpWeeklyRegenerate  = "weekly.regenerate"
)

// PlanOps lists every op value POST /plans accepts.
var PlanOps = []string{OpConfigSet, OpConfigRemove, OpConfigReset, OpAnalysisRun, OpAnalysisCalibrate, OpAnalysisDismiss, OpWeeklyRegenerate}

// WriteKinds are the kind values of config.set and config.remove (contract
// section 4.5.2); config.reset accepts only the two settings sections.
var WriteKinds = []string{"ua-rule", "content-rule", "group", "project", "member", "principal", "weekly-settings", "analysis-settings"}

// SettableFields lists, per kind, the field names a plan may set, add to or
// remove from (contract section 4.5.2). The analysis settings use dotted
// names for the model stage, exactly as the CLI sends them.
var SettableFields = map[string][]string{
	"ua-rule":         {"name", "enabled", "model_pattern", "user_agent_pattern"},
	"content-rule":    {"name", "enabled", "action", "model_pattern", "scan_scopes", "keywords"},
	"group":           {"name", "enabled"},
	"project":         {"name", "group_id", "enabled", "rules"},
	"member":          {"group_id"},
	"principal":       {"class"},
	"weekly-settings": {"idle_gap_seconds", "ranked_clients", "max_concurrent_roots", "max_single_request_roots"},
	"analysis-settings": {"run_at", "l1_settle_hours", "llm.enabled", "llm.base_url", "llm.model", "llm.structured_output",
		"llm.context_tokens", "llm.disable_thinking", "llm.max_output_tokens", "llm.max_concurrency", "llm.timeout_seconds",
		"llm.max_sessions_per_run"},
}

// ListFields lists, per kind, the fields add and remove may name.
var ListFields = map[string][]string{
	"content-rule":    {"scan_scopes", "keywords"},
	"project":         {"rules"},
	"weekly-settings": {"ranked_clients"},
}
