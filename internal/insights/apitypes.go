package insights

// JSON contract of the insights management API (doc/features/20-context-insights.md §7).
// The web frontend mirrors these shapes in src/types.ts. All token fields are
// integers; nullable numbers mean "not reported" or "unknown price".

// UsageTotals aggregates normalized usage over many requests. Cost is NewAPI's
// actual billing (doc/features/21-newapi-billing.md): CostUSD sums
// quota / quota_per_unit over the BilledRequests and is never mixed with an
// estimate; every other request counts as unbilled.
type UsageTotals struct {
	Requests         int64    `json:"requests"`
	UncachedInput    int64    `json:"uncached_input"`
	CacheRead        int64    `json:"cache_read"`
	CacheWrite       int64    `json:"cache_write"`
	Output           int64    `json:"output"`
	Reasoning        int64    `json:"reasoning"`
	PromptTotal      int64    `json:"prompt_total"`
	CacheHitRate     *float64 `json:"cache_hit_rate"` // nil when prompt_total is 0
	CostUSD          *float64 `json:"cost_usd"`       // nil when no request is billed
	BilledRequests   int64    `json:"billed_requests"`
	UnbilledRequests int64    `json:"unbilled_requests"` // requests - billed_requests
}

// OverviewResponse is GET /api/v1/insights/overview.
//
// The tz_offset_min query parameter is minutes EAST of UTC (UTC+8 sends 480),
// the negation of JavaScript's Date.getTimezoneOffset(); it defines the local
// calendar days of Daily and Heatmap. Heatmap is always the trailing 56 local
// days ending at the day that contains to_ns, independent of from_ns.
type OverviewResponse struct {
	FromNS   int64          `json:"from_ns,string"`
	ToNS     int64          `json:"to_ns,string"`
	Totals   UsageTotals    `json:"totals"`
	Sessions int64          `json:"sessions"`
	Trees    int64          `json:"trees"`
	Daily    []DailyUsage   `json:"daily"`
	Heatmap  []HeatmapDay   `json:"heatmap"`
	GroupBy  string         `json:"group_by"`
	Groups   []GroupUsage   `json:"groups"`
	Mix      CategoryValues `json:"composition"` // summed estimates anchored to prompt totals
	// BillingEnabled is true when the NewAPI management credential is
	// configured, so unbilled requests are genuinely unbilled rather than
	// unknowable.
	BillingEnabled bool `json:"billing_enabled"`
	// ClientLabels maps a client key to the display name its vocabulary rule
	// sets (ClientRule.Label); absent when no client has one. Group labels of
	// group_by=client already carry it.
	ClientLabels map[string]string `json:"client_labels,omitempty"`
}

// DailyUsage is one local calendar day (tz_offset_min query parameter).
type DailyUsage struct {
	Day   string      `json:"day"` // YYYY-MM-DD
	Usage UsageTotals `json:"usage"`
}

// HeatmapDay is one cell of the 8-week activity heatmap.
type HeatmapDay struct {
	Day      string `json:"day"`
	Requests int64  `json:"requests"`
	Sessions int64  `json:"sessions"`
}

// GroupUsage is one group_by bucket (model | protocol | client | caller | token).
type GroupUsage struct {
	Key   string      `json:"key"`
	Label string      `json:"label"`
	Usage UsageTotals `json:"usage"`
}

// SessionCard is one item of GET /api/v1/insights/sessions.
type SessionCard struct {
	SessionID     string         `json:"session_id"`
	SessionLink   string         `json:"session_link"`
	TreeID        string         `json:"tree_id,omitempty"` // hex root fingerprint prefix, when part of an agent tree
	Protocol      string         `json:"protocol"`
	Client        string         `json:"client"`
	Role          string         `json:"role"`
	FirstNS       int64          `json:"first_ns,string"`
	LastNS        int64          `json:"last_ns,string"`
	Steps         int64          `json:"steps"`
	Turns         int64          `json:"turns"`
	Models        []string       `json:"models"`
	Usage         UsageTotals    `json:"usage"`
	LastEstimate  CategoryValues `json:"last_composition"`
	LastPrompt    *int64         `json:"last_prompt_total"`
	ContextWindow *int64         `json:"context_window"`
	Subagents     int64          `json:"subagents"`
	Caller        *SessionCaller `json:"caller"` // admin only; nil for developer sessions
}

// SessionCaller is the NewAPI identity resolved for the session's last step.
type SessionCaller struct {
	Username  string `json:"username,omitempty"`
	TokenName string `json:"token_name,omitempty"`
}

// SessionsResponse is GET /api/v1/insights/sessions.
type SessionsResponse struct {
	Items          []SessionCard     `json:"items"`
	NextCursor     string            `json:"next_cursor,omitempty"`
	BillingEnabled bool              `json:"billing_enabled"`         // see OverviewResponse
	ClientLabels   map[string]string `json:"client_labels,omitempty"` // see OverviewResponse
}

// TrendStep is one request of a session trend.
type TrendStep struct {
	AuditID       string         `json:"audit_id"`
	StartedAtNS   int64          `json:"started_at_ns,string"`
	Turn          int64          `json:"turn"`
	TurnStart     bool           `json:"turn_start"`
	Model         string         `json:"model"`
	Role          string         `json:"role"`
	Estimate      CategoryValues `json:"estimate"`
	Usage         Usage          `json:"usage"`
	PromptTotal   *int64         `json:"prompt_total"`
	Events        []string       `json:"events"` // model_switch | compaction | prune | system_changed | tools_changed | injected
	AppendedItems *int64         `json:"appended_items"`
	RemovedItems  *int64         `json:"removed_items"`
	StopReason    string         `json:"stop_reason,omitempty"`
	ResponseKinds []string       `json:"response_kinds"` // thinking | tool_call | text
	FirstEventMS  *float64       `json:"first_event_ms"`
	GenerationMS  *float64       `json:"generation_ms"`
	ClientGapMS   *float64       `json:"client_gap_ms"` // previous tool_use response end -> this request start
	CostUSD       *float64       `json:"cost_usd"`      // this request's actual NewAPI billing; nil when not billed
}

// TrendResponse is GET /api/v1/insights/sessions/{session_id}/trend.
type TrendResponse struct {
	SessionID     string      `json:"session_id"`
	TreeID        string      `json:"tree_id,omitempty"`
	ContextWindow *int64      `json:"context_window"`
	Truncated     bool        `json:"truncated"` // more than 2000 steps; the most recent ones are returned
	Steps         []TrendStep `json:"steps"`
}

// TreeNode is one agent of GET /api/v1/insights/agent-trees/{tree_id}.
type TreeNode struct {
	NodeID       string `json:"node_id"` // hex fingerprint prefix
	ParentNodeID string `json:"parent_node_id,omitempty"`
	// Visible is false for a placeholder standing in for a parent that no
	// in-scope row describes: it is out of scope, expired, or not analysed yet.
	Visible   bool   `json:"visible"`
	SessionID string `json:"session_id,omitempty"`
	Client    string `json:"client"`
	Role      string `json:"role"`
	// Name is the client-declared agent name (X-Agent-Name and the like) read
	// from the encrypted detail of the node's latest non-auxiliary step; empty
	// when the client sent none or the detail could not be opened.
	Name           string         `json:"name,omitempty"`
	FirstNS        int64          `json:"first_ns,string"`
	LastNS         int64          `json:"last_ns,string"`
	Steps          int64          `json:"steps"`
	AuxRequests    int64          `json:"aux_requests"` // compaction/title/review/auxiliary steps of this node
	Usage          UsageTotals    `json:"usage"`
	LastEstimate   CategoryValues `json:"last_composition"`
	LastPrompt     *int64         `json:"last_prompt_total"`
	ContextWindow  *int64         `json:"context_window"`
	LinkSource     string         `json:"link_source,omitempty"`
	LinkConfidence int            `json:"link_confidence,omitempty"`
}

// TreeResponse is GET /api/v1/insights/agent-trees/{tree_id}. At most 40 nodes.
type TreeResponse struct {
	TreeID       string            `json:"tree_id"`
	Truncated    bool              `json:"truncated"`
	Nodes        []TreeNode        `json:"nodes"`
	ClientLabels map[string]string `json:"client_labels,omitempty"` // see OverviewResponse
}

// CompositionResponse is GET /api/v1/audits/{audit_id}/composition.
type CompositionResponse struct {
	AuditID         string            `json:"audit_id"`
	AnalysisVersion int               `json:"analysis_version"`
	Model           string            `json:"model"`
	Usage           Usage             `json:"usage"`
	PromptTotal     *int64            `json:"prompt_total"`
	Estimate        CategoryValues    `json:"estimate"`
	Anchored        *CategoryValues   `json:"anchored"` // estimate scaled to prompt_total; nil without usage
	ContextWindow   *int64            `json:"context_window"`
	Items           []CompositionItem `json:"items"`
	Tools           []ToolDef         `json:"tools"`
	FileOps         []FileOp          `json:"file_ops"`
	Agent           AgentIdentity     `json:"agent"`
	PreviousAuditID string            `json:"previous_audit_id,omitempty"`
	Diff            *CompositionDiff  `json:"diff"`
	Events          []string          `json:"events"`
	Truncated       bool              `json:"truncated"`
	ClientLabels    map[string]string `json:"client_labels,omitempty"` // see OverviewResponse
}

// CompositionItem is Item plus its relation to the previous step.
type CompositionItem struct {
	Item
	Change string `json:"change,omitempty"` // added | kept; empty without a previous step
}

// CompositionDiff compares this step with the previous step of its session.
type CompositionDiff struct {
	AddedItems   int64          `json:"added_items"`
	RemovedItems int64          `json:"removed_items"`
	ByCategory   CategoryValues `json:"by_category"` // signed estimate delta
}
