package insights

// JSON contract of the insights management API (doc/features/20-context-insights.md §7).
// The web frontend mirrors these shapes in src/types.ts. All token fields are
// integers; nullable numbers mean "not reported" or "unknown price".

// UsageTotals aggregates normalized usage over many requests.
type UsageTotals struct {
	Requests         int64    `json:"requests"`
	UncachedInput    int64    `json:"uncached_input"`
	CacheRead        int64    `json:"cache_read"`
	CacheWrite       int64    `json:"cache_write"`
	Output           int64    `json:"output"`
	Reasoning        int64    `json:"reasoning"`
	PromptTotal      int64    `json:"prompt_total"`
	CacheHitRate     *float64 `json:"cache_hit_rate"`     // nil when prompt_total is 0
	EstimatedCostUSD *float64 `json:"estimated_cost_usd"` // nil when nothing was priced
	UnpricedRequests int64    `json:"unpriced_requests"`
}

// OverviewResponse is GET /api/v1/insights/overview.
type OverviewResponse struct {
	FromNS   int64          `json:"from_ns"`
	ToNS     int64          `json:"to_ns"`
	Totals   UsageTotals    `json:"totals"`
	Sessions int64          `json:"sessions"`
	Trees    int64          `json:"trees"`
	Daily    []DailyUsage   `json:"daily"`
	Heatmap  []HeatmapDay   `json:"heatmap"`
	GroupBy  string         `json:"group_by"`
	Groups   []GroupUsage   `json:"groups"`
	Mix      CategoryValues `json:"composition"` // summed estimates anchored to prompt totals
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
	FirstNS       int64          `json:"first_ns"`
	LastNS        int64          `json:"last_ns"`
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
	Items      []SessionCard `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// TrendStep is one request of a session trend.
type TrendStep struct {
	AuditID       string         `json:"audit_id"`
	StartedAtNS   int64          `json:"started_at_ns"`
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
	CostUSD       *float64       `json:"cost_usd"`
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
	NodeID         string         `json:"node_id"` // hex fingerprint prefix
	ParentNodeID   string         `json:"parent_node_id,omitempty"`
	Visible        bool           `json:"visible"` // false: placeholder for an out-of-scope parent
	SessionID      string         `json:"session_id,omitempty"`
	Client         string         `json:"client"`
	Role           string         `json:"role"`
	FirstNS        int64          `json:"first_ns"`
	LastNS         int64          `json:"last_ns"`
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
	TreeID    string     `json:"tree_id"`
	Truncated bool       `json:"truncated"`
	Nodes     []TreeNode `json:"nodes"`
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
