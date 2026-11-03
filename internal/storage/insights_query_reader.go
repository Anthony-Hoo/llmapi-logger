package storage

const

// Insights usage groupings.

InsightsDimTotal = "total"

// Insights usage groupings.

const InsightsDimDay = "day"

// Insights usage groupings.

const InsightsDimModel = "model"

// Insights usage groupings.

const InsightsDimProtocol = "protocol"

// Insights usage groupings.

const InsightsDimClient = "client"

// Insights usage groupings.

const InsightsDimCaller = "caller"

// Insights usage groupings.

const InsightsDimToken = "token"

// Insights usage groupings.

const InsightsDimSession = "session"

// Insights usage groupings.

const InsightsDimNode = "node"

const

// Session list orderings.

InsightsSortRecent = "recent"

// Session list orderings.

const InsightsSortTokens = "tokens"

// Session list orderings.

const InsightsSortContext = "context"

// InsightsFilter selects analysis rows. FromNS is inclusive and ToNS exclusive;
// a zero ToNS disables the time condition (single session and tree reads).
type InsightsFilter struct {
	FromNS int64
	ToNS   int64
	Scope  *AuditScope
	// SessionIDs restricts to these analysis sessions.
	SessionIDs []string
	// RootPrefix restricts to agent trees whose root fingerprint starts with it.
	RootPrefix []byte
	// RootFPRs restricts to these full agent root fingerprints.
	RootFPRs [][]byte
}

// InsightsUsageSpec chooses the grouping of InsightsUsage.
type InsightsUsageSpec struct {
	Dimension   string
	TZOffsetMin int
}

// InsightsMix is the per-category sum of estimates, each row anchored to its own
// reported prompt total when usage exists (raw estimate otherwise).
type InsightsMix struct {
	System, Tools, User, Injected, Assistant, Reasoning, ToolResult, Media float64
}

// InsightsEstimate is one request's raw composition estimate.
type InsightsEstimate struct {
	System, Tools, User, Injected, Assistant, Reasoning, ToolResult, Media int64
}

// InsightsUsageRow is one group aggregate.
type InsightsUsageRow struct {
	Key, Label string
	Requests   int64
	// BilledRequests counts the requests whose token link carries NewAPI's
	// actual billing; CostUSD sums their quota / quota_per_unit and is nil
	// when there is none (doc/features/21-newapi-billing.md).
	BilledRequests int64
	CostUSD        *float64
	UncachedInput  int64
	CacheRead      int64
	CacheWrite     int64
	Output         int64
	Reasoning      int64
	Mix            InsightsMix
}

// InsightsDayCount is the activity of one local calendar day.
type InsightsDayCount struct {
	Day      string
	Requests int64
	Sessions int64
}

// InsightsSessionCursor is the keyset position after the last returned card.
type InsightsSessionCursor struct {
	Value     int64
	SessionID string
}

// InsightsSessionRow is one session aggregate plus the values of its last step.
type InsightsSessionRow struct {
	SessionID  string
	FirstNS    int64
	LastNS     int64
	Steps      int64
	Turns      int64
	Tokens     int64
	SortValue  int64
	Protocol   string
	Model      string
	Client     string
	Role       string
	Link       string
	Root       []byte
	Username   string
	TokenName  string
	LastPrompt *int64
	Estimate   InsightsEstimate
}

// InsightsSessionPage is one keyset page of session cards.
type InsightsSessionPage struct {
	Rows    []InsightsSessionRow
	HasMore bool
}

// InsightsTrendRow is one request of a session trend.
type InsightsTrendRow struct {
	AuditID       string
	StartedAtNS   int64
	EndedAtNS     *int64
	Protocol      string
	Model         string
	Role          string
	Root          []byte
	Estimate      InsightsEstimate
	UncachedInput *int64
	CacheRead     *int64
	CacheWrite    *int64
	Output        *int64
	Reasoning     *int64
	TurnStart     bool
	EventFlags    int
	AppendedItems *int64
	RemovedItems  *int64
	StopReason    string
	RespKinds     int
	FirstEventNS  *int64
	GenerationNS  *int64
	PrevAuditID   string
	// CostUSD is this request's actual NewAPI cost, nil unless billed.
	CostUSD *float64
}

// InsightsTreeNodeRow is one agent of a tree. Steps excludes auxiliary
// requests, which are counted in AuxRequests; the last-step values, including
// LastAuditID, come from the node's latest non-auxiliary request when it has
// one.
type InsightsTreeNodeRow struct {
	NodeFPR        []byte
	ParentFPR      []byte
	FirstNS        int64
	LastNS         int64
	Steps          int64
	AuxRequests    int64
	Role           string
	Client         string
	Model          string
	SessionID      string
	LinkSource     string
	LinkConfidence int
	LastAuditID    string
	LastPrompt     *int64
	Estimate       InsightsEstimate
}
