package storage

// Session analysis (doc/features/24-session-analysis.md) storage contracts.
// Every row described here is derived data outside the integrity chain.

// SessionCandidate is one agent-tree root with recent activity, together with
// what the last analysis of it saw. A root is due when it has gone quiet and
// either has never been analysed or has gained requests since.
type SessionCandidate struct {
	SessionKey    []byte
	LastStartedNS int64
	Requests      int64
	// AnalyzedLastNS is the last_ns of the stored signals row, 0 when none.
	AnalyzedLastNS   int64
	AnalyzedRequests int64
}

// SessionAuditRow is the plaintext projection of one request of a session:
// audit_records, audit_analysis, token_links and parsed_results columns only.
// Locally rejected requests are never returned.
type SessionAuditRow struct {
	AuditID           string
	StartedAtNS       int64
	EndedAtNS         *int64
	StatusCode        *int64
	APIKeyFPR         []byte
	Model             string
	Protocol          string
	UncachedInput     *int64
	CacheRead         *int64
	CacheWrite        *int64
	Output            *int64
	TurnStart         bool
	EventFlags        int
	StopReason        string
	RespToolCalls     int64
	ToolKindCounts    string
	AnalysisSessionID string
	AgentClient       string
	AgentRole         string
	AgentNodeFPR      []byte
	AgentParentFPR    []byte
	NewAPIUserID      *int64
	NewAPITokenID     *int64
	Quota             *int64
	QuotaPerUnit      *float64
	ErrorType         string
	UpstreamErrorCls  string
}

// SessionSignals is one row of session_signals.
type SessionSignals struct {
	SessionKey       []byte
	Kind             string
	APIKeyFPR        []byte
	NewAPIUserID     *int64
	NewAPITokenID    *int64
	Client           string
	MainSessionID    string
	MainModel        string
	FirstNS          int64
	LastNS           int64
	LastAuditID      string
	Requests         int64
	MainRequests     int64
	SubRequests      int64
	AuxRequests      int64
	Subagents        int64
	MaxDepth         int64
	UserTurns        int64
	ActiveNS         int64
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CostUSD          *float64
	Compactions      int64
	ModelSwitches    int64
	LengthStops      int64
	UpstreamErrors   int64
	ToolCalls        int64
	ToolFailures     int64
	ToolUnknown      int64
	MaxFailureStreak int64
	Loops            int64
	MaxLoopLength    int64
	ThrashFiles      int64
	MaxFileWrites    int64
	Verified         string
	ErrorPastes      int64
	Interrupts       int64
	Corrections      int64
	HeavyModel       bool
	DangerCounts     string
	SecretCounts     string
	Eligible         bool
	SkipReason       string
	SignalVersion    int64
	ComputedAtNS     int64
}

// Pack kinds.
const (
	PackKindSession    = "session"
	PackKindChatDigest = "chat_digest"
)

// SessionPack is one row of session_packs. PackEnc is AES-GCM ciphertext.
type SessionPack struct {
	SessionKey    []byte
	Kind          string
	APIKeyFPR     []byte
	NewAPITokenID *int64
	Client        string
	PackHash      string
	PackEnc       []byte
	RefMap        string
	TokenEstimate int64
	Truncated     bool
	Members       int64
	FirstNS       int64
	LastNS        int64
	LastAuditID   string
	BuiltAtNS     int64
}

// AnalysisView is one row of the append-only analysis_view_log.
type AnalysisView struct {
	AtNS          int64
	ViewerRole    string
	ViewerUserID  *int64
	ViewerTokenID *int64
	Resource      string
	SessionKey    []byte
}

// SessionTextFPR is one keyed sentence fingerprint of a session.
type SessionTextFPR struct {
	Source    string
	FPR       []byte
	APIKeyFPR []byte
	SeenAtNS  int64
}

// SessionTextFPR sources.
const (
	TextSourceUser             = "user_text"
	TextSourceInjectedRules    = "injected_rules"
	TextSourceFacetInstruction = "facet_instruction"
	TextSourceFacetSkill       = "facet_skill"
)

// SessionAnalysisRun is one row of session_analysis_runs.
type SessionAnalysisRun struct {
	ID            int64
	StartedAtNS   int64
	FinishedAtNS  int64
	Trigger       string
	Candidates    int64
	Analyzed      int64
	Skipped       int64
	SkipReasons   string
	Pruned        int64
	ErrorCategory string
}

// SessionSignalFilter selects session_signals rows for the management API.
// FromNS is inclusive, ToNS exclusive, both on last_ns. A nil Scope reads every
// session (administrator).
type SessionSignalFilter struct {
	FromNS     int64
	ToNS       int64
	Scope      *AuditScope
	Kind       string
	SessionKey []byte
	// Flags keeps only sessions with every listed signal: loop, thrash,
	// unverified, failures, corrections, heavy_model, danger, secret.
	Flags []string
}

// SessionSignalCursor is the keyset position after the last returned row.
type SessionSignalCursor struct {
	BeforeLastNS int64
	BeforeKey    []byte
}

// SessionSignalPage is one keyset page.
type SessionSignalPage struct {
	Rows    []SessionSignals
	HasMore bool
}

// SessionSignalTotals aggregates a set of sessions for the period view.
type SessionSignalTotals struct {
	Sessions        int64
	AgentSessions   int64
	ChatSessions    int64
	Eligible        int64
	CostUSD         float64
	BilledSessions  int64
	LoopSessions    int64
	LoopCostUSD     float64
	ThrashSessions  int64
	Unverified      int64
	WithWrites      int64
	FailureSessions int64
	Corrections     int64
	CorrectionSess  int64
	ErrorPasteSess  int64
	InterruptSess   int64
	HeavyModelSess  int64
	DangerSessions  int64
	SecretSessions  int64
	CompactionSess  int64
	InputTokens     int64
	CacheReadTokens int64
}
