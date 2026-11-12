package storage

import "encoding/binary"

// Session analysis (doc/features/24-session-analysis.md) storage contracts.
// Every row described here is derived data outside the integrity chain.

// SessionCandidate is the part of one agent-tree root that one API key sent,
// with recent activity, together with what the last analysis of it saw. Two
// keys reusing one client session id are two analysis sessions, so a key
// never sees content derived from another key's requests. It is due when it
// has gone quiet and either has never been analysed or has gained requests
// since.
type SessionCandidate struct {
	AgentRootFPR []byte
	// APIKeyFPR is nil for requests without a key fingerprint; they form
	// their own session.
	APIKeyFPR     []byte
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
	// SessionKey is the keyed fingerprint of (AgentRootFPR, APIKeyFPR).
	SessionKey   []byte
	AgentRootFPR []byte
	// DigestBucket is set for single-turn chats only: the keyed fingerprint
	// of their chat digest bucket. DigestPending (read only) reports that the
	// bucket's digest packs have not been rebuilt with this session yet.
	DigestBucket     []byte
	DigestPending    bool
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
	// ProjectID and Bucket book the session to a project of the organisation
	// reports (doc 23). Both are empty when org reports are off or the project
	// identity of its requests has not been extracted yet.
	ProjectID *int64
	Bucket    string
	// Read-only: the plaintext enums of the session's own facet, if any.
	FacetStatus   string
	FacetTaskType string
	FacetOutcome  string
}

// Session buckets (doc 24 section 11).
const (
	BucketAttributed   = "attributed"
	BucketUnattributed = "unattributed"
	BucketNoContext    = "no_context"
	BucketService      = "service"
)

// SessionProjectRef is the stored booking of one analysis session.
type SessionProjectRef struct {
	SessionKey   []byte
	AgentRootFPR []byte
	APIKeyFPR    []byte
	ProjectID    *int64
	Bucket       string
}

// Pack kinds.
const (
	PackKindSession    = "session"
	PackKindChatDigest = "chat_digest"
)

// ChatDigestBucket selects the single-turn chats of one API key (nil: none),
// client and local day [FromNS, ToNS), by their last request.
type ChatDigestBucket struct {
	APIKeyFPR []byte
	Client    string
	FromNS    int64
	ToNS      int64
}

// ChatDigestChunk is one chat digest pack and the sessions it holds.
type ChatDigestChunk struct {
	Pack    SessionPack
	Members [][]byte
}

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
	L1Candidates  int64
	L1OK          int64
	L1Invalid     int64
	L1Failed      int64
	L1InputTokens int64
	L1OutputToks  int64
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
	// ExcludeService drops sessions of service principals (reports).
	ExcludeService bool
	// ProjectID keeps the sessions booked to one project; UserIDs (non-nil)
	// keeps the sessions of those NewAPI users, none when empty.
	ProjectID *int64
	UserIDs   []int64
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
	// Contributors counts the distinct callers (NewAPI user, else API key).
	Contributors int64
}

// FacetRetryLimit is how many later runs ask the model again for a pack whose
// facet attempt failed. With the first attempt, one pack text is sent at most
// FacetRetryLimit+1 times per prompt version and model; after that the failed
// row stays until the pack, the prompt version or the model changes.
const FacetRetryLimit = 3

// SessionFacet is one row of session_facets. TextEnc is AES-GCM ciphertext
// of the facet's free text and evidence; the enum columns are plaintext.
type SessionFacet struct {
	SessionKey    []byte
	Kind          string
	APIKeyFPR     []byte
	NewAPITokenID *int64
	LastNS        int64
	PackHash      string
	PromptVersion string
	Model         string
	Status        string
	TaskType      string
	Outcome       string
	Collaboration string
	WorkRelevance string
	Friction      string
	Items         string
	InvalidFields string
	TextEnc       []byte
	InputTokens   int64
	OutputTokens  int64
	LatencyMS     int64
	Attempts      int64
	CreatedAtNS   int64
}

// FacetCalibration is one row of facet_calibrations.
type FacetCalibration struct {
	ID            int64
	CreatedAtNS   int64
	PromptVersion string
	Model         string
	Samples       int64
	Agreement     string
}

// Analysis scopes of suggestions and weekly statistics. Project and group
// scopes exist only with organisation reports.
const (
	ScopePerson  = "person"
	ScopeAll     = "all"
	ScopeProject = "project"
	ScopeGroup   = "group"
	// ScopeUser is one NewAPI user across all of that user's API keys; its
	// scope_key is IDScopeKey(user id). Administrators read it.
	ScopeUser = "user"
)

// AllScopeKey is the scope_key of the 'all' scope.
var AllScopeKey = make([]byte, 32)

// IDScopeKey is the scope_key of a project or group scope: the id as 8
// big-endian bytes after 24 zero bytes.
func IDScopeKey(id int64) []byte {
	key := make([]byte, 32)
	binary.BigEndian.PutUint64(key[24:], uint64(id))
	return key
}

// IDOfScopeKey is the inverse of IDScopeKey; ok is false for any other key.
func IDOfScopeKey(key []byte) (id int64, ok bool) {
	if len(key) != 32 {
		return 0, false
	}
	for _, value := range key[:24] {
		if value != 0 {
			return 0, false
		}
	}
	id = int64(binary.BigEndian.Uint64(key[24:]))
	return id, id > 0
}

// FacetScope selects the facets one report scope aggregates: every facet
// (zero value), one API key's, one project's, or those of a set of users.
// Project and user scopes read session facets only; a chat digest spans
// sessions and has neither.
type FacetScope struct {
	APIKeyFPR []byte
	ProjectID *int64
	UserIDs   []int64
	// UserID selects one NewAPI user: the facets of that user's sessions, and
	// the chat digests and sentence fingerprints of that user's API keys (a
	// digest spans sessions, so it is matched through its key).
	UserID *int64
}

// SessionUserTotals is the totals of the sessions of one NewAPI user. UserID
// is nil for the sessions whose caller was not resolved.
type SessionUserTotals struct {
	UserID *int64
	LastNS int64
	Totals SessionSignalTotals
}

// ScopeKey identifies one API key that was active in a period.
type ScopeKey struct {
	APIKeyFPR     []byte
	NewAPITokenID *int64
}

// FacetEnumRow is the plaintext part of one ok facet, for aggregation.
type FacetEnumRow struct {
	Kind          string
	TaskType      string
	Outcome       string
	Collaboration string
	Friction      string
	Items         string
}

// RepeatedFPR is one sentence fingerprint seen in several sessions.
type RepeatedFPR struct {
	FPR         []byte
	Kind        string // instruction | skill
	Sessions    int64
	FirstNS     int64
	LastNS      int64
	SessionKeys [][]byte
	Adopted     bool
}

// Suggestion is one row of analysis_suggestions.
type Suggestion struct {
	ID            int64
	Scope         string
	ScopeKey      []byte
	NewAPITokenID *int64
	Kind          string
	FPR           []byte
	Support       int64
	FirstSeenNS   int64
	LastSeenNS    int64
	Status        string
	TextEnc       []byte
	Evidence      string
	UpdatedAtNS   int64
}

// PeriodStats is one row of analysis_period_stats.
type PeriodStats struct {
	WeekStartNS     int64
	Scope           string
	ScopeKey        []byte
	NewAPITokenID   *int64
	Stats           string
	NarrativeEnc    []byte
	NarrativeSource string
	InputHash       string
	ComputedAtNS    int64
}
