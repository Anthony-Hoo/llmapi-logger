package storage

// AnalysisFingerprintSize is the length of every keyed fingerprint stored in
// audit_analysis and agent_spawn_hints.
const AnalysisFingerprintSize = 32

// AnalysisRow mirrors one audit_analysis row plus the audit's spawn hint
// fingerprints. It is derived data outside the integrity chain: every value is
// recomputable from captured evidence, and plaintext fields carry only numbers,
// enums, count objects and keyed fingerprints. DetailEnc must already be
// encrypted by the caller.
type AnalysisRow struct {
	AuditID         string
	AnalysisVersion int
	AnalyzedAtNS    int64
	Protocol        string
	Model           *string
	StartedAtNS     int64

	UncachedInput   *int64
	CacheRead       *int64
	CacheWrite      *int64
	Output          *int64
	Reasoning       *int64
	MaxOutputTokens *int64

	EstSystem     int64
	EstTools      int64
	EstUser       int64
	EstInjected   int64
	EstAssistant  int64
	EstReasoning  int64
	EstToolResult int64
	EstMedia      int64
	Items         int
	ToolDefs      int
	ToolResults   int
	Media         int

	StopReason     *string
	RespKinds      int
	RespToolCalls  int
	ToolKindCounts string // compact JSON object of counts; empty stores "{}"

	AnalysisSessionID *string
	SessionLink       *string
	PrevAuditID       *string
	TurnStart         bool
	AppendedItems     *int
	RemovedItems      *int
	EventFlags        int
	SystemFPR         []byte
	ToolsFPR          []byte

	FirstEventNS *int64
	GenerationNS *int64

	AgentClient         *string
	AgentRole           *string
	AgentNodeFPR        []byte
	AgentParentFPR      []byte
	AgentRootFPR        []byte
	AgentLinkSource     *string
	AgentLinkConfidence *int

	DetailEnc []byte

	// SpawnHints replaces the audit's agent_spawn_hints rows. Duplicates are
	// stored once; LoadAnalysis returns them in byte order.
	SpawnHints [][]byte
}
