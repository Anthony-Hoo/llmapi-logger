package storage

// AnalysisAuditMeta is the audit-level context the analyzer needs beyond the
// parser input. Event times are absolute; ConversationID is the OpenAI turn
// graph conversation of this audit, when one was written.
type AnalysisAuditMeta struct {
	AuditID        string
	StartedAtNS    int64
	EndedAtNS      *int64
	APIKeyFPR      []byte
	FirstEventAtNS *int64
	LastEventAtNS  *int64
	ConversationID *string
}

// AnalysisLinkCandidate is one earlier analysis row of a session, with the
// fields the linker compares against. DetailEnc is still encrypted under the
// row's own analysis_version.
type AnalysisLinkCandidate struct {
	AuditID             string
	AnalysisVersion     int
	StartedAtNS         int64
	Model               *string
	SystemFPR           []byte
	ToolsFPR            []byte
	EstimateTotal       int64
	AgentRole           *string
	AgentNodeFPR        []byte
	AgentParentFPR      []byte
	AgentRootFPR        []byte
	AgentLinkSource     *string
	AgentLinkConfidence *int
	DetailEnc           []byte
}

// SpawnHintMatch is one stored spawn hint that matched a child's opening text,
// with the analysis row of the audit that produced it.
type SpawnHintMatch struct {
	AuditID           string
	HintFPR           []byte
	AgentNodeFPR      []byte
	AgentRootFPR      []byte
	AnalysisSessionID *string
}
