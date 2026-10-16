package sqlite

import (
	"encoding/json"
	"errors"
)

// AnalysisFingerprintSize is the length of every keyed fingerprint stored in
// audit_analysis and agent_spawn_hints.
const AnalysisFingerprintSize = 32

var errInvalidAnalysis = errors.New("sqlite: invalid audit analysis")

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

// Enum columns are also guarded by CHECK constraints; validating here keeps
// a bad analyzer value a clean caller error instead of a rolled-back write.
func validateAnalysisRow(row AnalysisRow) error {
	if row.AuditID == "" || row.AnalysisVersion <= 0 || row.AnalyzedAtNS <= 0 || row.Protocol == "" || row.StartedAtNS <= 0 {
		return errInvalidAnalysis
	}
	for _, value := range []*int64{row.UncachedInput, row.CacheRead, row.CacheWrite, row.Output, row.Reasoning} {
		if invalidOptionalInt64(value) {
			return errInvalidAnalysis
		}
	}
	for _, value := range []int64{row.EstSystem, row.EstTools, row.EstUser, row.EstInjected,
		row.EstAssistant, row.EstReasoning, row.EstToolResult, row.EstMedia} {
		if value < 0 {
			return errInvalidAnalysis
		}
	}
	if row.Items < 0 || row.ToolDefs < 0 || row.ToolResults < 0 || row.Media < 0 ||
		row.RespKinds < 0 || row.RespToolCalls < 0 || row.EventFlags < 0 ||
		invalidOptionalInt(row.AppendedItems) || invalidOptionalInt(row.RemovedItems) {
		return errInvalidAnalysis
	}
	if !optionalEnum(row.StopReason, "end_turn", "tool_use", "length", "content_filter", "other") ||
		!optionalEnum(row.SessionLink, "agent", "conversation", "explicit", "inferred", "root") ||
		!optionalEnum(row.AgentRole, "main", "subagent", "compaction", "title", "review", "auxiliary") ||
		!optionalEnum(row.AgentLinkSource, "header", "body", "content") {
		return errInvalidAnalysis
	}
	if row.AgentLinkConfidence != nil && (*row.AgentLinkConfidence < 0 || *row.AgentLinkConfidence > 100) {
		return errInvalidAnalysis
	}
	for _, fingerprint := range [][]byte{row.SystemFPR, row.ToolsFPR, row.AgentNodeFPR, row.AgentParentFPR, row.AgentRootFPR} {
		if len(fingerprint) != 0 && len(fingerprint) != AnalysisFingerprintSize {
			return errInvalidAnalysis
		}
	}
	for _, hint := range row.SpawnHints {
		if len(hint) != AnalysisFingerprintSize {
			return errInvalidAnalysis
		}
	}
	if row.ToolKindCounts != "" {
		var counts map[string]int64
		if err := json.Unmarshal([]byte(row.ToolKindCounts), &counts); err != nil || counts == nil {
			return errInvalidAnalysis
		}
	}
	return nil
}

func optionalEnum(value *string, allowed ...string) bool {
	if value == nil {
		return true
	}
	for _, candidate := range allowed {
		if *value == candidate {
			return true
		}
	}
	return false
}

func cloneAnalysisRow(row AnalysisRow) AnalysisRow {
	row.Model = cloneString(row.Model)
	row.UncachedInput = cloneInt64(row.UncachedInput)
	row.CacheRead = cloneInt64(row.CacheRead)
	row.CacheWrite = cloneInt64(row.CacheWrite)
	row.Output = cloneInt64(row.Output)
	row.Reasoning = cloneInt64(row.Reasoning)
	row.MaxOutputTokens = cloneInt64(row.MaxOutputTokens)
	row.StopReason = cloneString(row.StopReason)
	row.AnalysisSessionID = cloneString(row.AnalysisSessionID)
	row.SessionLink = cloneString(row.SessionLink)
	row.PrevAuditID = cloneString(row.PrevAuditID)
	row.AppendedItems = cloneInt(row.AppendedItems)
	row.RemovedItems = cloneInt(row.RemovedItems)
	row.SystemFPR = cloneBytes(row.SystemFPR)
	row.ToolsFPR = cloneBytes(row.ToolsFPR)
	row.FirstEventNS = cloneInt64(row.FirstEventNS)
	row.GenerationNS = cloneInt64(row.GenerationNS)
	row.AgentClient = cloneString(row.AgentClient)
	row.AgentRole = cloneString(row.AgentRole)
	row.AgentNodeFPR = cloneBytes(row.AgentNodeFPR)
	row.AgentParentFPR = cloneBytes(row.AgentParentFPR)
	row.AgentRootFPR = cloneBytes(row.AgentRootFPR)
	row.AgentLinkSource = cloneString(row.AgentLinkSource)
	row.AgentLinkConfidence = cloneInt(row.AgentLinkConfidence)
	row.DetailEnc = cloneBytes(row.DetailEnc)
	if row.SpawnHints != nil {
		hints := make([][]byte, len(row.SpawnHints))
		for index, hint := range row.SpawnHints {
			hints[index] = cloneBytes(hint)
		}
		row.SpawnHints = hints
	}
	return row
}
