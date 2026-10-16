package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Read queries used by the insights linker while it derives one audit's
// analysis row. They read only plaintext index columns and still-encrypted
// detail blobs; decryption stays with the caller.

const (
	maxAnalysisLinkCandidates = 64
	maxSpawnHintQueryFPRs     = 32
	maxSpawnHintMatches       = 64
)

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

// LoadAnalysisAuditMeta reads the timestamps, api_key_fpr, response stream
// timeline bounds and OpenAI conversation of one audit from one snapshot.
func (store *Store) LoadAnalysisAuditMeta(ctx context.Context, auditID string) (AnalysisAuditMeta, error) {
	if ctx == nil {
		return AnalysisAuditMeta{}, errors.New("sqlite: nil context")
	}
	if auditID == "" {
		return AnalysisAuditMeta{}, errors.New("sqlite: empty audit id")
	}
	if store == nil || store.isClosed() {
		return AnalysisAuditMeta{}, ErrClosed
	}
	var meta AnalysisAuditMeta
	var ended, first, last sql.NullInt64
	var conversation sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT r.audit_id, r.started_at_ns, r.ended_at_ns, r.api_key_fpr,
       t.first_event_at_ns, t.last_event_at_ns, g.conversation_id
FROM audit_records AS r
LEFT JOIN body_streams AS b
  ON b.audit_id = r.audit_id AND b.stage = ?
LEFT JOIN stream_timelines AS t
  ON t.audit_id = b.audit_id AND t.stage = b.source_stage
LEFT JOIN turns AS g
  ON g.audit_id = r.audit_id
WHERE r.audit_id = ?`, StageResponseReceived, auditID).Scan(
		&meta.AuditID, &meta.StartedAtNS, &ended, &meta.APIKeyFPR, &first, &last, &conversation,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AnalysisAuditMeta{}, fmt.Errorf("sqlite: load analysis audit: %w", sql.ErrNoRows)
		}
		return AnalysisAuditMeta{}, fmt.Errorf("sqlite: load analysis audit: %w", err)
	}
	meta.APIKeyFPR = cloneBytes(meta.APIKeyFPR)
	meta.EndedAtNS = nullInt64Pointer(ended)
	meta.FirstEventAtNS = nullInt64Pointer(first)
	meta.LastEventAtNS = nullInt64Pointer(last)
	meta.ConversationID = nullStringPointer(conversation)
	return meta, nil
}

// LatestAgentRootFPR returns the agent_root_fpr of the most recent analysis
// row, other than excludeAuditID, whose node is nodeFPR. It returns nil when
// the node has no analysed request yet or its latest row has no root.
func (store *Store) LatestAgentRootFPR(ctx context.Context, nodeFPR []byte, excludeAuditID string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if len(nodeFPR) != AnalysisFingerprintSize {
		return nil, errors.New("sqlite: invalid agent node fingerprint")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	var root []byte
	err := store.readerDB.QueryRowContext(ctx, `
SELECT agent_root_fpr
FROM audit_analysis
WHERE agent_node_fpr = ? AND audit_id <> ?
ORDER BY started_at_ns DESC, audit_id DESC
LIMIT 1`, nodeFPR, excludeAuditID).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: load agent root: %w", err)
	}
	return cloneBytes(root), nil
}

// HasEarlierAnalysisStep reports whether the session already has an analysis
// row of any role ordered before (startedAtNS, auditID).
func (store *Store) HasEarlierAnalysisStep(ctx context.Context, sessionID string, startedAtNS int64, auditID string) (bool, error) {
	if ctx == nil {
		return false, errors.New("sqlite: nil context")
	}
	if sessionID == "" {
		return false, errors.New("sqlite: empty analysis session id")
	}
	if store == nil || store.isClosed() {
		return false, ErrClosed
	}
	var exists int
	err := store.readerDB.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM audit_analysis
    WHERE analysis_session_id = ?
      AND (started_at_ns < ? OR (started_at_ns = ? AND audit_id < ?))
)`, sessionID, startedAtNS, startedAtNS, auditID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("sqlite: check earlier analysis step: %w", err)
	}
	return exists != 0, nil
}

// ListAnalysisPrevCandidates returns up to limit earlier rows of the session,
// newest first, ordered before (startedAtNS, auditID). Auxiliary steps
// (compaction, title, review, auxiliary) are never candidates: they link to a
// previous step themselves but must not become the previous step of the main
// line.
func (store *Store) ListAnalysisPrevCandidates(ctx context.Context, sessionID string, startedAtNS int64, auditID string, limit int) ([]AnalysisLinkCandidate, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if sessionID == "" || limit <= 0 || limit > maxAnalysisLinkCandidates {
		return nil, errors.New("sqlite: invalid analysis candidate query")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, analysis_version, started_at_ns, model, system_fpr, tools_fpr,
       est_system + est_tools + est_user + est_injected + est_assistant +
       est_reasoning + est_tool_result + est_media,
       agent_role, agent_node_fpr, agent_parent_fpr, agent_root_fpr,
       agent_link_source, agent_link_confidence, detail_enc
FROM audit_analysis
WHERE analysis_session_id = ?
  AND (started_at_ns < ? OR (started_at_ns = ? AND audit_id < ?))
  AND (agent_role IS NULL OR agent_role IN ('main', 'subagent'))
ORDER BY started_at_ns DESC, audit_id DESC
LIMIT ?`, sessionID, startedAtNS, startedAtNS, auditID, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list analysis candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]AnalysisLinkCandidate, 0, limit)
	for rows.Next() {
		var candidate AnalysisLinkCandidate
		var model, role, linkSource sql.NullString
		var confidence sql.NullInt64
		if err := rows.Scan(
			&candidate.AuditID, &candidate.AnalysisVersion, &candidate.StartedAtNS, &model,
			&candidate.SystemFPR, &candidate.ToolsFPR, &candidate.EstimateTotal,
			&role, &candidate.AgentNodeFPR, &candidate.AgentParentFPR, &candidate.AgentRootFPR,
			&linkSource, &confidence, &candidate.DetailEnc,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan analysis candidate: %w", err)
		}
		candidate.Model = nullStringPointer(model)
		candidate.AgentRole = nullStringPointer(role)
		candidate.AgentLinkSource = nullStringPointer(linkSource)
		candidate.AgentLinkConfidence = nullIntPointer(confidence)
		candidate.SystemFPR = cloneBytes(candidate.SystemFPR)
		candidate.ToolsFPR = cloneBytes(candidate.ToolsFPR)
		candidate.AgentNodeFPR = cloneBytes(candidate.AgentNodeFPR)
		candidate.AgentParentFPR = cloneBytes(candidate.AgentParentFPR)
		candidate.AgentRootFPR = cloneBytes(candidate.AgentRootFPR)
		candidate.DetailEnc = cloneBytes(candidate.DetailEnc)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate analysis candidates: %w", err)
	}
	return candidates, nil
}

// MatchSpawnHints returns the spawn hints among hintFPRs recorded in
// [fromNS, toNS] by other audits of the same api_key_fpr. A nil or malformed
// api key fingerprint matches nothing: content matching never links across
// keys or to audits without a key.
func (store *Store) MatchSpawnHints(ctx context.Context, hintFPRs [][]byte, apiKeyFPR []byte, fromNS, toNS int64, excludeAuditID string) ([]SpawnHintMatch, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if len(apiKeyFPR) != AnalysisFingerprintSize || len(hintFPRs) == 0 || fromNS > toNS {
		return []SpawnHintMatch{}, nil
	}
	if len(hintFPRs) > maxSpawnHintQueryFPRs {
		return nil, fmt.Errorf("sqlite: spawn hint query exceeds %d fingerprints", maxSpawnHintQueryFPRs)
	}
	arguments := make([]any, 0, len(hintFPRs)+5)
	for _, hint := range hintFPRs {
		if len(hint) != AnalysisFingerprintSize {
			return nil, errors.New("sqlite: invalid spawn hint fingerprint")
		}
		arguments = append(arguments, hint)
	}
	arguments = append(arguments, fromNS, toNS, apiKeyFPR, excludeAuditID, maxSpawnHintMatches)
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT h.audit_id, h.hint_fpr, a.agent_node_fpr, a.agent_root_fpr, a.analysis_session_id
FROM agent_spawn_hints AS h
JOIN audit_records AS r ON r.audit_id = h.audit_id
JOIN audit_analysis AS a ON a.audit_id = h.audit_id
WHERE h.hint_fpr IN (`+placeholders(len(hintFPRs))+`)
  AND h.created_at_ns BETWEEN ? AND ?
  AND r.api_key_fpr IS NOT NULL AND r.api_key_fpr = ?
  AND h.audit_id <> ?
ORDER BY h.created_at_ns DESC, h.audit_id
LIMIT ?`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: match spawn hints: %w", err)
	}
	defer rows.Close()
	matches := make([]SpawnHintMatch, 0)
	for rows.Next() {
		var match SpawnHintMatch
		var sessionID sql.NullString
		if err := rows.Scan(&match.AuditID, &match.HintFPR, &match.AgentNodeFPR, &match.AgentRootFPR, &sessionID); err != nil {
			return nil, fmt.Errorf("sqlite: scan spawn hint match: %w", err)
		}
		match.HintFPR = cloneBytes(match.HintFPR)
		match.AgentNodeFPR = cloneBytes(match.AgentNodeFPR)
		match.AgentRootFPR = cloneBytes(match.AgentRootFPR)
		match.AnalysisSessionID = nullStringPointer(sessionID)
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate spawn hint matches: %w", err)
	}
	return matches, nil
}
