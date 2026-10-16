package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// LoadAnalysis reads one audit's analysis row and spawn hints from a single
// read-only snapshot. A missing row returns an error wrapping sql.ErrNoRows.
func (store *Store) LoadAnalysis(ctx context.Context, auditID string) (AnalysisRow, error) {
	if ctx == nil {
		return AnalysisRow{}, errors.New("sqlite: nil context")
	}
	if auditID == "" {
		return AnalysisRow{}, errors.New("sqlite: empty audit id")
	}
	if store == nil || store.isClosed() {
		return AnalysisRow{}, ErrClosed
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AnalysisRow{}, fmt.Errorf("sqlite: begin analysis read: %w", err)
	}
	defer transaction.Rollback()

	var row AnalysisRow
	var model, stopReason, sessionID, sessionLink, prevAuditID sql.NullString
	var agentClient, agentRole, agentLinkSource sql.NullString
	var uncached, cacheRead, cacheWrite, output, reasoning, maxOutput sql.NullInt64
	var appended, removed, firstEvent, generation, linkConfidence sql.NullInt64
	var turnStart int
	err = transaction.QueryRowContext(ctx, `
SELECT audit_id, analysis_version, analyzed_at_ns, protocol, model, started_at_ns,
       u_uncached_input, u_cache_read, u_cache_write, u_output, u_reasoning, max_output_tokens,
       est_system, est_tools, est_user, est_injected, est_assistant, est_reasoning,
       est_tool_result, est_media, n_items, n_tool_defs, n_tool_results, n_media,
       stop_reason, resp_kinds, resp_tool_calls, tool_kind_counts,
       analysis_session_id, session_link, prev_audit_id, turn_start,
       appended_items, removed_items, event_flags, system_fpr, tools_fpr,
       first_event_ns, generation_ns,
       agent_client, agent_role, agent_node_fpr, agent_parent_fpr, agent_root_fpr,
       agent_link_source, agent_link_confidence, detail_enc
FROM audit_analysis
WHERE audit_id = ?`, auditID).Scan(
		&row.AuditID, &row.AnalysisVersion, &row.AnalyzedAtNS, &row.Protocol, &model, &row.StartedAtNS,
		&uncached, &cacheRead, &cacheWrite, &output, &reasoning, &maxOutput,
		&row.EstSystem, &row.EstTools, &row.EstUser, &row.EstInjected, &row.EstAssistant, &row.EstReasoning,
		&row.EstToolResult, &row.EstMedia, &row.Items, &row.ToolDefs, &row.ToolResults, &row.Media,
		&stopReason, &row.RespKinds, &row.RespToolCalls, &row.ToolKindCounts,
		&sessionID, &sessionLink, &prevAuditID, &turnStart,
		&appended, &removed, &row.EventFlags, &row.SystemFPR, &row.ToolsFPR,
		&firstEvent, &generation,
		&agentClient, &agentRole, &row.AgentNodeFPR, &row.AgentParentFPR, &row.AgentRootFPR,
		&agentLinkSource, &linkConfidence, &row.DetailEnc,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AnalysisRow{}, fmt.Errorf("sqlite: load analysis: %w", sql.ErrNoRows)
		}
		return AnalysisRow{}, fmt.Errorf("sqlite: load analysis: %w", err)
	}
	row.Model = nullStringPointer(model)
	row.UncachedInput = nullInt64Pointer(uncached)
	row.CacheRead = nullInt64Pointer(cacheRead)
	row.CacheWrite = nullInt64Pointer(cacheWrite)
	row.Output = nullInt64Pointer(output)
	row.Reasoning = nullInt64Pointer(reasoning)
	row.MaxOutputTokens = nullInt64Pointer(maxOutput)
	row.StopReason = nullStringPointer(stopReason)
	row.AnalysisSessionID = nullStringPointer(sessionID)
	row.SessionLink = nullStringPointer(sessionLink)
	row.PrevAuditID = nullStringPointer(prevAuditID)
	row.TurnStart = turnStart != 0
	row.AppendedItems = nullIntPointer(appended)
	row.RemovedItems = nullIntPointer(removed)
	row.FirstEventNS = nullInt64Pointer(firstEvent)
	row.GenerationNS = nullInt64Pointer(generation)
	row.AgentClient = nullStringPointer(agentClient)
	row.AgentRole = nullStringPointer(agentRole)
	row.AgentLinkSource = nullStringPointer(agentLinkSource)
	row.AgentLinkConfidence = nullIntPointer(linkConfidence)
	row = cloneAnalysisRow(row)

	rows, err := transaction.QueryContext(ctx, `
SELECT hint_fpr FROM agent_spawn_hints WHERE audit_id = ? ORDER BY hint_fpr`, auditID)
	if err != nil {
		return AnalysisRow{}, fmt.Errorf("sqlite: load spawn hints: %w", err)
	}
	for rows.Next() {
		var hint []byte
		if err := rows.Scan(&hint); err != nil {
			_ = rows.Close()
			return AnalysisRow{}, fmt.Errorf("sqlite: scan spawn hint: %w", err)
		}
		row.SpawnHints = append(row.SpawnHints, cloneBytes(hint))
	}
	if err := rows.Close(); err != nil {
		return AnalysisRow{}, fmt.Errorf("sqlite: close spawn hints: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AnalysisRow{}, fmt.Errorf("sqlite: iterate spawn hints: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return AnalysisRow{}, fmt.Errorf("sqlite: commit analysis read: %w", err)
	}
	return row, nil
}
