package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SaveAnalysis upserts one audit's derived analysis and replaces its spawn
// hints. The write is queued like every other writer operation and runs in
// the batch's per-operation savepoint; a missing audit is an isolated
// sql.ErrNoRows, never a batch failure. Nothing here touches the integrity
// chain: analysis rows are recomputable and stay outside every signed digest.
func (store *Store) SaveAnalysis(ctx context.Context, row AnalysisRow) error {
	if err := validateAnalysisRow(row); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeSaveAnalysis, data: cloneAnalysisRow(row)})
}

func saveAnalysis(transaction *sql.Tx, row AnalysisRow) error {
	var exists int
	if err := transaction.QueryRow(`SELECT 1 FROM audit_records WHERE audit_id = ?`, row.AuditID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sqlite writer: save analysis for unknown audit: %w", sql.ErrNoRows)
		}
		return fmt.Errorf("sqlite writer: read analysis audit: %w", err)
	}
	toolKindCounts := row.ToolKindCounts
	if toolKindCounts == "" {
		toolKindCounts = "{}"
	}
	_, err := transaction.Exec(`
INSERT INTO audit_analysis (
    audit_id, analysis_version, analyzed_at_ns, protocol, model, started_at_ns,
    u_uncached_input, u_cache_read, u_cache_write, u_output, u_reasoning, max_output_tokens,
    est_system, est_tools, est_user, est_injected, est_assistant, est_reasoning,
    est_tool_result, est_media, n_items, n_tool_defs, n_tool_results, n_media,
    stop_reason, resp_kinds, resp_tool_calls, tool_kind_counts,
    analysis_session_id, session_link, prev_audit_id, turn_start,
    appended_items, removed_items, event_flags, system_fpr, tools_fpr,
    first_event_ns, generation_ns,
    agent_client, agent_role, agent_node_fpr, agent_parent_fpr, agent_root_fpr,
    agent_link_source, agent_link_confidence, detail_enc
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(audit_id) DO UPDATE SET
    analysis_version = excluded.analysis_version,
    analyzed_at_ns = excluded.analyzed_at_ns,
    protocol = excluded.protocol,
    model = excluded.model,
    started_at_ns = excluded.started_at_ns,
    u_uncached_input = excluded.u_uncached_input,
    u_cache_read = excluded.u_cache_read,
    u_cache_write = excluded.u_cache_write,
    u_output = excluded.u_output,
    u_reasoning = excluded.u_reasoning,
    max_output_tokens = excluded.max_output_tokens,
    est_system = excluded.est_system,
    est_tools = excluded.est_tools,
    est_user = excluded.est_user,
    est_injected = excluded.est_injected,
    est_assistant = excluded.est_assistant,
    est_reasoning = excluded.est_reasoning,
    est_tool_result = excluded.est_tool_result,
    est_media = excluded.est_media,
    n_items = excluded.n_items,
    n_tool_defs = excluded.n_tool_defs,
    n_tool_results = excluded.n_tool_results,
    n_media = excluded.n_media,
    stop_reason = excluded.stop_reason,
    resp_kinds = excluded.resp_kinds,
    resp_tool_calls = excluded.resp_tool_calls,
    tool_kind_counts = excluded.tool_kind_counts,
    analysis_session_id = excluded.analysis_session_id,
    session_link = excluded.session_link,
    prev_audit_id = excluded.prev_audit_id,
    turn_start = excluded.turn_start,
    appended_items = excluded.appended_items,
    removed_items = excluded.removed_items,
    event_flags = excluded.event_flags,
    system_fpr = excluded.system_fpr,
    tools_fpr = excluded.tools_fpr,
    first_event_ns = excluded.first_event_ns,
    generation_ns = excluded.generation_ns,
    agent_client = excluded.agent_client,
    agent_role = excluded.agent_role,
    agent_node_fpr = excluded.agent_node_fpr,
    agent_parent_fpr = excluded.agent_parent_fpr,
    agent_root_fpr = excluded.agent_root_fpr,
    agent_link_source = excluded.agent_link_source,
    agent_link_confidence = excluded.agent_link_confidence,
    detail_enc = excluded.detail_enc`,
		row.AuditID, row.AnalysisVersion, row.AnalyzedAtNS, row.Protocol, row.Model, row.StartedAtNS,
		row.UncachedInput, row.CacheRead, row.CacheWrite, row.Output, row.Reasoning, row.MaxOutputTokens,
		row.EstSystem, row.EstTools, row.EstUser, row.EstInjected, row.EstAssistant, row.EstReasoning,
		row.EstToolResult, row.EstMedia, row.Items, row.ToolDefs, row.ToolResults, row.Media,
		row.StopReason, row.RespKinds, row.RespToolCalls, toolKindCounts,
		row.AnalysisSessionID, row.SessionLink, row.PrevAuditID, boolInteger(row.TurnStart),
		row.AppendedItems, row.RemovedItems, row.EventFlags, nullableBytes(row.SystemFPR), nullableBytes(row.ToolsFPR),
		row.FirstEventNS, row.GenerationNS,
		row.AgentClient, row.AgentRole, nullableBytes(row.AgentNodeFPR), nullableBytes(row.AgentParentFPR), nullableBytes(row.AgentRootFPR),
		row.AgentLinkSource, row.AgentLinkConfidence, nullableBytes(row.DetailEnc),
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: upsert analysis: %w", err)
	}
	if _, err := transaction.Exec(`DELETE FROM agent_spawn_hints WHERE audit_id = ?`, row.AuditID); err != nil {
		return fmt.Errorf("sqlite writer: clear spawn hints: %w", err)
	}
	// Hints are keyed by the audit start so the content-matching fallback can
	// window them by request time; a recomputed row keeps the same timestamp.
	for _, hint := range row.SpawnHints {
		if _, err := transaction.Exec(`
INSERT OR IGNORE INTO agent_spawn_hints (audit_id, hint_fpr, created_at_ns)
VALUES (?, ?, ?)`, row.AuditID, hint, row.StartedAtNS); err != nil {
			return fmt.Errorf("sqlite writer: add spawn hint: %w", err)
		}
	}
	return nil
}
