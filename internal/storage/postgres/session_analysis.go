package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"llmapi-logger/internal/storage"
)

// derivedWrite is one writer-queue operation over derived tables. It runs in
// the batch's per-operation savepoint like every other write and never touches
// the integrity chain.
type derivedWrite func(dbTransaction) error

// maxSessionAuditRows bounds one session read; longer sessions are analysed
// from their first maxSessionAuditRows requests and flagged by the caller.
const maxSessionAuditRows = 20000

// ListSessionCandidates returns (agent-tree root, API key) pairs that were
// active since sinceNS, have had no request end at or after quietBeforeNS,
// and either have no session_signals row, have gained requests since it was
// computed, or were computed by an older signal version. Requests without a
// key fingerprint form their own pair. Most recent first.
func (store *Store) ListSessionCandidates(ctx context.Context, sinceNS, quietBeforeNS, signalVersion int64, limit int) ([]storage.SessionCandidate, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if limit <= 0 {
		return nil, errors.New("postgres: session candidate limit must be positive")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
WITH recent AS (
    SELECT an.agent_root_fpr AS root, a.api_key_fpr AS api_key, MAX(an.started_at_ns) AS last_started, COUNT(*) AS requests
    FROM audit_analysis AS an
    JOIN audit_records AS a ON a.audit_id = an.audit_id
    WHERE an.started_at_ns >= $1 AND an.agent_root_fpr IS NOT NULL AND a.forward_status <> $2
    GROUP BY an.agent_root_fpr, a.api_key_fpr
    HAVING MAX(COALESCE(a.ended_at_ns, a.started_at_ns)) < $3
)
SELECT r.root, r.api_key, r.last_started, r.requests, COALESCE(s.last_ns, 0), COALESCE(s.requests, 0)
FROM recent AS r
LEFT JOIN session_signals AS s ON s.agent_root_fpr = r.root AND s.api_key_fpr IS NOT DISTINCT FROM r.api_key
WHERE s.session_key IS NULL OR s.last_ns < r.last_started OR s.signal_version < $4
ORDER BY r.last_started DESC, r.root, r.api_key NULLS FIRST
LIMIT $5`, sinceNS, ForwardRejected, quietBeforeNS, signalVersion, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list session candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]storage.SessionCandidate, 0)
	for rows.Next() {
		var candidate storage.SessionCandidate
		if err := rows.Scan(&candidate.AgentRootFPR, &candidate.APIKeyFPR, &candidate.LastStartedNS, &candidate.Requests, &candidate.AnalyzedLastNS, &candidate.AnalyzedRequests); err != nil {
			return nil, fmt.Errorf("postgres: scan session candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate session candidates: %w", err)
	}
	return candidates, nil
}

// LoadSessionAudits reads the plaintext projection of every non-rejected
// request of one agent-tree root sent with one API key (nil: requests without
// a key fingerprint) in start order. The boolean reports whether the read was
// truncated at maxSessionAuditRows.
func (store *Store) LoadSessionAudits(ctx context.Context, agentRootFPR, apiKeyFPR []byte) ([]storage.SessionAuditRow, bool, error) {
	if ctx == nil {
		return nil, false, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, false, ErrClosed
	}
	if len(agentRootFPR) != 32 {
		return nil, false, errors.New("postgres: agent root fingerprint must be 32 bytes")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.status_code, a.api_key_fpr,
       COALESCE(an.model, ''), an.protocol,
       an.u_uncached_input, an.u_cache_read, an.u_cache_write, an.u_output,
       an.turn_start, an.event_flags, COALESCE(an.stop_reason, ''), an.resp_tool_calls, an.tool_kind_counts,
       COALESCE(an.analysis_session_id, ''), COALESCE(an.agent_client, ''), COALESCE(an.agent_role, ''),
       an.agent_node_fpr, an.agent_parent_fpr,
       t.newapi_user_id, t.newapi_token_id, t.quota, t.quota_per_unit,
       COALESCE(pr.error_type, ''), COALESCE(pr.upstream_error_class, '')
FROM audit_analysis AS an
JOIN audit_records AS a ON a.audit_id = an.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
LEFT JOIN parsed_results AS pr ON pr.audit_id = a.audit_id
WHERE an.agent_root_fpr = $1 AND a.api_key_fpr IS NOT DISTINCT FROM $4 AND a.forward_status <> $2
ORDER BY an.started_at_ns, a.audit_id
LIMIT $3`, agentRootFPR, ForwardRejected, maxSessionAuditRows+1, nullableBytes(apiKeyFPR))
	if err != nil {
		return nil, false, fmt.Errorf("postgres: load session audits: %w", err)
	}
	defer rows.Close()
	out := make([]storage.SessionAuditRow, 0)
	for rows.Next() {
		var row storage.SessionAuditRow
		var turnStart int64
		var eventFlags int64
		if err := rows.Scan(&row.AuditID, &row.StartedAtNS, &row.EndedAtNS, &row.StatusCode, &row.APIKeyFPR,
			&row.Model, &row.Protocol,
			&row.UncachedInput, &row.CacheRead, &row.CacheWrite, &row.Output,
			&turnStart, &eventFlags, &row.StopReason, &row.RespToolCalls, &row.ToolKindCounts,
			&row.AnalysisSessionID, &row.AgentClient, &row.AgentRole,
			&row.AgentNodeFPR, &row.AgentParentFPR,
			&row.NewAPIUserID, &row.NewAPITokenID, &row.Quota, &row.QuotaPerUnit,
			&row.ErrorType, &row.UpstreamErrorCls); err != nil {
			return nil, false, fmt.Errorf("postgres: scan session audit: %w", err)
		}
		row.TurnStart = turnStart != 0
		row.EventFlags = int(eventFlags)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("postgres: iterate session audits: %w", err)
	}
	truncated := len(out) > maxSessionAuditRows
	if truncated {
		out = out[:maxSessionAuditRows]
	}
	return out, truncated, nil
}

// SaveSessionSignals upserts one session's signals, replaces its user-text
// and injected-rule fingerprints, and writes its session pack, all in one
// transaction: a failure leaves the previous state, so the session stays due
// until signals and pack are both stored. pack nil (ineligible session, or no
// pack text) removes a stale session pack. Facet fingerprints are left alone.
func (store *Store) SaveSessionSignals(ctx context.Context, signals storage.SessionSignals, fprs []storage.SessionTextFPR, pack *storage.SessionPack) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if len(signals.SessionKey) != 32 || len(signals.AgentRootFPR) != 32 || (len(signals.DigestBucket) != 0 && len(signals.DigestBucket) != 32) || signals.LastAuditID == "" || signals.SignalVersion <= 0 {
		return errors.New("postgres: invalid session signals")
	}
	owned := signals
	owned.SessionKey = append([]byte(nil), signals.SessionKey...)
	owned.AgentRootFPR = append([]byte(nil), signals.AgentRootFPR...)
	owned.DigestBucket = append([]byte(nil), signals.DigestBucket...)
	owned.APIKeyFPR = append([]byte(nil), signals.APIKeyFPR...)
	ownedFPRs := make([]storage.SessionTextFPR, len(fprs))
	for index, fpr := range fprs {
		if len(fpr.FPR) != 32 {
			return errors.New("postgres: session text fingerprint must be 32 bytes")
		}
		ownedFPRs[index] = storage.SessionTextFPR{Source: fpr.Source, FPR: append([]byte(nil), fpr.FPR...), APIKeyFPR: append([]byte(nil), fpr.APIKeyFPR...), SeenAtNS: fpr.SeenAtNS}
	}
	var ownedPack *storage.SessionPack
	if pack != nil {
		if pack.Kind != storage.PackKindSession || !bytes.Equal(pack.SessionKey, signals.SessionKey) {
			return errors.New("postgres: a session's own pack must be a session pack with its key")
		}
		copied, _, err := ownSessionPack(*pack, nil)
		if err != nil {
			return err
		}
		ownedPack = &copied
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		return saveSessionSignals(tx, owned, ownedFPRs, ownedPack)
	})})
}

func saveSessionSignals(tx dbTransaction, s storage.SessionSignals, fprs []storage.SessionTextFPR, pack *storage.SessionPack) error {
	danger, secret := s.DangerCounts, s.SecretCounts
	if danger == "" {
		danger = "{}"
	}
	if secret == "" {
		secret = "{}"
	}
	// A session that leaves its chat digest bucket (it gained turns, or its
	// bucket changed) must not stay in that bucket's digests: they are dropped
	// with their facets and their other members are queued for the rebuild.
	var previousBucket []byte
	switch err := tx.QueryRow(`SELECT digest_bucket FROM session_signals WHERE session_key = $1`, s.SessionKey).Scan(&previousBucket); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("postgres writer: read previous digest bucket: %w", err)
	}
	if len(previousBucket) != 0 && !bytes.Equal(previousBucket, s.DigestBucket) {
		if err := dropChatDigestsOf(tx, `SELECT $1::bytea`, s.SessionKey); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`
INSERT INTO session_signals (
    session_key, agent_root_fpr, kind, api_key_fpr, newapi_user_id, newapi_token_id, client, main_session_id, main_model,
    first_ns, last_ns, last_audit_id, requests, main_requests, sub_requests, aux_requests, subagents, max_depth,
    user_turns, active_ns, input_tokens, output_tokens, cache_read_tokens, cost_usd,
    compactions, model_switches, length_stops, upstream_errors,
    tool_calls, tool_failures, tool_unknown, max_failure_streak, loops, max_loop_length, thrash_files, max_file_writes,
    verified, error_pastes, interrupts, corrections, heavy_model, danger_counts, secret_counts,
    eligible, skip_reason, signal_version, computed_at_ns, digest_bucket, digest_pending
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,
          $28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48::bytea,$48::bytea IS NOT NULL)
ON CONFLICT (session_key) DO UPDATE SET
    agent_root_fpr = excluded.agent_root_fpr, kind = excluded.kind, api_key_fpr = excluded.api_key_fpr, newapi_user_id = excluded.newapi_user_id,
    newapi_token_id = excluded.newapi_token_id, client = excluded.client, main_session_id = excluded.main_session_id,
    main_model = excluded.main_model, first_ns = excluded.first_ns, last_ns = excluded.last_ns,
    last_audit_id = excluded.last_audit_id, requests = excluded.requests, main_requests = excluded.main_requests,
    sub_requests = excluded.sub_requests, aux_requests = excluded.aux_requests, subagents = excluded.subagents,
    max_depth = excluded.max_depth, user_turns = excluded.user_turns, active_ns = excluded.active_ns,
    input_tokens = excluded.input_tokens, output_tokens = excluded.output_tokens,
    cache_read_tokens = excluded.cache_read_tokens, cost_usd = excluded.cost_usd,
    compactions = excluded.compactions, model_switches = excluded.model_switches,
    length_stops = excluded.length_stops, upstream_errors = excluded.upstream_errors,
    tool_calls = excluded.tool_calls, tool_failures = excluded.tool_failures, tool_unknown = excluded.tool_unknown,
    max_failure_streak = excluded.max_failure_streak, loops = excluded.loops, max_loop_length = excluded.max_loop_length,
    thrash_files = excluded.thrash_files, max_file_writes = excluded.max_file_writes, verified = excluded.verified,
    error_pastes = excluded.error_pastes, interrupts = excluded.interrupts, corrections = excluded.corrections,
    heavy_model = excluded.heavy_model, danger_counts = excluded.danger_counts, secret_counts = excluded.secret_counts,
    eligible = excluded.eligible, skip_reason = excluded.skip_reason, signal_version = excluded.signal_version,
    computed_at_ns = excluded.computed_at_ns, digest_bucket = excluded.digest_bucket,
    digest_pending = excluded.digest_pending`,
		s.SessionKey, s.AgentRootFPR, s.Kind, nullableBytes(s.APIKeyFPR), s.NewAPIUserID, s.NewAPITokenID, nullText(s.Client), nullText(s.MainSessionID), nullText(s.MainModel),
		s.FirstNS, s.LastNS, s.LastAuditID, s.Requests, s.MainRequests, s.SubRequests, s.AuxRequests, s.Subagents, s.MaxDepth,
		s.UserTurns, s.ActiveNS, s.InputTokens, s.OutputTokens, s.CacheReadTokens, s.CostUSD,
		s.Compactions, s.ModelSwitches, s.LengthStops, s.UpstreamErrors,
		s.ToolCalls, s.ToolFailures, s.ToolUnknown, s.MaxFailureStreak, s.Loops, s.MaxLoopLength, s.ThrashFiles, s.MaxFileWrites,
		s.Verified, s.ErrorPastes, s.Interrupts, s.Corrections, s.HeavyModel, danger, secret,
		s.Eligible, nullText(s.SkipReason), s.SignalVersion, s.ComputedAtNS, nullableBytes(s.DigestBucket))
	if err != nil {
		return fmt.Errorf("postgres writer: upsert session signals: %w", err)
	}
	// A session without a current pack keeps no stale one.
	if pack != nil {
		if err := upsertSessionPack(tx, *pack, nil); err != nil {
			return err
		}
	} else if _, err := tx.Exec(`DELETE FROM session_packs WHERE session_key = $1 AND kind = $2`, s.SessionKey, storage.PackKindSession); err != nil {
		return fmt.Errorf("postgres writer: drop stale session pack: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM session_text_fprs WHERE session_key = $1 AND source IN ($2, $3)`,
		s.SessionKey, storage.TextSourceUser, storage.TextSourceInjectedRules); err != nil {
		return fmt.Errorf("postgres writer: clear session text fingerprints: %w", err)
	}
	for _, fpr := range fprs {
		if _, err := tx.Exec(`
INSERT INTO session_text_fprs (session_key, source, fpr, api_key_fpr, seen_at_ns)
VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_key, source, fpr) DO UPDATE SET seen_at_ns = excluded.seen_at_ns`,
			s.SessionKey, fpr.Source, fpr.FPR, nullableBytes(fpr.APIKeyFPR), fpr.SeenAtNS); err != nil {
			return fmt.Errorf("postgres writer: add session text fingerprint: %w", err)
		}
	}
	return nil
}

// dropChatDigestsOf drops every chat digest that holds a session selected by
// members (a query returning session keys) and queues the digests' other
// members for a rebuild. Facets and member rows go with the packs.
func dropChatDigestsOf(tx dbTransaction, members string, args ...any) error {
	holders := `SELECT m.pack_key FROM session_pack_members AS m WHERE m.session_key IN (` + members + `)`
	if _, err := tx.Exec(`
UPDATE session_signals SET digest_pending = TRUE
WHERE digest_bucket IS NOT NULL
  AND session_key IN (SELECT other.session_key FROM session_pack_members AS other WHERE other.pack_key IN (`+holders+`))`, args...); err != nil {
		return fmt.Errorf("postgres writer: queue chat digest members: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM session_packs WHERE kind = 'chat_digest' AND session_key IN (`+holders+`)`, args...); err != nil {
		return fmt.Errorf("postgres writer: drop chat digests: %w", err)
	}
	return nil
}

// PruneSessionAnalysis removes session rows whose newest audit was deleted by
// retention (dependent rows cascade) and sentence fingerprints older than
// fingerprintCutoffNS. It returns the number of removed session rows.
func (store *Store) PruneSessionAnalysis(ctx context.Context, fingerprintCutoffNS int64) (int64, error) {
	if ctx == nil {
		return 0, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return 0, ErrClosed
	}
	var removed int64
	err := store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		// Digests holding an expiring session, or whose own newest audit
		// expired, are rebuilt from the members that remain.
		if err := dropChatDigestsOf(tx, `
SELECT s.session_key FROM session_signals AS s
WHERE NOT EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = s.last_audit_id)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`
UPDATE session_signals SET digest_pending = TRUE
WHERE digest_bucket IS NOT NULL AND session_key IN (
    SELECT m.session_key FROM session_pack_members AS m JOIN session_packs AS p ON p.session_key = m.pack_key
    WHERE NOT EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = p.last_audit_id))`); err != nil {
			return fmt.Errorf("postgres writer: queue members of expired digests: %w", err)
		}
		result, err := tx.Exec(`
DELETE FROM session_signals AS s
WHERE NOT EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = s.last_audit_id)`)
		if err != nil {
			return fmt.Errorf("postgres writer: prune session signals: %w", err)
		}
		removed, _ = result.RowsAffected()
		if _, err := tx.Exec(`
DELETE FROM session_packs AS p
WHERE NOT EXISTS (SELECT 1 FROM audit_records AS a WHERE a.audit_id = p.last_audit_id)`); err != nil {
			return fmt.Errorf("postgres writer: prune session packs: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM session_text_fprs WHERE seen_at_ns < $1`, fingerprintCutoffNS); err != nil {
			return fmt.Errorf("postgres writer: prune session text fingerprints: %w", err)
		}
		return nil
	})})
	return removed, err
}

// RecordSessionAnalysisRun appends one batch run summary.
func (store *Store) RecordSessionAnalysisRun(ctx context.Context, run storage.SessionAnalysisRun) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if run.SkipReasons == "" {
		run.SkipReasons = "{}"
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO session_analysis_runs (started_at_ns, finished_at_ns, trigger, candidates, analyzed, skipped, skip_reasons, pruned,
    l1_candidates, l1_ok, l1_invalid, l1_failed, l1_input_tokens, l1_output_tokens, error_category)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			run.StartedAtNS, run.FinishedAtNS, run.Trigger, run.Candidates, run.Analyzed, run.Skipped, run.SkipReasons, run.Pruned,
			run.L1Candidates, run.L1OK, run.L1Invalid, run.L1Failed, run.L1InputTokens, run.L1OutputToks, nullText(run.ErrorCategory))
		if err != nil {
			return fmt.Errorf("postgres writer: record session analysis run: %w", err)
		}
		return nil
	})})
}

// LatestSessionAnalysisRun returns the newest run, or sql.ErrNoRows.
func (store *Store) LatestSessionAnalysisRun(ctx context.Context) (storage.SessionAnalysisRun, error) {
	if ctx == nil {
		return storage.SessionAnalysisRun{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.SessionAnalysisRun{}, ErrClosed
	}
	var run storage.SessionAnalysisRun
	var category sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT id, started_at_ns, finished_at_ns, trigger, candidates, analyzed, skipped, skip_reasons, pruned,
       l1_candidates, l1_ok, l1_invalid, l1_failed, l1_input_tokens, l1_output_tokens, error_category
FROM session_analysis_runs ORDER BY id DESC LIMIT 1`).Scan(&run.ID, &run.StartedAtNS, &run.FinishedAtNS, &run.Trigger,
		&run.Candidates, &run.Analyzed, &run.Skipped, &run.SkipReasons, &run.Pruned,
		&run.L1Candidates, &run.L1OK, &run.L1Invalid, &run.L1Failed, &run.L1InputTokens, &run.L1OutputToks, &category)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.SessionAnalysisRun{}, sql.ErrNoRows
		}
		return storage.SessionAnalysisRun{}, fmt.Errorf("postgres: read session analysis run: %w", err)
	}
	run.ErrorCategory = category.String
	return run, nil
}

const sessionSignalColumns = `s.session_key, s.agent_root_fpr, s.digest_bucket, s.digest_pending, s.kind, s.api_key_fpr, s.newapi_user_id, s.newapi_token_id,
    COALESCE(s.client, ''), COALESCE(s.main_session_id, ''), COALESCE(s.main_model, ''),
    s.first_ns, s.last_ns, s.last_audit_id, s.requests, s.main_requests, s.sub_requests, s.aux_requests,
    s.subagents, s.max_depth, s.user_turns, s.active_ns, s.input_tokens, s.output_tokens, s.cache_read_tokens,
    s.cost_usd, s.compactions, s.model_switches, s.length_stops, s.upstream_errors,
    s.tool_calls, s.tool_failures, s.tool_unknown, s.max_failure_streak, s.loops, s.max_loop_length,
    s.thrash_files, s.max_file_writes, s.verified, s.error_pastes, s.interrupts, s.corrections,
    s.heavy_model, s.danger_counts, s.secret_counts, s.eligible, COALESCE(s.skip_reason, ''),
    s.signal_version, s.computed_at_ns,
    COALESCE((SELECT f.facet_status FROM session_facets AS f WHERE f.session_key = s.session_key), ''),
    COALESCE((SELECT f.task_type FROM session_facets AS f WHERE f.session_key = s.session_key), ''),
    COALESCE((SELECT f.outcome FROM session_facets AS f WHERE f.session_key = s.session_key), '')`

func scanSessionSignals(scanner interface{ Scan(...any) error }) (storage.SessionSignals, error) {
	var s storage.SessionSignals
	err := scanner.Scan(&s.SessionKey, &s.AgentRootFPR, &s.DigestBucket, &s.DigestPending, &s.Kind, &s.APIKeyFPR, &s.NewAPIUserID, &s.NewAPITokenID,
		&s.Client, &s.MainSessionID, &s.MainModel,
		&s.FirstNS, &s.LastNS, &s.LastAuditID, &s.Requests, &s.MainRequests, &s.SubRequests, &s.AuxRequests,
		&s.Subagents, &s.MaxDepth, &s.UserTurns, &s.ActiveNS, &s.InputTokens, &s.OutputTokens, &s.CacheReadTokens,
		&s.CostUSD, &s.Compactions, &s.ModelSwitches, &s.LengthStops, &s.UpstreamErrors,
		&s.ToolCalls, &s.ToolFailures, &s.ToolUnknown, &s.MaxFailureStreak, &s.Loops, &s.MaxLoopLength,
		&s.ThrashFiles, &s.MaxFileWrites, &s.Verified, &s.ErrorPastes, &s.Interrupts, &s.Corrections,
		&s.HeavyModel, &s.DangerCounts, &s.SecretCounts, &s.Eligible, &s.SkipReason,
		&s.SignalVersion, &s.ComputedAtNS,
		&s.FacetStatus, &s.FacetTaskType, &s.FacetOutcome)
	return s, err
}

var sessionSignalFlagConditions = map[string]string{
	"loop":        "s.loops > 0",
	"thrash":      "s.thrash_files > 0",
	"unverified":  "s.verified = 'no'",
	"failures":    "s.tool_failures > 0",
	"corrections": "s.corrections > 0",
	"error_paste": "s.error_pastes > 0",
	"interrupt":   "s.interrupts > 0",
	"heavy_model": "s.heavy_model",
	"danger":      "s.danger_counts <> '{}'",
	"secret":      "s.secret_counts <> '{}'",
	"compaction":  "s.compactions > 0",
}

// SessionSignalFlags lists the flag names accepted by SessionSignalFilter.
func SessionSignalFlags() []string {
	out := make([]string, 0, len(sessionSignalFlagConditions))
	for name := range sessionSignalFlagConditions {
		out = append(out, name)
	}
	return out
}

func sessionSignalWhere(filter storage.SessionSignalFilter) (string, []any, error) {
	conditions := make([]string, 0, 6)
	arguments := make([]any, 0, 6)
	push := func(value any) string {
		arguments = append(arguments, value)
		return parameter(len(arguments))
	}
	if filter.FromNS != 0 {
		conditions = append(conditions, "s.last_ns >= "+push(filter.FromNS))
	}
	if filter.ToNS != 0 {
		conditions = append(conditions, "s.last_ns < "+push(filter.ToNS))
	}
	if filter.Kind != "" {
		conditions = append(conditions, "s.kind = "+push(filter.Kind))
	}
	if len(filter.SessionKey) != 0 {
		conditions = append(conditions, "s.session_key = "+push(filter.SessionKey))
	}
	if filter.Scope != nil {
		if err := filter.Scope.Validate(); err != nil {
			return "", nil, err
		}
		ownership := "s.api_key_fpr = " + push(filter.Scope.Fingerprint)
		if filter.Scope.TokenID != nil {
			ownership = "(" + ownership + " OR s.newapi_token_id = " + push(*filter.Scope.TokenID) + ")"
		}
		conditions = append(conditions, ownership)
	}
	for _, flag := range filter.Flags {
		condition, ok := sessionSignalFlagConditions[flag]
		if !ok {
			return "", nil, fmt.Errorf("postgres: unknown session signal flag %q", flag)
		}
		conditions = append(conditions, condition)
	}
	if len(conditions) == 0 {
		return "TRUE", arguments, nil
	}
	return strings.Join(conditions, " AND "), arguments, nil
}

// ListSessionSignals returns one keyset page ordered by last_ns descending.
func (store *Store) ListSessionSignals(ctx context.Context, filter storage.SessionSignalFilter, cursor storage.SessionSignalCursor, limit int) (storage.SessionSignalPage, error) {
	if ctx == nil {
		return storage.SessionSignalPage{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.SessionSignalPage{}, ErrClosed
	}
	if limit <= 0 || limit > 500 {
		return storage.SessionSignalPage{}, errors.New("postgres: session signal limit out of range")
	}
	where, arguments, err := sessionSignalWhere(filter)
	if err != nil {
		return storage.SessionSignalPage{}, err
	}
	if cursor.BeforeLastNS != 0 && len(cursor.BeforeKey) != 0 {
		arguments = append(arguments, cursor.BeforeLastNS, cursor.BeforeKey)
		where += fmt.Sprintf(" AND (s.last_ns, s.session_key) < (%s, %s)", parameter(len(arguments)-1), parameter(len(arguments)))
	}
	arguments = append(arguments, limit+1)
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+sessionSignalColumns+`
FROM session_signals AS s WHERE `+where+`
ORDER BY s.last_ns DESC, s.session_key DESC LIMIT `+parameter(len(arguments)), arguments...)
	if err != nil {
		return storage.SessionSignalPage{}, fmt.Errorf("postgres: list session signals: %w", err)
	}
	defer rows.Close()
	page := storage.SessionSignalPage{Rows: make([]storage.SessionSignals, 0, limit)}
	for rows.Next() {
		row, err := scanSessionSignals(rows)
		if err != nil {
			return storage.SessionSignalPage{}, fmt.Errorf("postgres: scan session signals: %w", err)
		}
		page.Rows = append(page.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return storage.SessionSignalPage{}, fmt.Errorf("postgres: iterate session signals: %w", err)
	}
	if len(page.Rows) > limit {
		page.Rows = page.Rows[:limit]
		page.HasMore = true
	}
	return page, nil
}

// SessionSignalTotals aggregates the sessions selected by filter.
func (store *Store) SessionSignalTotals(ctx context.Context, filter storage.SessionSignalFilter) (storage.SessionSignalTotals, error) {
	if ctx == nil {
		return storage.SessionSignalTotals{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.SessionSignalTotals{}, ErrClosed
	}
	where, arguments, err := sessionSignalWhere(filter)
	if err != nil {
		return storage.SessionSignalTotals{}, err
	}
	var totals storage.SessionSignalTotals
	err = store.readerDB.QueryRowContext(ctx, `
SELECT COUNT(*),
       COUNT(*) FILTER (WHERE s.kind = 'agent'),
       COUNT(*) FILTER (WHERE s.kind = 'chat'),
       COUNT(*) FILTER (WHERE s.eligible),
       COALESCE(SUM(s.cost_usd), 0),
       COUNT(s.cost_usd),
       COUNT(*) FILTER (WHERE s.loops > 0),
       COALESCE(SUM(s.cost_usd) FILTER (WHERE s.loops > 0), 0),
       COUNT(*) FILTER (WHERE s.thrash_files > 0),
       COUNT(*) FILTER (WHERE s.verified = 'no'),
       COUNT(*) FILTER (WHERE s.verified <> 'no_writes'),
       COUNT(*) FILTER (WHERE s.tool_failures > 0),
       COALESCE(SUM(s.corrections), 0),
       COUNT(*) FILTER (WHERE s.corrections > 0),
       COUNT(*) FILTER (WHERE s.error_pastes > 0),
       COUNT(*) FILTER (WHERE s.interrupts > 0),
       COUNT(*) FILTER (WHERE s.heavy_model),
       COUNT(*) FILTER (WHERE s.danger_counts <> '{}'),
       COUNT(*) FILTER (WHERE s.secret_counts <> '{}'),
       COUNT(*) FILTER (WHERE s.compactions > 0),
       COALESCE(SUM(s.input_tokens), 0),
       COALESCE(SUM(s.cache_read_tokens), 0)
FROM session_signals AS s WHERE `+where, arguments...).Scan(
		&totals.Sessions, &totals.AgentSessions, &totals.ChatSessions, &totals.Eligible,
		&totals.CostUSD, &totals.BilledSessions, &totals.LoopSessions, &totals.LoopCostUSD,
		&totals.ThrashSessions, &totals.Unverified, &totals.WithWrites, &totals.FailureSessions,
		&totals.Corrections, &totals.CorrectionSess, &totals.ErrorPasteSess, &totals.InterruptSess,
		&totals.HeavyModelSess, &totals.DangerSessions, &totals.SecretSessions, &totals.CompactionSess,
		&totals.InputTokens, &totals.CacheReadTokens)
	if err != nil {
		return storage.SessionSignalTotals{}, fmt.Errorf("postgres: aggregate session signals: %w", err)
	}
	return totals, nil
}

func nullText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
