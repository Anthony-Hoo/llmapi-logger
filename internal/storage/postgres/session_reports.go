package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

// maxRepeatedSessionKeys bounds the member sessions returned per repeated
// fingerprint; they are only used to recover the sentence text and evidence.
const maxRepeatedSessionKeys = 10

// ActiveAnalysisKeys lists the API keys with analysed sessions whose last
// request falls in [fromNS, toNS).
func (store *Store) ActiveAnalysisKeys(ctx context.Context, fromNS, toNS int64) ([]storage.ScopeKey, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT s.api_key_fpr, MAX(s.newapi_token_id)
FROM session_signals AS s
WHERE s.last_ns >= $1 AND s.last_ns < $2 AND s.api_key_fpr IS NOT NULL
GROUP BY s.api_key_fpr
ORDER BY s.api_key_fpr`, fromNS, toNS)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active analysis keys: %w", err)
	}
	defer rows.Close()
	out := make([]storage.ScopeKey, 0)
	for rows.Next() {
		var key storage.ScopeKey
		if err := rows.Scan(&key.APIKeyFPR, &key.NewAPITokenID); err != nil {
			return nil, fmt.Errorf("postgres: scan active analysis key: %w", err)
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// FacetEnums returns the plaintext enums of the ok facets whose session's
// last request falls in [fromNS, toNS); apiKey nil reads every key.
func (store *Store) FacetEnums(ctx context.Context, fromNS, toNS int64, apiKey []byte) ([]storage.FacetEnumRow, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	query := `
SELECT f.kind, COALESCE(f.task_type, ''), COALESCE(f.outcome, ''), COALESCE(f.collaboration, ''), f.friction, f.items
FROM session_facets AS f
WHERE f.facet_status = 'ok' AND f.last_ns >= $1 AND f.last_ns < $2`
	arguments := []any{fromNS, toNS}
	if len(apiKey) != 0 {
		query += ` AND f.api_key_fpr = $3`
		arguments = append(arguments, apiKey)
	}
	rows, err := store.readerDB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: read facet enums: %w", err)
	}
	defer rows.Close()
	out := make([]storage.FacetEnumRow, 0)
	for rows.Next() {
		var row storage.FacetEnumRow
		if err := rows.Scan(&row.Kind, &row.TaskType, &row.Outcome, &row.Collaboration, &row.Friction, &row.Items); err != nil {
			return nil, fmt.Errorf("postgres: scan facet enums: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// RepeatedFingerprints groups sentence fingerprints seen since sinceNS by
// fingerprint and kind (user sentences and model-extracted instructions
// count as one instruction), keeping those seen in at least two sessions.
// Adopted reports whether the same fingerprint later appeared in injected
// rules (AGENTS.md / CLAUDE.md) of the same scope. apiKey nil reads all keys.
func (store *Store) RepeatedFingerprints(ctx context.Context, sinceNS int64, apiKey []byte, limit int) ([]storage.RepeatedFPR, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	keyCondition, ruleCondition := "", ""
	arguments := []any{sinceNS, limit, maxRepeatedSessionKeys}
	if len(apiKey) != 0 {
		arguments = append(arguments, apiKey)
		keyCondition = " AND t.api_key_fpr = $4"
		ruleCondition = " AND r.api_key_fpr = $4"
	}
	rows, err := store.readerDB.QueryContext(ctx, `
WITH grouped AS (
    SELECT t.fpr,
           CASE WHEN t.source = 'facet_skill' THEN 'skill' ELSE 'instruction' END AS kind,
           COUNT(DISTINCT t.session_key) AS sessions,
           MIN(t.seen_at_ns) AS first_seen,
           MAX(t.seen_at_ns) AS last_seen,
           (ARRAY_AGG(DISTINCT t.session_key))[1:$3] AS session_keys
    FROM session_text_fprs AS t
    WHERE t.source IN ('user_text', 'facet_instruction', 'facet_skill') AND t.seen_at_ns >= $1`+keyCondition+`
    GROUP BY t.fpr, CASE WHEN t.source = 'facet_skill' THEN 'skill' ELSE 'instruction' END
    HAVING COUNT(DISTINCT t.session_key) >= 2
)
SELECT g.fpr, g.kind, g.sessions, g.first_seen, g.last_seen, g.session_keys,
       EXISTS (SELECT 1 FROM session_text_fprs AS r
               WHERE r.fpr = g.fpr AND r.source = 'injected_rules' AND r.seen_at_ns >= g.first_seen`+ruleCondition+`)
FROM grouped AS g
ORDER BY g.sessions DESC, g.last_seen DESC, g.fpr
LIMIT $2`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: group repeated fingerprints: %w", err)
	}
	defer rows.Close()
	out := make([]storage.RepeatedFPR, 0)
	for rows.Next() {
		var row storage.RepeatedFPR
		var keys [][]byte
		if err := rows.Scan(&row.FPR, &row.Kind, &row.Sessions, &row.FirstNS, &row.LastNS, &keys, &row.Adopted); err != nil {
			return nil, fmt.Errorf("postgres: scan repeated fingerprint: %w", err)
		}
		row.SessionKeys = keys
		out = append(out, row)
	}
	return out, rows.Err()
}

// UpsertSuggestion inserts or refreshes one suggestion. A dismissed
// suggestion stays dismissed; an adopted one never returns to open.
func (store *Store) UpsertSuggestion(ctx context.Context, suggestion storage.Suggestion) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if len(suggestion.ScopeKey) != 32 || len(suggestion.FPR) != 32 || len(suggestion.TextEnc) == 0 {
		return errors.New("postgres: invalid suggestion")
	}
	owned := suggestion
	owned.ScopeKey = append([]byte(nil), suggestion.ScopeKey...)
	owned.FPR = append([]byte(nil), suggestion.FPR...)
	owned.TextEnc = append([]byte(nil), suggestion.TextEnc...)
	if owned.Evidence == "" {
		owned.Evidence = "[]"
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO analysis_suggestions (scope, scope_key, newapi_token_id, kind, fpr, support_sessions, first_seen_ns, last_seen_ns,
    status, text_enc, evidence, updated_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (scope, scope_key, kind, fpr) DO UPDATE SET
    newapi_token_id = excluded.newapi_token_id,
    support_sessions = GREATEST(analysis_suggestions.support_sessions, excluded.support_sessions),
    first_seen_ns = LEAST(analysis_suggestions.first_seen_ns, excluded.first_seen_ns),
    last_seen_ns = GREATEST(analysis_suggestions.last_seen_ns, excluded.last_seen_ns),
    status = CASE WHEN analysis_suggestions.status = 'dismissed' THEN 'dismissed'
                  WHEN analysis_suggestions.status = 'adopted_detected' OR excluded.status = 'adopted_detected' THEN 'adopted_detected'
                  ELSE 'open' END,
    text_enc = excluded.text_enc, evidence = excluded.evidence, updated_at_ns = excluded.updated_at_ns`,
			owned.Scope, owned.ScopeKey, owned.NewAPITokenID, owned.Kind, owned.FPR, owned.Support, owned.FirstSeenNS,
			owned.LastSeenNS, owned.Status, owned.TextEnc, owned.Evidence, owned.UpdatedAtNS)
		if err != nil {
			return fmt.Errorf("postgres writer: upsert suggestion: %w", err)
		}
		return nil
	})})
}

// ListSuggestions returns the suggestions of one scope, open first, then by
// support.
func (store *Store) ListSuggestions(ctx context.Context, scope string, scopeKey []byte, tokenID *int64, limit int) ([]storage.Suggestion, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	ownership := "s.scope_key = $2"
	arguments := []any{scope, scopeKey, limit}
	if tokenID != nil {
		ownership = "(s.scope_key = $2 OR s.newapi_token_id = $4)"
		arguments = append(arguments, *tokenID)
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT s.id, s.scope, s.scope_key, s.newapi_token_id, s.kind, s.fpr, s.support_sessions, s.first_seen_ns, s.last_seen_ns,
       s.status, s.text_enc, s.evidence, s.updated_at_ns
FROM analysis_suggestions AS s
WHERE s.scope = $1 AND `+ownership+`
ORDER BY (s.status = 'open') DESC, s.support_sessions DESC, s.last_seen_ns DESC, s.id
LIMIT $3`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list suggestions: %w", err)
	}
	defer rows.Close()
	out := make([]storage.Suggestion, 0)
	for rows.Next() {
		var row storage.Suggestion
		if err := rows.Scan(&row.ID, &row.Scope, &row.ScopeKey, &row.NewAPITokenID, &row.Kind, &row.FPR, &row.Support,
			&row.FirstSeenNS, &row.LastSeenNS, &row.Status, &row.TextEnc, &row.Evidence, &row.UpdatedAtNS); err != nil {
			return nil, fmt.Errorf("postgres: scan suggestion: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DismissSuggestion marks one suggestion of a scope dismissed. It returns
// sql.ErrNoRows when no such suggestion exists in that scope.
func (store *Store) DismissSuggestion(ctx context.Context, id int64, scope string, nowNS int64) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		result, err := tx.Exec(`UPDATE analysis_suggestions SET status = 'dismissed', updated_at_ns = $3 WHERE id = $1 AND scope = $2`, id, scope, nowNS)
		if err != nil {
			return fmt.Errorf("postgres writer: dismiss suggestion: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return sql.ErrNoRows
		}
		return nil
	})})
}

// SavePeriodStats upserts one week of one scope.
func (store *Store) SavePeriodStats(ctx context.Context, stats storage.PeriodStats) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if len(stats.ScopeKey) != 32 || stats.Stats == "" {
		return errors.New("postgres: invalid period stats")
	}
	owned := stats
	owned.ScopeKey = append([]byte(nil), stats.ScopeKey...)
	owned.NarrativeEnc = append([]byte(nil), stats.NarrativeEnc...)
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO analysis_period_stats (week_start_ns, scope, scope_key, newapi_token_id, stats, narrative_enc, narrative_source, input_hash, computed_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (week_start_ns, scope, scope_key) DO UPDATE SET
    newapi_token_id = excluded.newapi_token_id, stats = excluded.stats, narrative_enc = excluded.narrative_enc,
    narrative_source = excluded.narrative_source, input_hash = excluded.input_hash, computed_at_ns = excluded.computed_at_ns`,
			owned.WeekStartNS, owned.Scope, owned.ScopeKey, owned.NewAPITokenID, owned.Stats, nullableBytes(owned.NarrativeEnc),
			nullText(owned.NarrativeSource), owned.InputHash, owned.ComputedAtNS)
		if err != nil {
			return fmt.Errorf("postgres writer: save period stats: %w", err)
		}
		return nil
	})})
}

// LoadPeriodStats reads one week of one scope; tokenID also admits rows of a
// key known only by its NewAPI token. sql.ErrNoRows when absent.
func (store *Store) LoadPeriodStats(ctx context.Context, weekStartNS int64, scope string, scopeKey []byte, tokenID *int64) (storage.PeriodStats, error) {
	if ctx == nil {
		return storage.PeriodStats{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.PeriodStats{}, ErrClosed
	}
	ownership := "p.scope_key = $3"
	arguments := []any{weekStartNS, scope, scopeKey}
	if tokenID != nil {
		ownership = "(p.scope_key = $3 OR p.newapi_token_id = $4)"
		arguments = append(arguments, *tokenID)
	}
	var stats storage.PeriodStats
	var source sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT p.week_start_ns, p.scope, p.scope_key, p.newapi_token_id, p.stats, p.narrative_enc, p.narrative_source, p.input_hash, p.computed_at_ns
FROM analysis_period_stats AS p
WHERE p.week_start_ns = $1 AND p.scope = $2 AND `+ownership+`
ORDER BY (p.scope_key = $3) DESC
LIMIT 1`, arguments...).Scan(&stats.WeekStartNS, &stats.Scope, &stats.ScopeKey, &stats.NewAPITokenID, &stats.Stats,
		&stats.NarrativeEnc, &source, &stats.InputHash, &stats.ComputedAtNS)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.PeriodStats{}, sql.ErrNoRows
		}
		return storage.PeriodStats{}, fmt.Errorf("postgres: read period stats: %w", err)
	}
	stats.NarrativeSource = source.String
	return stats, nil
}

// TopCostSessions returns the most expensive sessions selected by filter.
func (store *Store) TopCostSessions(ctx context.Context, filter storage.SessionSignalFilter, limit int) ([]storage.SessionSignals, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	where, arguments, err := sessionSignalWhere(filter)
	if err != nil {
		return nil, err
	}
	arguments = append(arguments, limit)
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+sessionSignalColumns+`
FROM session_signals AS s WHERE `+where+` AND s.cost_usd IS NOT NULL
ORDER BY s.cost_usd DESC, s.last_ns DESC LIMIT `+parameter(len(arguments)), arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list costly sessions: %w", err)
	}
	defer rows.Close()
	out := make([]storage.SessionSignals, 0)
	for rows.Next() {
		row, err := scanSessionSignals(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan costly session: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
