package postgres

import "llmapi-logger/internal/storage"

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AnalysisBackfillCursor is the keyset position after which the next backfill
// page continues. Pages run oldest first, so the cursor only moves forwards.
type AnalysisBackfillCursor = storage.AnalysisBackfillCursor

// AnalysisBackfillCandidate names one parsed audit that has no current
// audit_analysis row.
type AnalysisBackfillCandidate = storage.AnalysisBackfillCandidate

// analysisBackfillQuery builds the candidate query. The cursor is a row
// comparison so that audit_records_started_idx (started_at_ns, audit_id)
// starts its range scan at the cursor: the parser worker starts each pass at
// its watermark, so in the steady state only rows written since the last pass
// are read, not the whole table.
func analysisBackfillQuery(version int, after *AnalysisBackfillCursor, limit int) (string, []any) {
	query := `
SELECT ar.audit_id, ar.started_at_ns
FROM audit_records AS ar
LEFT JOIN audit_analysis AS aa ON aa.audit_id = ar.audit_id
WHERE ar.ended_at_ns IS NOT NULL
  AND ar.parse_status IN ('ok', 'partial')
  AND (aa.audit_id IS NULL OR aa.analysis_version < $1)`
	arguments := []any{version}
	if after != nil {
		query += `
  AND (ar.started_at_ns, ar.audit_id) > ($2, $3)`
		arguments = append(arguments, after.StartedAtNS, after.AuditID)
	}
	query += `
ORDER BY ar.started_at_ns ASC, ar.audit_id ASC
LIMIT ` + parameter(len(arguments)+1)
	return query, append(arguments, limit)
}

// ListAnalysisBackfillCandidates returns up to limit ended audits whose parse
// status is ok or partial and whose audit_analysis row is missing or older than
// version, oldest first, so a session's earlier audits are analysed before the
// later ones that link to them. The LEFT JOIN uses the primary key. A nil
// after starts from the oldest audit.
func (store *Store) ListAnalysisBackfillCandidates(ctx context.Context, version int, after *AnalysisBackfillCursor, limit int) ([]AnalysisBackfillCandidate, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if version <= 0 || limit <= 0 || limit > maxParserReadLimit {
		return nil, fmt.Errorf("postgres: invalid analysis backfill request")
	}

	query, arguments := analysisBackfillQuery(version, after, limit)
	rows, err := store.readerDB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list analysis backfill candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]AnalysisBackfillCandidate, 0, limit)
	for rows.Next() {
		var candidate AnalysisBackfillCandidate
		if err := rows.Scan(&candidate.AuditID, &candidate.StartedAtNS); err != nil {
			return nil, fmt.Errorf("postgres: scan analysis backfill candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate analysis backfill candidates: %w", err)
	}
	return candidates, nil
}

// analysisBackfillHorizonQuery reads the newest audit position by one
// backward step of audit_records_started_idx.
const analysisBackfillHorizonQuery = `
SELECT started_at_ns, audit_id
FROM audit_records
ORDER BY started_at_ns DESC, audit_id DESC
LIMIT 1`

// AnalysisBackfillHorizon returns the newest audit position, in the order the
// insights backfill lists candidates. False means there is no audit.
func (store *Store) AnalysisBackfillHorizon(ctx context.Context) (AnalysisBackfillCursor, bool, error) {
	if ctx == nil {
		return AnalysisBackfillCursor{}, false, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return AnalysisBackfillCursor{}, false, ErrClosed
	}
	var horizon AnalysisBackfillCursor
	err := store.readerDB.QueryRowContext(ctx, analysisBackfillHorizonQuery).Scan(&horizon.StartedAtNS, &horizon.AuditID)
	if errors.Is(err, sql.ErrNoRows) {
		return AnalysisBackfillCursor{}, false, nil
	}
	if err != nil {
		return AnalysisBackfillCursor{}, false, fmt.Errorf("postgres: read analysis backfill horizon: %w", err)
	}
	return horizon, true, nil
}
