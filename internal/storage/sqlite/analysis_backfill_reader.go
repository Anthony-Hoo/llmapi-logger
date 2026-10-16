package sqlite

import (
	"context"
	"errors"
	"fmt"
)

// AnalysisBackfillCursor is the keyset position after which the next backfill
// page continues. Pages run oldest first, so the cursor only moves forwards.
type AnalysisBackfillCursor struct {
	StartedAtNS int64
	AuditID     string
}

// AnalysisBackfillCandidate names one parsed audit that has no current
// audit_analysis row.
type AnalysisBackfillCandidate struct {
	AuditID     string
	StartedAtNS int64
}

// ListAnalysisBackfillCandidates returns up to limit ended audits whose parse
// status is ok or partial and whose audit_analysis row is missing or older than
// version, oldest first, so a session's earlier audits are analysed before the
// later ones that link to them. The LEFT JOIN uses the primary key, and the
// audit_analysis_version_idx index keeps the version predicate cheap.
// A nil after starts from the oldest audit.
func (store *Store) ListAnalysisBackfillCandidates(ctx context.Context, version int, after *AnalysisBackfillCursor, limit int) ([]AnalysisBackfillCandidate, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if version <= 0 || limit <= 0 || limit > maxParserReadLimit {
		return nil, fmt.Errorf("sqlite: invalid analysis backfill request")
	}

	query := `
SELECT ar.audit_id, ar.started_at_ns
FROM audit_records AS ar
LEFT JOIN audit_analysis AS aa ON aa.audit_id = ar.audit_id
WHERE ar.ended_at_ns IS NOT NULL
  AND ar.parse_status IN ('ok', 'partial')
  AND (aa.audit_id IS NULL OR aa.analysis_version < ?)`
	arguments := []any{version}
	if after != nil {
		query += `
  AND (ar.started_at_ns > ? OR (ar.started_at_ns = ? AND ar.audit_id > ?))`
		arguments = append(arguments, after.StartedAtNS, after.StartedAtNS, after.AuditID)
	}
	query += `
ORDER BY ar.started_at_ns ASC, ar.audit_id ASC
LIMIT ?`
	arguments = append(arguments, limit)

	rows, err := store.readerDB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list analysis backfill candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]AnalysisBackfillCandidate, 0, limit)
	for rows.Next() {
		var candidate AnalysisBackfillCandidate
		if err := rows.Scan(&candidate.AuditID, &candidate.StartedAtNS); err != nil {
			return nil, fmt.Errorf("sqlite: scan analysis backfill candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate analysis backfill candidates: %w", err)
	}
	return candidates, nil
}
