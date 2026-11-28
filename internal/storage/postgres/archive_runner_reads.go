package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/archive"
)

// Reads the archive runner needs besides the snapshot's audit selection:
// the expired gaps to export (C.6, H.2) and an audit's current change stamp
// for the run-time read-equivalence sample (J.3).

// LatestSchemaVersion is the migration version an open store has: the
// source_schema_version of the bundles written from it.
const LatestSchemaVersion = latestSchemaVersion

// DueGaps returns the audit_gaps rows that ended before cutoffNS and are in
// no archive segment, in id order after afterID, at most limit. Gaps are
// only ever inserted, so a gap has no revision and is exported once.
func (snapshot *ArchiveSnapshot) DueGaps(cutoffNS, afterID int64, limit int) ([]archive.Gap, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres archive: invalid gap selection")
	}
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT g.id, g.started_at_ns, g.ended_at_ns, g.reason, g.request_count, g.detail, g.created_at_ns
FROM audit_gaps AS g
WHERE g.ended_at_ns < $1 AND g.id > $2
  AND NOT EXISTS (SELECT 1 FROM archive_gap_members AS m WHERE m.gap_id = g.id)
ORDER BY g.id
LIMIT $3`, cutoffNS, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: select gaps: %w", err)
	}
	var gaps []archive.Gap
	for rows.Next() {
		var gap archive.Gap
		if err := rows.Scan(&gap.ID, &gap.StartedAtNS, &gap.EndedAtNS, &gap.Reason, &gap.RequestCount, &gap.Detail, &gap.CreatedAtNS); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan gap: %w", err)
		}
		gaps = append(gaps, gap)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: select gaps: %w", err)
	}
	return gaps, nil
}

// ArchiveChangeStamp computes the audit's change stamp (M.1) as the hot
// store holds it now, in one read-only snapshot of the reader pool; exists
// is false when the audit is gone. The runner compares it with the export
// snapshot's stamp when a read-equivalence sample differs (J.3).
func (store *Store) ArchiveChangeStamp(ctx context.Context, auditID string) (stamp [32]byte, exists bool, err error) {
	if err := store.archiveReadable(ctx); err != nil {
		return stamp, false, err
	}
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return stamp, false, fmt.Errorf("postgres archive: begin stamp read: %w", err)
	}
	defer transaction.Rollback()
	return archiveChangeStamp(ctx, transaction, auditID)
}
