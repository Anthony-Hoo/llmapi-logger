package postgres

import (
	"context"
	"fmt"
)

// InsertAuditGaps persists a validated batch through the ordered writer. The
// fixed reason/detail pairs prevent callers from storing raw dependency errors.
func (store *Store) InsertAuditGaps(ctx context.Context, gaps []AuditGap) error {
	if len(gaps) == 0 {
		return nil
	}
	owned := make([]AuditGap, len(gaps))
	for index, gap := range gaps {
		if err := validateAuditGap(gap); err != nil {
			return fmt.Errorf("gap %d: %w", index, err)
		}
		owned[index] = gap
	}
	return store.submitSync(ctx, writeRequest{kind: writeInsertAuditGaps, data: owned})
}

func insertAuditGaps(transaction dbTransaction, gaps []AuditGap) error {
	for _, gap := range gaps {
		if _, err := transaction.Exec(`
INSERT INTO audit_gaps (
    started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6)`,
			gap.StartedAtNS,
			gap.EndedAtNS,
			gap.Reason,
			gap.RequestCount,
			gap.Detail,
			gap.CreatedAtNS,
		); err != nil {
			return fmt.Errorf("postgres writer: insert audit gap: %w", err)
		}
	}
	return nil
}
