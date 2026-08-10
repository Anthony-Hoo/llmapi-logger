package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type retentionRequest struct {
	CutoffNS   int64
	AuditLimit int
	GapLimit   int
	Result     RetentionResult
}

// DeleteExpired removes one bounded batch of terminal audits and gaps. Audit
// children are deleted by the schema's foreign-key cascades.
func (store *Store) DeleteExpired(ctx context.Context, cutoffNS int64, auditLimit, gapLimit int) (RetentionResult, error) {
	if cutoffNS <= 0 {
		return RetentionResult{}, errors.New("sqlite: invalid retention cutoff")
	}
	if auditLimit < 0 || auditLimit > RetentionBatchLimit || gapLimit < 0 || gapLimit > RetentionBatchLimit || (auditLimit == 0 && gapLimit == 0) {
		return RetentionResult{}, fmt.Errorf("sqlite: retention limits must each be between 0 and %d, with at least one positive", RetentionBatchLimit)
	}
	request := &retentionRequest{CutoffNS: cutoffNS, AuditLimit: auditLimit, GapLimit: gapLimit}
	if err := store.submitSync(ctx, writeRequest{kind: writeDeleteExpired, data: request}); err != nil {
		return RetentionResult{}, err
	}
	return request.Result, nil
}

func deleteExpired(transaction *sql.Tx, request *retentionRequest) error {
	if request == nil || request.CutoffNS <= 0 ||
		request.AuditLimit < 0 || request.AuditLimit > RetentionBatchLimit ||
		request.GapLimit < 0 || request.GapLimit > RetentionBatchLimit ||
		(request.AuditLimit == 0 && request.GapLimit == 0) {
		return errors.New("sqlite writer: invalid retention request")
	}

	audits, err := transaction.Exec(`
DELETE FROM audit_records
WHERE audit_id IN (
    SELECT audit_id
    FROM audit_records
    WHERE ended_at_ns IS NOT NULL
      AND started_at_ns < ?
      AND parse_status <> 'processing'
    ORDER BY started_at_ns, audit_id
    LIMIT ?
)`, request.CutoffNS, request.AuditLimit)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete expired audits: %w", err)
	}
	deletedAudits, err := audits.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: count deleted audits: %w", err)
	}

	gaps, err := transaction.Exec(`
DELETE FROM audit_gaps
WHERE id IN (
    SELECT id
    FROM audit_gaps
    WHERE ended_at_ns < ?
    ORDER BY ended_at_ns, id
    LIMIT ?
)`, request.CutoffNS, request.GapLimit)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete expired gaps: %w", err)
	}
	deletedGaps, err := gaps.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: count deleted gaps: %w", err)
	}

	request.Result = RetentionResult{
		DeletedAudits: int(deletedAudits),
		DeletedGaps:   int(deletedGaps),
	}
	return nil
}
