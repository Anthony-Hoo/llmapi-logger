package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type recoveryRequest struct {
	NowNS     int64
	Recovered int
}

// RecoverInterruptedAudits atomically finalizes audits left open by a prior
// process, repairs the recoverable body lengths from committed chunks, and
// inserts one aggregate process-exit gap. Repeating it is a no-op.
func (store *Store) RecoverInterruptedAudits(ctx context.Context, nowNS int64) (int, error) {
	if nowNS <= 0 {
		return 0, errors.New("sqlite: invalid recovery time")
	}
	request := &recoveryRequest{NowNS: nowNS}
	if err := store.submitSync(ctx, writeRequest{kind: writeRecoverInterruptedAudits, data: request}); err != nil {
		return 0, err
	}
	return request.Recovered, nil
}

func recoverInterruptedAudits(transaction *sql.Tx, request *recoveryRequest) error {
	if request == nil || request.NowNS <= 0 {
		return errors.New("sqlite writer: invalid recovery request")
	}

	var count int
	var startedAtNS sql.NullInt64
	if err := transaction.QueryRow(`
SELECT COUNT(*), MIN(started_at_ns)
FROM audit_records
WHERE ended_at_ns IS NULL`).Scan(&count, &startedAtNS); err != nil {
		return fmt.Errorf("sqlite writer: inspect interrupted audits: %w", err)
	}
	if count == 0 {
		request.Recovered = 0
		return nil
	}

	if _, err := transaction.Exec(`
WITH chunk_lengths AS (
    SELECT audit_id, stage,
           SUM(plaintext_length) AS stored_length,
           MAX("offset" + plaintext_length) AS observed_length
    FROM body_chunks
    GROUP BY audit_id, stage
)
UPDATE body_streams
SET stored_length = COALESCE((
        SELECT lengths.stored_length
        FROM chunk_lengths AS lengths
        WHERE lengths.audit_id = body_streams.audit_id
          AND lengths.stage = body_streams.stage
    ), 0),
    observed_length = MAX(
        COALESCE((
            SELECT lengths.stored_length
            FROM chunk_lengths AS lengths
            WHERE lengths.audit_id = body_streams.audit_id
              AND lengths.stage = body_streams.stage
        ), 0),
        COALESCE((
            SELECT lengths.observed_length
            FROM chunk_lengths AS lengths
            WHERE lengths.audit_id = body_streams.audit_id
              AND lengths.stage = body_streams.stage
        ), 0)
    ),
    sha256 = NULL,
    hash_complete = 0,
    eof_seen = 0,
    state = 'partial',
    error_code = 'process_exit'
WHERE state = 'streaming'
  AND EXISTS (
      SELECT 1
      FROM audit_records AS audit
      WHERE audit.audit_id = body_streams.audit_id
        AND audit.ended_at_ns IS NULL
  )`); err != nil {
		return fmt.Errorf("sqlite writer: recover body streams: %w", err)
	}

	if _, err := transaction.Exec(`
UPDATE http_stages
SET state = 'partial',
    ended_at_ns = COALESCE(ended_at_ns, ?),
    error_code = 'process_exit'
WHERE state = 'streaming'
  AND EXISTS (
      SELECT 1
      FROM audit_records AS audit
      WHERE audit.audit_id = http_stages.audit_id
        AND audit.ended_at_ns IS NULL
  )`, request.NowNS); err != nil {
		return fmt.Errorf("sqlite writer: recover HTTP stages: %w", err)
	}

	result, err := transaction.Exec(`
UPDATE audit_records
SET ended_at_ns = ?,
    forward_status = 'interrupted',
    capture_status = 'partial',
    error_code = 'process_exit'
WHERE ended_at_ns IS NULL`, request.NowNS)
	if err != nil {
		return fmt.Errorf("sqlite writer: recover interrupted audits: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: count recovered audits: %w", err)
	}
	if rows != int64(count) {
		return fmt.Errorf("sqlite writer: recovered %d audits after selecting %d", rows, count)
	}

	gap := AuditGap{
		StartedAtNS:  startedAtNS.Int64,
		EndedAtNS:    request.NowNS,
		Reason:       GapReasonProcessExit,
		RequestCount: count,
		Detail:       GapDetailProcessExit,
		CreatedAtNS:  request.NowNS,
	}
	if err := insertAuditGaps(transaction, []AuditGap{gap}); err != nil {
		return fmt.Errorf("sqlite writer: record recovery gap: %w", err)
	}
	request.Recovered = count
	return nil
}
