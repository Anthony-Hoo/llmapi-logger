package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

// stagedRestoreWrite is one RestoreStagedChunks operation; the writer fills
// in the result.
type stagedRestoreWrite struct {
	restore storage.StagedChunkRestore
	result  storage.StagedChunkRestoreResult
}

// RestoreStagedChunks inserts the chunks of one local staging file that the
// database does not have yet, in one writer operation, and says what it found
// (doc/design/issue-59-stage3-write-path.md F.7). It runs at start-up, before
// RecoverInterruptedAudits. A finalized audit is never changed. Repeating it
// is a no-op. It always gets a transaction of its own: a file may hold up to
// audit.staging.max_bytes of chunks.
func (store *Store) RestoreStagedChunks(ctx context.Context, restore storage.StagedChunkRestore) (storage.StagedChunkRestoreResult, error) {
	if restore.AuditID == "" {
		return storage.StagedChunkRestoreResult{}, errors.New("postgres: restore staged chunks: empty audit id")
	}
	write := &stagedRestoreWrite{restore: restore}
	if err := store.submitSync(ctx, writeRequest{kind: writeRestoreStagedChunks, data: write, payloadBytes: aloneWritePayloadBytes + 1}); err != nil {
		return storage.StagedChunkRestoreResult{}, err
	}
	return write.result, nil
}

func restoreStagedChunks(transaction dbTransaction, write *stagedRestoreWrite) error {
	auditID := write.restore.AuditID
	write.result = storage.StagedChunkRestoreResult{}
	var ended sql.NullInt64
	err := transaction.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id = $1", auditID).Scan(&ended)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		write.result.Outcome = storage.StagedRestoreNoAudit
		return nil
	case err != nil:
		return fmt.Errorf("postgres writer: read staged audit: %w", err)
	case ended.Valid:
		write.result.Outcome = storage.StagedRestoreFinalized
		return nil
	}
	bodies := map[string]string{}
	rows, err := transaction.Query("SELECT stage, source_stage FROM body_streams WHERE audit_id = $1", auditID)
	if err != nil {
		return fmt.Errorf("postgres writer: list staged bodies: %w", err)
	}
	for rows.Next() {
		var stage, source string
		if err := rows.Scan(&stage, &source); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres writer: scan staged body: %w", err)
		}
		bodies[stage] = source
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres writer: close staged bodies: %w", err)
	}
	stored := map[string]storage.StoredChunkRun{}
	rows, err = transaction.Query("SELECT stage, COUNT(*), COALESCE(SUM(plaintext_length), 0) FROM body_chunks WHERE audit_id = $1 GROUP BY stage", auditID)
	if err != nil {
		return fmt.Errorf("postgres writer: list staged chunk runs: %w", err)
	}
	for rows.Next() {
		var stage string
		var run storage.StoredChunkRun
		if err := rows.Scan(&stage, &run.Next, &run.End); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres writer: scan staged chunk run: %w", err)
		}
		stored[stage] = run
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres writer: close staged chunk runs: %w", err)
	}
	plan := storage.NewStagedRestorePlan(bodies, stored)
	if err := insertChunkRows(transaction, auditID, plan.Filter(write.restore.Chunks), nil); err != nil {
		return err
	}
	write.result = plan.Result()
	return nil
}
