package sqlite

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
// is a no-op.
func (store *Store) RestoreStagedChunks(ctx context.Context, restore storage.StagedChunkRestore) (storage.StagedChunkRestoreResult, error) {
	if restore.AuditID == "" {
		return storage.StagedChunkRestoreResult{}, errors.New("sqlite: restore staged chunks: empty audit id")
	}
	write := &stagedRestoreWrite{restore: restore}
	if err := store.submitSync(ctx, writeRequest{kind: writeRestoreStagedChunks, data: write}); err != nil {
		return storage.StagedChunkRestoreResult{}, err
	}
	return write.result, nil
}

func restoreStagedChunks(transaction *sql.Tx, write *stagedRestoreWrite) error {
	auditID := write.restore.AuditID
	write.result = storage.StagedChunkRestoreResult{}
	var ended sql.NullInt64
	err := transaction.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id = ?", auditID).Scan(&ended)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		write.result.Outcome = storage.StagedRestoreNoAudit
		return nil
	case err != nil:
		return fmt.Errorf("sqlite writer: read staged audit: %w", err)
	case ended.Valid:
		// A finalized audit is never changed. Say what it lacks, so the
		// import keeps a file whose chunks never reached the database.
		plan, err := loadStagedRestorePlan(transaction, auditID)
		if err != nil {
			return err
		}
		missing := 0
		if err := plan.Filter(write.restore.Chunks).Each(func(BodyChunk) error { missing++; return nil }); err != nil {
			return localWriteError("sqlite writer: read staged chunks failed")
		}
		write.result = plan.Result()
		write.result.Outcome = storage.StagedRestoreFinalized
		write.result.Missing = missing
		return nil
	}
	result, err := insertStagedChunks(transaction, auditID, write.restore.Chunks)
	if err != nil {
		return err
	}
	write.result = result
	return nil
}

// insertStagedChunks inserts, into an open audit, the staged chunks that
// continue each owning body's stored chunks (storage.StagedRestorePlan).
// The start-up import and the recovery of a failed final commit use it.
func insertStagedChunks(transaction *sql.Tx, auditID string, source ChunkSource) (storage.StagedChunkRestoreResult, error) {
	plan, err := loadStagedRestorePlan(transaction, auditID)
	if err != nil {
		return storage.StagedChunkRestoreResult{}, err
	}
	if err := insertOwnedChunks(transaction, auditID, plan.Filter(source), nil); err != nil {
		return storage.StagedChunkRestoreResult{}, err
	}
	return plan.Result(), nil
}

// loadStagedRestorePlan reads which bodies own their chunks and how far each
// body's stored chunks go.
func loadStagedRestorePlan(transaction *sql.Tx, auditID string) (*storage.StagedRestorePlan, error) {
	bodies := map[string]string{}
	rows, err := transaction.Query("SELECT stage, source_stage FROM body_streams WHERE audit_id = ?", auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: list staged bodies: %w", err)
	}
	for rows.Next() {
		var stage, source string
		if err := rows.Scan(&stage, &source); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("sqlite writer: scan staged body: %w", err)
		}
		bodies[stage] = source
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("sqlite writer: close staged bodies: %w", err)
	}
	stored := map[string]storage.StoredChunkRun{}
	rows, err = transaction.Query("SELECT stage, COUNT(*), COALESCE(SUM(plaintext_length), 0) FROM body_chunks WHERE audit_id = ? GROUP BY stage", auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: list staged chunk runs: %w", err)
	}
	for rows.Next() {
		var stage string
		var run storage.StoredChunkRun
		if err := rows.Scan(&stage, &run.Next, &run.End); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("sqlite writer: scan staged chunk run: %w", err)
		}
		stored[stage] = run
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("sqlite writer: close staged chunk runs: %w", err)
	}
	return storage.NewStagedRestorePlan(bodies, stored), nil
}
