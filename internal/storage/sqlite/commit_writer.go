package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// CommitAudit appends the final write of the unified write path and waits for
// its batch to commit, as FinishAuditWithResult does. It finalizes the rows
// earlier writes inserted, inserts the rest, and finalizes and signs the
// audit. The returned outcome is the committed one, which may be downgraded
// by earlier capture failures or, for an audit already finalized, is read
// back unchanged.
//
// A whole-batch failure, including a COMMIT with an uncertain outcome, is
// returned wrapping ErrWriteBatchFailed; the session may retry it. Only the
// attempt marked FinalAttempt leaves its outcome to write recovery when the
// batch fails or the queue is full. An operation-level failure is recorded
// for recovery at once and is never wrapped.
func (store *Store) CommitAudit(ctx context.Context, commit AuditCommit) (AuditFinish, error) {
	owned := cloneAuditCommit(commit)
	owned.Finish.Defaults()
	for index := range owned.Stages {
		if body := owned.Stages[index].Body; body != nil {
			commitBodyDefaults(body, owned.Stages[index].Timeline)
		}
	}
	if err := storage.ValidateAuditCommit(owned); err != nil {
		return AuditFinish{}, err
	}
	if storage.EffectiveCaptureVersion(owned.CaptureVersion) != storage.CaptureVersion1 {
		return AuditFinish{}, errUnsupportedCaptureVersion
	}
	if err := store.submitSync(ctx, writeRequest{kind: writeCommitAudit, data: &owned}); err != nil {
		return AuditFinish{}, err
	}
	return cloneAuditFinish(owned.Finish), nil
}

// commitBodyDefaults applies the defaults FinishStage applies to a body
// finish, so both paths store the same values for the same input.
func commitBodyDefaults(body *BodyStream, timeline *StreamTimeline) {
	if body.SourceStage == "" {
		body.SourceStage = body.Stage
	}
	if body.RetentionState == "" {
		body.RetentionState = RetentionPending
	}
	if !body.StreamTimelineComplete && body.StreamEventCount == 0 && timeline == nil {
		body.StreamTimelineComplete = true
	}
}

// commitAudit is one CommitAudit inside the writer's per-operation savepoint.
// It never changes a finalized audit. When the stored capture status is
// failed, an earlier write was lost; parts whose rows are missing are then
// skipped and left to finalizeIncompleteCapture, so the audit still finalizes
// as failed instead of failing on a foreign key.
func commitAudit(transaction *sql.Tx, commit *AuditCommit, signer *security.IntegritySigner) error {
	auditID := commit.Finish.AuditID
	var ended sql.NullInt64
	var captureStatus string
	if err := transaction.QueryRow("SELECT ended_at_ns, capture_status FROM audit_records WHERE audit_id = ?", auditID).Scan(&ended, &captureStatus); err != nil {
		return fmt.Errorf("sqlite writer: read commit state: %w", err)
	}
	if ended.Valid {
		// A retry after an uncertain acknowledgement lands here.
		return loadFinishedOutcome(transaction, &commit.Finish)
	}
	failed := captureStatus == CaptureFailed
	for _, stage := range commit.Stages {
		if err := commitStage(transaction, auditID, stage, failed); err != nil {
			return err
		}
	}
	headers := commit.Headers
	keepChunk := func(string) bool { return true }
	if failed {
		stages, err := storedStageSet(transaction, "http_stages", auditID)
		if err != nil {
			return err
		}
		bodies, err := storedStageSet(transaction, "body_streams", auditID)
		if err != nil {
			return err
		}
		headers = make([]HTTPHeader, 0, len(commit.Headers))
		for _, header := range commit.Headers {
			if stages[header.Stage] {
				headers = append(headers, header)
			}
		}
		keepChunk = func(stage string) bool { return bodies[stage] }
	}
	if err := insertHeaders(transaction, headers); err != nil {
		return err
	}
	if err := insertOwnedChunks(transaction, auditID, commit.Chunks, keepChunk); err != nil {
		return err
	}
	return finishAuditWithDedup(transaction, &commit.Finish, signer, commit.DedupInDB)
}

// commitStage finalizes one stage: it updates the stage and body rows an
// earlier write inserted and inserts the others with their final values,
// which are the values legacy reaches by inserting the initial row and
// applying FinishStage.
func commitStage(transaction *sql.Tx, auditID string, commit StageCommit, failed bool) error {
	stage := commit.Stage
	if commit.StageWritten {
		result, err := updateStageFinal(transaction, StageFinish{
			AuditID:       auditID,
			Stage:         stage.Stage,
			State:         stage.State,
			StatusCode:    stage.StatusCode,
			ContentLength: stage.ContentLength,
			EndedAtNS:     *stage.EndedAtNS,
			ErrorCode:     stage.ErrorCode,
		})
		if err != nil {
			return err
		}
		present, err := commitRowPresent(result, failed, "commit stage")
		if err != nil || !present {
			return err
		}
	} else if err := insertStage(transaction, stage); err != nil {
		return err
	}
	if commit.Body == nil {
		return nil
	}
	body := *commit.Body
	if commit.BodyWritten {
		result, err := updateBodyFinal(transaction, auditID, stage.Stage, &body.SourceStage, bodyFinishOf(body))
		if err != nil {
			return err
		}
		present, err := commitRowPresent(result, failed, "commit body")
		if err != nil || !present {
			return err
		}
	} else {
		if failed && body.SourceStage != stage.Stage {
			present, err := stageRowExists(transaction, auditID, body.SourceStage)
			if err != nil || !present {
				return err
			}
		}
		if err := insertBody(transaction, body); err != nil {
			return err
		}
	}
	if commit.Timeline != nil {
		return upsertStreamTimeline(transaction, auditID, stage.Stage, *commit.Timeline)
	}
	return nil
}

// commitRowPresent checks that an update of an earlier written row found it.
// A missing row is expected only after a lost write, which has failed the
// audit; otherwise the store and the session disagree.
func commitRowPresent(result sql.Result, failed bool, operation string) (bool, error) {
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlite writer: %s rows affected: %w", operation, err)
	}
	switch {
	case rows == 1:
		return true, nil
	case rows == 0 && failed:
		return false, nil
	case rows == 0:
		return false, localWriteError(fmt.Sprintf("sqlite writer: %s affected no rows", operation))
	default:
		return false, fmt.Errorf("sqlite writer: %s affected %d rows", operation, rows)
	}
}

func stageRowExists(transaction *sql.Tx, auditID, stage string) (bool, error) {
	var exists int
	if err := transaction.QueryRow("SELECT EXISTS (SELECT 1 FROM http_stages WHERE audit_id = ? AND stage = ?)", auditID, stage).Scan(&exists); err != nil {
		return false, fmt.Errorf("sqlite writer: read stage row: %w", err)
	}
	return exists == 1, nil
}

// storedStageSet lists the stages that have a row in table (http_stages or
// body_streams) for one audit.
func storedStageSet(transaction *sql.Tx, table, auditID string) (map[string]bool, error) {
	rows, err := transaction.Query("SELECT stage FROM "+table+" WHERE audit_id = ?", auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: list %s stages: %w", table, err)
	}
	stages := make(map[string]bool, 4)
	for rows.Next() {
		var stage string
		if err := rows.Scan(&stage); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("sqlite writer: scan %s stage: %w", table, err)
		}
		stages[stage] = true
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("sqlite writer: close %s stages: %w", table, err)
	}
	return stages, nil
}

func bodyFinishOf(body BodyStream) BodyFinish {
	return BodyFinish{
		ObservedLength:         body.ObservedLength,
		StoredLength:           body.StoredLength,
		SHA256:                 body.SHA256,
		HashComplete:           body.HashComplete,
		EOFSeen:                body.EOFSeen,
		State:                  body.State,
		RetentionState:         body.RetentionState,
		FirstObservedAtNS:      body.FirstObservedAtNS,
		LastObservedAtNS:       body.LastObservedAtNS,
		ChunkCount:             body.ChunkCount,
		StreamEventCount:       body.StreamEventCount,
		StreamTimelineComplete: body.StreamTimelineComplete,
		ErrorCode:              body.ErrorCode,
	}
}

func cloneAuditCommit(commit AuditCommit) AuditCommit {
	owned := commit
	owned.Finish = cloneAuditFinish(commit.Finish)
	owned.Chunks = cloneChunkSource(commit.Chunks)
	if commit.HeaderBlock != nil {
		block := *commit.HeaderBlock
		block.DataEnc = cloneBytes(block.DataEnc)
		owned.HeaderBlock = &block
	}
	owned.Headers = nil
	for _, header := range commit.Headers {
		owned.Headers = append(owned.Headers, cloneHTTPHeader(header))
	}
	owned.Stages = nil
	for _, stage := range commit.Stages {
		stage.Stage = cloneHTTPStage(stage.Stage)
		stage.ContentType = cloneString(stage.ContentType)
		stage.ContentEncoding = cloneString(stage.ContentEncoding)
		if stage.Body != nil {
			body := cloneBodyStream(*stage.Body)
			stage.Body = &body
		}
		if stage.Timeline != nil {
			timeline := *stage.Timeline
			timeline.FirstEventAtNS = cloneInt64(timeline.FirstEventAtNS)
			timeline.LastEventAtNS = cloneInt64(timeline.LastEventAtNS)
			timeline.DataEnc = cloneBytes(timeline.DataEnc)
			stage.Timeline = &timeline
		}
		owned.Stages = append(owned.Stages, stage)
	}
	return owned
}
