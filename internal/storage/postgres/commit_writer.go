package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// commitWrite is the writer's owned copy of one AuditCommit. finishAudit
// updates Finish in place to the committed outcome. As for a checkpoint, the
// chunk source is handed over, not copied.
type commitWrite struct {
	AuditCommit
}

// finishRequest is the FinishAudit the commit ends with, for the failure
// bookkeeping that records the outcome alone.
func (commit *commitWrite) finishRequest(sequence uint64) writeRequest {
	finish := cloneAuditFinish(commit.Finish)
	return writeRequest{kind: writeFinishAudit, data: &finish, sequence: sequence}
}

func (commit *commitWrite) chunkBounds() [4]int64 {
	return chunkBoundsOf(commit.Chunks)
}

// CommitAudit writes the rest of an audit and finalizes it, waiting for its
// batch like FinishAuditWithResult (B.6). It returns the committed outcome,
// which a recorded capture failure may have downgraded. A failure of the whole
// batch, including an uncertain COMMIT, wraps ErrWriteBatchFailed and may be
// retried: an audit that is already finalized is only read back.
func (store *Store) CommitAudit(ctx context.Context, commit AuditCommit) (AuditFinish, error) {
	commit.Finish.Defaults()
	commit.Stages = append([]StageCommit(nil), commit.Stages...)
	for index := range commit.Stages {
		if body := commit.Stages[index].Body; body != nil {
			owned := *body
			commitBodyDefaults(&owned, commit.Stages[index].Timeline)
			commit.Stages[index].Body = &owned
		}
	}
	if err := validateAuditFinish(commit.Finish); err != nil {
		return AuditFinish{}, err
	}
	if err := storage.ValidateAuditCommit(commit); err != nil {
		return AuditFinish{}, err
	}
	if err := requireCaptureVersion(commit.CaptureVersion); err != nil {
		return AuditFinish{}, err
	}
	owned := cloneAuditCommit(commit)
	payload := max(commit.PayloadBytes, chunkPayloadBytes(commit.Chunks))
	if err := store.submitSync(ctx, writeRequest{kind: writeCommitAudit, data: owned, payloadBytes: payload}); err != nil {
		return AuditFinish{}, err
	}
	return owned.Finish, nil
}

// commitBodyDefaults applies the defaults StageFinish gives a finished body.
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

// presentRows lists the stage and body rows of an audit that a failed
// checkpoint may have left incomplete.
type presentRows struct {
	stages map[string]bool
	bodies map[string]bool
}

func loadPresentRows(transaction dbTransaction, auditID string) (*presentRows, error) {
	rows, err := transaction.Query(`
SELECT 's', stage FROM http_stages WHERE audit_id = $1
UNION ALL
SELECT 'b', stage FROM body_streams WHERE audit_id = $1`, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres writer: read stored capture rows: %w", err)
	}
	present := &presentRows{stages: make(map[string]bool), bodies: make(map[string]bool)}
	for rows.Next() {
		var table, stage string
		if err := rows.Scan(&table, &stage); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres writer: scan stored capture rows: %w", err)
		}
		if table == "s" {
			present.stages[stage] = true
		} else {
			present.bodies[stage] = true
		}
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres writer: close stored capture rows: %w", err)
	}
	return present, nil
}

// applyCommit is the commit's single savepoint (B.6):
//
//  1. an audit already finalized is only read back;
//  2. stages an earlier write inserted are finished with finishStage, the
//     others are inserted with their final values, and so are bodies no
//     checkpoint wrote;
//  3. a request pair merged at checkpoint 1 that no longer qualifies points
//     back at itself (its own chunks come with the commit's chunks);
//  4. the remaining header groups (version 1) or the complete header block
//     (version 2) and the remaining chunks are written;
//  5. finishAudit finalizes, merging in the database only the pairs the
//     session left to it.
//
// When a recorded capture failure marked the audit failed, a checkpoint may
// be missing. Parts whose rows are absent are skipped, as the legacy writes
// would have failed one by one, and finalizeIncompleteCapture reconciles.
func applyCommit(transaction dbTransaction, commit *commitWrite, signer *security.IntegritySigner) error {
	auditID := commit.Finish.AuditID
	var ended sql.NullInt64
	var captureStatus string
	var captureVersion int
	if err := transaction.QueryRow("SELECT ended_at_ns, capture_status, capture_version FROM audit_records WHERE audit_id=$1 FOR UPDATE", auditID).Scan(&ended, &captureStatus, &captureVersion); err != nil {
		return fmt.Errorf("postgres writer: read commit audit: %w", err)
	}
	if ended.Valid {
		// A retry after an uncertain commit, or recovery got there first.
		return loadFinishedOutcome(transaction, &commit.Finish)
	}
	// capture_version is fixed by BeginAudit; the commit must be of the same
	// version (D.3).
	if captureVersion != storage.EffectiveCaptureVersion(commit.CaptureVersion) {
		return localWriteError("postgres writer: commit capture version differs from the audit row")
	}
	var present *presentRows
	if captureStatus == CaptureFailed {
		var err error
		if present, err = loadPresentRows(transaction, auditID); err != nil {
			return err
		}
	}
	stagePresent := func(stage string) bool { return present == nil || present.stages[stage] }
	bodyPresent := func(stage string) bool { return present == nil || present.bodies[stage] }

	newStages := make([]HTTPStage, 0, len(commit.Stages))
	newContents := make(map[string]StageContent, len(commit.Stages))
	newBodies := make([]BodyStream, 0, len(commit.Stages))
	type pendingTimeline struct {
		stage    string
		timeline *StreamTimeline
	}
	timelines := make([]pendingTimeline, 0, 1)
	insertedStages := make(map[string]bool, len(commit.Stages))
	insertedBodies := make(map[string]bool, len(commit.Stages))
	for _, stage := range commit.Stages {
		name := stage.Stage.Stage
		if !stage.StageWritten {
			newStages = append(newStages, cloneHTTPStage(stage.Stage))
			newContents[name] = StageContent{Stage: name, ContentType: stage.ContentType, ContentEncoding: stage.ContentEncoding}
			insertedStages[name] = true
			if stage.Body != nil {
				newBodies = append(newBodies, *stage.Body)
				insertedBodies[name] = true
				if stage.Timeline != nil {
					timelines = append(timelines, pendingTimeline{name, stage.Timeline})
				}
			}
			continue
		}
		if !stagePresent(name) || stage.BodyWritten && !bodyPresent(name) {
			// The failed checkpoint's rows are missing: as a legacy
			// FinishStage on them would have, leave the stage to
			// finalizeIncompleteCapture.
			continue
		}
		if stage.BodyWritten {
			if (name == StageRequestSent || name == StageResponseSent) && stage.Body.SourceStage == name {
				// Un-merge a duplicate written in merged form (B.5); a body
				// that was never merged is left as it is.
				if _, err := transaction.Exec(`
UPDATE body_streams SET source_stage = $1
WHERE audit_id = $2 AND stage = $1 AND source_stage <> $1`, name, auditID); err != nil {
					return fmt.Errorf("postgres writer: unmerge duplicate body stream: %w", err)
				}
			}
			if err := finishStage(transaction, stageFinishOf(stage, true)); err != nil {
				return err
			}
			continue
		}
		if err := finishStage(transaction, stageFinishOf(stage, false)); err != nil {
			return err
		}
		if stage.Body != nil {
			newBodies = append(newBodies, *stage.Body)
			insertedBodies[name] = true
			if stage.Timeline != nil {
				timelines = append(timelines, pendingTimeline{name, stage.Timeline})
			}
		}
	}
	if err := insertStageRows(transaction, newStages, newContents); err != nil {
		return err
	}
	if err := insertBodyRows(transaction, newBodies); err != nil {
		return err
	}
	for _, pending := range timelines {
		if err := saveStreamTimeline(transaction, auditID, pending.stage, pending.timeline); err != nil {
			return err
		}
	}
	headers := commit.Headers
	if present != nil {
		headers = make([]HTTPHeader, 0, len(commit.Headers))
		for _, header := range commit.Headers {
			if present.stages[header.Stage] || insertedStages[header.Stage] {
				headers = append(headers, header)
			}
		}
	}
	if err := insertHeaderRows(transaction, headers); err != nil {
		return err
	}
	// Version 2: the complete block, nil when the last checkpoint already
	// wrote the same one.
	if err := upsertHeaderBlock(transaction, auditID, commit.HeaderBlock); err != nil {
		return err
	}
	var keep func(string) bool
	if present != nil {
		keep = func(stage string) bool { return present.bodies[stage] || insertedBodies[stage] }
	}
	if err := insertChunkRows(transaction, auditID, commit.Chunks, keep); err != nil {
		return err
	}
	return finishAudit(transaction, &commit.Finish, signer, commit.DedupInDB)
}

// stageFinishOf is the FinishStage a legacy session sends for the stage;
// withBody false leaves the body to a separate insert.
func stageFinishOf(stage StageCommit, withBody bool) StageFinish {
	finish := StageFinish{
		AuditID:       stage.Stage.AuditID,
		Stage:         stage.Stage.Stage,
		State:         stage.Stage.State,
		StatusCode:    stage.Stage.StatusCode,
		ContentLength: stage.Stage.ContentLength,
		EndedAtNS:     *stage.Stage.EndedAtNS,
		ErrorCode:     stage.Stage.ErrorCode,
	}
	if withBody && stage.Body != nil {
		body := stage.Body
		finish.Body = &BodyFinish{
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
			Timeline:               stage.Timeline,
			ErrorCode:              body.ErrorCode,
		}
	}
	return finish
}

func cloneAuditCommit(commit AuditCommit) *commitWrite {
	owned := &commitWrite{AuditCommit: AuditCommit{
		Finish:         cloneAuditFinish(commit.Finish),
		CaptureVersion: commit.CaptureVersion,
		Stages:         make([]StageCommit, len(commit.Stages)),
		Headers:        make([]HTTPHeader, len(commit.Headers)),
		HeaderBlock:    cloneHeaderBlock(commit.HeaderBlock),
		Chunks:         commit.Chunks,
		DedupInDB:      commit.DedupInDB,
		FinalAttempt:   commit.FinalAttempt,
		PayloadBytes:   commit.PayloadBytes,
	}}
	for index, stage := range commit.Stages {
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
		owned.Stages[index] = stage
	}
	for index, header := range commit.Headers {
		owned.Headers[index] = cloneHTTPHeader(header)
	}
	return owned
}
