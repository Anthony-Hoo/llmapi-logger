package audit

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"llmapi-logger/internal/storage"
)

// finish fixes the forward status and every stage and body state (the
// decisions, mismatch, timelines and clock reads the legacy path made the
// same way), builds one AuditCommit and waits for it, retrying as design B.8
// says.
func (session *Session) finish() error {
	session.mu.Lock()
	session.committing = true
	if session.forwardStatus == storage.ForwardInProgress {
		if session.request != nil && session.request.Err() != nil && !session.responseLogicallyCompleteLocked() {
			session.forwardStatus = storage.ForwardClientCancelled
			session.errorCode = stringPointer("client_cancelled")
		} else {
			session.forwardStatus = storage.ForwardCompleted
		}
	}
	if session.forwardStatus == storage.ForwardClientCancelled || session.forwardStatus == storage.ForwardNewAPIError || session.forwardStatus == storage.ForwardProxyError {
		session.captureFault = true
	}

	stageNames := make([]string, 0, len(session.stages))
	for name := range session.stages {
		stageNames = append(stageNames, name)
	}
	sort.Slice(stageNames, func(left, right int) bool { return stageOrder(stageNames[left]) < stageOrder(stageNames[right]) })

	// Every body ends here. The chunks of the stages that are nobody's
	// duplicate are needed whatever the pair decision, so they are sealed
	// before the stage states are fixed and a sealing failure shows in them.
	var chunks chunkSet
	for _, name := range stageNames {
		stage := session.stages[name]
		if stage.body != nil {
			session.flushBodyLocked(stage, stage.body, true)
		}
		if pairedBodySourceStage(name) == "" {
			chunks = append(chunks, session.sealUnwrittenLocked(stage)...)
		}
	}
	finishes := make(map[string]*storage.StageFinish, len(stageNames))
	for _, name := range stageNames {
		finish := session.finishStageLocked(session.stages[name])
		finishes[name] = &finish
	}

	commit := storage.AuditCommit{CaptureVersion: session.manager.captureVersion}
	mergedFrom := make(map[string]string, 2)
	for index, pair := range [2][2]string{{storage.StageRequestReceived, storage.StageRequestSent}, {storage.StageResponseReceived, storage.StageResponseSent}} {
		duplicate := session.stages[pair[1]]
		if duplicate == nil || duplicate.body == nil || finishes[pair[1]].Body == nil {
			continue
		}
		switch {
		case index == 0 && session.inboundNotStored,
			!duplicate.merged && (duplicate.bodyRowWritten || hasWrittenChunks(duplicate.body)):
			// The rows decide, as legacy: the store merges in the database
			// when the pair qualifies.
			commit.DedupInDB[index] = true
		case finishes[pair[0]] != nil && finalMergeable(finishes[pair[0]].Body, finishes[pair[1]].Body):
			mergedFrom[pair[1]] = pair[0]
			continue
		}
		// Not merged (or merged at checkpoint 1 and no longer equal): the
		// duplicate writes its own chunks, borrowed prefix included.
		stored := duplicate.body.storedLength
		chunks = append(chunks, session.sealUnwrittenLocked(duplicate)...)
		if duplicate.body.storedLength != stored {
			patchSealFailure(finishes[pair[1]], duplicate)
		}
	}

	if session.bodyEncoder != nil {
		session.bodyEncoder.Release()
		session.bodyEncoder = nil
	}

	forwardStatus := session.forwardStatus
	statusCode := cloneInt(session.statusCode)
	blockedBy := cloneString(session.blockedBy)
	blockCode := cloneString(session.blockCode)
	errorCode := cloneString(session.errorCode)
	newAPIRequestID := cloneString(session.newAPIRequestID)
	captureStatus := storage.CaptureComplete
	if session.captureFault {
		captureStatus = storage.CapturePartial
	}
	parseStatus := storage.ParsePending
	if forwardStatus == storage.ForwardRejected {
		parseStatus = storage.ParseSkipped
	}
	endedAtNS := session.now().UnixNano()

	versionTwo := session.headerBlockLocked()
	var blockStages []*stageCapture
	for _, name := range stageNames {
		stage := session.stages[name]
		finish := finishes[name]
		final := stageStartValues(session.auditID, stage)
		final.State = finish.State
		final.StatusCode = cloneInt(finish.StatusCode)
		final.ContentLength = cloneInt64(finish.ContentLength)
		final.EndedAtNS = &finish.EndedAtNS
		final.ErrorCode = finish.ErrorCode
		stageCommit := storage.StageCommit{Stage: final, StageWritten: stage.rowWritten, BodyWritten: stage.bodyRowWritten}
		if versionTwo {
			content := stageContent(stage)
			stageCommit.ContentType, stageCommit.ContentEncoding = content.ContentType, content.ContentEncoding
			if !stage.rowWritten || session.hasStageRowLocked(stage) {
				blockStages = append(blockStages, stage)
			}
		}
		if bodyFinish := finish.Body; bodyFinish != nil {
			body := bodyStreamOf(session.auditID, name, bodyFinish)
			if source, ok := mergedFrom[name]; ok {
				sourceBody := finishes[source].Body
				body.SourceStage = source
				body.StoredLength, body.ChunkCount = sourceBody.StoredLength, sourceBody.ChunkCount
				body.StreamEventCount, body.StreamTimelineComplete = sourceBody.StreamEventCount, sourceBody.StreamTimelineComplete
			}
			stageCommit.Body = &body
			stageCommit.Timeline = bodyFinish.Timeline
			if bodyFinish.Timeline != nil {
				commit.PayloadBytes += int64(len(bodyFinish.Timeline.DataEnc))
			}
		}
		for _, group := range stage.groups {
			if !group.written {
				commit.Headers = append(commit.Headers, group.rows...)
			}
		}
		commit.Stages = append(commit.Stages, stageCommit)
	}
	auditID, stager := session.auditID, session.manager.stager
	commit.Chunks = chunks.commitSource(func() { stager.Discard(auditID) })
	commit.PayloadBytes += chunks.payloadBytes()
	// Version 2: the complete block, nil when the last checkpoint wrote the
	// same one (C.8). A block that cannot be sealed fails the commit before it
	// is sent; startup recovery then finalizes the audit with the block the
	// checkpoints wrote.
	var blockErr error
	if versionTwo {
		commit.HeaderBlock, _, blockErr = session.blockForLocked(blockStages)
		if commit.HeaderBlock != nil {
			commit.PayloadBytes += int64(len(commit.HeaderBlock.DataEnc))
		}
	}
	commit.Finish = storage.AuditFinish{
		AuditID:         session.auditID,
		EndedAtNS:       endedAtNS,
		StatusCode:      statusCode,
		ForwardStatus:   forwardStatus,
		CaptureStatus:   captureStatus,
		ParseStatus:     parseStatus,
		BlockedBy:       blockedBy,
		BlockCode:       blockCode,
		ErrorCode:       errorCode,
		NewAPIRequestID: newAPIRequestID,
	}
	if responseStage := session.stages[storage.StageResponseSent]; responseStage != nil {
		ttft := responseStage.startedAtNS - session.started.UnixNano()
		if ttft < 0 {
			ttft = 0
		}
		commit.Finish.TTFTNS = &ttft
	}
	session.mu.Unlock()

	var writeErrors []error
	commitWithRetries := session.commitWithRetries
	if blockErr != nil {
		commitWithRetries = func(storage.AuditCommit) (storage.AuditFinish, error) {
			return storage.AuditFinish{}, fmt.Errorf("seal header block: %w", blockErr)
		}
	}
	persisted, commitErr := commitWithRetries(commit)
	session.releaseStaged(commitErr == nil)
	if err := commitErr; err != nil {
		writeErrors = append(writeErrors, fmt.Errorf("commit audit: %w", err))
		captureStatus = storage.CapturePartial
		if errorCode == nil {
			errorCode = stringPointer("audit_finalize_failed")
		}
		session.recordGapReason(gapReasonForWrite(err))
		session.logCaptureFailure("", "finish_audit_failed")
	} else {
		captureStatus = persisted.CaptureStatus
		errorCode = cloneString(persisted.ErrorCode)
		if parseStatus == storage.ParsePending {
			session.handOver(&commit, persisted)
		}
	}
	if newAPIRequestID != nil && session.callerNotify != nil && len(writeErrors) == 0 {
		_ = session.callerNotify(session.auditID)
	}
	terminalErrorCode := valueOrEmpty(errorCode)
	if len(writeErrors) != 0 && terminalErrorCode == "" {
		terminalErrorCode = "audit_finalize_failed"
	}
	terminal := TerminalSummary{
		AuditID:       session.auditID,
		ForwardStatus: forwardStatus,
		CaptureStatus: captureStatus,
		ParseStatus:   parseStatus,
		BlockedBy:     valueOrEmpty(blockedBy),
		BlockCode:     valueOrEmpty(blockCode),
		ErrorCode:     terminalErrorCode,
	}
	if statusCode != nil {
		terminal.StatusCode = *statusCode
		terminal.HasStatusCode = true
	}
	session.mu.Lock()
	session.releaseRetainedLocked()
	session.clearHeaderFieldsLocked()
	session.terminal = &terminal
	session.mu.Unlock()
	return errors.Join(writeErrors...)
}

// releaseStaged ends the session's use of its staging file once the commit
// is decided. An acknowledged commit holds every staged chunk, so the file is
// removed (F.5). When the commit failed for good, the file stays: the store
// remembered the staged chunks with the failure (storage.StagedChunkHolder)
// and inserts them when its recovery finalizes the audit as failed, then
// removes the file; if the process stops first, the next start imports
// them before recovering the audit.
func (session *Session) releaseStaged(committed bool) {
	session.mu.Lock()
	staged := session.stagedChunks
	session.stagedChunks = false
	session.mu.Unlock()
	if !staged {
		return
	}
	if committed {
		session.manager.stager.Discard(session.auditID)
	} else {
		session.manager.stager.Keep(session.auditID)
	}
}

// commitWithRetries sends the commit and retries a queue-full rejection or a
// failed batch (including an uncertain COMMIT, which the store reads back as
// already finalized). Any other error is final at once. The retry count is
// read once, before the first attempt, so the attempt that is the last one
// can say so even when no retry is allowed.
func (session *Session) commitWithRetries(commit storage.AuditCommit) (storage.AuditFinish, error) {
	retries := session.manager.CommitRetries()
	for attempt := 0; ; attempt++ {
		commit.FinalAttempt = attempt >= retries
		persisted, err := session.store.CommitAudit(session.writeCtx, commit)
		if err == nil || attempt >= retries || !retryableCommitError(err) {
			return persisted, err
		}
		session.manager.sleep(commitRetryDelay(attempt + 1))
	}
}

func retryableCommitError(err error) bool {
	return errors.Is(err, storage.ErrQueueFull) || errors.Is(err, storage.ErrWriteBatchFailed)
}

// commitRetryDelay is the wait before retry k (1-based): 100 ms doubling,
// at most one second.
func commitRetryDelay(retry int) time.Duration {
	delay := 100 * time.Millisecond
	for step := 1; step < retry && delay < time.Second; step++ {
		delay *= 2
	}
	return min(delay, time.Second)
}

// finalMergeable is the in-memory form of the store's merge conditions
// (design B.5) on final body values.
func finalMergeable(source, duplicate *storage.BodyFinish) bool {
	ready := func(body *storage.BodyFinish) bool {
		return body != nil && body.State == storage.StageStateComplete && body.HashComplete && body.EOFSeen &&
			body.StoredLength == body.ObservedLength
	}
	return ready(source) && ready(duplicate) && source.ObservedLength == duplicate.ObservedLength &&
		len(source.SHA256) == 32 && bytes.Equal(source.SHA256, duplicate.SHA256)
}

func hasWrittenChunks(body *bodyCapture) bool {
	if body.unified == nil {
		return false
	}
	for _, chunk := range body.unified.chunks {
		if chunk.written {
			return true
		}
	}
	return false
}

// patchSealFailure updates the final values of a duplicate whose chunk could
// not be sealed after its state was fixed.
func patchSealFailure(finish *storage.StageFinish, stage *stageCapture) {
	body := stage.body
	finish.State = storage.StageStatePartial
	finish.ErrorCode = optionalString(stage.errorCode)
	if finish.Body != nil {
		finish.Body.StoredLength = body.storedLength
		finish.Body.ChunkCount = body.chunkCount
		finish.Body.State = storage.StageStatePartial
		if finish.Body.ErrorCode == nil {
			finish.Body.ErrorCode = optionalString(body.errorCode)
		}
	}
}

func bodyStreamOf(auditID, stage string, finish *storage.BodyFinish) storage.BodyStream {
	return storage.BodyStream{
		AuditID:                auditID,
		Stage:                  stage,
		SourceStage:            stage,
		ObservedLength:         finish.ObservedLength,
		StoredLength:           finish.StoredLength,
		SHA256:                 finish.SHA256,
		HashComplete:           finish.HashComplete,
		EOFSeen:                finish.EOFSeen,
		State:                  finish.State,
		RetentionState:         finish.RetentionState,
		FirstObservedAtNS:      finish.FirstObservedAtNS,
		LastObservedAtNS:       finish.LastObservedAtNS,
		ChunkCount:             finish.ChunkCount,
		StreamEventCount:       finish.StreamEventCount,
		StreamTimelineComplete: finish.StreamTimelineComplete,
		ErrorCode:              finish.ErrorCode,
	}
}
