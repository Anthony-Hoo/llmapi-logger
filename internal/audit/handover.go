package audit

import (
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/storage"
)

// The hand-over (issue #59 stage 3, design G.2): when CommitAudit has
// succeeded on the unified write path, the session hands the committed audit
// to the parser through the manager's hand-over callback, the parser worker's
// Submit. It hands over the plaintext it still holds when the committed
// outcome is the one it submitted, the parse is pending, the evidence in
// memory is exactly what was stored, and the global budget admits it;
// otherwise an id-only job, which the worker parses from the database.
// Finish waits for the commit only, never for the parse: Submit does not
// block, and when its queue is full nothing is submitted and the audit is
// left to the pending scan.

// SetHandover installs the callback that takes a committed audit on the
// unified write path. Nil, the default, falls back to the completion
// notifier. The callback owns the job: it must call the job's Release
// exactly once, whether or not it takes the job (parser.Worker.Submit does).
func (manager *Manager) SetHandover(submit func(handover.Job) bool) {
	if manager == nil {
		return
	}
	manager.notifyMu.Lock()
	manager.handover = submit
	manager.notifyMu.Unlock()
}

func (manager *Manager) handoverFunc() func(handover.Job) bool {
	if manager == nil {
		return nil
	}
	manager.notifyMu.RLock()
	defer manager.notifyMu.RUnlock()
	return manager.handover
}

// handOver is the end of a successful unified Finish whose parse is pending.
func (session *Session) handOver(commit *storage.AuditCommit, persisted storage.AuditFinish) {
	submit := session.manager.handoverFunc()
	if submit == nil {
		if session.notify != nil {
			_ = session.notify(session.auditID)
		}
		return
	}
	session.mu.Lock()
	job := session.jobLocked(commit, persisted)
	session.mu.Unlock()
	_ = submit(job)
}

// jobLocked builds the job of the committed audit. A job with evidence takes
// the plaintext out of the session, so the session's release at the end of
// Finish leaves it alone; the job's share of the global budget moves with it
// and is released by the job's Release.
func (session *Session) jobLocked(commit *storage.AuditCommit, persisted storage.AuditFinish) handover.Job {
	audit := session.identity
	audit.AuditID = session.auditID
	audit.ForwardStatus = persisted.ForwardStatus
	audit.CaptureStatus = persisted.CaptureStatus
	audit.ParseStatus = storage.ParsePending
	job := handover.Job{Audit: audit}
	evidence, ok := session.evidenceLocked(commit, persisted)
	if !ok {
		return job
	}
	size := evidence.Bytes()
	budget := session.manager.budget
	if !budget.fits(size) {
		// Under pressure the plaintext is not kept for the parse (F.2).
		return job
	}
	for _, name := range [2]string{storage.StageRequestReceived, storage.StageResponseReceived} {
		stage := session.stages[name]
		if stage == nil {
			continue
		}
		// Version 2 fields go with the job; version 1 rows are ciphertext
		// the session never clears.
		stage.headerFields = nil
		if stage.body == nil || stage.body.unified == nil {
			continue
		}
		held := stage.body.unified
		for _, chunk := range held.chunks {
			moved := int64(len(chunk.data))
			chunk.data = nil
			held.ownBytes -= moved
			session.memoryHeld -= moved
		}
	}
	job.Evidence = evidence
	job.Release = handover.Once(func() {
		evidence.Clear()
		budget.release(size)
	})
	return job
}

// evidenceLocked collects the evidence of request_received and
// response_received as the committed rows hold it, or reports that the
// session cannot vouch for it.
func (session *Session) evidenceLocked(commit *storage.AuditCommit, persisted storage.AuditFinish) (*handover.Evidence, bool) {
	submitted := commit.Finish
	if persisted.CaptureStatus != submitted.CaptureStatus || persisted.ForwardStatus != submitted.ForwardStatus ||
		valueOrEmpty(persisted.ErrorCode) != valueOrEmpty(submitted.ErrorCode) ||
		(persisted.ParseStatus != "" && persisted.ParseStatus != storage.ParsePending) {
		// Downgraded, for example by a failed checkpoint: what was stored is
		// not what the session holds.
		return nil, false
	}
	if session.inboundNotStored {
		return nil, false
	}
	for _, stage := range session.stages {
		if stage.body != nil && stage.body.unified != nil {
			for _, chunk := range stage.body.unified.chunks {
				if chunk.staged != nil {
					// Seam for local staging (design F.3 to F.5): staged
					// content is not in memory. Once internal/audit/staging
					// can read a staged chunk back, its plaintext can be
					// handed over here instead of falling back to an id-only
					// job.
					return nil, false
				}
			}
		}
	}
	evidence := &handover.Evidence{CaptureVersion: commit.CaptureVersion}
	if evidence.CaptureVersion == 0 {
		evidence.CaptureVersion = storage.CaptureVersion1
	}
	for _, target := range [2]struct {
		name  string
		stage *handover.Stage
	}{{storage.StageRequestReceived, &evidence.Request}, {storage.StageResponseReceived, &evidence.Response}} {
		committed := committedStage(commit, target.name)
		capture := session.stages[target.name]
		if committed == nil || capture == nil {
			continue
		}
		stage := handover.Stage{Present: true, StatusCode: cloneInt(committed.Stage.StatusCode)}
		if evidence.CaptureVersion == storage.CaptureVersion2 {
			stage.Headers = capture.headerFields
		} else {
			for _, group := range capture.groups {
				if group.kind == storage.HeaderKindHeader {
					stage.HeaderRows = append(stage.HeaderRows, group.rows...)
				}
			}
		}
		if committed.Body != nil {
			body := *committed.Body
			chunks, ok := heldPlaintext(capture.body, body, target.name)
			if !ok {
				return nil, false
			}
			stage.Body, stage.Chunks = &body, chunks
		}
		*target.stage = stage
	}
	return evidence, true
}

func committedStage(commit *storage.AuditCommit, name string) *storage.StageCommit {
	for index := range commit.Stages {
		if commit.Stages[index].Stage.Stage == name {
			return &commit.Stages[index]
		}
	}
	return nil
}

// heldPlaintext returns the plaintext of a body's stored chunks when the
// session holds all of it: every chunk closed, in memory in full, contiguous,
// and together exactly the committed row's stored length and chunk count. A
// chunk lost at sealing, released under budget pressure or staged fails it.
func heldPlaintext(body *bodyCapture, committed storage.BodyStream, stage string) ([]handover.Chunk, bool) {
	if body == nil || body.unified == nil || body.unified.open != nil || committed.SourceStage != stage {
		return nil, false
	}
	chunks := make([]handover.Chunk, 0, len(body.unified.chunks))
	var offset int64
	for index, chunk := range body.unified.chunks {
		if !chunk.closed || chunk.staged != nil || chunk.offset != offset || int64(len(chunk.data)) != chunk.length {
			return nil, false
		}
		chunks = append(chunks, handover.Chunk{Seq: int64(index), Offset: chunk.offset, Data: chunk.data})
		offset += chunk.length
	}
	if offset != committed.StoredLength || int64(len(chunks)) != committed.ChunkCount {
		return nil, false
	}
	return chunks, true
}
