package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/parser/streamterminal"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// The unified write path (design B.1) writes an audit in at most four
// operations: BeginAudit with the inbound stage, checkpoint 1 when the
// request_sent body ends, checkpoint 2 when response_sent starts, and
// CommitAudit at Finish. A checkpoint writes what is new since the previous
// write and is not waited for; when it cannot be enqueued its content stays
// in memory and goes with the next write.

// headerGroup is one sealed (stage, kind) group of version 1 header rows.
type headerGroup struct {
	kind    string
	rows    []storage.HTTPHeader
	written bool
}

// beginUnified admits a request on the unified path: the inbound stage is
// started in memory (snapshot and sealed headers) and written by the same
// BeginAudit as the audit row.
func (manager *Manager) beginUnified(ctx context.Context, request *http.Request, match routing.Match, record storage.AuditRecord, started time.Time) (*Session, error) {
	session := newSession(manager, ctx, record.AuditID, match.RouteID, started)
	session.terminalMatcher = streamterminal.MatcherFor(match.Parser)
	session.identity = storage.ParserAudit{AuditID: record.AuditID, Protocol: record.Protocol, ParserName: record.ParserName, Path: record.Path}
	stage := session.startStage(storage.StageRequestReceived, request.Proto, request.Method, request.Host, nil, contentLengthPointer(request.ContentLength), request.Header, hasBody(request.Body))
	session.mu.Lock()
	inbound := storage.InboundStage{Stage: stageStartValues(session.auditID, stage)}
	for _, group := range stage.groups {
		inbound.Headers = append(inbound.Headers, group.rows...)
	}
	record.Inbound = &inbound
	record.CaptureVersion = manager.captureVersion
	inboundWritten := true
	var shape blockShape
	if session.headerBlockLocked() {
		// Version 2: the sealed User-Agent and a block with the inbound
		// stage alone (K items 1 and 8). Without a block the stage is left
		// to the next write.
		shape, inboundWritten = session.sealInboundLocked(stage, &record)
		if !inboundWritten {
			record.Inbound = nil
		}
	}
	session.mu.Unlock()
	err := manager.store.BeginAudit(ctx, record)
	switch {
	case err == nil && !inboundWritten:
	case err == nil:
		session.mu.Lock()
		session.markStageWrittenLocked(stage)
		if session.headerBlockLocked() {
			session.markBlockWrittenLocked(shape)
		}
		session.mu.Unlock()
	case errors.Is(err, storage.ErrInboundStageNotStored):
		session.inboundStageNotStored(stage)
	default:
		manager.recordGap(gapReasonForWrite(err))
		return nil, fmt.Errorf("audit: begin record: %w", err)
	}
	if manager.gaps != nil {
		manager.gaps.trigger()
	}
	session.WrapRequestReceived(request)
	return session, nil
}

// inboundStageNotStored handles a start row committed without its inbound
// stage. The audit is admitted; the stage is treated as legacy treats a
// request_received whose StartStage failed after BeginAudit: faulted with
// start_stage_failed and the same degraded-capture log line. Its rows are
// not offered again, and the request pair is never merged in memory.
func (session *Session) inboundStageNotStored(stage *stageCapture) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.inboundNotStored = true
	session.markStageWrittenLocked(stage)
	stage.faulted = true
	stage.errorCode = "start_stage_failed"
	session.captureFault = true
	// No gap: the store rejected the row inside its writer and already
	// marked the audit failed, which is what legacy records when the writer
	// rejects its StartStage; a gap stands for evidence lost before the
	// writer, as for a refused enqueue.
	session.logCaptureFailure(stage.name, stage.errorCode)
}

func (session *Session) markStageWrittenLocked(stage *stageCapture) {
	stage.rowWritten = true
	for index := range stage.groups {
		stage.groups[index].written = true
	}
}

// addHeaderGroupLocked seals one header group from a snapshot taken now, with
// the loop and AAD legacy uses for per-value rows (capture_version 1).
func (session *Session) addHeaderGroupLocked(stage *stageCapture, kind string, headers http.Header) {
	fields := headerblock.Snapshot(headers)
	rows := make([]storage.HTTPHeader, 0, len(fields))
	for _, field := range fields {
		for index, value := range field.Values {
			aad, err := security.AAD(session.auditID, "header", stage.name, kind, field.Name, strconv.Itoa(index))
			if err != nil {
				session.markStageFaultLocked(stage, "header_encryption_failed")
				continue
			}
			encrypted, err := session.cipher.Encrypt(aad, value)
			if err != nil {
				session.markStageFaultLocked(stage, "header_encryption_failed")
				continue
			}
			rows = append(rows, storage.HTTPHeader{
				AuditID:     session.auditID,
				Stage:       stage.name,
				Kind:        kind,
				Name:        field.Name,
				ValueIndex:  index,
				ValueLength: len(value),
				ValueEnc:    encrypted,
			})
		}
		clear(field.Values)
	}
	if len(rows) != 0 {
		stage.groups = append(stage.groups, headerGroup{kind: kind, rows: rows})
	}
}

// attachUnifiedBodyLocked gives a new body its unified retention state. A
// duplicate stage borrows from its source while their bytes agree.
func (session *Session) attachUnifiedBodyLocked(stage *stageCapture, body *bodyCapture) {
	body.persisted = true
	body.unified = &unifiedBody{}
	if sourceName := pairedBodySourceStage(stage.name); sourceName != "" &&
		(stage.name != storage.StageRequestSent || !session.inboundNotStored) {
		if source := session.stages[sourceName]; source != nil && source.body != nil && source.body.unified != nil {
			body.unified.source = source.body
			body.unified.borrowing = true
			source.body.unified.borrowed = true
		}
	}
	if stage.name == storage.StageRequestReceived && session.inboundNotStored {
		body.faulted = true
		body.errorCode = "start_stage_failed"
	}
}

// readBodyEnded is checkpoint 1's trigger: the request_sent body ended (EOF,
// Close or a read error, after its trailers).
func (session *Session) readBodyEnded(stageName string) {
	if session == nil || session.manager == nil || stageName != storage.StageRequestSent {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	stage := session.stages[stageName]
	if session.requestSentEnded || stage == nil || stage.body == nil {
		return
	}
	session.requestSentEnded = true
	if session.forwardInProgressLocked() {
		session.checkpointLocked()
	}
}

// responseSentStarted is checkpoint 2's trigger: the response headers are
// being forwarded and the upstream response stage exists.
func (session *Session) responseSentStarted() {
	if session == nil || session.manager == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.stages[storage.StageResponseReceived] != nil && session.forwardInProgressLocked() {
		session.checkpointLocked()
	}
}

func (session *Session) forwardInProgressLocked() bool {
	return !session.committing && session.forwardStatus == storage.ForwardInProgress &&
		(session.request == nil || session.request.Err() == nil)
}

// checkpointLocked enqueues everything new since the previous write: stage
// rows, header groups, request body rows and sealed request chunks. Response
// bodies are left to the commit.
func (session *Session) checkpointLocked() {
	checkpoint := storage.AuditCheckpoint{AuditID: session.auditID, CaptureVersion: session.manager.captureVersion}
	versionTwo := session.headerBlockLocked()
	var chunks storage.ChunkList
	var newStages, chunkStages, blockStages []*stageCapture
	var newBodies []*stageCapture
	merges := map[*stageCapture]bool{}
	for _, name := range stageNamesInOrder {
		stage := session.stages[name]
		if stage == nil {
			continue
		}
		if !stage.rowWritten {
			checkpoint.Stages = append(checkpoint.Stages, stageStartValues(session.auditID, stage))
			newStages = append(newStages, stage)
			if versionTwo {
				checkpoint.Contents = append(checkpoint.Contents, stageContent(stage))
			}
		}
		if !stage.rowWritten || session.hasStageRowLocked(stage) {
			blockStages = append(blockStages, stage)
		}
		for _, group := range stage.groups {
			if !group.written {
				checkpoint.Headers = append(checkpoint.Headers, group.rows...)
			}
		}
		if name != storage.StageRequestReceived && name != storage.StageRequestSent || stage.body == nil {
			continue
		}
		merge := false
		if !stage.bodyRowWritten {
			row := storage.BodyStream{AuditID: session.auditID, Stage: name, SourceStage: name, State: storage.StageStateStreaming, RetentionState: storage.RetentionPending}
			if name == storage.StageRequestSent && !session.inboundNotStored {
				if source := session.stages[storage.StageRequestReceived]; source != nil && mergeableNow(source.body, stage.body) {
					row.SourceStage = storage.StageRequestReceived
					merge = true
				}
			}
			checkpoint.Bodies = append(checkpoint.Bodies, row)
			newBodies = append(newBodies, stage)
			merges[stage] = merge
		}
		if stage.merged || merge {
			continue
		}
		if sealed := session.sealUnwrittenLocked(stage); len(sealed) != 0 {
			chunks = append(chunks, sealed...)
		}
		chunkStages = append(chunkStages, stage)
	}
	var shape blockShape
	if versionTwo {
		// The whole block of the stages written so far, this checkpoint's
		// included (C.8); left out when the last one written is the same.
		block, blockShape, err := session.blockForLocked(blockStages)
		if err != nil {
			session.logCheckpointDeferred(err)
			return
		}
		checkpoint.HeaderBlock, shape = block, blockShape
	}
	if len(checkpoint.Stages) == 0 && len(checkpoint.Headers) == 0 && len(checkpoint.Bodies) == 0 && len(chunks) == 0 && checkpoint.HeaderBlock == nil {
		return
	}
	if len(chunks) != 0 {
		checkpoint.Chunks = chunks
	}
	if err := session.store.Checkpoint(session.writeCtx, checkpoint); err != nil {
		// Nothing is lost: the content is still in memory and goes with the
		// next write. Sealed chunks are sealed again then.
		session.logCheckpointDeferred(err)
		return
	}
	for _, stage := range newStages {
		stage.rowWritten = true
	}
	if checkpoint.HeaderBlock != nil {
		session.markBlockWrittenLocked(shape)
	}
	for _, stage := range session.stages {
		for index := range stage.groups {
			stage.groups[index].written = true
		}
	}
	for _, stage := range newBodies {
		stage.bodyRowWritten = true
		stage.merged = merges[stage]
	}
	for _, stage := range chunkStages {
		markSealedWritten(stage)
	}
}

func (session *Session) logCheckpointDeferred(err error) {
	if session.logger == nil {
		return
	}
	session.logger.Warn("audit capture degraded", "audit_id", session.auditID, "route_id", session.routeID,
		"error_code", "capture_checkpoint_deferred", "storage_error", storage.ErrorClass(err))
}

// mergeableNow reports whether a duplicate body can be written merged into
// its source now: both ended without fault, fully retained, with the same
// length and digest.
func mergeableNow(source, duplicate *bodyCapture) bool {
	ready := func(body *bodyCapture) bool {
		return body != nil && body.unified != nil && body.eofSeen && body.hashComplete && !body.faulted &&
			body.storedLength == body.observedLength && body.unified.open == nil
	}
	return ready(source) && ready(duplicate) && source.observedLength == duplicate.observedLength &&
		bytes.Equal(source.digest.Sum(nil), duplicate.digest.Sum(nil))
}

var stageNamesInOrder = [...]string{
	storage.StageRequestReceived,
	storage.StageRequestSent,
	storage.StageResponseReceived,
	storage.StageResponseSent,
}

func stageStartValues(auditID string, stage *stageCapture) storage.HTTPStage {
	return storage.HTTPStage{
		AuditID:       auditID,
		Stage:         stage.name,
		State:         storage.StageStateStreaming,
		Proto:         stage.proto,
		Method:        stage.method,
		Host:          stage.host,
		StatusCode:    cloneInt(stage.statusCode),
		ContentLength: cloneInt64(stage.contentLength),
		StartedAtNS:   stage.startedAtNS,
	}
}
