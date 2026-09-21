package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/uaguard"

	sqlitecodes "modernc.org/sqlite/lib"
)

type writeKind uint8

const (
	writeBeginAudit writeKind = iota + 1
	writeStartStage
	writeStartBody
	writeAddHeaders
	writeAddChunk
	writeFinishStage
	writeFinishAudit
	writeResetProcessingParses
	writeClaimPendingParse
	writeReleaseProcessingParse
	writeSaveParsedResult
	writeSaveParsedAudit
	writeRecoverInterruptedAudits
	writeInsertAuditGaps
	writeDeleteExpired
	writeUpsertTokenLink
	writeRetryCallerLookup
	writeCreateUserAgentRule
	writeUpdateUserAgentRule
	writeDeleteUserAgentRule
)

type writeRequest struct {
	kind     writeKind
	data     any
	ack      chan error
	sequence uint64
}

// BeginAudit enqueues a parent audit row and waits until its batch commits.
func (store *Store) BeginAudit(ctx context.Context, record AuditRecord) error {
	record.defaults()
	if err := validateAuditRecord(record); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeBeginAudit, data: cloneAuditRecord(record)})
}

// StartStage non-blockingly appends an observed HTTP stage to the writer
// queue. A nil error means accepted by the queue, not yet committed.
func (store *Store) StartStage(ctx context.Context, stage HTTPStage) error {
	stage.defaults()
	if err := validateStage(stage); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeStartStage, data: cloneHTTPStage(stage)})
}

// StartBody non-blockingly appends a lazily created body stream.
func (store *Store) StartBody(ctx context.Context, body BodyStream) error {
	body.defaults()
	if err := validateBodyStream(body); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeStartBody, data: cloneBodyStream(body)})
}

// AddHeaders non-blockingly appends a group of encrypted Header or Trailer
// values as one ordered write operation.
func (store *Store) AddHeaders(ctx context.Context, headers []HTTPHeader) error {
	if len(headers) == 0 {
		return nil
	}
	owned := make([]HTTPHeader, len(headers))
	for index, header := range headers {
		if err := validateHeader(header); err != nil {
			return fmt.Errorf("header %d: %w", index, err)
		}
		owned[index] = cloneHTTPHeader(header)
	}
	return store.submitAsync(ctx, writeRequest{kind: writeAddHeaders, data: owned})
}

// AddChunk non-blockingly appends one encrypted owning body chunk.
func (store *Store) AddChunk(ctx context.Context, chunk BodyChunk) error {
	chunk.defaults()
	if err := validateChunk(chunk); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeAddChunk, data: cloneBodyChunk(chunk)})
}

// FinishStage non-blockingly appends a stage and optional body finalization.
func (store *Store) FinishStage(ctx context.Context, finish StageFinish) error {
	finish.defaults()
	if err := validateStageFinish(finish); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeFinishStage, data: cloneStageFinish(finish)})
}

// FinishAudit appends the terminal audit outcome and waits for its batch to
// commit. Since the writer is ordered, this is also a barrier for all earlier
// accepted operations.
func (store *Store) FinishAudit(ctx context.Context, finish AuditFinish) error {
	_, err := store.FinishAuditWithResult(ctx, finish)
	return err
}

// FinishAuditWithResult returns the effective terminal outcome only after the
// outer transaction commits. In particular, asynchronous capture failures may
// downgrade the submitted status. No outcome is returned on a failed or
// canceled acknowledgement, even if an accepted write later commits.
func (store *Store) FinishAuditWithResult(ctx context.Context, finish AuditFinish) (AuditFinish, error) {
	finish.defaults()
	if err := validateAuditFinish(finish); err != nil {
		return AuditFinish{}, err
	}
	owned := cloneAuditFinish(finish)
	if err := store.submitSync(ctx, writeRequest{kind: writeFinishAudit, data: &owned}); err != nil {
		return AuditFinish{}, err
	}
	return owned, nil
}

func (store *Store) submitAsync(ctx context.Context, request writeRequest) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return ErrClosed
	}

	store.submitMu.Lock()
	defer store.submitMu.Unlock()
	if store.closed {
		return ErrClosed
	}
	request.sequence = store.submittedSequence + 1
	select {
	case store.queue <- request:
		store.submittedSequence = request.sequence
		return nil
	default:
		if request.kind == writeFinishAudit {
			// Replaying must wait for every earlier accepted stage write.
			store.rememberFailedWrite(request, store.submittedSequence)
		}
		return ErrQueueFull
	}
}

func (store *Store) submitSync(ctx context.Context, request writeRequest) error {
	request.ack = make(chan error, 1)
	if err := store.submitAsync(ctx, request); err != nil {
		return err
	}
	select {
	case err := <-request.ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (store *Store) runWriter() {
	defer close(store.done)
	ticker := time.NewTicker(captureRecoveryInterval)
	defer ticker.Stop()
	for {
		var first writeRequest
		var open bool
		select {
		case first, open = <-store.queue:
		case <-ticker.C:
			store.recoverCaptureWrites()
			continue
		case <-store.recoveryWake:
			store.recoverCaptureWrites()
			continue
		}
		if !open {
			store.recoverCaptureWrites()
			return
		}

		batch := make([]writeRequest, 0, writerBatchSize)
		batch = append(batch, first)
		timer := time.NewTimer(writerBatchDelay)
		queueClosed := false

	collect:
		for len(batch) < writerBatchSize {
			select {
			case request, open := <-store.queue:
				if !open {
					queueClosed = true
					break collect
				}
				batch = append(batch, request)
			case <-timer.C:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		results, wrote, err := store.commitBatch(batch)
		if err != nil {
			store.healthy.Store(false)
			if store.logger != nil {
				store.logger.Warn("audit writer batch failed", "error_category", "writer_batch_failed",
					"storage_error", ErrorClass(err), "write_count", len(batch))
			}
			for _, request := range batch {
				store.rememberFailedWrite(request, request.sequence)
			}
		} else if wrote {
			store.healthy.Store(true)
		}
		if err == nil {
			for index, request := range batch {
				if request.kind == writeFinishAudit {
					if results[index] != nil && !errors.Is(results[index], sql.ErrNoRows) {
						store.rememberFailedWrite(request, request.sequence)
					} else if results[index] == nil {
						store.forgetFinishedRecovery(request.data.(*AuditFinish).AuditID)
					}
				}
			}
		}
		for _, request := range batch {
			store.processedSequence = max(store.processedSequence, request.sequence)
		}
		for index, request := range batch {
			if request.ack != nil {
				if err != nil {
					request.ack <- err
				} else {
					request.ack <- results[index]
				}
			}
		}
		if queueClosed {
			store.recoverCaptureWrites()
			return
		}
	}
}

// Known local errors can be isolated. Storage errors fail the whole batch even
// when SQLite would allow rolling back the statement and committing no writes.
func (store *Store) commitBatch(batch []writeRequest) ([]error, bool, error) {
	transaction, err := store.writerDB.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("sqlite writer: begin batch: %w", err)
	}
	defer transaction.Rollback()
	results := make([]error, len(batch))
	wrote := false
	for index, request := range batch {
		if _, err := transaction.Exec("SAVEPOINT writer_operation"); err != nil {
			return nil, false, fmt.Errorf("sqlite writer: savepoint: %w", err)
		}
		var before int64
		if !wrote {
			if err := transaction.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
				return nil, false, fmt.Errorf("sqlite writer: read write counter: %w", err)
			}
		}
		results[index] = store.applyWrite(transaction, request)
		if results[index] != nil {
			var integrityFailure storedObjectIntegrityError
			if errors.As(results[index], &integrityFailure) {
				// Detection remains valid even if this operation rolls back.
				// Isolate its write failure, but latch readiness unhealthy.
				store.payloadState.Store(integrityPayloadsFailed)
			}
			if !canIsolateWriteError(results[index]) {
				return nil, false, results[index]
			}
			if _, err := transaction.Exec("ROLLBACK TO writer_operation"); err != nil {
				return nil, false, fmt.Errorf("sqlite writer: rollback operation: %w", err)
			}
			// total_changes includes rolled-back statements. Exclude those;
			// only a later committed failure marker can prove write recovery.
			if !wrote {
				if err := transaction.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
					return nil, false, fmt.Errorf("sqlite writer: read rollback counter: %w", err)
				}
			}
			if err := markCaptureWriteFailed(transaction, request); err != nil {
				return nil, false, err
			}
		}
		if !wrote {
			var after int64
			if err := transaction.QueryRow("SELECT total_changes()").Scan(&after); err != nil {
				return nil, false, fmt.Errorf("sqlite writer: read mutation counter: %w", err)
			}
			wrote = after > before
		}
		if _, err := transaction.Exec("RELEASE writer_operation"); err != nil {
			return nil, false, fmt.Errorf("sqlite writer: release operation: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, false, fmt.Errorf("sqlite writer: commit batch: %w", err)
	}
	return results, wrote, nil
}

type localWriteError string

func (err localWriteError) Error() string { return string(err) }

type storedObjectIntegrityError string

func (err storedObjectIntegrityError) Error() string { return string(err) }

// This controls rollback scope, not health: object integrity faults are
// isolated but also latch payloadState failed. Unclassified errors and storage
// failures must abort the outer transaction.
func canIsolateWriteError(err error) bool {
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		return coded.Code()&0xff == sqlitecodes.SQLITE_CONSTRAINT
	}
	var local localWriteError
	var integrityFailure storedObjectIntegrityError
	return errors.As(err, &local) || errors.As(err, &integrityFailure) || errors.Is(err, ErrRecoveryOverflow) || errors.Is(err, auditmodel.ErrReconstruction) ||
		errors.Is(err, sql.ErrNoRows) || errors.Is(err, uaguard.ErrNotFound)
}

// Async capture has no acknowledgement. Persist the failure on its audit so
// finalization in this or any later batch cannot claim complete evidence.
// A parser or management operation must never taint unrelated capture.
func markCaptureWriteFailed(transaction *sql.Tx, request writeRequest) error {
	var auditIDs []string
	headerStages := make(map[[2]string]struct{})
	switch request.kind {
	case writeStartStage:
		auditIDs = []string{request.data.(HTTPStage).AuditID}
	case writeStartBody:
		auditIDs = []string{request.data.(BodyStream).AuditID}
	case writeAddHeaders:
		seen := make(map[string]bool)
		for _, header := range request.data.([]HTTPHeader) {
			headerStages[[2]string{header.AuditID, header.Stage}] = struct{}{}
			if !seen[header.AuditID] {
				seen[header.AuditID] = true
				auditIDs = append(auditIDs, header.AuditID)
			}
		}
	case writeAddChunk:
		auditIDs = []string{request.data.(BodyChunk).AuditID}
	case writeFinishStage:
		auditIDs = []string{request.data.(StageFinish).AuditID}
	}
	for _, auditID := range auditIDs {
		if _, err := transaction.Exec(`
UPDATE audit_records SET capture_status = 'failed', error_code = 'capture_write_failed'
WHERE audit_id = ? AND ended_at_ns IS NULL`, auditID); err != nil {
			return fmt.Errorf("sqlite writer: record capture failure: %w", err)
		}
	}
	for identity := range headerStages {
		if _, err := transaction.Exec(`
UPDATE http_stages SET state = 'partial', error_code = 'capture_headers_failed'
WHERE audit_id = ? AND stage = ?
  AND EXISTS (SELECT 1 FROM audit_records a WHERE a.audit_id = http_stages.audit_id AND a.ended_at_ns IS NULL)`,
			identity[0], identity[1]); err != nil {
			return fmt.Errorf("sqlite writer: record header stage failure: %w", err)
		}
	}
	if request.kind == writeAddChunk {
		chunk := request.data.(BodyChunk)
		if _, err := transaction.Exec(`
UPDATE body_streams SET observed_length = MAX(observed_length, ?), error_code = ?
WHERE audit_id = ? AND stage = ? AND state = 'streaming'
  AND EXISTS (SELECT 1 FROM audit_records a WHERE a.audit_id = body_streams.audit_id AND a.ended_at_ns IS NULL)`,
			chunk.Offset+int64(chunk.PlaintextLength), CaptureChunkMissing, chunk.AuditID, chunk.Stage); err != nil {
			return fmt.Errorf("sqlite writer: record missing chunk: %w", err)
		}
	}
	return nil
}

func (store *Store) applyWrite(transaction *sql.Tx, request writeRequest) error {
	signer := store.integrity.Load()
	switch request.kind {
	case writeBeginAudit:
		if store.recoveryOverflow.Load() {
			return ErrRecoveryOverflow
		}
		return insertAudit(transaction, request.data.(AuditRecord))
	case writeStartStage:
		return insertStage(transaction, request.data.(HTTPStage))
	case writeStartBody:
		return insertBody(transaction, request.data.(BodyStream))
	case writeAddHeaders:
		return insertHeaders(transaction, request.data.([]HTTPHeader))
	case writeAddChunk:
		return insertChunk(transaction, request.data.(BodyChunk))
	case writeFinishStage:
		return finishStage(transaction, request.data.(StageFinish))
	case writeFinishAudit:
		store.recoveryMu.Lock()
		entry, pending := store.recoveries[request.data.(*AuditFinish).AuditID]
		store.recoveryMu.Unlock()
		if pending && !entry.marked {
			// A failed recovery attempt and this batch use separate
			// transactions. The later finish must not outrun its marker.
			entry.finish = nil
			if _, err := store.recoverCaptureEntry(transaction, request.data.(*AuditFinish).AuditID, entry); err != nil {
				return err
			}
		}
		if store.recoveryOverflow.Load() {
			if _, err := transaction.Exec(`UPDATE audit_records
SET capture_status='failed', error_code='capture_recovery_overflow'
WHERE audit_id=? AND ended_at_ns IS NULL`, request.data.(*AuditFinish).AuditID); err != nil {
				return err
			}
		}
		return finishAudit(transaction, request.data.(*AuditFinish), signer)
	case writeResetProcessingParses:
		return resetProcessingParses(transaction)
	case writeClaimPendingParse:
		return claimPendingParse(transaction, request.data.(*parseClaim))
	case writeReleaseProcessingParse:
		return releaseProcessingParse(transaction, request.data.(string), signer, time.Now())
	case writeSaveParsedResult:
		return saveParsedResult(transaction, request.data.(ParsedResult), signer)
	case writeSaveParsedAudit:
		return saveParsedAudit(transaction, request.data.(ParsedAudit), signer)
	case writeRecoverInterruptedAudits:
		return recoverInterruptedAudits(transaction, request.data.(*recoveryRequest), signer)
	case writeInsertAuditGaps:
		return insertAuditGaps(transaction, request.data.([]AuditGap))
	case writeDeleteExpired:
		return deleteExpired(transaction, request.data.(*retentionRequest))
	case writeUpsertTokenLink:
		return upsertTokenLink(transaction, request.data.(TokenLink))
	case writeRetryCallerLookup:
		return retryCallerLookup(transaction, request.data.(CallerRetry))
	case writeCreateUserAgentRule:
		return createUserAgentRule(transaction, request.data.(uaguard.Rule))
	case writeUpdateUserAgentRule:
		return updateUserAgentRule(transaction, request.data.(uaguard.Rule))
	case writeDeleteUserAgentRule:
		return deleteUserAgentRule(transaction, request.data.(int64))
	default:
		return fmt.Errorf("sqlite writer: unknown operation %d", request.kind)
	}
}

func insertAudit(transaction *sql.Tx, record AuditRecord) error {
	_, err := transaction.Exec(`
INSERT INTO audit_records (
    audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
    method, path, request_uri_enc, mode, status_code, ttft_ns, forward_status,
    capture_status, parse_status, blocked_by, block_code, error_code,
    newapi_request_id, caller_status, caller_attempts, caller_next_at_ns,
    caller_updated_at_ns, api_key_fpr
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.AuditID,
		record.StartedAtNS,
		record.EndedAtNS,
		record.RouteID,
		record.Protocol,
		record.ParserName,
		record.Method,
		record.Path,
		record.RequestURIEnc,
		record.Mode,
		record.StatusCode,
		record.TTFTNS,
		record.ForwardStatus,
		record.CaptureStatus,
		record.ParseStatus,
		record.BlockedBy,
		record.BlockCode,
		record.ErrorCode,
		record.NewAPIRequestID,
		record.CallerStatus,
		record.CallerAttempts,
		record.CallerNextAtNS,
		record.CallerUpdatedAtNS,
		nullableBytes(record.APIKeyFPR),
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: begin audit: %w", err)
	}
	return nil
}

func insertStage(transaction *sql.Tx, stage HTTPStage) error {
	_, err := transaction.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, status_code,
    content_length, started_at_ns, ended_at_ns, error_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stage.AuditID,
		stage.Stage,
		stage.State,
		stage.Proto,
		stage.Method,
		stage.Host,
		stage.StatusCode,
		stage.ContentLength,
		stage.StartedAtNS,
		stage.EndedAtNS,
		stage.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: start stage: %w", err)
	}
	return nil
}

func insertBody(transaction *sql.Tx, body BodyStream) error {
	_, err := transaction.Exec(`
INSERT INTO body_streams (
    audit_id, stage, source_stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state, retention_state,
    first_observed_at_ns, last_observed_at_ns, chunk_count,
    stream_event_count, stream_timeline_complete, error_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		body.AuditID,
		body.Stage,
		body.SourceStage,
		body.ObservedLength,
		body.StoredLength,
		nullableBytes(body.SHA256),
		boolInteger(body.HashComplete),
		boolInteger(body.EOFSeen),
		body.State,
		body.RetentionState,
		body.FirstObservedAtNS,
		body.LastObservedAtNS,
		body.ChunkCount,
		body.StreamEventCount,
		boolInteger(body.StreamTimelineComplete),
		body.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: start body: %w", err)
	}
	return nil
}

func insertHeaders(transaction *sql.Tx, headers []HTTPHeader) error {
	for _, header := range headers {
		_, err := transaction.Exec(`
INSERT INTO http_headers (
    audit_id, stage, kind, name, value_index, value_length, value_enc
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			header.AuditID,
			header.Stage,
			header.Kind,
			header.Name,
			header.ValueIndex,
			header.ValueLength,
			header.ValueEnc,
		)
		if err != nil {
			return fmt.Errorf("sqlite writer: add header: %w", err)
		}
	}
	return nil
}

func insertChunk(transaction *sql.Tx, chunk BodyChunk) error {
	_, err := transaction.Exec(`
INSERT INTO body_chunks (
    audit_id, stage, seq, "offset", plaintext_length, encoded_length,
    observed_at_ns, compression, data_enc
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		chunk.AuditID,
		chunk.Stage,
		chunk.Seq,
		chunk.Offset,
		chunk.PlaintextLength,
		chunk.EncodedLength,
		chunk.ObservedAtNS,
		chunk.Compression,
		chunk.DataEnc,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: add chunk: %w", err)
	}
	return nil
}

func finishStage(transaction *sql.Tx, finish StageFinish) error {
	result, err := transaction.Exec(`
UPDATE http_stages
SET state = CASE WHEN error_code IN ('capture_headers_failed','capture_storage_failed') THEN 'partial' ELSE ? END,
    status_code = ?, content_length = ?, ended_at_ns = ?,
    error_code = CASE WHEN error_code IN ('capture_headers_failed','capture_storage_failed') THEN error_code ELSE ? END
WHERE audit_id = ? AND stage = ?`,
		finish.State,
		finish.StatusCode,
		finish.ContentLength,
		finish.EndedAtNS,
		finish.ErrorCode,
		finish.AuditID,
		finish.Stage,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: finish stage: %w", err)
	}
	if err := requireOneRow(result, "finish stage"); err != nil {
		return err
	}
	if finish.Body == nil {
		return nil
	}

	result, err = transaction.Exec(`
UPDATE body_streams
SET observed_length = ?, stored_length = ?, sha256 = ?, hash_complete = ?,
    eof_seen = ?, state = ?, retention_state = ?,
    first_observed_at_ns = ?, last_observed_at_ns = ?, chunk_count = ?,
    stream_event_count = ?, stream_timeline_complete = ?, error_code = ?
WHERE audit_id = ? AND stage = ?`,
		finish.Body.ObservedLength,
		finish.Body.StoredLength,
		nullableBytes(finish.Body.SHA256),
		boolInteger(finish.Body.HashComplete),
		boolInteger(finish.Body.EOFSeen),
		finish.Body.State,
		finish.Body.RetentionState,
		finish.Body.FirstObservedAtNS,
		finish.Body.LastObservedAtNS,
		finish.Body.ChunkCount,
		finish.Body.StreamEventCount,
		boolInteger(finish.Body.StreamTimelineComplete),
		finish.Body.ErrorCode,
		finish.AuditID,
		finish.Stage,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: finish body: %w", err)
	}
	if err := requireOneRow(result, "finish body"); err != nil {
		return err
	}
	if finish.Body.Timeline != nil {
		timeline := finish.Body.Timeline
		if _, err := transaction.Exec(`
INSERT INTO stream_timelines (
    audit_id, stage, event_count, first_event_at_ns, last_event_at_ns,
    timeline_complete, compression, plaintext_length, timeline_enc
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(audit_id, stage) DO UPDATE SET
    event_count = excluded.event_count,
    first_event_at_ns = excluded.first_event_at_ns,
    last_event_at_ns = excluded.last_event_at_ns,
    timeline_complete = excluded.timeline_complete,
    compression = excluded.compression,
    plaintext_length = excluded.plaintext_length,
    timeline_enc = excluded.timeline_enc`,
			finish.AuditID, finish.Stage, timeline.EventCount,
			timeline.FirstEventAtNS, timeline.LastEventAtNS,
			boolInteger(timeline.Complete), timeline.Compression,
			timeline.PlaintextLength, timeline.DataEnc,
		); err != nil {
			return fmt.Errorf("sqlite writer: save stream timeline: %w", err)
		}
	}
	return nil
}

func finishAudit(transaction *sql.Tx, finish *AuditFinish, signer *security.IntegritySigner) error {
	// Recovery and a caller retry may meet after an uncertain Ack. A second
	// finalization must not overwrite parsing/caller state or sign a new event.
	var ended sql.NullInt64
	if err := transaction.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id=?", finish.AuditID).Scan(&ended); err != nil {
		return fmt.Errorf("sqlite writer: read finalization state: %w", err)
	}
	if ended.Valid {
		return loadFinishedOutcome(transaction, finish)
	}
	var storedCaptureStatus string
	var storedErrorCode sql.NullString
	if err := transaction.QueryRow("SELECT capture_status, error_code FROM audit_records WHERE audit_id = ?", finish.AuditID).Scan(&storedCaptureStatus, &storedErrorCode); err != nil {
		return fmt.Errorf("sqlite writer: read capture status: %w", err)
	}
	if storedCaptureStatus == CaptureFailed {
		finish.CaptureStatus = CaptureFailed
		code := "capture_write_failed"
		if storedErrorCode.Valid {
			code = storedErrorCode.String
		}
		finish.ErrorCode = &code
	} else {
		if err := deduplicateEquivalentBodyStages(transaction, finish.AuditID); err != nil {
			return err
		}
	}
	if finish.CaptureStatus != CaptureComplete {
		if err := finalizeIncompleteCapture(transaction, finish.AuditID, finish.EndedAtNS); err != nil {
			return err
		}
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET ended_at_ns = ?, status_code = ?, ttft_ns = ?, forward_status = ?, capture_status = ?,
    parse_status = ?, blocked_by = ?, block_code = ?, error_code = ?,
    newapi_request_id = ?,
    caller_status = CASE WHEN ? IS NULL THEN 'none' ELSE 'pending' END,
    caller_attempts = 0,
    caller_next_at_ns = CASE WHEN ? IS NULL THEN NULL ELSE ? END,
    caller_updated_at_ns = CASE WHEN ? IS NULL THEN NULL ELSE ? END
WHERE audit_id = ?`,
		finish.EndedAtNS,
		finish.StatusCode,
		finish.TTFTNS,
		finish.ForwardStatus,
		finish.CaptureStatus,
		finish.ParseStatus,
		finish.BlockedBy,
		finish.BlockCode,
		finish.ErrorCode,
		finish.NewAPIRequestID,
		finish.NewAPIRequestID,
		finish.NewAPIRequestID,
		finish.EndedAtNS,
		finish.NewAPIRequestID,
		finish.EndedAtNS,
		finish.AuditID,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: finish audit: %w", err)
	}
	if err := requireOneRow(result, "finish audit"); err != nil {
		return err
	}
	if finish.ForwardStatus != ForwardCompleted || finish.CaptureStatus != CaptureComplete ||
		finish.StatusCode == nil || *finish.StatusCode < 200 || *finish.StatusCode >= 400 ||
		finish.ParseStatus == ParseSkipped {
		if _, err := transaction.Exec(`
UPDATE body_streams
SET retention_state = 'full'
WHERE audit_id = ?`, finish.AuditID); err != nil {
			return fmt.Errorf("sqlite writer: retain terminal raw evidence: %w", err)
		}
	}
	payloadDigest, err := capturePayloadDigest(context.Background(), transaction, finish.AuditID)
	if err != nil {
		return err
	}
	if err := appendIntegrityEvent(transaction, signer, finish.AuditID, integrityCaptureFinalized, payloadDigest, finish.EndedAtNS); err != nil {
		return err
	}
	return nil
}

func loadFinishedOutcome(transaction *sql.Tx, finish *AuditFinish) error {
	var status, ttft sql.NullInt64
	var blocked, blockCode, errorCode, requestID sql.NullString
	err := transaction.QueryRow(`SELECT ended_at_ns, status_code, ttft_ns, forward_status,
capture_status, parse_status, blocked_by, block_code, error_code, newapi_request_id
FROM audit_records WHERE audit_id=?`, finish.AuditID).Scan(
		&finish.EndedAtNS, &status, &ttft, &finish.ForwardStatus, &finish.CaptureStatus,
		&finish.ParseStatus, &blocked, &blockCode, &errorCode, &requestID)
	if err != nil {
		return fmt.Errorf("sqlite writer: read committed outcome: %w", err)
	}
	finish.StatusCode = nullIntPointer(status)
	finish.TTFTNS = nullInt64Pointer(ttft)
	finish.BlockedBy, finish.BlockCode = nullStringPointer(blocked), nullStringPointer(blockCode)
	finish.ErrorCode, finish.NewAPIRequestID = nullStringPointer(errorCode), nullStringPointer(requestID)
	return nil
}

// Reconcile every damaged body, including a successful FinishStage whose
// in-memory totals include chunks that never committed. Keep the observed
// length, but describe only the actual stored bytes as retained evidence.
// A sealed timeline and a collector stage code describe what was observed, so
// both survive. A finished body without a sealed timeline already reports it
// incomplete; only a body that never finished still needs the flag cleared.
func finalizeIncompleteCapture(transaction *sql.Tx, auditID string, endedAtNS int64) error {
	if _, err := transaction.Exec(`
WITH chunk_lengths AS (
    SELECT stage, SUM(plaintext_length) AS stored_length,
           MAX("offset" + plaintext_length) AS observed_length, COUNT(*) AS chunk_count,
           MAX(seq) + 1 AS sequence_count
    FROM body_chunks WHERE audit_id = ? GROUP BY stage
)
UPDATE body_streams
SET stored_length = COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0),
    observed_length = MAX(observed_length, COALESCE((SELECT observed_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)),
    chunk_count = COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0),
    sha256 = NULL, hash_complete = 0, eof_seen = 0,
    state = 'partial', retention_state = 'full',
    stream_timeline_complete = CASE WHEN state = 'streaming' THEN 0 ELSE stream_timeline_complete END,
    error_code = CASE WHEN error_code = 'capture_chunk_missing'
        OR (state <> 'streaming' AND (
            stored_length > COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
            OR chunk_count > COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)))
        OR EXISTS (SELECT 1 FROM chunk_lengths WHERE stage = body_streams.source_stage
            AND (sequence_count <> chunk_count OR observed_length <> stored_length))
        THEN 'capture_chunk_missing' ELSE 'capture_write_failed' END
WHERE audit_id = ? AND (
    state = 'streaming' OR error_code = 'capture_chunk_missing'
    OR stored_length <> COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
    OR chunk_count <> COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
    OR EXISTS (SELECT 1 FROM chunk_lengths WHERE stage = body_streams.source_stage
        AND (sequence_count <> chunk_count OR observed_length <> stored_length))
)`, auditID, auditID); err != nil {
		return fmt.Errorf("sqlite writer: finalize incomplete body: %w", err)
	}
	if _, err := transaction.Exec(`
UPDATE http_stages
SET state = 'partial', ended_at_ns = COALESCE(ended_at_ns, ?),
    error_code = COALESCE(error_code, 'capture_write_failed')
WHERE audit_id = ? AND (state = 'streaming' OR error_code IN ('capture_headers_failed', 'capture_storage_failed') OR EXISTS (
    SELECT 1 FROM body_streams b WHERE b.audit_id = http_stages.audit_id AND b.stage = http_stages.stage
      AND b.state = 'partial' AND b.error_code IN ('capture_write_failed', 'capture_chunk_missing')
))`, endedAtNS, auditID); err != nil {
		return fmt.Errorf("sqlite writer: finalize incomplete stage: %w", err)
	}
	return nil
}

type bodyDedupState struct {
	SourceStage      string
	ObservedLength   int64
	StoredLength     int64
	Digest           []byte
	HashComplete     int
	EOFSeen          int
	State            string
	ChunkCount       int64
	StreamEventCount int64
	TimelineComplete int
}

func deduplicateEquivalentBodyStages(transaction *sql.Tx, auditID string) error {
	for _, pair := range [][2]string{
		{StageRequestReceived, StageRequestSent},
		{StageResponseReceived, StageResponseSent},
	} {
		if err := deduplicateEquivalentBodyPair(transaction, auditID, pair[0], pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func deduplicateEquivalentBodyPair(transaction *sql.Tx, auditID, sourceStage, duplicateStage string) error {
	source, found, err := readBodyDedupState(transaction, auditID, sourceStage)
	if err != nil || !found {
		return err
	}
	duplicate, found, err := readBodyDedupState(transaction, auditID, duplicateStage)
	if err != nil || !found {
		return err
	}
	if source.SourceStage != sourceStage || duplicate.SourceStage != duplicateStage ||
		source.State != StageStateComplete || duplicate.State != StageStateComplete ||
		source.HashComplete == 0 || duplicate.HashComplete == 0 || source.EOFSeen == 0 || duplicate.EOFSeen == 0 ||
		source.StoredLength != source.ObservedLength || duplicate.StoredLength != duplicate.ObservedLength ||
		source.ObservedLength != duplicate.ObservedLength || len(source.Digest) != 32 || !bytes.Equal(source.Digest, duplicate.Digest) {
		return nil
	}
	sourceChunkCount, sourceChunkLength, err := bodyChunkAggregate(transaction, auditID, sourceStage)
	if err != nil {
		return err
	}
	duplicateChunkCount, duplicateChunkLength, err := bodyChunkAggregate(transaction, auditID, duplicateStage)
	if err != nil {
		return err
	}
	if sourceChunkCount != source.ChunkCount || sourceChunkLength != source.StoredLength ||
		duplicateChunkCount != duplicate.ChunkCount || duplicateChunkLength != duplicate.StoredLength {
		return nil
	}
	if _, err := transaction.Exec(`DELETE FROM body_chunks WHERE audit_id = ? AND stage = ?`, auditID, duplicateStage); err != nil {
		return fmt.Errorf("sqlite writer: delete duplicate body chunks: %w", err)
	}
	result, err := transaction.Exec(`
UPDATE body_streams
SET source_stage = ?, stored_length = ?, chunk_count = ?,
    stream_event_count = ?, stream_timeline_complete = ?
WHERE audit_id = ? AND stage = ? AND source_stage = ?`,
		sourceStage, source.StoredLength, source.ChunkCount,
		source.StreamEventCount, source.TimelineComplete,
		auditID, duplicateStage, duplicateStage,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: link duplicate body stream: %w", err)
	}
	return requireOneRow(result, "link duplicate body stream")
}

func readBodyDedupState(transaction *sql.Tx, auditID, stage string) (bodyDedupState, bool, error) {
	var result bodyDedupState
	err := transaction.QueryRow(`
SELECT source_stage, observed_length, stored_length, sha256,
       hash_complete, eof_seen, state, chunk_count,
       stream_event_count, stream_timeline_complete
FROM body_streams
WHERE audit_id = ? AND stage = ?`, auditID, stage).Scan(
		&result.SourceStage,
		&result.ObservedLength,
		&result.StoredLength,
		&result.Digest,
		&result.HashComplete,
		&result.EOFSeen,
		&result.State,
		&result.ChunkCount,
		&result.StreamEventCount,
		&result.TimelineComplete,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return bodyDedupState{}, false, nil
	}
	if err != nil {
		return bodyDedupState{}, false, fmt.Errorf("sqlite writer: read body dedup state: %w", err)
	}
	return result, true, nil
}

func bodyChunkAggregate(transaction *sql.Tx, auditID, stage string) (int64, int64, error) {
	var count, length int64
	if err := transaction.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(plaintext_length), 0)
FROM body_chunks
WHERE audit_id = ? AND stage = ?`, auditID, stage).Scan(&count, &length); err != nil {
		return 0, 0, fmt.Errorf("sqlite writer: read body chunk aggregate: %w", err)
	}
	return count, length, nil
}

func requireOneRow(result sql.Result, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: %s rows affected: %w", operation, err)
	}
	if rows != 1 {
		if rows == 0 {
			return localWriteError(fmt.Sprintf("sqlite writer: %s affected no rows", operation))
		}
		return fmt.Errorf("sqlite writer: %s affected %d rows", operation, rows)
	}
	return nil
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func cloneAuditRecord(record AuditRecord) AuditRecord {
	record.RequestURIEnc = cloneBytes(record.RequestURIEnc)
	record.EndedAtNS = cloneInt64(record.EndedAtNS)
	record.StatusCode = cloneInt(record.StatusCode)
	record.TTFTNS = cloneInt64(record.TTFTNS)
	record.BlockedBy = cloneString(record.BlockedBy)
	record.BlockCode = cloneString(record.BlockCode)
	record.ErrorCode = cloneString(record.ErrorCode)
	record.NewAPIRequestID = cloneString(record.NewAPIRequestID)
	record.CallerNextAtNS = cloneInt64(record.CallerNextAtNS)
	record.CallerUpdatedAtNS = cloneInt64(record.CallerUpdatedAtNS)
	record.APIKeyFPR = cloneBytes(record.APIKeyFPR)
	return record
}

func cloneHTTPStage(stage HTTPStage) HTTPStage {
	stage.StatusCode = cloneInt(stage.StatusCode)
	stage.ContentLength = cloneInt64(stage.ContentLength)
	stage.EndedAtNS = cloneInt64(stage.EndedAtNS)
	stage.ErrorCode = cloneString(stage.ErrorCode)
	return stage
}

func cloneHTTPHeader(header HTTPHeader) HTTPHeader {
	header.ValueEnc = cloneBytes(header.ValueEnc)
	return header
}

func cloneBodyStream(body BodyStream) BodyStream {
	body.SHA256 = cloneBytes(body.SHA256)
	body.FirstObservedAtNS = cloneInt64(body.FirstObservedAtNS)
	body.LastObservedAtNS = cloneInt64(body.LastObservedAtNS)
	body.ErrorCode = cloneString(body.ErrorCode)
	return body
}

func cloneBodyChunk(chunk BodyChunk) BodyChunk {
	chunk.DataEnc = cloneBytes(chunk.DataEnc)
	return chunk
}

func cloneStageFinish(finish StageFinish) StageFinish {
	finish.StatusCode = cloneInt(finish.StatusCode)
	finish.ContentLength = cloneInt64(finish.ContentLength)
	finish.ErrorCode = cloneString(finish.ErrorCode)
	if finish.Body != nil {
		body := *finish.Body
		body.SHA256 = cloneBytes(body.SHA256)
		body.FirstObservedAtNS = cloneInt64(body.FirstObservedAtNS)
		body.LastObservedAtNS = cloneInt64(body.LastObservedAtNS)
		if body.Timeline != nil {
			timeline := *body.Timeline
			timeline.FirstEventAtNS = cloneInt64(timeline.FirstEventAtNS)
			timeline.LastEventAtNS = cloneInt64(timeline.LastEventAtNS)
			timeline.DataEnc = cloneBytes(timeline.DataEnc)
			body.Timeline = &timeline
		}
		body.ErrorCode = cloneString(body.ErrorCode)
		finish.Body = &body
	}
	return finish
}

func cloneAuditFinish(finish AuditFinish) AuditFinish {
	finish.StatusCode = cloneInt(finish.StatusCode)
	finish.TTFTNS = cloneInt64(finish.TTFTNS)
	finish.BlockedBy = cloneString(finish.BlockedBy)
	finish.BlockCode = cloneString(finish.BlockCode)
	finish.ErrorCode = cloneString(finish.ErrorCode)
	finish.NewAPIRequestID = cloneString(finish.NewAPIRequestID)
	return finish
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
