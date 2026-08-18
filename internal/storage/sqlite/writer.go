package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/uaguard"
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
	kind writeKind
	data any
	ack  chan error
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
	finish.defaults()
	if err := validateAuditFinish(finish); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeFinishAudit, data: cloneAuditFinish(finish)})
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

	store.submitMu.RLock()
	defer store.submitMu.RUnlock()
	if store.closed {
		return ErrClosed
	}
	select {
	case store.queue <- request:
		return nil
	default:
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
	for {
		first, open := <-store.queue
		if !open {
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

		err := store.commitBatch(batch)
		store.healthy.Store(err == nil)
		for _, request := range batch {
			if request.ack != nil {
				request.ack <- err
			}
		}
		if queueClosed {
			return
		}
	}
}

func (store *Store) commitBatch(batch []writeRequest) error {
	transaction, err := store.writerDB.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("sqlite writer: begin batch: %w", err)
	}
	for _, request := range batch {
		if err := store.applyWrite(transaction, request); err != nil {
			_ = transaction.Rollback()
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("sqlite writer: commit batch: %w", err)
	}
	return nil
}

func (store *Store) applyWrite(transaction *sql.Tx, request writeRequest) error {
	signer := store.integrity.Load()
	switch request.kind {
	case writeBeginAudit:
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
		return finishAudit(transaction, request.data.(AuditFinish), signer)
	case writeResetProcessingParses:
		return resetProcessingParses(transaction)
	case writeClaimPendingParse:
		return claimPendingParse(transaction, request.data.(*parseClaim))
	case writeReleaseProcessingParse:
		return releaseProcessingParse(transaction, request.data.(string))
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
SET state = ?, status_code = ?, content_length = ?, ended_at_ns = ?, error_code = ?
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

func finishAudit(transaction *sql.Tx, finish AuditFinish, signer *security.IntegritySigner) error {
	if err := deduplicateEquivalentBodyStages(transaction, finish.AuditID); err != nil {
		return err
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
