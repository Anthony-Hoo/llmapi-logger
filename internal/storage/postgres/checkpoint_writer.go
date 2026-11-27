package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"llmapi-logger/internal/storage"
)

// checkpointWrite is the writer's owned copy of one AuditCheckpoint. Its
// chunk source is not copied: the session hands its sealed chunks over and
// never changes them afterwards.
type checkpointWrite struct {
	AuditCheckpoint
}

// Checkpoint non-blockingly appends one in-flight write of the staged write
// path (doc/design/issue-59-stage3-write-path.md B.3). Like StartStage, a nil
// error means accepted by the queue, not committed; a full queue returns
// ErrQueueFull at once, and the session folds the content into its next write.
func (store *Store) Checkpoint(ctx context.Context, checkpoint AuditCheckpoint) error {
	checkpoint.Stages = append([]HTTPStage(nil), checkpoint.Stages...)
	for index := range checkpoint.Stages {
		checkpoint.Stages[index].Defaults()
	}
	checkpoint.Bodies = append([]BodyStream(nil), checkpoint.Bodies...)
	for index := range checkpoint.Bodies {
		checkpoint.Bodies[index].Defaults()
	}
	if err := storage.ValidateAuditCheckpoint(checkpoint); err != nil {
		return err
	}
	if err := requireCaptureVersion(checkpoint.CaptureVersion); err != nil {
		return err
	}
	if list, ok := checkpoint.Chunks.(storage.ChunkList); ok && len(list) == 0 {
		checkpoint.Chunks = nil
	}
	if len(checkpoint.Stages) == 0 && len(checkpoint.Headers) == 0 && len(checkpoint.Bodies) == 0 &&
		checkpoint.HeaderBlock == nil && checkpoint.Chunks == nil {
		return nil
	}
	owned := &checkpointWrite{AuditCheckpoint: AuditCheckpoint{
		AuditID:        checkpoint.AuditID,
		CaptureVersion: checkpoint.CaptureVersion,
		Stages:         make([]HTTPStage, len(checkpoint.Stages)),
		Headers:        make([]HTTPHeader, len(checkpoint.Headers)),
		Bodies:         make([]BodyStream, len(checkpoint.Bodies)),
		Chunks:         checkpoint.Chunks,
	}}
	for index, stage := range checkpoint.Stages {
		owned.Stages[index] = cloneHTTPStage(stage)
	}
	for index, header := range checkpoint.Headers {
		owned.Headers[index] = cloneHTTPHeader(header)
	}
	for index, body := range checkpoint.Bodies {
		owned.Bodies[index] = cloneBodyStream(body)
	}
	return store.submitAsync(ctx, writeRequest{kind: writeCheckpoint, data: owned, payloadBytes: chunkPayloadBytes(checkpoint.Chunks)})
}

// requireCaptureVersion admits the capture versions this schema can store.
// Version 2 needs migration 007, which adds the header block and the new
// columns; until then a version 2 write is a local error.
func requireCaptureVersion(version int) error {
	switch storage.EffectiveCaptureVersion(version) {
	case storage.CaptureVersion1:
		return nil
	default:
		return localWriteError(fmt.Sprintf("postgres writer: capture version %d is not supported by this schema", version))
	}
}

// applyCheckpoint inserts the checkpoint's rows in one savepoint, in the
// shape the legacy StartStage, AddHeaders, StartBody and AddChunk leave for an
// in-flight request (B.4): only inserts, never final values.
func applyCheckpoint(transaction dbTransaction, checkpoint *checkpointWrite) error {
	var ended sql.NullInt64
	var captureStatus string
	if err := transaction.QueryRow("SELECT ended_at_ns, capture_status FROM audit_records WHERE audit_id=$1", checkpoint.AuditID).Scan(&ended, &captureStatus); err != nil {
		return fmt.Errorf("postgres writer: read checkpoint audit: %w", err)
	}
	if ended.Valid {
		// A checkpoint queued behind its own finalization adds nothing to
		// signed evidence.
		return nil
	}
	headers, bodies := checkpoint.Headers, checkpoint.Bodies
	var keep func(string) bool
	if captureStatus == CaptureFailed {
		// A recorded failure may have left a parent row missing (the inbound
		// stage BeginAudit could not write, or an earlier checkpoint). Write
		// what still has its parents, as the legacy operations would have
		// failed one by one on the rest.
		present, err := loadPresentRows(transaction, checkpoint.AuditID)
		if err != nil {
			return err
		}
		for _, stage := range checkpoint.Stages {
			present.stages[stage.Stage] = true
		}
		headers = make([]HTTPHeader, 0, len(checkpoint.Headers))
		for _, header := range checkpoint.Headers {
			if present.stages[header.Stage] {
				headers = append(headers, header)
			}
		}
		bodies = make([]BodyStream, 0, len(checkpoint.Bodies))
		for _, body := range checkpoint.Bodies {
			if present.stages[body.Stage] && present.stages[body.SourceStage] {
				bodies = append(bodies, body)
				present.bodies[body.Stage] = true
			}
		}
		keep = func(stage string) bool { return present.bodies[stage] }
	}
	if err := insertStageRows(transaction, checkpoint.Stages); err != nil {
		return err
	}
	if err := insertHeaderRows(transaction, headers); err != nil {
		return err
	}
	if err := insertBodyRows(transaction, bodies); err != nil {
		return err
	}
	return insertChunkRows(transaction, checkpoint.AuditID, checkpoint.Chunks, keep)
}

func (checkpoint *checkpointWrite) chunkBounds() [4]int64 {
	return chunkBoundsOf(checkpoint.Chunks)
}

// chunkBoundsOf returns, per stage in capture order, the end offset of the
// furthest chunk, or -1 for a stage without chunks. Failure bookkeeping uses
// it; an unreadable source contributes the chunks read before the error.
func chunkBoundsOf(source ChunkSource) [4]int64 {
	bounds := [4]int64{-1, -1, -1, -1}
	if source == nil {
		return bounds
	}
	_ = source.Each(func(chunk BodyChunk) error {
		if order := storage.StageOrder(chunk.Stage); order >= 0 {
			bounds[order] = max(bounds[order], chunk.Offset+int64(chunk.PlaintextLength))
		}
		return nil
	})
	return bounds
}

// chunkPayloadBytes sizes the ciphertext of an in-memory chunk list. Any other
// source holds chunks staged on disk, which only a body above the memory
// budget has, so it counts as large.
func chunkPayloadBytes(source ChunkSource) int64 {
	switch chunks := source.(type) {
	case nil:
		return 0
	case storage.ChunkList:
		var total int64
		for _, chunk := range chunks {
			total += int64(len(chunk.DataEnc))
		}
		return total
	default:
		return aloneWritePayloadBytes + 1
	}
}

// insertStageRows is insertStage for several rows in one statement.
func insertStageRows(transaction dbTransaction, stages []HTTPStage) error {
	return forEachInsertBatch(len(stages), nil, func(start, end int) error {
		values := make([]string, 0, end-start)
		arguments := make([]any, 0, (end-start)*11)
		for index, stage := range stages[start:end] {
			values = append(values, "("+placeholders(11, index*11)+")")
			arguments = append(arguments, stage.AuditID, stage.Stage, stage.State, stage.Proto, stage.Method, stage.Host,
				stage.StatusCode, stage.ContentLength, stage.StartedAtNS, stage.EndedAtNS, stage.ErrorCode)
		}
		if _, err := transaction.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, status_code,
    content_length, started_at_ns, ended_at_ns, error_code
) VALUES `+strings.Join(values, ","), arguments...); err != nil {
			return fmt.Errorf("postgres writer: start stage: %w", err)
		}
		return nil
	})
}

// insertHeaderRows is insertHeaders with up to 400 rows or about 4 MiB per
// statement.
func insertHeaderRows(transaction dbTransaction, headers []HTTPHeader) error {
	return forEachInsertBatch(len(headers), func(index int) int { return len(headers[index].ValueEnc) + len(headers[index].Name) }, func(start, end int) error {
		values := make([]string, 0, end-start)
		arguments := make([]any, 0, (end-start)*7)
		for index, header := range headers[start:end] {
			values = append(values, "("+placeholders(7, index*7)+")")
			arguments = append(arguments, header.AuditID, header.Stage, header.Kind, header.Name,
				header.ValueIndex, header.ValueLength, header.ValueEnc)
		}
		if _, err := transaction.Exec(`
INSERT INTO http_headers (
    audit_id, stage, kind, name, value_index, value_length, value_enc
) VALUES `+strings.Join(values, ","), arguments...); err != nil {
			return fmt.Errorf("postgres writer: add header: %w", err)
		}
		return nil
	})
}

// insertBodyRows is insertBody for several rows in one statement. The rows
// are in stage order, so a merged duplicate follows its source.
func insertBodyRows(transaction dbTransaction, bodies []BodyStream) error {
	return forEachInsertBatch(len(bodies), nil, func(start, end int) error {
		values := make([]string, 0, end-start)
		arguments := make([]any, 0, (end-start)*16)
		for index, body := range bodies[start:end] {
			values = append(values, "("+placeholders(16, index*16)+")")
			arguments = append(arguments, body.AuditID, body.Stage, body.SourceStage, body.ObservedLength, body.StoredLength,
				nullableBytes(body.SHA256), boolInteger(body.HashComplete), boolInteger(body.EOFSeen), body.State,
				body.RetentionState, body.FirstObservedAtNS, body.LastObservedAtNS, body.ChunkCount,
				body.StreamEventCount, boolInteger(body.StreamTimelineComplete), body.ErrorCode)
		}
		if _, err := transaction.Exec(`
INSERT INTO body_streams (
    audit_id, stage, source_stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state, retention_state,
    first_observed_at_ns, last_observed_at_ns, chunk_count,
    stream_event_count, stream_timeline_complete, error_code
) VALUES `+strings.Join(values, ","), arguments...); err != nil {
			return fmt.Errorf("postgres writer: start body: %w", err)
		}
		return nil
	})
}

// insertChunkRows reads the source once and inserts its chunks with the
// limits of forEachInsertBatch: at most 400 rows, and about 4 MiB of
// ciphertext unless a single chunk is larger. keep, when non-nil, drops the
// chunks of stages it rejects.
func insertChunkRows(transaction dbTransaction, auditID string, source ChunkSource, keep func(stage string) bool) error {
	if source == nil {
		return nil
	}
	batch := make([]BodyChunk, 0, 8)
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		values := make([]string, 0, len(batch))
		arguments := make([]any, 0, len(batch)*9)
		for index, chunk := range batch {
			values = append(values, "("+placeholders(9, index*9)+")")
			arguments = append(arguments, chunk.AuditID, chunk.Stage, chunk.Seq, chunk.Offset, chunk.PlaintextLength,
				chunk.EncodedLength, chunk.ObservedAtNS, chunk.Compression, chunk.DataEnc)
		}
		batch, size = batch[:0], 0
		if _, err := transaction.Exec(`
INSERT INTO body_chunks (
    audit_id, stage, seq, "offset", plaintext_length, encoded_length,
    observed_at_ns, compression, data_enc
) VALUES `+strings.Join(values, ","), arguments...); err != nil {
			return fmt.Errorf("postgres writer: add chunk: %w", err)
		}
		return nil
	}
	err := source.Each(func(chunk BodyChunk) error {
		chunk.Defaults()
		if err := storage.ValidateOwnedChunk(auditID, chunk); err != nil {
			return localWriteError("postgres writer: " + err.Error())
		}
		if keep != nil && !keep(chunk.Stage) {
			return nil
		}
		if len(batch) > 0 && (len(batch) >= graphHashQueryBatch || size+len(chunk.DataEnc) > objectInsertBatchBytes) {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, chunk)
		size += len(chunk.DataEnc)
		return nil
	})
	if err != nil {
		return err
	}
	return flush()
}

func cloneInboundStage(inbound InboundStage) InboundStage {
	inbound.Stage = cloneHTTPStage(inbound.Stage)
	headers := make([]HTTPHeader, len(inbound.Headers))
	for index, header := range inbound.Headers {
		headers[index] = cloneHTTPHeader(header)
	}
	inbound.Headers = headers
	inbound.HeaderBlock = cloneHeaderBlock(inbound.HeaderBlock)
	inbound.ContentType = cloneString(inbound.ContentType)
	inbound.ContentEncoding = cloneString(inbound.ContentEncoding)
	return inbound
}

func cloneHeaderBlock(block *HeaderBlock) *HeaderBlock {
	if block == nil {
		return nil
	}
	owned := *block
	owned.DataEnc = cloneBytes(block.DataEnc)
	return &owned
}
