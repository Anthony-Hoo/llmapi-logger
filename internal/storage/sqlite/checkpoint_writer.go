package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

// Checkpoint non-blockingly appends one in-flight write of the unified write
// path: new stage rows, header groups, initial body rows and sealed chunks,
// in the shape legacy StartStage, AddHeaders, StartBody and AddChunk leave
// for an in-flight request. A nil error means accepted by the queue, not yet
// committed. On ErrQueueFull nothing is remembered: the session still holds
// the content and folds it into its next write.
func (store *Store) Checkpoint(ctx context.Context, checkpoint AuditCheckpoint) error {
	owned := cloneAuditCheckpoint(checkpoint)
	for index := range owned.Stages {
		owned.Stages[index].Defaults()
	}
	for index := range owned.Bodies {
		owned.Bodies[index].Defaults()
	}
	if err := storage.ValidateAuditCheckpoint(owned); err != nil {
		return err
	}
	if storage.EffectiveCaptureVersion(owned.CaptureVersion) != storage.CaptureVersion1 {
		return errUnsupportedCaptureVersion
	}
	return store.submitAsync(ctx, writeRequest{kind: writeCheckpoint, data: owned})
}

// writeAuditCheckpoint is one checkpoint inside the writer's per-operation
// savepoint. A finalized audit is never changed. Any failure rolls back the
// whole checkpoint; markCaptureWriteFailed then fails the audit.
func writeAuditCheckpoint(transaction *sql.Tx, checkpoint AuditCheckpoint) error {
	var ended sql.NullInt64
	var captureStatus string
	if err := transaction.QueryRow("SELECT ended_at_ns, capture_status FROM audit_records WHERE audit_id = ?", checkpoint.AuditID).Scan(&ended, &captureStatus); err != nil {
		return fmt.Errorf("sqlite writer: read checkpoint state: %w", err)
	}
	if ended.Valid {
		return nil
	}
	for _, stage := range checkpoint.Stages {
		if err := insertStage(transaction, stage); err != nil {
			return err
		}
	}
	if captureStatus != CaptureFailed {
		if err := insertHeaders(transaction, checkpoint.Headers); err != nil {
			return err
		}
		for _, body := range checkpoint.Bodies {
			if err := insertBody(transaction, body); err != nil {
				return err
			}
		}
		return insertOwnedChunks(transaction, checkpoint.AuditID, checkpoint.Chunks, nil)
	}
	// An earlier write was lost (for example the inbound stage row at
	// BeginAudit), so the session may send parts whose parent row is
	// missing. Legacy loses exactly those operations, each on its own; skip
	// them instead of losing the whole checkpoint on a foreign key.
	stages, err := storedStageSet(transaction, "http_stages", checkpoint.AuditID)
	if err != nil {
		return err
	}
	var headers []HTTPHeader
	for _, header := range checkpoint.Headers {
		if stages[header.Stage] {
			headers = append(headers, header)
		}
	}
	if err := insertHeaders(transaction, headers); err != nil {
		return err
	}
	for _, body := range checkpoint.Bodies {
		if !stages[body.Stage] || !stages[body.SourceStage] {
			continue
		}
		if err := insertBody(transaction, body); err != nil {
			return err
		}
	}
	bodies, err := storedStageSet(transaction, "body_streams", checkpoint.AuditID)
	if err != nil {
		return err
	}
	return insertOwnedChunks(transaction, checkpoint.AuditID, checkpoint.Chunks, func(stage string) bool { return bodies[stage] })
}

// insertOwnedChunks inserts every chunk of source. keep, when non-nil, skips
// chunks whose stage it rejects. A chunk that fails validation or a source
// that cannot be read is a local error, so only this operation rolls back;
// a database error from an insert keeps its own class.
func insertOwnedChunks(transaction *sql.Tx, auditID string, source ChunkSource, keep func(stage string) bool) error {
	if source == nil {
		return nil
	}
	var insertErr error
	err := source.Each(func(chunk BodyChunk) error {
		chunk.Defaults()
		if err := storage.ValidateOwnedChunk(auditID, chunk); err != nil {
			return localWriteError("sqlite writer: " + err.Error())
		}
		if keep != nil && !keep(chunk.Stage) {
			return nil
		}
		if err := insertChunk(transaction, chunk); err != nil {
			insertErr = err
			return err
		}
		return nil
	})
	if insertErr != nil {
		return insertErr
	}
	if err != nil {
		var local localWriteError
		if errors.As(err, &local) {
			return err
		}
		return localWriteError("sqlite writer: read owned chunks failed")
	}
	return nil
}

// chunkBounds returns, per stage, the end offset of the furthest chunk in
// source. A source that fails part way still reports what it yielded.
func chunkBounds(source ChunkSource) map[string]int64 {
	bounds := make(map[string]int64)
	if source == nil {
		return bounds
	}
	each := source.Each
	if metadata, ok := source.(chunkMetadataSource); ok {
		// Staged chunks: their bounds need no file read, which matters as
		// this runs under the recovery and submit locks.
		each = metadata.EachMetadata
	}
	_ = each(func(chunk BodyChunk) error {
		bounds[chunk.Stage] = max(bounds[chunk.Stage], chunk.Offset+int64(chunk.PlaintextLength))
		return nil
	})
	return bounds
}

// chunkMetadataSource is a chunk source that can yield its chunks without
// their ciphertext (internal/audit's source over staged chunks).
type chunkMetadataSource interface {
	EachMetadata(visit func(BodyChunk) error) error
}

func checkpointChunkBounds(checkpoint AuditCheckpoint) map[string]int64 {
	return chunkBounds(checkpoint.Chunks)
}

func cloneAuditCheckpoint(checkpoint AuditCheckpoint) AuditCheckpoint {
	owned := AuditCheckpoint{
		AuditID:        checkpoint.AuditID,
		CaptureVersion: checkpoint.CaptureVersion,
		Chunks:         cloneChunkSource(checkpoint.Chunks),
	}
	if checkpoint.HeaderBlock != nil {
		block := *checkpoint.HeaderBlock
		block.DataEnc = cloneBytes(block.DataEnc)
		owned.HeaderBlock = &block
	}
	for _, stage := range checkpoint.Stages {
		owned.Stages = append(owned.Stages, cloneHTTPStage(stage))
	}
	for _, content := range checkpoint.Contents {
		content.ContentType = cloneString(content.ContentType)
		content.ContentEncoding = cloneString(content.ContentEncoding)
		owned.Contents = append(owned.Contents, content)
	}
	for _, header := range checkpoint.Headers {
		owned.Headers = append(owned.Headers, cloneHTTPHeader(header))
	}
	for _, body := range checkpoint.Bodies {
		owned.Bodies = append(owned.Bodies, cloneBodyStream(body))
	}
	return owned
}

// cloneChunkSource copies chunks held in memory. Any other source is a
// repeatable, immutable view by contract (staging file positions) and is
// kept as is.
func cloneChunkSource(source ChunkSource) ChunkSource {
	list, ok := source.(storage.ChunkList)
	if !ok {
		return source
	}
	owned := make(storage.ChunkList, len(list))
	for index, chunk := range list {
		owned[index] = cloneBodyChunk(chunk)
	}
	return owned
}
