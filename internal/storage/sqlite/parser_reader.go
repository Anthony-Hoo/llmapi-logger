package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const maxParserReadLimit = 1000

// ListPendingParseIDs returns ended, non-rejected audits that still need
// parsing. Ordering is stable so a full queue eventually makes progress.
func (store *Store) ListPendingParseIDs(ctx context.Context, limit int) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if limit <= 0 || limit > maxParserReadLimit {
		return nil, fmt.Errorf("sqlite: invalid pending parse limit %d", limit)
	}

	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id
FROM audit_records
WHERE ended_at_ns IS NOT NULL
  AND parse_status = 'pending'
  AND forward_status <> 'rejected'
ORDER BY started_at_ns, audit_id
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list pending parses: %w", err)
	}
	defer rows.Close()

	ids := make([]string, 0, limit)
	for rows.Next() {
		var auditID string
		if err := rows.Scan(&auditID); err != nil {
			return nil, fmt.Errorf("sqlite: scan pending parse: %w", err)
		}
		ids = append(ids, auditID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate pending parses: %w", err)
	}
	return ids, nil
}

// LoadParserAudit returns only the immutable metadata needed to select and
// invoke a protocol parser.
func (store *Store) LoadParserAudit(ctx context.Context, auditID string) (ParserAudit, error) {
	if ctx == nil {
		return ParserAudit{}, errors.New("sqlite: nil context")
	}
	if auditID == "" {
		return ParserAudit{}, errors.New("sqlite: empty audit id")
	}
	if store == nil || store.isClosed() {
		return ParserAudit{}, ErrClosed
	}

	var audit ParserAudit
	err := store.readerDB.QueryRowContext(ctx, `
SELECT audit_id, protocol, parser_name, path, forward_status, capture_status, parse_status
FROM audit_records
WHERE audit_id = ?`, auditID).Scan(
		&audit.AuditID,
		&audit.Protocol,
		&audit.ParserName,
		&audit.Path,
		&audit.ForwardStatus,
		&audit.CaptureStatus,
		&audit.ParseStatus,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ParserAudit{}, sql.ErrNoRows
		}
		return ParserAudit{}, fmt.Errorf("sqlite: load parser audit: %w", err)
	}
	return audit, nil
}

// LoadParserStage reads one canonical stage, its body aggregate, and only the
// encrypted headers required to decode JSON or SSE evidence.
func (store *Store) LoadParserStage(ctx context.Context, auditID, stageName string) (ParserStage, error) {
	if ctx == nil {
		return ParserStage{}, errors.New("sqlite: nil context")
	}
	if auditID == "" || !validStage(stageName) {
		return ParserStage{}, errors.New("sqlite: invalid parser stage identity")
	}
	if store == nil || store.isClosed() {
		return ParserStage{}, ErrClosed
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ParserStage{}, fmt.Errorf("sqlite: begin parser stage read: %w", err)
	}
	defer transaction.Rollback()

	result := ParserStage{}
	var statusCode, contentLength, endedAt sql.NullInt64
	var errorCode sql.NullString
	err = transaction.QueryRowContext(ctx, `
SELECT audit_id, stage, state, proto, method, host, status_code,
       content_length, started_at_ns, ended_at_ns, error_code
FROM http_stages
WHERE audit_id = ? AND stage = ?`, auditID, stageName).Scan(
		&result.Stage.AuditID,
		&result.Stage.Stage,
		&result.Stage.State,
		&result.Stage.Proto,
		&result.Stage.Method,
		&result.Stage.Host,
		&statusCode,
		&contentLength,
		&result.Stage.StartedAtNS,
		&endedAt,
		&errorCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ParserStage{}, sql.ErrNoRows
		}
		return ParserStage{}, fmt.Errorf("sqlite: load parser stage: %w", err)
	}
	result.Stage.StatusCode = nullIntPointer(statusCode)
	result.Stage.ContentLength = nullInt64Pointer(contentLength)
	result.Stage.EndedAtNS = nullInt64Pointer(endedAt)
	result.Stage.ErrorCode = nullStringPointer(errorCode)

	var body BodyStream
	var digest []byte
	var hashComplete, eofSeen, timelineComplete int
	var firstObserved, lastObserved sql.NullInt64
	var bodyError sql.NullString
	err = transaction.QueryRowContext(ctx, `
SELECT audit_id, stage, source_stage, observed_length, stored_length, sha256,
	   hash_complete, eof_seen, state, retention_state,
	   first_observed_at_ns, last_observed_at_ns, chunk_count,
	   stream_event_count, stream_timeline_complete, error_code
FROM body_streams
WHERE audit_id = ? AND stage = ?`, auditID, stageName).Scan(
		&body.AuditID,
		&body.Stage,
		&body.SourceStage,
		&body.ObservedLength,
		&body.StoredLength,
		&digest,
		&hashComplete,
		&eofSeen,
		&body.State,
		&body.RetentionState,
		&firstObserved,
		&lastObserved,
		&body.ChunkCount,
		&body.StreamEventCount,
		&timelineComplete,
		&bodyError,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ParserStage{}, fmt.Errorf("sqlite: load parser body: %w", err)
	}
	if err == nil {
		body.SHA256 = cloneBytes(digest)
		body.HashComplete = hashComplete != 0
		body.EOFSeen = eofSeen != 0
		body.FirstObservedAtNS = nullInt64Pointer(firstObserved)
		body.LastObservedAtNS = nullInt64Pointer(lastObserved)
		body.StreamTimelineComplete = timelineComplete != 0
		body.ErrorCode = nullStringPointer(bodyError)
		result.Body = &body
	}

	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ? AND stage = ? AND kind = 'header'
  AND lower(name) IN ('content-type', 'content-encoding')
ORDER BY lower(name), value_index`, auditID, stageName)
	if err != nil {
		return ParserStage{}, fmt.Errorf("sqlite: load parser headers: %w", err)
	}
	for rows.Next() {
		var header HTTPHeader
		if err := rows.Scan(
			&header.AuditID,
			&header.Stage,
			&header.Kind,
			&header.Name,
			&header.ValueIndex,
			&header.ValueLength,
			&header.ValueEnc,
		); err != nil {
			_ = rows.Close()
			return ParserStage{}, fmt.Errorf("sqlite: scan parser header: %w", err)
		}
		header.ValueEnc = cloneBytes(header.ValueEnc)
		result.Headers = append(result.Headers, header)
	}
	if err := rows.Close(); err != nil {
		return ParserStage{}, fmt.Errorf("sqlite: close parser headers: %w", err)
	}
	if err := rows.Err(); err != nil {
		return ParserStage{}, fmt.Errorf("sqlite: iterate parser headers: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return ParserStage{}, fmt.Errorf("sqlite: commit parser stage read: %w", err)
	}
	return result, nil
}

// ReadParserChunks returns ciphertext chunks strictly after afterSeq, ordered
// by sequence number. Use -1 to start from the first chunk.
func (store *Store) ReadParserChunks(ctx context.Context, auditID, stageName string, afterSeq int64, limit int) ([]BodyChunk, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if auditID == "" || !validStage(stageName) || afterSeq < -1 || limit <= 0 || limit > maxParserReadLimit {
		return nil, errors.New("sqlite: invalid parser chunk query")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}

	var sourceStage string
	if err := store.readerDB.QueryRowContext(ctx, `SELECT source_stage FROM body_streams WHERE audit_id = ? AND stage = ?`, auditID, stageName).Scan(&sourceStage); err != nil {
		return nil, fmt.Errorf("sqlite: resolve parser chunk source: %w", err)
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, stage, seq, "offset", plaintext_length, encoded_length,
       observed_at_ns, compression, data_enc
FROM body_chunks
WHERE audit_id = ? AND stage = ? AND seq > ?
ORDER BY seq
LIMIT ?`, auditID, sourceStage, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read parser chunks: %w", err)
	}
	defer rows.Close()

	chunks := make([]BodyChunk, 0, limit)
	for rows.Next() {
		var chunk BodyChunk
		if err := rows.Scan(
			&chunk.AuditID,
			&chunk.Stage,
			&chunk.Seq,
			&chunk.Offset,
			&chunk.PlaintextLength,
			&chunk.EncodedLength,
			&chunk.ObservedAtNS,
			&chunk.Compression,
			&chunk.DataEnc,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan parser chunk: %w", err)
		}
		chunk.DataEnc = cloneBytes(chunk.DataEnc)
		chunks = append(chunks, chunk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate parser chunks: %w", err)
	}
	return chunks, nil
}
