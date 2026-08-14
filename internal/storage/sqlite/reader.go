package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const stageOrderSQL = `CASE stage
    WHEN 'request_for_newapi_received_from_nginx' THEN 1
    WHEN 'request_sent_to_newapi' THEN 2
    WHEN 'response_received_from_newapi' THEN 3
    WHEN 'response_from_newapi_sent_to_nginx' THEN 4
    ELSE 5
END`

// HasAudits reports whether at least one audit parent row exists.
func (store *Store) HasAudits(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return false, ErrClosed
	}
	var exists int
	if err := store.readerDB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM audit_records LIMIT 1)").Scan(&exists); err != nil {
		return false, fmt.Errorf("sqlite: check audits: %w", err)
	}
	return exists != 0, nil
}

// Snapshot returns one transactionally consistent view of an audit and all
// currently persisted encrypted HTTP evidence.
func (store *Store) Snapshot(ctx context.Context, auditID string) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, errors.New("sqlite: nil context")
	}
	if auditID == "" {
		return Snapshot{}, errors.New("sqlite: empty audit id")
	}
	if store == nil || store.isClosed() {
		return Snapshot{}, ErrClosed
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Snapshot{}, fmt.Errorf("sqlite: begin snapshot: %w", err)
	}
	defer transaction.Rollback()

	snapshot := Snapshot{}
	if err := scanAudit(transaction.QueryRowContext(ctx, `
SELECT audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
       method, path, request_uri_enc, mode, status_code, forward_status,
       capture_status, parse_status, blocked_by, block_code, error_code,
       newapi_request_id, caller_status, caller_attempts, caller_next_at_ns,
       caller_updated_at_ns
FROM audit_records
WHERE audit_id = ?`, auditID), &snapshot.Audit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Snapshot{}, sql.ErrNoRows
		}
		return Snapshot{}, fmt.Errorf("sqlite: read audit snapshot: %w", err)
	}

	if snapshot.Stages, err = readStages(ctx, transaction, auditID); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Headers, err = readHeaders(ctx, transaction, auditID); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Bodies, err = readBodies(ctx, transaction, auditID); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Chunks, err = readChunks(ctx, transaction, auditID); err != nil {
		return Snapshot{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("sqlite: commit snapshot: %w", err)
	}
	return snapshot, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanAudit(row rowScanner, destination *AuditRecord) error {
	var endedAt sql.NullInt64
	var statusCode sql.NullInt64
	var blockedBy sql.NullString
	var blockCode sql.NullString
	var errorCode sql.NullString
	var requestID sql.NullString
	var callerNextAt, callerUpdatedAt sql.NullInt64
	if err := row.Scan(
		&destination.AuditID,
		&destination.StartedAtNS,
		&endedAt,
		&destination.RouteID,
		&destination.Protocol,
		&destination.ParserName,
		&destination.Method,
		&destination.Path,
		&destination.RequestURIEnc,
		&destination.Mode,
		&statusCode,
		&destination.ForwardStatus,
		&destination.CaptureStatus,
		&destination.ParseStatus,
		&blockedBy,
		&blockCode,
		&errorCode,
		&requestID,
		&destination.CallerStatus,
		&destination.CallerAttempts,
		&callerNextAt,
		&callerUpdatedAt,
	); err != nil {
		return err
	}
	destination.RequestURIEnc = cloneBytes(destination.RequestURIEnc)
	destination.EndedAtNS = nullInt64Pointer(endedAt)
	destination.StatusCode = nullIntPointer(statusCode)
	destination.BlockedBy = nullStringPointer(blockedBy)
	destination.BlockCode = nullStringPointer(blockCode)
	destination.ErrorCode = nullStringPointer(errorCode)
	destination.NewAPIRequestID = nullStringPointer(requestID)
	destination.CallerNextAtNS = nullInt64Pointer(callerNextAt)
	destination.CallerUpdatedAtNS = nullInt64Pointer(callerUpdatedAt)
	return nil
}

func readStages(ctx context.Context, transaction *sql.Tx, auditID string) ([]HTTPStage, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, state, proto, method, host, status_code,
       content_length, started_at_ns, ended_at_ns, error_code
FROM http_stages
WHERE audit_id = ?
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read stages: %w", err)
	}
	defer rows.Close()

	stages := make([]HTTPStage, 0, 4)
	for rows.Next() {
		var stage HTTPStage
		var statusCode, contentLength, endedAt sql.NullInt64
		var errorCode sql.NullString
		if err := rows.Scan(
			&stage.AuditID,
			&stage.Stage,
			&stage.State,
			&stage.Proto,
			&stage.Method,
			&stage.Host,
			&statusCode,
			&contentLength,
			&stage.StartedAtNS,
			&endedAt,
			&errorCode,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan stage: %w", err)
		}
		stage.StatusCode = nullIntPointer(statusCode)
		stage.ContentLength = nullInt64Pointer(contentLength)
		stage.EndedAtNS = nullInt64Pointer(endedAt)
		stage.ErrorCode = nullStringPointer(errorCode)
		stages = append(stages, stage)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate stages: %w", err)
	}
	return stages, nil
}

func readHeaders(ctx context.Context, transaction *sql.Tx, auditID string) ([]HTTPHeader, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ?
ORDER BY `+stageOrderSQL+`, kind, name, value_index`, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read headers: %w", err)
	}
	defer rows.Close()

	headers := make([]HTTPHeader, 0)
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
			return nil, fmt.Errorf("sqlite: scan header: %w", err)
		}
		header.ValueEnc = cloneBytes(header.ValueEnc)
		headers = append(headers, header)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate headers: %w", err)
	}
	return headers, nil
}

func readBodies(ctx context.Context, transaction *sql.Tx, auditID string) ([]BodyStream, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, source_stage, observed_length, stored_length, sha256,
	   hash_complete, eof_seen, state, retention_state,
	   first_observed_at_ns, last_observed_at_ns, chunk_count,
	   stream_event_count, stream_timeline_complete, error_code
FROM body_streams
WHERE audit_id = ?
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read bodies: %w", err)
	}
	defer rows.Close()

	bodies := make([]BodyStream, 0, 4)
	for rows.Next() {
		var body BodyStream
		var digest []byte
		var hashComplete, eofSeen, timelineComplete int
		var firstObserved, lastObserved sql.NullInt64
		var errorCode sql.NullString
		if err := rows.Scan(
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
			&errorCode,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan body: %w", err)
		}
		body.SHA256 = cloneBytes(digest)
		body.HashComplete = hashComplete != 0
		body.EOFSeen = eofSeen != 0
		body.FirstObservedAtNS = nullInt64Pointer(firstObserved)
		body.LastObservedAtNS = nullInt64Pointer(lastObserved)
		body.StreamTimelineComplete = timelineComplete != 0
		body.ErrorCode = nullStringPointer(errorCode)
		bodies = append(bodies, body)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate bodies: %w", err)
	}
	return bodies, nil
}

func readChunks(ctx context.Context, transaction *sql.Tx, auditID string) ([]BodyChunk, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, seq, "offset", plaintext_length, encoded_length,
       observed_at_ns, compression, data_enc
FROM body_chunks
WHERE audit_id = ?
ORDER BY `+stageOrderSQL+`, seq`, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: read chunks: %w", err)
	}
	defer rows.Close()

	chunks := make([]BodyChunk, 0)
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
			return nil, fmt.Errorf("sqlite: scan chunk: %w", err)
		}
		chunk.DataEnc = cloneBytes(chunk.DataEnc)
		chunks = append(chunks, chunk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate chunks: %w", err)
	}
	return chunks, nil
}

func nullIntPointer(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	converted := int(value.Int64)
	return &converted
}

func nullInt64Pointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	converted := value.Int64
	return &converted
}

func nullStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	converted := value.String
	return &converted
}
