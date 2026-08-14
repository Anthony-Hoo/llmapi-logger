package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

const (
	integrityCaptureFinalized     = "capture_finalized"
	integritySemanticCompacted    = "semantic_compacted"
	integrityReconstructionFailed = "reconstruction_failed"
	capturePayloadDomain          = "llmapi-logger/capture-payload/v1\x00"
	semanticPayloadDomain         = "llmapi-logger/semantic-payload/v1\x00"
	reconstructionFailureDomain   = "llmapi-logger/reconstruction-failure/v1\x00"
)

// EnableIntegrity derives the event-chain signer from the audit master key
// and verifies every existing event before accepting new audit writes. It is
// intended to run during startup immediately after Open.
func (store *Store) EnableIntegrity(ctx context.Context, masterKey []byte) error {
	if ctx == nil {
		return errors.New("sqlite: nil integrity context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	signer, err := security.NewIntegritySigner(masterKey)
	if err != nil {
		return err
	}
	if err := verifyIntegrityChain(ctx, store.writerDB, signer); err != nil {
		store.healthy.Store(false)
		return err
	}
	store.integrity.Store(signer)
	return nil
}

func (store *Store) IntegrityEnabled() bool {
	return store != nil && store.integrity.Load() != nil
}

type integrityEvent struct {
	Sequence      int64
	AuditID       string
	EventType     string
	PreviousMAC   []byte
	PayloadDigest []byte
	EventMAC      []byte
	CreatedAtNS   int64
}

func appendIntegrityEvent(transaction *sql.Tx, signer *security.IntegritySigner, auditID, eventType string, payloadDigest []byte, createdAtNS int64) error {
	if signer == nil {
		return nil
	}
	var previousMAC []byte
	err := transaction.QueryRow(`
SELECT event_mac
FROM integrity_events
ORDER BY sequence DESC
LIMIT 1`).Scan(&previousMAC)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("sqlite integrity: read previous event: %w", err)
	}
	mac, err := signer.MAC(previousMAC, auditID, eventType, payloadDigest, createdAtNS)
	if err != nil {
		return fmt.Errorf("sqlite integrity: sign event: %w", err)
	}
	if _, err := transaction.Exec(`
INSERT INTO integrity_events (
    audit_id, event_type, previous_mac, payload_digest, event_mac, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?)`,
		auditID, eventType, nullableBytes(previousMAC), payloadDigest, mac, createdAtNS,
	); err != nil {
		return fmt.Errorf("sqlite integrity: insert event: %w", err)
	}
	return nil
}

func verifyIntegrityChain(ctx context.Context, database *sql.DB, signer *security.IntegritySigner) error {
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("sqlite integrity: begin verification: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `
SELECT sequence, audit_id, event_type, previous_mac,
       payload_digest, event_mac, created_at_ns
FROM integrity_events
ORDER BY sequence`)
	if err != nil {
		return fmt.Errorf("sqlite integrity: read events: %w", err)
	}
	var events []integrityEvent
	for rows.Next() {
		var event integrityEvent
		if err := rows.Scan(
			&event.Sequence,
			&event.AuditID,
			&event.EventType,
			&event.PreviousMAC,
			&event.PayloadDigest,
			&event.EventMAC,
			&event.CreatedAtNS,
		); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite integrity: scan event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlite integrity: close events: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite integrity: iterate events: %w", err)
	}
	var previous []byte
	for _, event := range events {
		if !bytes.Equal(event.PreviousMAC, previous) ||
			!signer.Verify(event.PreviousMAC, event.AuditID, event.EventType, event.PayloadDigest, event.EventMAC, event.CreatedAtNS) {
			return errors.New("sqlite integrity: event chain verification failed")
		}
		var auditExists int
		if err := transaction.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_records WHERE audit_id = ?)`, event.AuditID).Scan(&auditExists); err != nil {
			return fmt.Errorf("sqlite integrity: check event audit: %w", err)
		}
		if auditExists != 0 {
			current, err := integrityPayloadDigest(ctx, transaction, event.AuditID, event.EventType)
			if err != nil || !bytes.Equal(current, event.PayloadDigest) {
				return errors.New("sqlite integrity: current audit payload verification failed")
			}
		}
		previous = append(previous[:0], event.EventMAC...)
	}
	var missingCapture int
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM audit_records AS a
WHERE a.ended_at_ns IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM integrity_events AS e
      WHERE e.audit_id = a.audit_id AND e.event_type = 'capture_finalized'
  )`).Scan(&missingCapture); err != nil {
		return fmt.Errorf("sqlite integrity: count missing capture events: %w", err)
	}
	if missingCapture != 0 {
		return errors.New("sqlite integrity: terminal audits are missing capture events")
	}
	var missingSemantic int
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM turns AS t
WHERE NOT EXISTS (
    SELECT 1 FROM integrity_events AS e
    WHERE e.audit_id = t.audit_id AND e.event_type = 'semantic_compacted'
)`).Scan(&missingSemantic); err != nil {
		return fmt.Errorf("sqlite integrity: count missing semantic events: %w", err)
	}
	if missingSemantic != 0 {
		return errors.New("sqlite integrity: turns are missing semantic events")
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("sqlite integrity: commit verification: %w", err)
	}
	return nil
}

func integrityPayloadDigest(ctx context.Context, transaction *sql.Tx, auditID, eventType string) ([]byte, error) {
	switch eventType {
	case integrityCaptureFinalized:
		return capturePayloadDigest(ctx, transaction, auditID)
	case integritySemanticCompacted:
		return semanticPayloadDigest(ctx, transaction, auditID)
	case integrityReconstructionFailed:
		return reconstructionFailurePayloadDigest(ctx, transaction, auditID)
	default:
		return nil, errors.New("sqlite integrity: unsupported event type")
	}
}

type digestEncoder struct {
	digest hash.Hash
}

func newDigestEncoder(domain string) *digestEncoder {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	return &digestEncoder{digest: digest}
}

func (encoder *digestEncoder) field(value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = encoder.digest.Write(length[:])
	_, _ = encoder.digest.Write(value)
}

func (encoder *digestEncoder) text(value string) { encoder.field([]byte(value)) }

func (encoder *digestEncoder) integer(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	encoder.field(encoded[:])
}

func (encoder *digestEncoder) nullableInteger(value sql.NullInt64) {
	if !value.Valid {
		encoder.field(nil)
		return
	}
	encoder.integer(value.Int64)
}

func (encoder *digestEncoder) nullableText(value sql.NullString) {
	if !value.Valid {
		encoder.field(nil)
		return
	}
	encoder.text(value.String)
}

func (encoder *digestEncoder) blobDigest(value []byte) {
	if len(value) == 0 {
		encoder.field(nil)
		return
	}
	digest := sha256.Sum256(value)
	encoder.field(digest[:])
}

func (encoder *digestEncoder) sum() []byte { return encoder.digest.Sum(nil) }

func capturePayloadDigest(ctx context.Context, transaction *sql.Tx, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(capturePayloadDomain)
	encoder.text(auditID)
	var startedAt, endedAt int64
	var routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus string
	var requestURI []byte
	var statusCode, ttft sql.NullInt64
	var blockedBy, blockCode, errorCode, requestID sql.NullString
	if err := transaction.QueryRowContext(ctx, `
SELECT started_at_ns, ended_at_ns, route_id, protocol, parser_name,
       method, path, request_uri_enc, mode, status_code, ttft_ns,
       forward_status, capture_status, blocked_by, block_code, error_code,
       newapi_request_id
FROM audit_records
WHERE audit_id = ?`, auditID).Scan(
		&startedAt, &endedAt, &routeID, &protocol, &parserName,
		&method, &path, &requestURI, &mode, &statusCode, &ttft,
		&forwardStatus, &captureStatus, &blockedBy, &blockCode, &errorCode,
		&requestID,
	); err != nil {
		return nil, fmt.Errorf("sqlite integrity: read capture audit: %w", err)
	}
	encoder.integer(startedAt)
	encoder.integer(endedAt)
	for _, value := range []string{routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus} {
		encoder.text(value)
	}
	encoder.blobDigest(requestURI)
	encoder.nullableInteger(statusCode)
	encoder.nullableInteger(ttft)
	encoder.nullableText(blockedBy)
	encoder.nullableText(blockCode)
	encoder.nullableText(errorCode)
	encoder.nullableText(requestID)

	stageRows, err := transaction.QueryContext(ctx, `
SELECT stage, state, proto, method, host, status_code, content_length,
       started_at_ns, ended_at_ns, error_code
FROM http_stages
WHERE audit_id = ?
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite integrity: read capture stages: %w", err)
	}
	for stageRows.Next() {
		var stage, state, proto, stageMethod, host string
		var stageStatus, contentLength, stageEnded sql.NullInt64
		var stageStarted int64
		var stageError sql.NullString
		if err := stageRows.Scan(&stage, &state, &proto, &stageMethod, &host, &stageStatus, &contentLength, &stageStarted, &stageEnded, &stageError); err != nil {
			_ = stageRows.Close()
			return nil, err
		}
		encoder.text("stage")
		for _, value := range []string{stage, state, proto, stageMethod, host} {
			encoder.text(value)
		}
		encoder.nullableInteger(stageStatus)
		encoder.nullableInteger(contentLength)
		encoder.integer(stageStarted)
		encoder.nullableInteger(stageEnded)
		encoder.nullableText(stageError)
	}
	if err := closeRows(stageRows); err != nil {
		return nil, err
	}

	headerRows, err := transaction.QueryContext(ctx, `
SELECT stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ?
ORDER BY `+stageOrderSQL+`, kind, name, value_index`, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite integrity: read capture headers: %w", err)
	}
	for headerRows.Next() {
		var stage, kind, name string
		var index, length int64
		var encrypted []byte
		if err := headerRows.Scan(&stage, &kind, &name, &index, &length, &encrypted); err != nil {
			_ = headerRows.Close()
			return nil, err
		}
		encoder.text("header")
		encoder.text(stage)
		encoder.text(kind)
		encoder.text(name)
		encoder.integer(index)
		encoder.integer(length)
		encoder.blobDigest(encrypted)
	}
	if err := closeRows(headerRows); err != nil {
		return nil, err
	}

	bodyRows, err := transaction.QueryContext(ctx, `
SELECT stage, source_stage, observed_length, sha256, hash_complete,
       eof_seen, state, first_observed_at_ns, last_observed_at_ns, error_code
FROM body_streams
WHERE audit_id = ?
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("sqlite integrity: read capture bodies: %w", err)
	}
	for bodyRows.Next() {
		var stage, sourceStage, state string
		var observed int64
		var digest []byte
		var hashComplete, eofSeen int64
		var first, last sql.NullInt64
		var bodyError sql.NullString
		if err := bodyRows.Scan(&stage, &sourceStage, &observed, &digest, &hashComplete, &eofSeen, &state, &first, &last, &bodyError); err != nil {
			_ = bodyRows.Close()
			return nil, err
		}
		encoder.text("body")
		encoder.text(stage)
		encoder.text(sourceStage)
		encoder.integer(observed)
		encoder.field(digest)
		encoder.integer(hashComplete)
		encoder.integer(eofSeen)
		encoder.text(state)
		encoder.nullableInteger(first)
		encoder.nullableInteger(last)
		encoder.nullableText(bodyError)
	}
	if err := closeRows(bodyRows); err != nil {
		return nil, err
	}
	return encoder.sum(), nil
}

func semanticPayloadDigest(ctx context.Context, transaction *sql.Tx, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(semanticPayloadDomain)
	encoder.text(auditID)
	if err := appendParsedResultDigest(ctx, transaction, encoder, auditID); err != nil {
		return nil, err
	}
	var turnID, conversationID, requestLayout, responseLayout, reconstructionStatus string
	var requestEnvelopeHash, responseEnvelopeHash, requestSequenceHash, responseSequenceHash []byte
	var requestReconstructionHash, responseReconstructionHash []byte
	var requestCount, responseCount, createdAt int64
	var previousResponseID, responseID sql.NullString
	if err := transaction.QueryRowContext(ctx, `
SELECT turn_id, conversation_id, request_layout, response_layout,
       request_envelope_hash, response_envelope_hash,
       request_item_count, response_item_count,
       request_sequence_hash, response_sequence_hash,
       request_reconstruction_hash, response_reconstruction_hash,
       reconstruction_status, previous_response_id, response_id, created_at_ns
FROM turns
WHERE audit_id = ?`, auditID).Scan(
		&turnID, &conversationID, &requestLayout, &responseLayout,
		&requestEnvelopeHash, &responseEnvelopeHash,
		&requestCount, &responseCount,
		&requestSequenceHash, &responseSequenceHash,
		&requestReconstructionHash, &responseReconstructionHash,
		&reconstructionStatus, &previousResponseID, &responseID, &createdAt,
	); err != nil {
		return nil, fmt.Errorf("sqlite integrity: read semantic turn: %w", err)
	}
	for _, value := range []string{turnID, conversationID, requestLayout, responseLayout, reconstructionStatus} {
		encoder.text(value)
	}
	for _, value := range [][]byte{requestEnvelopeHash, responseEnvelopeHash, requestSequenceHash, responseSequenceHash, requestReconstructionHash, responseReconstructionHash} {
		encoder.field(value)
	}
	encoder.integer(requestCount)
	encoder.integer(responseCount)
	encoder.nullableText(previousResponseID)
	encoder.nullableText(responseID)
	encoder.integer(createdAt)

	memo := make(map[string][]auditmodel.ObjectRef)
	requestRefs, err := loadRequestRefs(transaction, turnID, memo, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	responseRefs, err := loadResponseRefs(transaction, turnID)
	if err != nil {
		return nil, err
	}
	appendRefsDigest(encoder, "request_ref", requestRefs)
	appendRefsDigest(encoder, "response_ref", responseRefs)
	hashes := [][]byte{requestEnvelopeHash, responseEnvelopeHash}
	for _, ref := range requestRefs {
		hashes = append(hashes, ref.ObjectHash)
	}
	for _, ref := range responseRefs {
		hashes = append(hashes, ref.ObjectHash)
	}
	objects, err := readGraphObjects(ctx, transaction, hashes)
	if err != nil {
		return nil, err
	}
	for _, object := range objects {
		encoder.text("content_object")
		encoder.field(object.Hash)
		encoder.field(object.SemanticHash)
		encoder.text(object.Kind)
		encoder.text(object.Compression)
		encoder.integer(object.PlaintextLength)
		encoder.integer(object.EncodedLength)
		encoder.blobDigest(object.DataEnc)
	}
	if err := appendObjectReferenceDigest(ctx, transaction, encoder, objects); err != nil {
		return nil, err
	}
	binaries, err := readGraphBinaries(ctx, transaction, objects)
	if err != nil {
		return nil, err
	}
	sort.Slice(binaries, func(left, right int) bool { return bytes.Compare(binaries[left].Hash, binaries[right].Hash) < 0 })
	for _, binary := range binaries {
		encoder.text("binary_object")
		encoder.field(binary.Hash)
		encoder.text(binary.MediaType)
		encoder.text(binary.Compression)
		encoder.integer(binary.PlaintextLength)
		encoder.integer(binary.EncodedLength)
		encoder.blobDigest(binary.DataEnc)
	}
	retentionRows, err := transaction.QueryContext(ctx, `
SELECT b.stage, b.retention_state, b.stream_event_count,
       b.stream_timeline_complete, t.compression,
       t.plaintext_length, t.timeline_enc
FROM body_streams AS b
LEFT JOIN stream_timelines AS t
  ON t.audit_id = b.audit_id AND t.stage = b.stage
WHERE b.audit_id = ?
ORDER BY CASE b.stage
    WHEN 'request_for_newapi_received_from_nginx' THEN 1
    WHEN 'request_sent_to_newapi' THEN 2
    WHEN 'response_received_from_newapi' THEN 3
    WHEN 'response_from_newapi_sent_to_nginx' THEN 4
    ELSE 5
END`, auditID)
	if err != nil {
		return nil, err
	}
	for retentionRows.Next() {
		var stage, retention string
		var eventCount, complete int64
		var compression sql.NullString
		var plaintextLength sql.NullInt64
		var timeline []byte
		if err := retentionRows.Scan(&stage, &retention, &eventCount, &complete, &compression, &plaintextLength, &timeline); err != nil {
			_ = retentionRows.Close()
			return nil, err
		}
		encoder.text("retention")
		encoder.text(stage)
		encoder.text(retention)
		encoder.integer(eventCount)
		encoder.integer(complete)
		encoder.nullableText(compression)
		encoder.nullableInteger(plaintextLength)
		encoder.blobDigest(timeline)
	}
	if err := closeRows(retentionRows); err != nil {
		return nil, err
	}
	return encoder.sum(), nil
}

func reconstructionFailurePayloadDigest(ctx context.Context, transaction *sql.Tx, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(reconstructionFailureDomain)
	encoder.text(auditID)
	if err := appendParsedResultDigest(ctx, transaction, encoder, auditID); err != nil {
		return nil, err
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT stage, observed_length, sha256, state, retention_state, error_code
FROM body_streams
WHERE audit_id = ?
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var stage, state, retention string
		var observed int64
		var digest []byte
		var errorCode sql.NullString
		if err := rows.Scan(&stage, &observed, &digest, &state, &retention, &errorCode); err != nil {
			_ = rows.Close()
			return nil, err
		}
		encoder.text(stage)
		encoder.integer(observed)
		encoder.field(digest)
		encoder.text(state)
		encoder.text(retention)
		encoder.nullableText(errorCode)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return encoder.sum(), nil
}

func appendParsedResultDigest(ctx context.Context, transaction *sql.Tx, encoder *digestEncoder, auditID string) error {
	var parserName, parserVersion, status string
	var requestModel, responseModel, responseID, errorType, errorCode sql.NullString
	var requestedStream, observedStream, usageInput, usageOutput, usageTotal sql.NullInt64
	var messageCount, toolCallCount, hasToolCall sql.NullInt64
	var parsedJSON []byte
	var parsedAt int64
	if err := transaction.QueryRowContext(ctx, `
SELECT parser_name, parser_version, status, request_model, response_model,
       requested_stream, observed_stream, response_id, usage_input,
       usage_output, usage_total, error_type, error_code, message_count,
       tool_call_count, has_tool_call, parsed_json_enc, parsed_at_ns
FROM parsed_results
WHERE audit_id = ?`, auditID).Scan(
		&parserName, &parserVersion, &status, &requestModel, &responseModel,
		&requestedStream, &observedStream, &responseID, &usageInput,
		&usageOutput, &usageTotal, &errorType, &errorCode, &messageCount,
		&toolCallCount, &hasToolCall, &parsedJSON, &parsedAt,
	); err != nil {
		return fmt.Errorf("sqlite integrity: read parsed result: %w", err)
	}
	encoder.text(parserName)
	encoder.text(parserVersion)
	encoder.text(status)
	encoder.nullableText(requestModel)
	encoder.nullableText(responseModel)
	encoder.nullableInteger(requestedStream)
	encoder.nullableInteger(observedStream)
	encoder.nullableText(responseID)
	encoder.nullableInteger(usageInput)
	encoder.nullableInteger(usageOutput)
	encoder.nullableInteger(usageTotal)
	encoder.nullableText(errorType)
	encoder.nullableText(errorCode)
	encoder.nullableInteger(messageCount)
	encoder.nullableInteger(toolCallCount)
	encoder.nullableInteger(hasToolCall)
	encoder.blobDigest(parsedJSON)
	encoder.integer(parsedAt)
	return nil
}

func appendRefsDigest(encoder *digestEncoder, marker string, refs []auditmodel.ObjectRef) {
	for _, ref := range refs {
		encoder.text(marker)
		encoder.text(ref.Slot)
		encoder.field(ref.ObjectHash)
		encoder.field(ref.SemanticHash)
	}
}

func appendObjectReferenceDigest(ctx context.Context, transaction *sql.Tx, encoder *digestEncoder, objects []auditmodel.StoredContent) error {
	if len(objects) == 0 {
		return nil
	}
	hashes := make([][]byte, 0, len(objects))
	for _, object := range objects {
		hashes = append(hashes, object.Hash)
	}
	for start := 0; start < len(hashes); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(hashes))
		arguments := make([]any, 0, end-start)
		for _, value := range hashes[start:end] {
			arguments = append(arguments, value)
		}
		binaryRows, err := transaction.QueryContext(ctx, `
SELECT object_hash, json_pointer, binary_hash, media_type, encoding
FROM content_binary_refs
WHERE object_hash IN (`+placeholders(len(arguments))+`)
ORDER BY object_hash, json_pointer, binary_hash`, arguments...)
		if err != nil {
			return err
		}
		for binaryRows.Next() {
			var objectHash, binaryHash []byte
			var pointer, mediaType, encoding string
			if err := binaryRows.Scan(&objectHash, &pointer, &binaryHash, &mediaType, &encoding); err != nil {
				_ = binaryRows.Close()
				return err
			}
			encoder.text("binary_ref")
			encoder.field(objectHash)
			encoder.text(pointer)
			encoder.field(binaryHash)
			encoder.text(mediaType)
			encoder.text(encoding)
		}
		if err := closeRows(binaryRows); err != nil {
			return err
		}
		externalRows, err := transaction.QueryContext(ctx, `
SELECT object_hash, json_pointer, ref_kind, value_hash, value_enc
FROM content_external_refs
WHERE object_hash IN (`+placeholders(len(arguments))+`)
ORDER BY object_hash, json_pointer, ref_kind`, arguments...)
		if err != nil {
			return err
		}
		for externalRows.Next() {
			var objectHash, valueHash, valueEnc []byte
			var pointer, kind string
			if err := externalRows.Scan(&objectHash, &pointer, &kind, &valueHash, &valueEnc); err != nil {
				_ = externalRows.Close()
				return err
			}
			encoder.text("external_ref")
			encoder.field(objectHash)
			encoder.text(pointer)
			encoder.text(kind)
			encoder.field(valueHash)
			encoder.blobDigest(valueEnc)
		}
		if err := closeRows(externalRows); err != nil {
			return err
		}
	}
	return nil
}

func closeRows(rows *sql.Rows) error {
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil {
		return iterationErr
	}
	return closeErr
}
