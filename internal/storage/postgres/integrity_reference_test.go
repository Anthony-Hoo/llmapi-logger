package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// This file keeps the payload digests exactly as they were computed before
// PostgreSQL hashed the ciphertext: every encrypted column is selected, carried
// into the process and hashed there. It is the fixed point the production
// digests are compared against, so it must not be refactored onto production
// helpers that read digests instead of ciphertext. Shared helpers it still
// calls (loadRequestRefs, loadResponseRefs, readGraphBinaries, appendRefsDigest,
// the encoder primitives) return the same values they did then.

func referenceBlobDigest(encoder *digestEncoder, value []byte) {
	if len(value) == 0 {
		encoder.field(nil)
		return
	}
	digest := sha256.Sum256(value)
	encoder.field(digest[:])
}

func referenceIntegrityPayloadDigest(ctx context.Context, transaction dbTransaction, cache *integrityGraphCache, auditID, eventType string) ([]byte, error) {
	switch eventType {
	case integrityCaptureFinalized:
		var version int64
		if err := transaction.QueryRowContext(ctx, `SELECT capture_version FROM audit_records WHERE audit_id = $1`, auditID).Scan(&version); err != nil {
			return nil, err
		}
		switch version {
		case CaptureVersion1:
			return referenceCapturePayloadDigest(ctx, transaction, auditID)
		case CaptureVersion2:
			return referenceCapturePayloadDigestV2(ctx, transaction, auditID)
		default:
			return nil, errors.New("postgres integrity: unknown capture version")
		}
	case integritySemanticCompacted:
		return referenceSemanticPayloadDigest(ctx, transaction, cache, auditID)
	case integrityReconstructionFailed:
		return referenceReconstructionFailurePayloadDigest(ctx, transaction, auditID)
	default:
		return nil, errors.New("postgres integrity: unsupported event type")
	}
}

func referenceReadIntegrityObjects(ctx context.Context, transaction dbTransaction, cache *integrityGraphCache, hashes [][]byte) ([]integrityObject, error) {
	unique := uniqueHashes(hashes)
	missing := make([][]byte, 0, len(unique))
	for _, hash := range unique {
		if _, cached := cache.objects[hex.EncodeToString(hash)]; !cached {
			missing = append(missing, hash)
		}
	}
	for start := 0; start < len(missing); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(missing))
		arguments := make([]any, 0, end-start)
		for _, hash := range missing[start:end] {
			arguments = append(arguments, hash)
		}
		rows, err := transaction.QueryContext(ctx, `
SELECT object_hash, semantic_hash, kind, compression,
       plaintext_length, encoded_length, data_enc
FROM content_objects
WHERE object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return nil, fmt.Errorf("postgres integrity: read graph content objects: %w", err)
		}
		for rows.Next() {
			var object integrityObject
			var data []byte
			if err := rows.Scan(
				&object.Hash,
				&object.SemanticHash,
				&object.Kind,
				&object.Compression,
				&object.PlaintextLength,
				&object.EncodedLength,
				&data,
			); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres integrity: scan graph content object: %w", err)
			}
			object.Hash = cloneBytes(object.Hash)
			object.SemanticHash = cloneBytes(object.SemanticHash)
			if len(data) != 0 {
				digest := sha256.Sum256(data)
				object.DataDigest = digest[:]
			}
			cache.objects[hex.EncodeToString(object.Hash)] = object
		}
		if err := closeRows(rows); err != nil {
			return nil, err
		}
	}
	result := make([]integrityObject, 0, len(unique))
	for _, hash := range unique {
		object, cached := cache.objects[hex.EncodeToString(hash)]
		if !cached {
			return nil, errors.New("postgres integrity: turn graph references a missing content object")
		}
		result = append(result, object)
	}
	return result, nil
}

func referenceCapturePayloadDigest(ctx context.Context, transaction dbTransaction, auditID string) ([]byte, error) {
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
WHERE audit_id = $1`, auditID).Scan(
		&startedAt, &endedAt, &routeID, &protocol, &parserName,
		&method, &path, &requestURI, &mode, &statusCode, &ttft,
		&forwardStatus, &captureStatus, &blockedBy, &blockCode, &errorCode,
		&requestID,
	); err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture audit: %w", err)
	}
	encoder.integer(startedAt)
	encoder.integer(endedAt)
	for _, value := range []string{routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus} {
		encoder.text(value)
	}
	referenceBlobDigest(encoder, requestURI)
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
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture stages: %w", err)
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
WHERE audit_id = $1
ORDER BY `+stageOrderSQL+`, kind, name, value_index`, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture headers: %w", err)
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
		referenceBlobDigest(encoder, encrypted)
	}
	if err := closeRows(headerRows); err != nil {
		return nil, err
	}

	bodyRows, err := transaction.QueryContext(ctx, `
SELECT stage, source_stage, observed_length, sha256, hash_complete,
       eof_seen, state, first_observed_at_ns, last_observed_at_ns, error_code
FROM body_streams
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture bodies: %w", err)
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

func referenceSemanticPayloadDigest(ctx context.Context, transaction dbTransaction, cache *integrityGraphCache, auditID string) ([]byte, error) {
	if cache == nil {
		cache = newIntegrityGraphCache()
	}
	encoder := newDigestEncoder(semanticPayloadDomain)
	encoder.text(auditID)
	if err := referenceAppendParsedResultDigest(ctx, transaction, encoder, auditID); err != nil {
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
WHERE audit_id = $1`, auditID).Scan(
		&turnID, &conversationID, &requestLayout, &responseLayout,
		&requestEnvelopeHash, &responseEnvelopeHash,
		&requestCount, &responseCount,
		&requestSequenceHash, &responseSequenceHash,
		&requestReconstructionHash, &responseReconstructionHash,
		&reconstructionStatus, &previousResponseID, &responseID, &createdAt,
	); err != nil {
		return nil, fmt.Errorf("postgres integrity: read semantic turn: %w", err)
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

	requestRefs, err := loadRequestRefs(transaction, turnID, cache.refs, make(map[string]bool))
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
	objects, err := referenceReadIntegrityObjects(ctx, transaction, cache, hashes)
	if err != nil {
		return nil, err
	}
	objectHashes := make([][]byte, 0, len(objects))
	for _, object := range objects {
		encoder.text("content_object")
		encoder.field(object.Hash)
		encoder.field(object.SemanticHash)
		encoder.text(object.Kind)
		encoder.text(object.Compression)
		encoder.integer(object.PlaintextLength)
		encoder.integer(object.EncodedLength)
		encoder.field(object.DataDigest)
		objectHashes = append(objectHashes, object.Hash)
	}
	if err := referenceAppendObjectReferenceDigest(ctx, transaction, encoder, objectHashes); err != nil {
		return nil, err
	}
	binaries, err := readGraphBinaries(ctx, transaction, objectHashes)
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
		referenceBlobDigest(encoder, binary.DataEnc)
	}
	retentionRows, err := transaction.QueryContext(ctx, `
SELECT b.stage, b.retention_state, b.stream_event_count,
       b.stream_timeline_complete, t.compression,
       t.plaintext_length, t.timeline_enc
FROM body_streams AS b
LEFT JOIN stream_timelines AS t
  ON t.audit_id = b.audit_id AND t.stage = b.stage
WHERE b.audit_id = $1
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
		referenceBlobDigest(encoder, timeline)
	}
	if err := closeRows(retentionRows); err != nil {
		return nil, err
	}
	return encoder.sum(), nil
}

func referenceReconstructionFailurePayloadDigest(ctx context.Context, transaction dbTransaction, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(reconstructionFailureDomain)
	encoder.text(auditID)
	if err := referenceAppendParsedResultDigest(ctx, transaction, encoder, auditID); err != nil {
		return nil, err
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT stage, observed_length, sha256, state, retention_state, error_code
FROM body_streams
WHERE audit_id = $1
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

func referenceAppendParsedResultDigest(ctx context.Context, transaction dbTransaction, encoder *digestEncoder, auditID string) error {
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
WHERE audit_id = $1`, auditID).Scan(
		&parserName, &parserVersion, &status, &requestModel, &responseModel,
		&requestedStream, &observedStream, &responseID, &usageInput,
		&usageOutput, &usageTotal, &errorType, &errorCode, &messageCount,
		&toolCallCount, &hasToolCall, &parsedJSON, &parsedAt,
	); err != nil {
		return fmt.Errorf("postgres integrity: read parsed result: %w", err)
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
	referenceBlobDigest(encoder, parsedJSON)
	encoder.integer(parsedAt)
	return nil
}

func referenceAppendObjectReferenceDigest(ctx context.Context, transaction dbTransaction, encoder *digestEncoder, hashes [][]byte) error {
	if len(hashes) == 0 {
		return nil
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
			referenceBlobDigest(encoder, valueEnc)
		}
		if err := closeRows(externalRows); err != nil {
			return err
		}
	}
	return nil
}
