package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
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
// and verifies the recorded event chain before accepting new audit writes. It
// is intended to run during startup immediately after Open.
//
// It checks only what the event count bounds: MAC linkage across the chain and
// the presence of an event for every terminal audit and every turn. Re-deriving
// each event's payload digest has to walk the whole turn graph behind that
// event, which grows with conversation depth rather than event count, so it is
// split into VerifyIntegrityPayloads for the caller to run once serving.
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

// VerifyIntegrityPayloads re-derives the signed payload of every recorded event
// from the audit rows it still covers and compares it against the digest stored
// when the event was appended. EnableIntegrity proves the chain itself was not
// rewritten; this proves the rows underneath it did not change.
//
// It reads through the reader pool because the writer pool holds a single
// connection: a pass measured in minutes on the writer would stall every audit
// write for its duration. The outcome is sticky, since the writer resets the
// general health flag on each committed batch.
func (store *Store) VerifyIntegrityPayloads(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlite: nil integrity context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if err := verifyIntegrityPayloads(ctx, store.readerDB); err != nil {
		// Shutdown cancels the context and tears down the reader pool
		// mid-pass. That is an interrupted verification, not a detected
		// mismatch, and must not leave the store permanently unhealthy.
		if ctx.Err() == nil && !store.isClosed() {
			store.payloadState.Store(integrityPayloadsFailed)
		}
		return err
	}
	store.payloadState.Store(integrityPayloadsVerified)
	return nil
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

// payloadTarget is one event the payload pass has to re-derive, carrying the
// conversation its audit belongs to so the pass can group by turn graph.
type payloadTarget struct {
	AuditID        string
	EventType      string
	PayloadDigest  []byte
	ConversationID string
}

func verifyIntegrityPayloads(ctx context.Context, database *sql.DB) error {
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("sqlite integrity: begin payload verification: %w", err)
	}
	defer transaction.Rollback()
	// Only events whose audit still exists carry rows to re-derive from;
	// retention removes the audit behind older events but keeps the chain.
	// Ordering by conversation lets one cache serve a whole turn chain,
	// because a turn's ancestors never live in another conversation.
	rows, err := transaction.QueryContext(ctx, `
SELECT e.audit_id, e.event_type, e.payload_digest, COALESCE(t.conversation_id, '')
FROM integrity_events AS e
JOIN audit_records AS a ON a.audit_id = e.audit_id
LEFT JOIN turns AS t ON t.audit_id = e.audit_id
ORDER BY COALESCE(t.conversation_id, ''), e.sequence`)
	if err != nil {
		return fmt.Errorf("sqlite integrity: read payload targets: %w", err)
	}
	// Drained before the per-event queries below, which reuse this
	// transaction's single connection.
	var targets []payloadTarget
	for rows.Next() {
		var target payloadTarget
		if err := rows.Scan(&target.AuditID, &target.EventType, &target.PayloadDigest, &target.ConversationID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite integrity: scan payload target: %w", err)
		}
		targets = append(targets, target)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlite integrity: close payload targets: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite integrity: iterate payload targets: %w", err)
	}

	cache := newIntegrityGraphCache()
	conversation := ""
	for index, target := range targets {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("sqlite integrity: payload verification canceled: %w", err)
		}
		if index == 0 || target.ConversationID != conversation {
			conversation = target.ConversationID
			cache.reset()
		}
		current, err := integrityPayloadDigest(ctx, transaction, cache, target.AuditID, target.EventType)
		if err != nil || !bytes.Equal(current, target.PayloadDigest) {
			return errors.New("sqlite integrity: current audit payload verification failed")
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("sqlite integrity: commit payload verification: %w", err)
	}
	return nil
}

// integrityGraphCache memoizes the turn-graph reads that dominate payload
// verification. loadRequestRefs walks a turn's entire ancestor chain, so a
// cache living for one event alone re-derives every ancestor once per
// descendant and turns a K-turn conversation into O(K^2) chain walks. Parent
// turns never cross conversations, so resetting on a conversation boundary
// collapses that to O(K) while keeping peak memory bounded by the largest
// single conversation rather than by the whole database.
type integrityGraphCache struct {
	refs    map[string][]auditmodel.ObjectRef
	objects map[string]integrityObject
}

func newIntegrityGraphCache() *integrityGraphCache {
	return &integrityGraphCache{
		refs:    make(map[string][]auditmodel.ObjectRef),
		objects: make(map[string]integrityObject),
	}
}

func (cache *integrityGraphCache) reset() {
	if cache == nil {
		return
	}
	clear(cache.refs)
	clear(cache.objects)
}

// integrityObject holds only what a payload digest consumes from a content
// object. The stored ciphertext is reduced to its SHA-256 on read because that
// is all the encoder writes, so caching a whole conversation's object set costs
// a digest per object instead of the ciphertext itself.
type integrityObject struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	Compression     string
	PlaintextLength int64
	EncodedLength   int64
	DataDigest      []byte
}

// readIntegrityObjects mirrors readGraphObjects, including its sorted unique
// ordering, but serves repeats from the cache and keeps only digests.
func readIntegrityObjects(ctx context.Context, transaction *sql.Tx, cache *integrityGraphCache, hashes [][]byte) ([]integrityObject, error) {
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
			return nil, fmt.Errorf("sqlite integrity: read graph content objects: %w", err)
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
				return nil, fmt.Errorf("sqlite integrity: scan graph content object: %w", err)
			}
			object.Hash = cloneBytes(object.Hash)
			object.SemanticHash = cloneBytes(object.SemanticHash)
			// Matches digestEncoder.blobDigest: empty ciphertext hashes as an
			// absent field rather than as the digest of an empty string.
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
			return nil, errors.New("sqlite integrity: turn graph references a missing content object")
		}
		result = append(result, object)
	}
	return result, nil
}

func integrityPayloadDigest(ctx context.Context, transaction *sql.Tx, cache *integrityGraphCache, auditID, eventType string) ([]byte, error) {
	switch eventType {
	case integrityCaptureFinalized:
		return capturePayloadDigest(ctx, transaction, auditID)
	case integritySemanticCompacted:
		return semanticPayloadDigest(ctx, transaction, cache, auditID)
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

// semanticPayloadDigest derives the digest signed by a semantic_compacted
// event. The cache is shared across every event of one conversation on the
// verification path and single-use on the write path; either way the emitted
// byte sequence is identical, which is what makes the two comparable.
func semanticPayloadDigest(ctx context.Context, transaction *sql.Tx, cache *integrityGraphCache, auditID string) ([]byte, error) {
	if cache == nil {
		cache = newIntegrityGraphCache()
	}
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
	objects, err := readIntegrityObjects(ctx, transaction, cache, hashes)
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
	if err := appendObjectReferenceDigest(ctx, transaction, encoder, objectHashes); err != nil {
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

func appendObjectReferenceDigest(ctx context.Context, transaction *sql.Tx, encoder *digestEncoder, hashes [][]byte) error {
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
