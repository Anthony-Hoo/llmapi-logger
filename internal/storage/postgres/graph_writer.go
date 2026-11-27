package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const parentCandidateLimit = 32

type turnParent struct {
	TurnID         string
	ConversationID string
	BaseKind       string
	Reason         string
	Confidence     int
	Base           []auditmodel.ObjectRef
	cost           int
}

type storedTurnHeader struct {
	ParentTurnID        *string
	ParentBase          string
	RequestItemCount    int
	RequestSequenceHash []byte
}

func saveParsedAudit(transaction dbTransaction, value ParsedAudit, signer *security.IntegritySigner) error {
	if err := upsertParsedResult(transaction, value.Result); err != nil {
		return err
	}

	graphVerified := false
	var reconstructed []auditmodel.ObjectRef
	if value.Turn != nil {
		var err error
		if reconstructed, err = persistTurn(transaction, *value.Turn); err != nil {
			return err
		}
		graphVerified = true
	}

	decision, err := decideRawRetention(transaction, value, graphVerified)
	if err != nil {
		return err
	}
	if err := applySideRetention(transaction, value.Result.AuditID, decision.ReleaseRequest, StageRequestReceived, StageRequestSent); err != nil {
		return err
	}
	if err := applySideRetention(transaction, value.Result.AuditID, decision.ReleaseResponse, StageResponseReceived, StageResponseSent); err != nil {
		return err
	}

	parent, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = $1, parse_next_at_ns = NULL
WHERE audit_id = $2
  AND parser_name = $3
  AND parse_status = 'processing'
  AND forward_status <> 'rejected'`, value.Result.Status, value.Result.AuditID, value.Result.ParserName)
	if err != nil {
		return fmt.Errorf("postgres writer: finish parse status: %w", err)
	}
	if err := requireOneRow(parent, "finish parse status"); err != nil {
		return err
	}
	if graphVerified {
		// The digest starts from the request refs persistTurn has just
		// rebuilt and verified in this transaction, so it does not walk the
		// chain again. A full walk would verify the same rows and return the
		// same refs: since then only body chunks, body streams and the parse
		// status were written, and the walk's limits were checked against the
		// whole chain when those refs were rebuilt.
		cache := newIntegrityGraphCache()
		cache.refs[value.Turn.AuditID] = reconstructed
		payloadDigest, err := semanticPayloadDigest(context.Background(), transaction, cache, value.Result.AuditID)
		if err != nil {
			return err
		}
		if err := appendIntegrityEvent(transaction, signer, value.Result.AuditID, integritySemanticCompacted, payloadDigest, value.Result.ParsedAtNS); err != nil {
			return err
		}
	} else if value.Result.ErrorCode != nil && (*value.Result.ErrorCode == "reconstruction_failed" || *value.Result.ErrorCode == "normalization_failed") {
		payloadDigest, err := reconstructionFailurePayloadDigest(context.Background(), transaction, value.Result.AuditID)
		if err != nil {
			return err
		}
		if err := appendIntegrityEvent(transaction, signer, value.Result.AuditID, integrityReconstructionFailed, payloadDigest, value.Result.ParsedAtNS); err != nil {
			return err
		}
	}
	return nil
}

func upsertParsedResult(transaction dbTransaction, result ParsedResult) error {
	_, err := transaction.Exec(`
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status,
    request_model, response_model, requested_stream, observed_stream,
    response_id, usage_input, usage_output, usage_total,
    error_type, error_code, upstream_error_class,
    message_count, tool_call_count, has_tool_call,
    parsed_json_enc, parsed_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
ON CONFLICT(audit_id) DO UPDATE SET
    parser_name = excluded.parser_name,
    parser_version = excluded.parser_version,
    status = excluded.status,
    request_model = excluded.request_model,
    response_model = excluded.response_model,
    requested_stream = excluded.requested_stream,
    observed_stream = excluded.observed_stream,
    response_id = excluded.response_id,
    usage_input = excluded.usage_input,
    usage_output = excluded.usage_output,
    usage_total = excluded.usage_total,
    error_type = excluded.error_type,
    error_code = excluded.error_code,
    upstream_error_class = excluded.upstream_error_class,
    message_count = excluded.message_count,
    tool_call_count = excluded.tool_call_count,
    has_tool_call = excluded.has_tool_call,
    parsed_json_enc = excluded.parsed_json_enc,
    parsed_at_ns = excluded.parsed_at_ns`,
		result.AuditID,
		result.ParserName,
		result.ParserVersion,
		result.Status,
		result.RequestModel,
		result.ResponseModel,
		boolDatabaseValue(result.RequestedStream),
		boolDatabaseValue(result.ObservedStream),
		result.ResponseID,
		result.UsageInput,
		result.UsageOutput,
		result.UsageTotal,
		result.ErrorType,
		result.ErrorCode,
		result.UpstreamErrorClass,
		result.MessageCount,
		result.ToolCallCount,
		boolDatabaseValue(result.HasToolCall),
		nullableBytes(result.ParsedJSONEnc),
		result.ParsedAtNS,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: save parsed result: %w", err)
	}
	return nil
}

// rawRetentionDecision is the rule saveParsedAudit applies. Tests replace it
// to write rows the way an older binary did.
var rawRetentionDecision = storage.DecideRawRetention

// decideRawRetention reads the outcome of the audit and decides, per side,
// whether its raw is released (storage.DecideRawRetention).
func decideRawRetention(transaction dbTransaction, value ParsedAudit, graphVerified bool) (storage.RawRetention, error) {
	result := value.Result
	if !graphVerified || value.Turn == nil {
		return rawRetentionDecision(storage.RawRetentionOutcome{ParseStatus: result.Status}), nil
	}
	outcome := storage.RawRetentionOutcome{
		ParseStatus:        result.Status,
		TurnVerified:       graphVerified,
		RequestNormalized:  value.Turn.RequestLayout != auditmodel.LayoutNone,
		UpstreamErrorClass: result.UpstreamErrorClass,
	}
	var statusCode sql.NullInt64
	var responseBodies int
	if err := transaction.QueryRow(`
SELECT forward_status, capture_status, status_code,
       (SELECT COUNT(*) FROM body_streams WHERE audit_id = $1 AND stage IN ($2, $3))
FROM audit_records
WHERE audit_id = $1`, result.AuditID, StageResponseReceived, StageResponseSent).Scan(&outcome.ForwardStatus, &outcome.CaptureStatus, &statusCode, &responseBodies); err != nil {
		return storage.RawRetention{}, fmt.Errorf("postgres writer: read raw retention outcome: %w", err)
	}
	// A request-only turn: a response body was captured and the turn does not
	// carry it.
	outcome.ResponseOmitted = value.Turn.ResponseLayout == auditmodel.LayoutNone && responseBodies > 0
	if statusCode.Valid {
		outcome.StatusCode = &statusCode.Int64
	}
	var mergedStages int
	if err := transaction.QueryRow(`
SELECT COUNT(*)
FROM body_streams
WHERE audit_id = $1
  AND ((stage = $2 AND source_stage = $2) OR (stage = $3 AND source_stage = $2))
  AND state = 'complete'
  AND (error_code IS NULL OR error_code <> 'body_stage_mismatch')`,
		result.AuditID, StageRequestReceived, StageRequestSent).Scan(&mergedStages); err != nil {
		return storage.RawRetention{}, fmt.Errorf("postgres writer: read request stage merge: %w", err)
	}
	outcome.RequestStagesMerged = mergedStages == 2
	return rawRetentionDecision(outcome), nil
}

// applySideRetention sets the retention of one side's two stages. Releasing
// deletes the side's chunks, which belong to whichever of its stages is the
// source_stage (merging never crosses sides), and zeroes the stored counters.
func applySideRetention(transaction dbTransaction, auditID string, release bool, first, second string) error {
	retention := RetentionFull
	if release {
		retention = RetentionMetadata
		if _, err := transaction.Exec(`DELETE FROM body_chunks WHERE audit_id = $1 AND stage IN ($2, $3)`, auditID, first, second); err != nil {
			return fmt.Errorf("postgres writer: delete compacted raw chunks: %w", err)
		}
	}
	if _, err := transaction.Exec(`
UPDATE body_streams
SET retention_state = $1,
    stored_length = CASE WHEN $2 = 'metadata' THEN 0 ELSE stored_length END,
    chunk_count = CASE WHEN $3 = 'metadata' THEN 0 ELSE chunk_count END
WHERE audit_id = $4 AND stage IN ($5, $6)`, retention, retention, retention, auditID, first, second); err != nil {
		return fmt.Errorf("postgres writer: update raw retention: %w", err)
	}
	return nil
}

func persistPreparedTurn(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	_, err := persistTurn(transaction, turn)
	return err
}

// persistTurn writes the turn and returns its request refs, rebuilt from the
// stored rows and verified against the prepared sequence.
func persistTurn(transaction dbTransaction, turn auditmodel.PreparedTurn) ([]auditmodel.ObjectRef, error) {
	if err := insertBinaryObjects(transaction, turn); err != nil {
		return nil, err
	}
	if err := insertContentObjects(transaction, turn); err != nil {
		return nil, err
	}
	parent, chains, err := chooseTurnParent(transaction, turn)
	if err != nil {
		return nil, err
	}
	conversationID, err := ensureConversation(transaction, turn, parent)
	if err != nil {
		return nil, err
	}
	base := []auditmodel.ObjectRef(nil)
	parentTurnID := any(nil)
	parentBase := "root"
	linkReason := "root"
	linkConfidence := 100
	if parent != nil {
		base = parent.Base
		parentTurnID = parent.TurnID
		parentBase = parent.BaseKind
		linkReason = parent.Reason
		linkConfidence = parent.Confidence
	}
	operations := auditmodel.BuildDelta(base, turn.RequestRefs)
	if err := insertTurn(transaction, turn, conversationID, parentTurnID, parentBase, linkReason, linkConfidence); err != nil {
		return nil, err
	}
	if err := insertContextOperations(transaction, turn.AuditID, operations); err != nil {
		return nil, err
	}
	if err := insertResponseItems(transaction, turn.AuditID, turn.ResponseRefs); err != nil {
		return nil, err
	}
	if _, err := transaction.Exec(`UPDATE conversations SET updated_at_ns = GREATEST(updated_at_ns, $1) WHERE conversation_id = $2`, turn.CreatedAtNS, conversationID); err != nil {
		return nil, fmt.Errorf("postgres writer: update conversation timestamp: %w", err)
	}

	reconstructed, err := reloadPersistedRequestRefs(transaction, turn, parent, chains, len(operations))
	if err != nil {
		return nil, err
	}
	if len(reconstructed) != len(turn.RequestRefs) || !bytes.Equal(auditmodel.SequenceHash(reconstructed), turn.RequestSequenceHash) {
		return nil, localWriteError("postgres writer: persisted request sequence failed reconstruction")
	}
	response, err := loadResponseRefs(transaction, turn.AuditID)
	if err != nil {
		return nil, err
	}
	if len(response) != len(turn.ResponseRefs) || !bytes.Equal(auditmodel.SequenceHash(response), turn.ResponseSequenceHash) {
		return nil, localWriteError("postgres writer: persisted response sequence failed reconstruction")
	}
	return reconstructed, nil
}

// reloadPersistedRequestRefs rebuilds the just-written turn's request from
// the stored rows. Its parent's chain was loaded and verified a moment ago in
// this transaction and has not changed since, so the walk starts from the
// parent's refs and reads only the new turn's rows. It first refuses what a
// walk back to the root would have refused, in the same order and with the
// same errors: more turns or reference rows on the whole chain than the
// preload limits allow, or a turn with too many request items.
func reloadPersistedRequestRefs(transaction dbTransaction, turn auditmodel.PreparedTurn, parent *turnParent, chains *candidateChains, operations int) ([]auditmodel.ObjectRef, error) {
	full := func() ([]auditmodel.ObjectRef, error) {
		return loadRequestRefs(transaction, turn.AuditID, make(map[string][]auditmodel.ObjectRef), make(map[string]bool))
	}
	if parent == nil || chains == nil {
		return full()
	}
	frame, framed := chains.frames[parent.TurnID]
	parentRefs, loaded := chains.refs[parent.TurnID]
	if !framed || !loaded {
		return full()
	}
	if frame.depth+1 > maxAncestorHeaders {
		return nil, localWriteError("postgres writer: ancestor header limit exceeded")
	}
	if len(turn.RequestRefs) > maxAncestorReferenceRows {
		return nil, localWriteError("postgres writer: reconstructed reference limit exceeded")
	}
	rows := frame.rows + operations
	if parent.BaseKind == "post_turn" {
		// The post_turn base is the parent's request followed by its response.
		rows += len(parent.Base) - len(parentRefs)
	}
	if rows > maxAncestorReferenceRows {
		return nil, localWriteError("postgres writer: ancestor reference limit exceeded")
	}
	return loadRequestRefs(transaction, turn.AuditID, map[string][]auditmodel.ObjectRef{parent.TurnID: parentRefs}, make(map[string]bool))
}

// Object writes send only what the database does not hold yet. Existence is
// decided here, inside the writer transaction, and not taken from the
// preparation lookup: that lookup runs on a read connection before the
// transaction, and retention's object GC, which runs on this same writer, may
// delete an unreferenced object in between. Because every object write and
// every GC run share the one writer, what these batched reads see cannot
// change before commit, so no row lock is needed.
//
// The reads select key and identity columns only, never data_enc or
// value_enc, and existing rows are never written: the ciphertext the lookup
// already authenticated stays in the database, and every digest computed
// over stored rows keeps its input.

// objectInsertBatchBytes caps the ciphertext one multi-row object insert
// carries, so a turn with many large objects does not build one huge
// statement. A single object larger than the cap is sent alone.
const objectInsertBatchBytes = 4 << 20

type binaryIdentity struct {
	mediaType       string
	plaintextLength int64
}

type contentIdentity struct {
	semanticHash    []byte
	kind            string
	plaintextLength int64
}

type binaryRefKey struct{ objectHash, jsonPointer, binaryHash string }

type binaryRefIdentity struct{ mediaType, encoding string }

type externalRefKey struct{ objectHash, jsonPointer, refKind string }

type ownedBinaryRef struct {
	objectHash []byte
	reference  auditmodel.BinaryReference
}

type ownedExternalRef struct {
	objectHash []byte
	reference  auditmodel.ExternalReference
}

func insertBinaryObjects(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	missing, err := checkBinaryObjects(transaction, turn.Binaries)
	if err != nil {
		return err
	}
	return forEachInsertBatch(len(missing), func(index int) int { return len(missing[index].DataEnc) }, func(start, end int) error {
		batch := missing[start:end]
		values := make([]string, 0, len(batch))
		arguments := make([]any, 0, len(batch)*7)
		for index, object := range batch {
			values = append(values, "("+placeholders(7, index*7)+")")
			arguments = append(arguments, object.Hash, object.MediaType, object.Compression, object.PlaintextLength,
				object.EncodedLength, object.DataEnc, turn.CreatedAtNS)
		}
		result, err := transaction.Exec(`
INSERT INTO binary_objects (
    binary_hash, media_type, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES `+strings.Join(values, ",")+`
ON CONFLICT(binary_hash) DO NOTHING`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: insert binary object: %w", err)
		}
		return verifyShortInsert(result, len(batch), "binary object", func() (int, error) {
			stillMissing, err := checkBinaryObjects(transaction, batch)
			return len(stillMissing), err
		})
	})
}

// checkBinaryObjects compares every given object with the stored row of the
// same hash and returns the objects no row exists for, each hash once.
func checkBinaryObjects(transaction dbTransaction, objects []auditmodel.BinaryObject) ([]auditmodel.BinaryObject, error) {
	hashes := make([][]byte, 0, len(objects))
	for _, object := range objects {
		hashes = append(hashes, object.Hash)
	}
	stored := make(map[string]binaryIdentity, len(objects))
	err := forEachHashBatch(hashes, func(arguments []any) error {
		rows, err := transaction.Query(`
SELECT binary_hash, media_type, plaintext_length
FROM binary_objects
WHERE binary_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: read binary object identity: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var hash []byte
			var identity binaryIdentity
			if err := rows.Scan(&hash, &identity.mediaType, &identity.plaintextLength); err != nil {
				return fmt.Errorf("postgres writer: read binary object identity: %w", err)
			}
			stored[string(hash)] = identity
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("postgres writer: read binary object identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var missing []auditmodel.BinaryObject
	for _, object := range objects {
		identity, exists := stored[string(object.Hash)]
		if !exists {
			// A repeated hash in the same turn is then checked against the
			// first occurrence, as the row it is about to become.
			stored[string(object.Hash)] = binaryIdentity{mediaType: object.MediaType, plaintextLength: object.PlaintextLength}
			missing = append(missing, object)
			continue
		}
		// Only properties of the stored plaintext take part in the identity
		// check. compression and encoded_length describe how the existing row
		// was encoded, not what it holds: the codec picks them per write, so an
		// encoder that emits a different number of bytes for the same input —
		// a gzip implementation change across a toolchain upgrade, say — makes
		// them disagree with a row written by an earlier build. Treating that
		// as corruption would reject every turn reusing such an object, and an
		// existing row is never written, so it keeps the encoding its own
		// data_enc was produced with and stays self-consistent either way.
		if identity.mediaType != object.MediaType || identity.plaintextLength != object.PlaintextLength {
			return nil, storedObjectIntegrityError("postgres writer: binary object hash collision or corruption")
		}
	}
	return missing, nil
}

func insertContentObjects(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	missing, err := checkContentObjects(transaction, turn.Objects)
	if err != nil {
		return err
	}
	err = forEachInsertBatch(len(missing), func(index int) int { return len(missing[index].DataEnc) }, func(start, end int) error {
		batch := missing[start:end]
		values := make([]string, 0, len(batch))
		arguments := make([]any, 0, len(batch)*8)
		for index, object := range batch {
			values = append(values, "("+placeholders(8, index*8)+")")
			arguments = append(arguments, object.Hash, object.SemanticHash, object.Kind, object.Compression,
				object.PlaintextLength, object.EncodedLength, object.DataEnc, turn.CreatedAtNS)
		}
		result, err := transaction.Exec(`
INSERT INTO content_objects (
    object_hash, semantic_hash, kind, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES `+strings.Join(values, ",")+`
ON CONFLICT(object_hash) DO NOTHING`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: insert content object: %w", err)
		}
		return verifyShortInsert(result, len(batch), "content object", func() (int, error) {
			stillMissing, err := checkContentObjects(transaction, batch)
			return len(stillMissing), err
		})
	})
	if err != nil {
		return err
	}

	// A new object cannot have reference rows yet, since both reference
	// tables point at content_objects. Only objects that already existed are
	// looked up; any of their reference rows found missing is written again,
	// which repairs a row lost on its own.
	inserted := make(map[string]bool, len(missing))
	for _, object := range missing {
		inserted[string(object.Hash)] = true
	}
	var binaryRefs, storedBinaryRefs []ownedBinaryRef
	var externalRefs, storedExternalRefs []ownedExternalRef
	for _, object := range turn.Objects {
		for _, reference := range object.BinaryRefs {
			owned := ownedBinaryRef{objectHash: object.Hash, reference: reference}
			binaryRefs = append(binaryRefs, owned)
			if !inserted[string(object.Hash)] {
				storedBinaryRefs = append(storedBinaryRefs, owned)
			}
		}
		for _, reference := range object.ExternalRefs {
			owned := ownedExternalRef{objectHash: object.Hash, reference: reference}
			externalRefs = append(externalRefs, owned)
			if !inserted[string(object.Hash)] {
				storedExternalRefs = append(storedExternalRefs, owned)
			}
		}
	}
	if err := insertBinaryReferences(transaction, binaryRefs, storedBinaryRefs); err != nil {
		return err
	}
	return insertExternalReferences(transaction, externalRefs, storedExternalRefs)
}

// checkContentObjects compares every given object with the stored row of the
// same hash and returns the objects no row exists for, each hash once.
func checkContentObjects(transaction dbTransaction, objects []auditmodel.ContentObject) ([]auditmodel.ContentObject, error) {
	hashes := make([][]byte, 0, len(objects))
	for _, object := range objects {
		hashes = append(hashes, object.Hash)
	}
	stored := make(map[string]contentIdentity, len(objects))
	err := forEachHashBatch(hashes, func(arguments []any) error {
		rows, err := transaction.Query(`
SELECT object_hash, semantic_hash, kind, plaintext_length
FROM content_objects
WHERE object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: read content object identity: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var hash []byte
			var identity contentIdentity
			if err := rows.Scan(&hash, &identity.semanticHash, &identity.kind, &identity.plaintextLength); err != nil {
				return fmt.Errorf("postgres writer: read content object identity: %w", err)
			}
			stored[string(hash)] = identity
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("postgres writer: read content object identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var missing []auditmodel.ContentObject
	for _, object := range objects {
		identity, exists := stored[string(object.Hash)]
		if !exists {
			stored[string(object.Hash)] = contentIdentity{semanticHash: object.SemanticHash, kind: object.Kind, plaintextLength: object.PlaintextLength}
			missing = append(missing, object)
			continue
		}
		// compression and encoded_length are left out for the reason given in
		// checkBinaryObjects.
		if !bytes.Equal(identity.semanticHash, object.SemanticHash) || identity.kind != object.Kind ||
			identity.plaintextLength != object.PlaintextLength {
			return nil, storedObjectIntegrityError("postgres writer: content object hash collision or corruption")
		}
	}
	return missing, nil
}

// insertBinaryReferences writes the references in all that have no row yet.
// Only the owners of stored are looked up; the rest belong to objects this
// transaction has just inserted.
func insertBinaryReferences(transaction dbTransaction, all, stored []ownedBinaryRef) error {
	missing, err := checkBinaryReferences(transaction, all, stored)
	if err != nil {
		return err
	}
	return forEachInsertBatch(len(missing), nil, func(start, end int) error {
		batch := missing[start:end]
		values := make([]string, 0, len(batch))
		arguments := make([]any, 0, len(batch)*5)
		for index, owned := range batch {
			values = append(values, "("+placeholders(5, index*5)+")")
			arguments = append(arguments, owned.objectHash, owned.reference.JSONPointer, owned.reference.BinaryHash,
				owned.reference.MediaType, owned.reference.Encoding)
		}
		result, err := transaction.Exec(`
INSERT INTO content_binary_refs (
    object_hash, json_pointer, binary_hash, media_type, encoding
) VALUES `+strings.Join(values, ",")+`
ON CONFLICT(object_hash, json_pointer, binary_hash) DO NOTHING`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: insert content binary ref: %w", err)
		}
		return verifyShortInsert(result, len(batch), "content binary ref", func() (int, error) {
			stillMissing, err := checkBinaryReferences(transaction, batch, batch)
			return len(stillMissing), err
		})
	})
}

func checkBinaryReferences(transaction dbTransaction, all, stored []ownedBinaryRef) ([]ownedBinaryRef, error) {
	owners := make([][]byte, 0, len(stored))
	for _, owned := range stored {
		owners = append(owners, owned.objectHash)
	}
	rowsByKey := make(map[binaryRefKey]binaryRefIdentity, len(all))
	err := forEachHashBatch(owners, func(arguments []any) error {
		rows, err := transaction.Query(`
SELECT object_hash, json_pointer, binary_hash, media_type, encoding
FROM content_binary_refs
WHERE object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: read binary reference identity: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var objectHash, binaryHash []byte
			var jsonPointer string
			var identity binaryRefIdentity
			if err := rows.Scan(&objectHash, &jsonPointer, &binaryHash, &identity.mediaType, &identity.encoding); err != nil {
				return fmt.Errorf("postgres writer: read binary reference identity: %w", err)
			}
			rowsByKey[binaryRefKey{string(objectHash), jsonPointer, string(binaryHash)}] = identity
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("postgres writer: read binary reference identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var missing []ownedBinaryRef
	for _, owned := range all {
		key := binaryRefKey{string(owned.objectHash), owned.reference.JSONPointer, string(owned.reference.BinaryHash)}
		identity, exists := rowsByKey[key]
		if !exists {
			rowsByKey[key] = binaryRefIdentity{mediaType: owned.reference.MediaType, encoding: owned.reference.Encoding}
			missing = append(missing, owned)
			continue
		}
		if identity.mediaType != owned.reference.MediaType || identity.encoding != owned.reference.Encoding {
			return nil, storedObjectIntegrityError("postgres writer: content binary reference collision or corruption")
		}
	}
	return missing, nil
}

// insertExternalReferences is insertBinaryReferences for external references.
// An existing row keeps its value_enc: the identity is value_hash, and the
// ciphertext differs per seal only by its nonce.
func insertExternalReferences(transaction dbTransaction, all, stored []ownedExternalRef) error {
	missing, err := checkExternalReferences(transaction, all, stored)
	if err != nil {
		return err
	}
	return forEachInsertBatch(len(missing), func(index int) int { return len(missing[index].reference.ValueEnc) }, func(start, end int) error {
		batch := missing[start:end]
		values := make([]string, 0, len(batch))
		arguments := make([]any, 0, len(batch)*5)
		for index, owned := range batch {
			values = append(values, "("+placeholders(5, index*5)+")")
			arguments = append(arguments, owned.objectHash, owned.reference.JSONPointer, owned.reference.Kind,
				owned.reference.ValueHash, owned.reference.ValueEnc)
		}
		result, err := transaction.Exec(`
INSERT INTO content_external_refs (
    object_hash, json_pointer, ref_kind, value_hash, value_enc
) VALUES `+strings.Join(values, ",")+`
ON CONFLICT(object_hash, json_pointer, ref_kind) DO NOTHING`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: insert content external ref: %w", err)
		}
		return verifyShortInsert(result, len(batch), "content external ref", func() (int, error) {
			stillMissing, err := checkExternalReferences(transaction, batch, batch)
			return len(stillMissing), err
		})
	})
}

func checkExternalReferences(transaction dbTransaction, all, stored []ownedExternalRef) ([]ownedExternalRef, error) {
	owners := make([][]byte, 0, len(stored))
	for _, owned := range stored {
		owners = append(owners, owned.objectHash)
	}
	rowsByKey := make(map[externalRefKey][]byte, len(all))
	err := forEachHashBatch(owners, func(arguments []any) error {
		rows, err := transaction.Query(`
SELECT object_hash, json_pointer, ref_kind, value_hash
FROM content_external_refs
WHERE object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return fmt.Errorf("postgres writer: read external reference identity: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var objectHash, valueHash []byte
			var jsonPointer, refKind string
			if err := rows.Scan(&objectHash, &jsonPointer, &refKind, &valueHash); err != nil {
				return fmt.Errorf("postgres writer: read external reference identity: %w", err)
			}
			rowsByKey[externalRefKey{string(objectHash), jsonPointer, refKind}] = valueHash
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("postgres writer: read external reference identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var missing []ownedExternalRef
	for _, owned := range all {
		key := externalRefKey{string(owned.objectHash), owned.reference.JSONPointer, owned.reference.Kind}
		valueHash, exists := rowsByKey[key]
		if !exists {
			rowsByKey[key] = owned.reference.ValueHash
			missing = append(missing, owned)
			continue
		}
		if !bytes.Equal(valueHash, owned.reference.ValueHash) {
			return nil, storedObjectIntegrityError("postgres writer: content external reference collision or corruption")
		}
	}
	return missing, nil
}

// forEachHashBatch runs one query per graphHashQueryBatch distinct hashes, which
// keeps each statement far below PostgreSQL's 65535 bind parameters.
func forEachHashBatch(hashes [][]byte, run func([]any) error) error {
	seen := make(map[string]bool, len(hashes))
	distinct := make([]any, 0, len(hashes))
	for _, hash := range hashes {
		if seen[string(hash)] {
			continue
		}
		seen[string(hash)] = true
		distinct = append(distinct, hash)
	}
	for start := 0; start < len(distinct); start += graphHashQueryBatch {
		if err := run(distinct[start:min(start+graphHashQueryBatch, len(distinct))]); err != nil {
			return err
		}
	}
	return nil
}

// forEachInsertBatch splits count rows into multi-row inserts of at most
// graphHashQueryBatch rows (at most 8 bind parameters each) and, when size is
// given, at most objectInsertBatchBytes of payload unless one row alone is
// larger.
func forEachInsertBatch(count int, size func(int) int, run func(start, end int) error) error {
	for start := 0; start < count; {
		end, total := start, 0
		for end < count && end-start < graphHashQueryBatch {
			if size != nil {
				rowSize := size(end)
				if end > start && total+rowSize > objectInsertBatchBytes {
					break
				}
				total += rowSize
			}
			end++
		}
		if err := run(start, end); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// verifyShortInsert handles an insert that stored fewer rows than it sent.
// The rows were missing when this transaction looked, so a conflict means a
// row appeared in between; it is accepted only after the same identity check
// an existing row gets, and a row that is still absent fails the write.
func verifyShortInsert(result sql.Result, sent int, what string, recheck func() (int, error)) error {
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres writer: count inserted %s rows: %w", what, err)
	}
	if inserted == int64(sent) {
		return nil
	}
	stillMissing, err := recheck()
	if err != nil {
		return err
	}
	if stillMissing != 0 {
		return localWriteError("postgres writer: " + what + " insert did not store every row")
	}
	return nil
}

func ensureConversation(transaction dbTransaction, turn auditmodel.PreparedTurn, parent *turnParent) (string, error) {
	if parent != nil {
		return parent.ConversationID, nil
	}
	conversationID := "conv_" + turn.AuditID
	if len(turn.ConversationKeyHash) == 32 {
		conversationID = "conv_" + hex.EncodeToString(turn.ConversationKeyHash)
	}
	if _, err := transaction.Exec(`
INSERT INTO conversations (conversation_id, protocol, key_hash, created_at_ns, updated_at_ns)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(conversation_id) DO NOTHING`,
		conversationID, turn.Protocol, nullableBytes(turn.ConversationKeyHash), turn.CreatedAtNS, turn.CreatedAtNS,
	); err != nil {
		return "", fmt.Errorf("postgres writer: insert conversation: %w", err)
	}
	var protocol string
	var keyHash []byte
	if err := transaction.QueryRow(`
SELECT protocol, key_hash
FROM conversations
WHERE conversation_id = $1`, conversationID).Scan(&protocol, &keyHash); err != nil {
		return "", fmt.Errorf("postgres writer: verify conversation: %w", err)
	}
	if protocol != turn.Protocol || !bytes.Equal(keyHash, turn.ConversationKeyHash) {
		return "", localWriteError("postgres writer: conversation identity collision")
	}
	return conversationID, nil
}

func insertTurn(transaction dbTransaction, turn auditmodel.PreparedTurn, conversationID string, parentTurnID any, parentBase, reason string, confidence int) error {
	_, err := transaction.Exec(`
INSERT INTO turns (
    turn_id, audit_id, conversation_id, parent_turn_id, parent_base,
    link_reason, link_confidence, request_layout, response_layout,
    request_envelope_hash, response_envelope_hash,
    request_item_count, response_item_count,
    request_sequence_hash, response_sequence_hash,
    request_reconstruction_hash, response_reconstruction_hash,
    reconstruction_status, previous_response_id, response_id, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 'verified', $18, $19, $20)`,
		turn.AuditID, turn.AuditID, conversationID, parentTurnID, parentBase,
		reason, confidence, turn.RequestLayout, turn.ResponseLayout,
		turn.RequestEnvelopeHash, turn.ResponseEnvelopeHash,
		len(turn.RequestRefs), len(turn.ResponseRefs),
		turn.RequestSequenceHash, turn.ResponseSequenceHash,
		turn.RequestReconstructionHash, turn.ResponseReconstructionHash,
		nullableString(turn.PreviousResponseID), nullableString(turn.ResponseID), turn.CreatedAtNS,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: insert turn: %w", err)
	}
	return nil
}

func insertContextOperations(transaction dbTransaction, turnID string, operations []auditmodel.ContextOp) error {
	for index, operation := range operations {
		var slot any
		var objectHash any
		var semanticHash any
		if operation.Ref != nil {
			slot = operation.Ref.Slot
			objectHash = operation.Ref.ObjectHash
			semanticHash = operation.Ref.SemanticHash
		}
		if _, err := transaction.Exec(`
INSERT INTO turn_context_ops (
    turn_id, op_index, operation, item_count, slot, object_hash, semantic_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			turnID, index, operation.Operation, operation.Count, slot, objectHash, semanticHash,
		); err != nil {
			return fmt.Errorf("postgres writer: insert turn context op: %w", err)
		}
	}
	return nil
}

func insertResponseItems(transaction dbTransaction, turnID string, refs []auditmodel.ObjectRef) error {
	for index, ref := range refs {
		if _, err := transaction.Exec(`
INSERT INTO turn_response_items (
    turn_id, ordinal, slot, object_hash, semantic_hash
) VALUES ($1, $2, $3, $4, $5)`, turnID, index, ref.Slot, ref.ObjectHash, ref.SemanticHash); err != nil {
			return fmt.Errorf("postgres writer: insert turn response item: %w", err)
		}
	}
	return nil
}

// chooseTurnParent also returns the parent chains it loaded, for the writes
// that follow in the same transaction; they are nil when the candidates were
// evaluated without them.
func chooseTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn) (*turnParent, *candidateChains, error) {
	if turn.PreviousResponseID != "" {
		candidate, err := loadCandidateByResponseID(transaction, turn.Protocol, turn.PreviousResponseID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, err
		}
		if candidate != nil {
			return evaluateForced(transaction, turn, *candidate, "previous_response_id", 100)
		}
	}
	if len(turn.ConversationKeyHash) == 32 {
		candidates, err := listTurnCandidates(transaction, `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND c.key_hash = $2 AND t.created_at_ns < $3
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $4`, turn.Protocol, turn.ConversationKeyHash, turn.CreatedAtNS, parentCandidateLimit)
		if err != nil {
			return nil, nil, err
		}
		// A provider-side conversation is one chain whose requests carry only
		// the new input, so content cannot confirm the link; follow the latest
		// earlier turn as the provider does.
		if turn.ServerManagedContext {
			if len(candidates) == 0 {
				return nil, nil, nil
			}
			return evaluateForced(transaction, turn, candidates[0], "conversation_key", 95)
		}
		// A conversation key groups a client session, not one agent: Codex
		// sends the root session id as prompt_cache_key for the parent and
		// every sub-agent, and OpenCode sends a sub-agent's direct parent
		// session id, so the latest keyed turn may belong to a
		// concurrent sibling. Rank the session's recent turns by content
		// instead. When none qualifies, including the key's first turn, the
		// turn starts a new root in its own keyed conversation: the
		// protocol-wide search below would attach it to another session and
		// drop the key, so later turns with this key could not find it.
		return bestTurnParent(transaction, turn, candidates, linkConversationKey)
	}

	candidates, err := listKeylessCandidates(transaction, turn.Protocol, turn.CreatedAtNS)
	if err != nil {
		return nil, nil, err
	}
	return bestTurnParent(transaction, turn, candidates, linkInferred)
}

// listKeylessCandidates returns the newest turns of protocol created before
// createdAt, for a turn without a conversation key.
func listKeylessCandidates(transaction dbTransaction, protocol string, createdAt int64) ([]turnCandidate, error) {
	if query, ok := keylessCandidateQueries[protocol]; ok {
		return listTurnCandidates(transaction, query, createdAt, parentCandidateLimit)
	}
	return listTurnCandidates(transaction, keylessCandidateQuery, protocol, createdAt, parentCandidateLimit)
}

// keylessCandidateQuery is the protocol-wide parent search of a turn without
// a conversation key: the newest earlier turns of the protocol, walked along
// turns_created_idx.
const keylessCandidateQuery = `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND t.created_at_ns < $2
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $3`

// keylessCandidateQueries holds the same search with the protocol written
// into the text, one statement per protocol the parsers produce. pgx caches
// prepared statements, and a generic plan of the parameterised form does not
// know the protocol: for a protocol with fewer than 32 earlier turns it walks
// the whole index, where a plan that knows the protocol is rare starts from
// its conversations instead. The literals are these compile-time constants,
// never the turn's value, which is only compared against them; any other
// protocol uses the parameterised form. Rows and order are the same.
var keylessCandidateQueries = func() map[string]string {
	const template = `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = '%s' AND t.created_at_ns < $1
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $2`
	queries := map[string]string{}
	for _, protocol := range []string{"openai", "anthropic", "gemini"} {
		queries[protocol] = fmt.Sprintf(template, protocol)
	}
	return queries
}()

// evaluateForced evaluates the one candidate a forced link names.
func evaluateForced(transaction dbTransaction, turn auditmodel.PreparedTurn, candidate turnCandidate, reason string, confidence int) (*turnParent, *candidateChains, error) {
	chains := loadCandidateChains(transaction, []turnCandidate{candidate})
	parent, err := evaluateCandidate(transaction, turn, candidate, reason, confidence, linkForced, chains.memo())
	return parent, chains, err
}

type turnCandidate struct{ turnID, conversationID string }

type linkMode int

const (
	// linkForced accepts the candidate whatever its content.
	linkForced linkMode = iota
	// linkConversationKey accepts a turn from the keyed conversation on the
	// same content evidence as linkInferred, but records conversation_key.
	linkConversationKey
	// linkInferred accepts only a strong context relationship.
	linkInferred
)

func listTurnCandidates(transaction dbTransaction, query string, arguments ...any) ([]turnCandidate, error) {
	rows, err := transaction.Query(query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres writer: list turn parent candidates: %w", err)
	}
	defer rows.Close()
	var candidates []turnCandidate
	for rows.Next() {
		var item turnCandidate
		if err := rows.Scan(&item.turnID, &item.conversationID); err != nil {
			return nil, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

// bestTurnParent returns the accepted candidate with the lowest delta cost.
// Candidates arrive newest first, so ties go to the most recent turn.
func bestTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn, candidates []turnCandidate, mode linkMode) (*turnParent, *candidateChains, error) {
	// The candidates usually lie on one chain. loadCandidateChains walks it
	// once, oldest candidate first, and the memo then answers every
	// candidate without a walk. The evaluation order and the comparison are
	// unchanged.
	chains := loadCandidateChains(transaction, candidates)
	memo := chains.memo()
	var best *turnParent
	for _, candidate := range candidates {
		evaluated, err := evaluateCandidate(transaction, turn, candidate, "", 0, mode, memo)
		if err != nil {
			return nil, nil, err
		}
		if evaluated != nil && (best == nil || evaluated.cost < best.cost) {
			best = evaluated
		}
	}
	return best, chains, nil
}

func loadCandidateByResponseID(transaction dbTransaction, protocol, responseID string) (*turnCandidate, error) {
	var value turnCandidate
	err := transaction.QueryRow(`
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND t.response_id = $2
ORDER BY t.created_at_ns DESC, t.turn_id DESC LIMIT 1`, protocol, responseID).Scan(&value.turnID, &value.conversationID)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func evaluateCandidate(transaction dbTransaction, turn auditmodel.PreparedTurn, candidate turnCandidate, forcedReason string, forcedConfidence int, mode linkMode, memo map[string][]auditmodel.ObjectRef) (*turnParent, error) {
	request, err := loadRequestRefs(transaction, candidate.turnID, memo, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	response, err := loadResponseRefs(transaction, candidate.turnID)
	if err != nil {
		return nil, err
	}
	post := append(cloneObjectRefs(request), response...)
	requestCost := auditmodel.DeltaCost(auditmodel.BuildDelta(request, turn.RequestRefs))
	postCost := auditmodel.DeltaCost(auditmodel.BuildDelta(post, turn.RequestRefs))
	baseKind := "post_turn"
	base := post
	cost := postCost
	if requestCost <= postCost {
		baseKind = "request"
		base = request
		cost = requestCost
	}
	reason := forcedReason
	confidence := forcedConfidence
	if mode != linkForced {
		accepted, inferredReason, inferredConfidence := strongContextRelationship(request, response, turn.RequestRefs)
		if !accepted {
			return nil, nil
		}
		reason, confidence = inferredReason, inferredConfidence
		if mode == linkConversationKey {
			reason, confidence = "conversation_key", 95
		}
	}
	if reason == "" {
		reason = "context_edit"
	}
	var childCount int
	if err := transaction.QueryRow(`SELECT COUNT(*) FROM turns WHERE parent_turn_id = $1`, candidate.turnID).Scan(&childCount); err != nil {
		return nil, err
	}
	retry := sameRefSequence(request, turn.RequestRefs)
	if !retry && childCount > 0 {
		var matchingSibling bool
		if err := transaction.QueryRow(`
SELECT EXISTS(
    SELECT 1
    FROM turns
    WHERE parent_turn_id = $1 AND request_sequence_hash = $2
)`, candidate.turnID, turn.RequestSequenceHash).Scan(&matchingSibling); err != nil {
			return nil, err
		}
		retry = matchingSibling
	}
	if retry {
		reason = "retry"
		confidence = max(confidence, 90)
	} else if childCount > 0 {
		reason = "branch"
	}
	return &turnParent{
		TurnID: candidate.turnID, ConversationID: candidate.conversationID,
		BaseKind: baseKind, Reason: reason, Confidence: confidence, Base: cloneObjectRefs(base), cost: cost,
	}, nil
}

func strongContextRelationship(request, response, current []auditmodel.ObjectRef) (bool, string, int) {
	if sameRefSequence(request, current) {
		return true, "retry", 90
	}
	post := append(cloneObjectRefs(request), response...)
	commonPost := semanticPrefix(post, current)
	if len(post) >= 2 && commonPost >= len(post)-1 {
		return true, "continuation", 85
	}
	commonRequest := semanticPrefix(request, current)
	minimum := min(len(request), len(current))
	if minimum >= 2 && commonRequest >= 2 && commonRequest*100/minimum >= 70 {
		return true, "context_edit", 75
	}
	return false, "", 0
}

func sameRefSequence(left, right []auditmodel.ObjectRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Slot != right[index].Slot || !bytes.Equal(left[index].ObjectHash, right[index].ObjectHash) {
			return false
		}
	}
	return true
}

func semanticPrefix(left, right []auditmodel.ObjectRef) int {
	count := 0
	for count < len(left) && count < len(right) && left[count].Slot == right[count].Slot && bytes.Equal(left[count].SemanticHash, right[count].SemanticHash) {
		count++
	}
	return count
}

// loadRequestRefs walks parent headers iteratively, then applies immutable refs
// forward. Only requested endpoints enter the bounded memo: retaining every
// full ancestor history made an increasing chain quadratic in live memory.
func loadRequestRefs(transaction dbTransaction, turnID string, memo map[string][]auditmodel.ObjectRef, visiting map[string]bool) ([]auditmodel.ObjectRef, error) {
	if cached, ok := memo[turnID]; ok {
		return cloneObjectRefs(cached), nil
	}
	headers, err := preloadAncestorHeaders(transaction, turnID, memo, maxAncestorHeaders)
	if err != nil {
		return nil, err
	}
	type frame struct {
		id     string
		header storedTurnHeader
	}
	var path []frame
	seen := make(map[string]bool)
	current := turnID
	var result []auditmodel.ObjectRef
	for {
		if seen[current] || visiting[current] {
			return nil, localWriteError("postgres writer: turn parent cycle")
		}
		seen[current] = true
		if cached, ok := memo[current]; ok {
			result = cached
			break
		}
		header, exists := headers[current]
		if !exists {
			return nil, fmt.Errorf("postgres writer: load turn header: %w", sql.ErrNoRows)
		}
		parent := sql.NullString{}
		if header.ParentTurnID != nil {
			parent.String = *header.ParentTurnID
			parent.Valid = true
		}
		if header.RequestItemCount > maxAncestorReferenceRows {
			return nil, localWriteError("postgres writer: reconstructed reference limit exceeded")
		}
		if parent.Valid && header.ParentBase != "request" && header.ParentBase != "post_turn" {
			return nil, localWriteError("postgres writer: invalid non-root parent base")
		}
		if !parent.Valid && header.ParentBase != "root" {
			return nil, localWriteError("postgres writer: root turn has non-root base")
		}
		path = append(path, frame{current, header})
		if !parent.Valid {
			break
		}
		current = parent.String
	}
	ids := make([]string, 0, len(path))
	responseIDs := make([]string, 0, len(path))
	for _, frame := range path {
		ids = append(ids, frame.id)
		if frame.header.ParentBase == "post_turn" {
			responseIDs = append(responseIDs, *frame.header.ParentTurnID)
		}
	}
	operationsByTurn, responsesByTurn, err := preloadAncestorReferences(transaction, ids, responseIDs, maxAncestorReferenceRows)
	if err != nil {
		return nil, err
	}
	for i := len(path) - 1; i >= 0; i-- {
		frame := path[i]
		base := result
		if frame.header.ParentBase == "post_turn" {
			response := responsesByTurn[*frame.header.ParentTurnID]
			// Do not append into a memoized ancestor's backing array.
			base = append(append([]auditmodel.ObjectRef(nil), base...), response...)
		}
		operations := operationsByTurn[frame.id]
		result, err = applyImmutableRefs(base, operations)
		if err != nil {
			return nil, err
		}
		if len(result) != frame.header.RequestItemCount || !bytes.Equal(auditmodel.SequenceHash(result), frame.header.RequestSequenceHash) {
			return nil, localWriteError("postgres writer: stored turn sequence hash mismatch")
		}
	}
	// Bound retained endpoints by both count and total references. All memoized
	// bytes are immutable within this transaction; returned refs are owned copies.
	total := len(result)
	for _, refs := range memo {
		total += len(refs)
	}
	if len(memo) >= memoEndpointLimit || total > memoReferenceLimit {
		clear(memo)
	}
	if len(result) <= memoReferenceLimit {
		memo[turnID] = result
	}
	return cloneObjectRefs(result), nil
}

func applyImmutableRefs(base []auditmodel.ObjectRef, operations []auditmodel.ContextOp) ([]auditmodel.ObjectRef, error) {
	result := make([]auditmodel.ObjectRef, 0, len(base)+len(operations))
	position := 0
	for _, op := range operations {
		switch op.Operation {
		case auditmodel.OperationRetain, auditmodel.OperationDelete:
			if op.Count <= 0 || op.Count > len(base)-position || op.Ref != nil {
				return nil, auditmodel.ErrReconstruction
			}
			if op.Operation == auditmodel.OperationRetain {
				result = append(result, base[position:position+op.Count]...)
			}
			position += op.Count
		case auditmodel.OperationInsert:
			if op.Count != 1 || op.Ref == nil || len(op.Ref.ObjectHash) == 0 || op.Ref.Slot == "" {
				return nil, auditmodel.ErrReconstruction
			}
			result = append(result, *op.Ref)
		default:
			return nil, auditmodel.ErrReconstruction
		}
	}
	if position != len(base) {
		return nil, auditmodel.ErrReconstruction
	}
	return result, nil
}

func loadContextOperations(transaction dbTransaction, turnID string) ([]auditmodel.ContextOp, error) {
	rows, err := transaction.Query(`
SELECT operation, item_count, slot, object_hash, semantic_hash
FROM turn_context_ops
WHERE turn_id = $1
ORDER BY op_index`, turnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var operations []auditmodel.ContextOp
	for rows.Next() {
		var operation auditmodel.ContextOp
		var slot sql.NullString
		var objectHash, semanticHash []byte
		if err := rows.Scan(&operation.Operation, &operation.Count, &slot, &objectHash, &semanticHash); err != nil {
			return nil, err
		}
		if operation.Operation == auditmodel.OperationInsert {
			operation.Ref = &auditmodel.ObjectRef{Slot: slot.String, ObjectHash: cloneBytes(objectHash), SemanticHash: cloneBytes(semanticHash)}
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

func loadResponseRefs(transaction dbTransaction, turnID string) ([]auditmodel.ObjectRef, error) {
	rows, err := transaction.Query(`
SELECT slot, object_hash, semantic_hash
FROM turn_response_items
WHERE turn_id = $1
ORDER BY ordinal`, turnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []auditmodel.ObjectRef
	for rows.Next() {
		var ref auditmodel.ObjectRef
		if err := rows.Scan(&ref.Slot, &ref.ObjectHash, &ref.SemanticHash); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func sortedObjectHashes(objects []auditmodel.ContentObject) [][]byte {
	hashes := make([][]byte, 0, len(objects))
	for _, object := range objects {
		hashes = append(hashes, object.Hash)
	}
	sort.Slice(hashes, func(left, right int) bool { return bytes.Compare(hashes[left], hashes[right]) < 0 })
	return hashes
}
