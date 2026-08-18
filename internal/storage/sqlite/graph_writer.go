package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

const parentCandidateLimit = 32

type turnParent struct {
	TurnID         string
	ConversationID string
	BaseKind       string
	Reason         string
	Confidence     int
	Base           []auditmodel.ObjectRef
}

type storedTurnHeader struct {
	ParentTurnID        *string
	ParentBase          string
	RequestItemCount    int
	RequestSequenceHash []byte
}

func saveParsedAudit(transaction *sql.Tx, value ParsedAudit, signer *security.IntegritySigner) error {
	if err := upsertParsedResult(transaction, value.Result); err != nil {
		return err
	}

	graphVerified := false
	if value.Turn != nil {
		if err := persistPreparedTurn(transaction, *value.Turn); err != nil {
			return err
		}
		graphVerified = true
	}

	discardRaw, err := shouldDiscardRawEvidence(transaction, value.Result, graphVerified)
	if err != nil {
		return err
	}
	retention := RetentionFull
	if discardRaw {
		retention = RetentionMetadata
		if _, err := transaction.Exec(`DELETE FROM body_chunks WHERE audit_id = ?`, value.Result.AuditID); err != nil {
			return fmt.Errorf("sqlite writer: delete compacted raw chunks: %w", err)
		}
	}
	if _, err := transaction.Exec(`
UPDATE body_streams
SET retention_state = ?,
    stored_length = CASE WHEN ? = 'metadata' THEN 0 ELSE stored_length END,
    chunk_count = CASE WHEN ? = 'metadata' THEN 0 ELSE chunk_count END
WHERE audit_id = ?`, retention, retention, retention, value.Result.AuditID); err != nil {
		return fmt.Errorf("sqlite writer: update raw retention: %w", err)
	}

	parent, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = ?
WHERE audit_id = ?
  AND parser_name = ?
  AND parse_status = 'processing'
  AND forward_status <> 'rejected'`, value.Result.Status, value.Result.AuditID, value.Result.ParserName)
	if err != nil {
		return fmt.Errorf("sqlite writer: finish parse status: %w", err)
	}
	if err := requireOneRow(parent, "finish parse status"); err != nil {
		return err
	}
	if graphVerified {
		// A nil cache means single-use: one write covers one audit, so there
		// is no ancestor chain to amortize across.
		payloadDigest, err := semanticPayloadDigest(context.Background(), transaction, nil, value.Result.AuditID)
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

func upsertParsedResult(transaction *sql.Tx, result ParsedResult) error {
	_, err := transaction.Exec(`
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status,
    request_model, response_model, requested_stream, observed_stream,
    response_id, usage_input, usage_output, usage_total,
    error_type, error_code, message_count, tool_call_count, has_tool_call,
    parsed_json_enc, parsed_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		result.MessageCount,
		result.ToolCallCount,
		boolDatabaseValue(result.HasToolCall),
		nullableBytes(result.ParsedJSONEnc),
		result.ParsedAtNS,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: save parsed result: %w", err)
	}
	return nil
}

func shouldDiscardRawEvidence(transaction *sql.Tx, result ParsedResult, graphVerified bool) (bool, error) {
	if result.Status != ParseOK || !graphVerified {
		return false, nil
	}
	var forwardStatus, captureStatus string
	var statusCode sql.NullInt64
	if err := transaction.QueryRow(`
SELECT forward_status, capture_status, status_code
FROM audit_records
WHERE audit_id = ?`, result.AuditID).Scan(&forwardStatus, &captureStatus, &statusCode); err != nil {
		return false, fmt.Errorf("sqlite writer: read raw retention outcome: %w", err)
	}
	return forwardStatus == ForwardCompleted && captureStatus == CaptureComplete && statusCode.Valid && statusCode.Int64 >= 200 && statusCode.Int64 < 400, nil
}

func persistPreparedTurn(transaction *sql.Tx, turn auditmodel.PreparedTurn) error {
	if err := insertBinaryObjects(transaction, turn); err != nil {
		return err
	}
	if err := insertContentObjects(transaction, turn); err != nil {
		return err
	}
	parent, err := chooseTurnParent(transaction, turn)
	if err != nil {
		return err
	}
	conversationID, err := ensureConversation(transaction, turn, parent)
	if err != nil {
		return err
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
		return err
	}
	if err := insertContextOperations(transaction, turn.AuditID, operations); err != nil {
		return err
	}
	if err := insertResponseItems(transaction, turn.AuditID, turn.ResponseRefs); err != nil {
		return err
	}
	if _, err := transaction.Exec(`UPDATE conversations SET updated_at_ns = MAX(updated_at_ns, ?) WHERE conversation_id = ?`, turn.CreatedAtNS, conversationID); err != nil {
		return fmt.Errorf("sqlite writer: update conversation timestamp: %w", err)
	}

	memo := make(map[string][]auditmodel.ObjectRef)
	reconstructed, err := loadRequestRefs(transaction, turn.AuditID, memo, make(map[string]bool))
	if err != nil {
		return err
	}
	if len(reconstructed) != len(turn.RequestRefs) || !bytes.Equal(auditmodel.SequenceHash(reconstructed), turn.RequestSequenceHash) {
		return errors.New("sqlite writer: persisted request sequence failed reconstruction")
	}
	response, err := loadResponseRefs(transaction, turn.AuditID)
	if err != nil {
		return err
	}
	if len(response) != len(turn.ResponseRefs) || !bytes.Equal(auditmodel.SequenceHash(response), turn.ResponseSequenceHash) {
		return errors.New("sqlite writer: persisted response sequence failed reconstruction")
	}
	return nil
}

func insertBinaryObjects(transaction *sql.Tx, turn auditmodel.PreparedTurn) error {
	for _, object := range turn.Binaries {
		if _, err := transaction.Exec(`
INSERT INTO binary_objects (
    binary_hash, media_type, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(binary_hash) DO NOTHING`,
			object.Hash, object.MediaType, object.Compression, object.PlaintextLength,
			object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return fmt.Errorf("sqlite writer: insert binary object: %w", err)
		}
		var mediaType, compression string
		var plaintextLength, encodedLength int64
		if err := transaction.QueryRow(`
SELECT media_type, compression, plaintext_length, encoded_length
FROM binary_objects
WHERE binary_hash = ?`, object.Hash).Scan(&mediaType, &compression, &plaintextLength, &encodedLength); err != nil ||
			mediaType != object.MediaType || compression != object.Compression ||
			plaintextLength != object.PlaintextLength || encodedLength != object.EncodedLength {
			return errors.New("sqlite writer: binary object hash collision or corruption")
		}
	}
	return nil
}

func insertContentObjects(transaction *sql.Tx, turn auditmodel.PreparedTurn) error {
	for _, object := range turn.Objects {
		if _, err := transaction.Exec(`
INSERT INTO content_objects (
    object_hash, semantic_hash, kind, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(object_hash) DO NOTHING`,
			object.Hash, object.SemanticHash, object.Kind, object.Compression,
			object.PlaintextLength, object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return fmt.Errorf("sqlite writer: insert content object: %w", err)
		}
		var semanticHash []byte
		var kind, compression string
		var plaintextLength, encodedLength int64
		if err := transaction.QueryRow(`
SELECT semantic_hash, kind, compression, plaintext_length, encoded_length
FROM content_objects WHERE object_hash = ?`, object.Hash).Scan(&semanticHash, &kind, &compression, &plaintextLength, &encodedLength); err != nil ||
			!bytes.Equal(semanticHash, object.SemanticHash) || kind != object.Kind || compression != object.Compression ||
			plaintextLength != object.PlaintextLength || encodedLength != object.EncodedLength {
			return errors.New("sqlite writer: content object hash collision or corruption")
		}
		for _, reference := range object.BinaryRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_binary_refs (
    object_hash, json_pointer, binary_hash, media_type, encoding
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(object_hash, json_pointer, binary_hash) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.BinaryHash, reference.MediaType, reference.Encoding,
			); err != nil {
				return fmt.Errorf("sqlite writer: insert content binary ref: %w", err)
			}
			var mediaType, encoding string
			if err := transaction.QueryRow(`
SELECT media_type, encoding
FROM content_binary_refs
WHERE object_hash = ? AND json_pointer = ? AND binary_hash = ?`,
				object.Hash, reference.JSONPointer, reference.BinaryHash,
			).Scan(&mediaType, &encoding); err != nil || mediaType != reference.MediaType || encoding != reference.Encoding {
				return errors.New("sqlite writer: content binary reference collision or corruption")
			}
		}
		for _, reference := range object.ExternalRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_external_refs (
    object_hash, json_pointer, ref_kind, value_hash, value_enc
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(object_hash, json_pointer, ref_kind) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.Kind, reference.ValueHash, reference.ValueEnc,
			); err != nil {
				return fmt.Errorf("sqlite writer: insert content external ref: %w", err)
			}
			var valueHash []byte
			if err := transaction.QueryRow(`
SELECT value_hash
FROM content_external_refs
WHERE object_hash = ? AND json_pointer = ? AND ref_kind = ?`,
				object.Hash, reference.JSONPointer, reference.Kind,
			).Scan(&valueHash); err != nil || !bytes.Equal(valueHash, reference.ValueHash) {
				return errors.New("sqlite writer: content external reference collision or corruption")
			}
		}
	}
	return nil
}

func ensureConversation(transaction *sql.Tx, turn auditmodel.PreparedTurn, parent *turnParent) (string, error) {
	if parent != nil {
		return parent.ConversationID, nil
	}
	conversationID := "conv_" + turn.AuditID
	if len(turn.ConversationKeyHash) == 32 {
		conversationID = "conv_" + hex.EncodeToString(turn.ConversationKeyHash)
	}
	if _, err := transaction.Exec(`
INSERT INTO conversations (conversation_id, protocol, key_hash, created_at_ns, updated_at_ns)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(conversation_id) DO NOTHING`,
		conversationID, turn.Protocol, nullableBytes(turn.ConversationKeyHash), turn.CreatedAtNS, turn.CreatedAtNS,
	); err != nil {
		return "", fmt.Errorf("sqlite writer: insert conversation: %w", err)
	}
	var protocol string
	var keyHash []byte
	if err := transaction.QueryRow(`
SELECT protocol, key_hash
FROM conversations
WHERE conversation_id = ?`, conversationID).Scan(&protocol, &keyHash); err != nil {
		return "", fmt.Errorf("sqlite writer: verify conversation: %w", err)
	}
	if protocol != turn.Protocol || !bytes.Equal(keyHash, turn.ConversationKeyHash) {
		return "", errors.New("sqlite writer: conversation identity collision")
	}
	return conversationID, nil
}

func insertTurn(transaction *sql.Tx, turn auditmodel.PreparedTurn, conversationID string, parentTurnID any, parentBase, reason string, confidence int) error {
	_, err := transaction.Exec(`
INSERT INTO turns (
    turn_id, audit_id, conversation_id, parent_turn_id, parent_base,
    link_reason, link_confidence, request_layout, response_layout,
    request_envelope_hash, response_envelope_hash,
    request_item_count, response_item_count,
    request_sequence_hash, response_sequence_hash,
    request_reconstruction_hash, response_reconstruction_hash,
    reconstruction_status, previous_response_id, response_id, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?)`,
		turn.AuditID, turn.AuditID, conversationID, parentTurnID, parentBase,
		reason, confidence, turn.RequestLayout, turn.ResponseLayout,
		turn.RequestEnvelopeHash, turn.ResponseEnvelopeHash,
		len(turn.RequestRefs), len(turn.ResponseRefs),
		turn.RequestSequenceHash, turn.ResponseSequenceHash,
		turn.RequestReconstructionHash, turn.ResponseReconstructionHash,
		nullableString(turn.PreviousResponseID), nullableString(turn.ResponseID), turn.CreatedAtNS,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: insert turn: %w", err)
	}
	return nil
}

func insertContextOperations(transaction *sql.Tx, turnID string, operations []auditmodel.ContextOp) error {
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
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			turnID, index, operation.Operation, operation.Count, slot, objectHash, semanticHash,
		); err != nil {
			return fmt.Errorf("sqlite writer: insert turn context op: %w", err)
		}
	}
	return nil
}

func insertResponseItems(transaction *sql.Tx, turnID string, refs []auditmodel.ObjectRef) error {
	for index, ref := range refs {
		if _, err := transaction.Exec(`
INSERT INTO turn_response_items (
    turn_id, ordinal, slot, object_hash, semantic_hash
) VALUES (?, ?, ?, ?, ?)`, turnID, index, ref.Slot, ref.ObjectHash, ref.SemanticHash); err != nil {
			return fmt.Errorf("sqlite writer: insert turn response item: %w", err)
		}
	}
	return nil
}

func chooseTurnParent(transaction *sql.Tx, turn auditmodel.PreparedTurn) (*turnParent, error) {
	if turn.PreviousResponseID != "" {
		candidate, err := loadCandidateByResponseID(transaction, turn.Protocol, turn.PreviousResponseID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if candidate != nil {
			return evaluateCandidate(transaction, turn, *candidate, "previous_response_id", 100, true)
		}
	}
	if len(turn.ConversationKeyHash) == 32 {
		candidate, err := loadCandidateByConversationKey(transaction, turn.Protocol, turn.ConversationKeyHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if candidate != nil {
			return evaluateCandidate(transaction, turn, *candidate, "conversation_key", 95, true)
		}
	}

	rows, err := transaction.Query(`
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = ? AND t.created_at_ns < ?
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT ?`, turn.Protocol, turn.CreatedAtNS, parentCandidateLimit)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: list turn parent candidates: %w", err)
	}
	defer rows.Close()
	type candidate struct{ turnID, conversationID string }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.turnID, &item.conversationID); err != nil {
			return nil, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var best *turnParent
	bestCost := int(^uint(0) >> 1)
	for _, candidate := range candidates {
		evaluated, err := evaluateCandidate(transaction, turn, candidate, "", 0, false)
		if err != nil {
			return nil, err
		}
		if evaluated == nil {
			continue
		}
		cost := auditmodel.DeltaCost(auditmodel.BuildDelta(evaluated.Base, turn.RequestRefs))
		if best == nil || cost < bestCost {
			best = evaluated
			bestCost = cost
		}
	}
	return best, nil
}

func loadCandidateByResponseID(transaction *sql.Tx, protocol, responseID string) (*struct{ turnID, conversationID string }, error) {
	var value struct{ turnID, conversationID string }
	err := transaction.QueryRow(`
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = ? AND t.response_id = ?
ORDER BY t.created_at_ns DESC, t.turn_id DESC LIMIT 1`, protocol, responseID).Scan(&value.turnID, &value.conversationID)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func loadCandidateByConversationKey(transaction *sql.Tx, protocol string, keyHash []byte) (*struct{ turnID, conversationID string }, error) {
	var value struct{ turnID, conversationID string }
	err := transaction.QueryRow(`
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = ? AND c.key_hash = ?
ORDER BY t.created_at_ns DESC, t.turn_id DESC LIMIT 1`, protocol, keyHash).Scan(&value.turnID, &value.conversationID)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func evaluateCandidate(transaction *sql.Tx, turn auditmodel.PreparedTurn, candidate struct{ turnID, conversationID string }, forcedReason string, forcedConfidence int, force bool) (*turnParent, error) {
	memo := make(map[string][]auditmodel.ObjectRef)
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
	if requestCost <= postCost {
		baseKind = "request"
		base = request
	}
	reason := forcedReason
	confidence := forcedConfidence
	if !force {
		accepted, inferredReason, inferredConfidence := strongContextRelationship(request, response, turn.RequestRefs)
		if !accepted {
			return nil, nil
		}
		reason = inferredReason
		confidence = inferredConfidence
	}
	if reason == "" {
		reason = "context_edit"
	}
	var childCount int
	if err := transaction.QueryRow(`SELECT COUNT(*) FROM turns WHERE parent_turn_id = ?`, candidate.turnID).Scan(&childCount); err != nil {
		return nil, err
	}
	retry := sameRefSequence(request, turn.RequestRefs)
	if !retry && childCount > 0 {
		var matchingSibling int
		if err := transaction.QueryRow(`
SELECT EXISTS(
    SELECT 1
    FROM turns
    WHERE parent_turn_id = ? AND request_sequence_hash = ?
)`, candidate.turnID, turn.RequestSequenceHash).Scan(&matchingSibling); err != nil {
			return nil, err
		}
		retry = matchingSibling != 0
	}
	if retry {
		reason = "retry"
		confidence = max(confidence, 90)
	} else if childCount > 0 {
		reason = "branch"
	}
	return &turnParent{
		TurnID: candidate.turnID, ConversationID: candidate.conversationID,
		BaseKind: baseKind, Reason: reason, Confidence: confidence, Base: cloneObjectRefs(base),
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

func loadRequestRefs(transaction *sql.Tx, turnID string, memo map[string][]auditmodel.ObjectRef, visiting map[string]bool) ([]auditmodel.ObjectRef, error) {
	if cached, exists := memo[turnID]; exists {
		return cloneObjectRefs(cached), nil
	}
	if visiting[turnID] {
		return nil, errors.New("sqlite writer: turn parent cycle")
	}
	visiting[turnID] = true
	defer delete(visiting, turnID)

	var header storedTurnHeader
	var parent sql.NullString
	if err := transaction.QueryRow(`
SELECT parent_turn_id, parent_base, request_item_count, request_sequence_hash
FROM turns WHERE turn_id = ?`, turnID).Scan(&parent, &header.ParentBase, &header.RequestItemCount, &header.RequestSequenceHash); err != nil {
		return nil, fmt.Errorf("sqlite writer: load turn header: %w", err)
	}
	if parent.Valid {
		header.ParentTurnID = &parent.String
	}
	base := []auditmodel.ObjectRef(nil)
	if header.ParentTurnID != nil {
		parentRequest, err := loadRequestRefs(transaction, *header.ParentTurnID, memo, visiting)
		if err != nil {
			return nil, err
		}
		base = parentRequest
		if header.ParentBase == "post_turn" {
			parentResponse, err := loadResponseRefs(transaction, *header.ParentTurnID)
			if err != nil {
				return nil, err
			}
			base = append(base, parentResponse...)
		} else if header.ParentBase != "request" {
			return nil, errors.New("sqlite writer: invalid non-root parent base")
		}
	} else if header.ParentBase != "root" {
		return nil, errors.New("sqlite writer: root turn has non-root base")
	}
	operations, err := loadContextOperations(transaction, turnID)
	if err != nil {
		return nil, err
	}
	result, err := auditmodel.ApplyDelta(base, operations)
	if err != nil {
		return nil, err
	}
	if len(result) != header.RequestItemCount || !bytes.Equal(auditmodel.SequenceHash(result), header.RequestSequenceHash) {
		return nil, errors.New("sqlite writer: stored turn sequence hash mismatch")
	}
	memo[turnID] = cloneObjectRefs(result)
	return result, nil
}

func loadContextOperations(transaction *sql.Tx, turnID string) ([]auditmodel.ContextOp, error) {
	rows, err := transaction.Query(`
SELECT operation, item_count, slot, object_hash, semantic_hash
FROM turn_context_ops
WHERE turn_id = ?
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

func loadResponseRefs(transaction *sql.Tx, turnID string) ([]auditmodel.ObjectRef, error) {
	rows, err := transaction.Query(`
SELECT slot, object_hash, semantic_hash
FROM turn_response_items
WHERE turn_id = ?
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
