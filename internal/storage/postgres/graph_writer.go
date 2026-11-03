package postgres

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
		if _, err := transaction.Exec(`DELETE FROM body_chunks WHERE audit_id = $1`, value.Result.AuditID); err != nil {
			return fmt.Errorf("postgres writer: delete compacted raw chunks: %w", err)
		}
	}
	if _, err := transaction.Exec(`
UPDATE body_streams
SET retention_state = $1,
    stored_length = CASE WHEN $2 = 'metadata' THEN 0 ELSE stored_length END,
    chunk_count = CASE WHEN $3 = 'metadata' THEN 0 ELSE chunk_count END
WHERE audit_id = $4`, retention, retention, retention, value.Result.AuditID); err != nil {
		return fmt.Errorf("postgres writer: update raw retention: %w", err)
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

func shouldDiscardRawEvidence(transaction dbTransaction, result ParsedResult, graphVerified bool) (bool, error) {
	if result.Status != ParseOK || !graphVerified {
		return false, nil
	}
	var forwardStatus, captureStatus string
	var statusCode sql.NullInt64
	if err := transaction.QueryRow(`
SELECT forward_status, capture_status, status_code
FROM audit_records
WHERE audit_id = $1`, result.AuditID).Scan(&forwardStatus, &captureStatus, &statusCode); err != nil {
		return false, fmt.Errorf("postgres writer: read raw retention outcome: %w", err)
	}
	return forwardStatus == ForwardCompleted && captureStatus == CaptureComplete && statusCode.Valid && statusCode.Int64 >= 200 && statusCode.Int64 < 400, nil
}

func persistPreparedTurn(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
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
	if _, err := transaction.Exec(`UPDATE conversations SET updated_at_ns = GREATEST(updated_at_ns, $1) WHERE conversation_id = $2`, turn.CreatedAtNS, conversationID); err != nil {
		return fmt.Errorf("postgres writer: update conversation timestamp: %w", err)
	}

	memo := make(map[string][]auditmodel.ObjectRef)
	reconstructed, err := loadRequestRefs(transaction, turn.AuditID, memo, make(map[string]bool))
	if err != nil {
		return err
	}
	if len(reconstructed) != len(turn.RequestRefs) || !bytes.Equal(auditmodel.SequenceHash(reconstructed), turn.RequestSequenceHash) {
		return localWriteError("postgres writer: persisted request sequence failed reconstruction")
	}
	response, err := loadResponseRefs(transaction, turn.AuditID)
	if err != nil {
		return err
	}
	if len(response) != len(turn.ResponseRefs) || !bytes.Equal(auditmodel.SequenceHash(response), turn.ResponseSequenceHash) {
		return localWriteError("postgres writer: persisted response sequence failed reconstruction")
	}
	return nil
}

func insertBinaryObjects(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	for _, object := range turn.Binaries {
		if _, err := transaction.Exec(`
INSERT INTO binary_objects (
    binary_hash, media_type, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT(binary_hash) DO NOTHING`,
			object.Hash, object.MediaType, object.Compression, object.PlaintextLength,
			object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return fmt.Errorf("postgres writer: insert binary object: %w", err)
		}
		var mediaType string
		var plaintextLength int64
		// Only properties of the stored plaintext take part in the identity
		// check. compression and encoded_length describe how the existing row
		// was encoded, not what it holds: the codec picks them per write, so an
		// encoder that emits a different number of bytes for the same input —
		// a gzip implementation change across a toolchain upgrade, say — makes
		// them disagree with a row written by an earlier build. Treating that
		// as corruption would reject every turn reusing such an object, and the
		// insert above is DO NOTHING, so the row keeps the encoding its own
		// data_enc was produced with and stays self-consistent either way.
		if err := transaction.QueryRow(`
SELECT media_type, plaintext_length
FROM binary_objects
WHERE binary_hash = $1`, object.Hash).Scan(&mediaType, &plaintextLength); err != nil {
			return fmt.Errorf("postgres writer: read binary object identity: %w", err)
		}
		if mediaType != object.MediaType || plaintextLength != object.PlaintextLength {
			return storedObjectIntegrityError("postgres writer: binary object hash collision or corruption")
		}
	}
	return nil
}

func insertContentObjects(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	for _, object := range turn.Objects {
		if _, err := transaction.Exec(`
INSERT INTO content_objects (
    object_hash, semantic_hash, kind, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT(object_hash) DO NOTHING`,
			object.Hash, object.SemanticHash, object.Kind, object.Compression,
			object.PlaintextLength, object.EncodedLength, object.DataEnc, turn.CreatedAtNS,
		); err != nil {
			return fmt.Errorf("postgres writer: insert content object: %w", err)
		}
		var semanticHash []byte
		var kind string
		var plaintextLength int64
		// compression and encoded_length are left out for the reason given in
		// insertBinaryObjects.
		if err := transaction.QueryRow(`
SELECT semantic_hash, kind, plaintext_length
FROM content_objects WHERE object_hash = $1`, object.Hash).Scan(&semanticHash, &kind, &plaintextLength); err != nil {
			return fmt.Errorf("postgres writer: read content object identity: %w", err)
		}
		if !bytes.Equal(semanticHash, object.SemanticHash) || kind != object.Kind ||
			plaintextLength != object.PlaintextLength {
			return storedObjectIntegrityError("postgres writer: content object hash collision or corruption")
		}
		for _, reference := range object.BinaryRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_binary_refs (
    object_hash, json_pointer, binary_hash, media_type, encoding
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(object_hash, json_pointer, binary_hash) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.BinaryHash, reference.MediaType, reference.Encoding,
			); err != nil {
				return fmt.Errorf("postgres writer: insert content binary ref: %w", err)
			}
			var mediaType, encoding string
			if err := transaction.QueryRow(`
SELECT media_type, encoding
FROM content_binary_refs
WHERE object_hash = $1 AND json_pointer = $2 AND binary_hash = $3`,
				object.Hash, reference.JSONPointer, reference.BinaryHash,
			).Scan(&mediaType, &encoding); err != nil {
				return fmt.Errorf("postgres writer: read binary reference identity: %w", err)
			}
			if mediaType != reference.MediaType || encoding != reference.Encoding {
				return storedObjectIntegrityError("postgres writer: content binary reference collision or corruption")
			}
		}
		for _, reference := range object.ExternalRefs {
			if _, err := transaction.Exec(`
INSERT INTO content_external_refs (
    object_hash, json_pointer, ref_kind, value_hash, value_enc
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(object_hash, json_pointer, ref_kind) DO NOTHING`,
				object.Hash, reference.JSONPointer, reference.Kind, reference.ValueHash, reference.ValueEnc,
			); err != nil {
				return fmt.Errorf("postgres writer: insert content external ref: %w", err)
			}
			var valueHash []byte
			if err := transaction.QueryRow(`
SELECT value_hash
FROM content_external_refs
WHERE object_hash = $1 AND json_pointer = $2 AND ref_kind = $3`,
				object.Hash, reference.JSONPointer, reference.Kind,
			).Scan(&valueHash); err != nil {
				return fmt.Errorf("postgres writer: read external reference identity: %w", err)
			}
			if !bytes.Equal(valueHash, reference.ValueHash) {
				return storedObjectIntegrityError("postgres writer: content external reference collision or corruption")
			}
		}
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

func chooseTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn) (*turnParent, error) {
	if turn.PreviousResponseID != "" {
		candidate, err := loadCandidateByResponseID(transaction, turn.Protocol, turn.PreviousResponseID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if candidate != nil {
			return evaluateCandidate(transaction, turn, *candidate, "previous_response_id", 100, linkForced, make(map[string][]auditmodel.ObjectRef))
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
			return nil, err
		}
		// A provider-side conversation is one chain whose requests carry only
		// the new input, so content cannot confirm the link; follow the latest
		// earlier turn as the provider does.
		if turn.ServerManagedContext {
			if len(candidates) == 0 {
				return nil, nil
			}
			return evaluateCandidate(transaction, turn, candidates[0], "conversation_key", 95, linkForced, make(map[string][]auditmodel.ObjectRef))
		}
		// A conversation key groups a client session, not one agent: Codex and
		// OpenCode send the root session id as prompt_cache_key for the parent
		// and every sub-agent, so the latest keyed turn may belong to a
		// concurrent sibling. Rank the session's recent turns by content
		// instead. When none qualifies, including the key's first turn, the
		// turn starts a new root in its own keyed conversation: the
		// protocol-wide search below would attach it to another session and
		// drop the key, so later turns with this key could not find it.
		return bestTurnParent(transaction, turn, candidates, linkConversationKey)
	}

	candidates, err := listTurnCandidates(transaction, `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND t.created_at_ns < $2
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $3`, turn.Protocol, turn.CreatedAtNS, parentCandidateLimit)
	if err != nil {
		return nil, err
	}
	return bestTurnParent(transaction, turn, candidates, linkInferred)
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
func bestTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn, candidates []turnCandidate, mode linkMode) (*turnParent, error) {
	// Candidates usually share most of their ancestry, so one memo spares each
	// of them a full walk back to its root.
	memo := make(map[string][]auditmodel.ObjectRef)
	var best *turnParent
	for _, candidate := range candidates {
		evaluated, err := evaluateCandidate(transaction, turn, candidate, "", 0, mode, memo)
		if err != nil {
			return nil, err
		}
		if evaluated != nil && (best == nil || evaluated.cost < best.cost) {
			best = evaluated
		}
	}
	return best, nil
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
	if len(memo) >= 32 || total > 65536 {
		clear(memo)
	}
	if len(result) <= 65536 {
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
