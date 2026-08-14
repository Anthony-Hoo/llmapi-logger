package auditmodel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"llmapi-logger/internal/security"
)

type preparedPlainItem struct {
	Item       Item
	Object     ContentObject
	Value      any
	Canonical  []byte
	BinaryRefs []BinaryReference
}

// Prepare canonicalizes, hashes, compresses, encrypts, and locally verifies a
// normalized turn. It returns no plaintext provider values.
func Prepare(turn Turn, cipher security.Cipher) (PreparedTurn, error) {
	if cipher == nil || turn.AuditID == "" || turn.Protocol == "" || turn.ParserName == "" || turn.RequestLayout == "" || turn.ResponseLayout == "" || turn.CreatedAtNS <= 0 {
		return PreparedTurn{}, ErrInvalidModel
	}
	accumulator := newBinaryAccumulator()
	objects := make(map[string]ContentObject)

	requestItems, requestRefs, err := prepareItems(cipher, accumulator, turn.RequestItems, objects)
	if err != nil {
		return PreparedTurn{}, err
	}
	responseItems, responseRefs, err := prepareItems(cipher, accumulator, turn.ResponseItems, objects)
	if err != nil {
		return PreparedTurn{}, err
	}

	requestEnvelope, requestEnvelopeObject, err := prepareEnvelope(cipher, accumulator, "request_envelope", turn.RequestEnvelope)
	if err != nil {
		return PreparedTurn{}, err
	}
	objects[hashHex(requestEnvelopeObject.Hash)] = requestEnvelopeObject
	responseEnvelope, responseEnvelopeObject, err := prepareEnvelope(cipher, accumulator, "response_envelope", turn.ResponseEnvelope)
	if err != nil {
		return PreparedTurn{}, err
	}
	objects[hashHex(responseEnvelopeObject.Hash)] = responseEnvelopeObject

	requestOriginal, err := accumulator.transform(turn.RequestOriginal)
	if err != nil {
		return PreparedTurn{}, err
	}
	responseOriginal, err := accumulator.transform(turn.ResponseOriginal)
	if err != nil {
		return PreparedTurn{}, err
	}

	requestRebuilt, err := Assemble(turn.RequestLayout, requestEnvelope, plainItems(requestItems))
	if err != nil {
		return PreparedTurn{}, fmt.Errorf("%w: request: %v", ErrReconstruction, err)
	}
	responseRebuilt, err := Assemble(turn.ResponseLayout, responseEnvelope, plainItems(responseItems))
	if err != nil {
		return PreparedTurn{}, fmt.Errorf("%w: response: %v", ErrReconstruction, err)
	}
	requestCanonical, err := CanonicalJSON(requestRebuilt)
	if err != nil {
		return PreparedTurn{}, err
	}
	requestOriginalCanonical, err := CanonicalJSON(requestOriginal.Value)
	if err != nil || !EqualHash(sha256Bytes(requestCanonical), sha256Bytes(requestOriginalCanonical)) {
		return PreparedTurn{}, fmt.Errorf("%w: request canonical mismatch", ErrReconstruction)
	}
	responseCanonical, err := CanonicalJSON(responseRebuilt)
	if err != nil {
		return PreparedTurn{}, err
	}
	responseOriginalCanonical, err := CanonicalJSON(responseOriginal.Value)
	if err != nil || !EqualHash(sha256Bytes(responseCanonical), sha256Bytes(responseOriginalCanonical)) {
		return PreparedTurn{}, fmt.Errorf("%w: response canonical mismatch", ErrReconstruction)
	}

	binaries := make([]BinaryObject, 0, len(accumulator.objects))
	binaryKeys := make([]string, 0, len(accumulator.objects))
	for key := range accumulator.objects {
		binaryKeys = append(binaryKeys, key)
	}
	sort.Strings(binaryKeys)
	for _, key := range binaryKeys {
		sealed, err := sealBinary(cipher, accumulator.objects[key])
		if err != nil {
			return PreparedTurn{}, err
		}
		binaries = append(binaries, sealed)
	}

	objectValues := make([]ContentObject, 0, len(objects))
	objectKeys := make([]string, 0, len(objects))
	for key := range objects {
		objectKeys = append(objectKeys, key)
	}
	sort.Strings(objectKeys)
	for _, key := range objectKeys {
		objectValues = append(objectValues, objects[key])
	}

	return PreparedTurn{
		AuditID:                    turn.AuditID,
		Protocol:                   turn.Protocol,
		ParserName:                 turn.ParserName,
		RequestLayout:              turn.RequestLayout,
		ResponseLayout:             turn.ResponseLayout,
		RequestEnvelopeHash:        append([]byte(nil), requestEnvelopeObject.Hash...),
		ResponseEnvelopeHash:       append([]byte(nil), responseEnvelopeObject.Hash...),
		RequestRefs:                requestRefs,
		ResponseRefs:               responseRefs,
		RequestSequenceHash:        SequenceHash(requestRefs),
		ResponseSequenceHash:       SequenceHash(responseRefs),
		RequestReconstructionHash:  ReconstructionHash(requestCanonical),
		ResponseReconstructionHash: ReconstructionHash(responseCanonical),
		PreviousResponseID:         turn.PreviousResponseID,
		ResponseID:                 turn.ResponseID,
		ConversationKeyHash:        ConversationKeyHash(turn.ConversationKey),
		CreatedAtNS:                turn.CreatedAtNS,
		Objects:                    objectValues,
		Binaries:                   binaries,
	}, nil
}

func prepareItems(cipher security.Cipher, accumulator *binaryAccumulator, items []Item, objects map[string]ContentObject) ([]preparedPlainItem, []ObjectRef, error) {
	prepared := make([]preparedPlainItem, 0, len(items))
	refs := make([]ObjectRef, 0, len(items))
	for _, item := range items {
		if item.Slot == "" || item.Kind == "" {
			return nil, nil, ErrInvalidModel
		}
		transformed, err := accumulator.transform(item.Value)
		if err != nil {
			return nil, nil, err
		}
		wrapper := DecodedObject{SchemaVersion: SchemaVersion, Kind: item.Kind, Value: transformed.Value}
		canonical, err := CanonicalJSON(wrapper)
		if err != nil {
			return nil, nil, err
		}
		hash := ContentHash(canonical)
		semanticHash, err := SemanticHash(item.Kind, transformed.Value)
		if err != nil {
			return nil, nil, err
		}
		compression, encrypted, encodedLength, err := sealContent(cipher, hash, item.Kind, canonical)
		if err != nil {
			return nil, nil, err
		}
		externalRefs, err := sealExternalRefs(cipher, hash, transformed.ExternalRefs)
		if err != nil {
			return nil, nil, err
		}
		object := ContentObject{
			Hash:            hash,
			SemanticHash:    semanticHash,
			Kind:            item.Kind,
			Compression:     compression,
			PlaintextLength: int64(len(canonical)),
			EncodedLength:   encodedLength,
			DataEnc:         encrypted,
			BinaryRefs:      cloneBinaryRefs(transformed.BinaryRefs),
			ExternalRefs:    externalRefs,
		}
		key := hashHex(hash)
		if existing, exists := objects[key]; exists && !EqualHash(existing.SemanticHash, semanticHash) {
			return nil, nil, ErrIntegrity
		}
		objects[key] = object
		prepared = append(prepared, preparedPlainItem{
			Item:      Item{Slot: item.Slot, Kind: item.Kind, Value: transformed.Value},
			Object:    object,
			Value:     transformed.Value,
			Canonical: canonical,
		})
		refs = append(refs, ObjectRef{Slot: item.Slot, ObjectHash: append([]byte(nil), hash...), SemanticHash: append([]byte(nil), semanticHash...)})
	}
	return prepared, refs, nil
}

func prepareEnvelope(cipher security.Cipher, accumulator *binaryAccumulator, kind string, value any) (any, ContentObject, error) {
	transformed, err := accumulator.transform(value)
	if err != nil {
		return nil, ContentObject{}, err
	}
	wrapper := DecodedObject{SchemaVersion: SchemaVersion, Kind: kind, Value: transformed.Value}
	canonical, err := CanonicalJSON(wrapper)
	if err != nil {
		return nil, ContentObject{}, err
	}
	hash := ContentHash(canonical)
	compression, encrypted, encodedLength, err := sealContent(cipher, hash, kind, canonical)
	if err != nil {
		return nil, ContentObject{}, err
	}
	externalRefs, err := sealExternalRefs(cipher, hash, transformed.ExternalRefs)
	if err != nil {
		return nil, ContentObject{}, err
	}
	return transformed.Value, ContentObject{
		Hash:            hash,
		SemanticHash:    append([]byte(nil), hash...),
		Kind:            kind,
		Compression:     compression,
		PlaintextLength: int64(len(canonical)),
		EncodedLength:   encodedLength,
		DataEnc:         encrypted,
		BinaryRefs:      cloneBinaryRefs(transformed.BinaryRefs),
		ExternalRefs:    externalRefs,
	}, nil
}

func sealExternalRefs(cipher security.Cipher, objectHash []byte, values []plainExternalReference) ([]ExternalReference, error) {
	result := make([]ExternalReference, 0, len(values))
	for _, value := range values {
		aad, err := security.AAD("external_ref", hashHex(objectHash), value.JSONPointer, value.Kind)
		if err != nil {
			return nil, err
		}
		encrypted, err := cipher.Encrypt(aad, []byte(value.Value))
		if err != nil {
			return nil, err
		}
		result = append(result, ExternalReference{
			JSONPointer: value.JSONPointer,
			Kind:        value.Kind,
			ValueHash:   ExternalValueHash(value.Kind, value.Value),
			ValueEnc:    encrypted,
		})
	}
	return result, nil
}

func semanticProjection(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			switch key {
			case "id", "status", "created_at", "completed_at", "sequence_number":
				continue
			}
			result[key] = semanticProjection(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = semanticProjection(child)
		}
		return result
	default:
		return typed
	}
}

// SemanticHash ignores provider occurrence fields used only for parent-turn
// inference. Exact content addressing always continues to use ContentHash.
func SemanticHash(kind string, value any) ([]byte, error) {
	if kind == "" {
		return nil, ErrInvalidModel
	}
	canonical, err := CanonicalJSON(map[string]any{"kind": kind, "value": semanticProjection(value)})
	if err != nil {
		return nil, err
	}
	return ContentHash(canonical), nil
}

func plainItems(values []preparedPlainItem) []Item {
	items := make([]Item, 0, len(values))
	for _, value := range values {
		items = append(items, value.Item)
	}
	return items
}

func cloneBinaryRefs(values []BinaryReference) []BinaryReference {
	result := make([]BinaryReference, len(values))
	for index, value := range values {
		result[index] = value
		result[index].BinaryHash = append([]byte(nil), value.BinaryHash...)
	}
	return result
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

var _ = json.Number("")
