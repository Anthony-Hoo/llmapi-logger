package auditmodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"llmapi-logger/internal/security"
)

// ObjectLookup returns existing ciphertext for any subset of the requested
// hashes. It must not return plaintext. Lookup failures abort preparation.
// The callback is invoked once per turn; implementations should batch reads.
type ObjectLookup func(contentHashes, binaryHashes [][]byte) ([]StoredContent, []StoredBinary, error)

type plainContentCandidate struct {
	Object       ContentObject
	Canonical    []byte
	ExternalRefs []plainExternalReference
}

// Prepare canonicalizes, hashes, compresses, encrypts, and locally verifies a
// normalized turn. It returns no plaintext provider values.
func Prepare(turn Turn, cipher security.Cipher) (PreparedTurn, error) {
	return PrepareWithLookup(turn, cipher, nil)
}

// PrepareWithLookup reuses stored encoding only after authenticating and
// checking it against the current canonical plaintext. Compression/nonce are
// not identity. No cross-request plaintext cache or trust-only hit path exists.
func PrepareWithLookup(turn Turn, cipher security.Cipher, lookup ObjectLookup) (PreparedTurn, error) {
	if cipher == nil || turn.AuditID == "" || turn.Protocol == "" || turn.ParserName == "" || turn.RequestLayout == "" || turn.ResponseLayout == "" || turn.CreatedAtNS <= 0 {
		return PreparedTurn{}, ErrInvalidModel
	}
	accumulator := newBinaryAccumulator()
	encoder := &contentEncoder{}
	defer encoder.release()
	objects := make(map[string]plainContentCandidate)
	defer func() {
		for _, value := range objects {
			clear(value.Canonical)
		}
	}()

	requestItems, requestRefs, err := prepareItems(accumulator, turn.RequestItems, objects)
	if err != nil {
		return PreparedTurn{}, err
	}
	responseItems, responseRefs, err := prepareItems(accumulator, turn.ResponseItems, objects)
	if err != nil {
		return PreparedTurn{}, err
	}

	requestEnvelope, requestEnvelopeObject, err := prepareEnvelope(accumulator, "request_envelope", turn.RequestEnvelope)
	if err != nil {
		return PreparedTurn{}, err
	}
	if err := addEnvelopeCandidate(objects, requestEnvelopeObject); err != nil {
		return PreparedTurn{}, err
	}
	responseEnvelope, responseEnvelopeObject, err := prepareEnvelope(accumulator, "response_envelope", turn.ResponseEnvelope)
	if err != nil {
		return PreparedTurn{}, err
	}
	if err := addEnvelopeCandidate(objects, responseEnvelopeObject); err != nil {
		return PreparedTurn{}, err
	}

	requestOriginal, err := accumulator.transform(turn.RequestOriginal)
	if err != nil {
		return PreparedTurn{}, err
	}
	responseOriginal, err := accumulator.transform(turn.ResponseOriginal)
	if err != nil {
		return PreparedTurn{}, err
	}

	requestRebuilt, err := Assemble(turn.RequestLayout, requestEnvelope, requestItems)
	if err != nil {
		return PreparedTurn{}, fmt.Errorf("%w: request: %v", ErrReconstruction, err)
	}
	responseRebuilt, err := Assemble(turn.ResponseLayout, responseEnvelope, responseItems)
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

	objectValues, binaries, err := sealCandidates(cipher, encoder, objects, accumulator.objects, lookup)
	if err != nil {
		return PreparedTurn{}, err
	}

	return PreparedTurn{
		AuditID:                    turn.AuditID,
		Protocol:                   turn.Protocol,
		ParserName:                 turn.ParserName,
		RequestLayout:              turn.RequestLayout,
		ResponseLayout:             turn.ResponseLayout,
		RequestEnvelopeHash:        append([]byte(nil), requestEnvelopeObject.Object.Hash...),
		ResponseEnvelopeHash:       append([]byte(nil), responseEnvelopeObject.Object.Hash...),
		RequestRefs:                requestRefs,
		ResponseRefs:               responseRefs,
		RequestSequenceHash:        SequenceHash(requestRefs),
		ResponseSequenceHash:       SequenceHash(responseRefs),
		RequestReconstructionHash:  ReconstructionHash(requestCanonical),
		ResponseReconstructionHash: ReconstructionHash(responseCanonical),
		PreviousResponseID:         turn.PreviousResponseID,
		ResponseID:                 turn.ResponseID,
		ConversationKeyHash:        ConversationKeyHash(turn.ConversationKey),
		ServerManagedContext:       turn.ServerManagedContext,
		CreatedAtNS:                turn.CreatedAtNS,
		Objects:                    objectValues,
		Binaries:                   binaries,
	}, nil
}

func prepareItems(accumulator *binaryAccumulator, items []Item, objects map[string]plainContentCandidate) ([]Item, []ObjectRef, error) {
	prepared := make([]Item, 0, len(items))
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
		key := hashHex(hash)
		candidate, exists := objects[key]
		if exists {
			object := candidate.Object
			if object.Kind != item.Kind || object.PlaintextLength != int64(len(canonical)) || !EqualHash(object.SemanticHash, semanticHash) || !bytes.Equal(candidate.Canonical, canonical) {
				clear(canonical)
				return nil, nil, ErrIntegrity
			}
			clear(canonical)
		} else {
			objects[key] = plainContentCandidate{
				Object:    ContentObject{Hash: hash, SemanticHash: semanticHash, Kind: item.Kind, PlaintextLength: int64(len(canonical)), BinaryRefs: cloneBinaryRefs(transformed.BinaryRefs)},
				Canonical: canonical, ExternalRefs: transformed.ExternalRefs,
			}
		}
		prepared = append(prepared, Item{Slot: item.Slot, Kind: item.Kind, Value: transformed.Value})
		refs = append(refs, ObjectRef{Slot: item.Slot, ObjectHash: append([]byte(nil), hash...), SemanticHash: append([]byte(nil), semanticHash...)})
	}
	return prepared, refs, nil
}

func prepareEnvelope(accumulator *binaryAccumulator, kind string, value any) (any, plainContentCandidate, error) {
	transformed, err := accumulator.transform(value)
	if err != nil {
		return nil, plainContentCandidate{}, err
	}
	wrapper := DecodedObject{SchemaVersion: SchemaVersion, Kind: kind, Value: transformed.Value}
	canonical, err := CanonicalJSON(wrapper)
	if err != nil {
		return nil, plainContentCandidate{}, err
	}
	hash := ContentHash(canonical)
	return transformed.Value, plainContentCandidate{
		Object:    ContentObject{Hash: hash, SemanticHash: append([]byte(nil), hash...), Kind: kind, PlaintextLength: int64(len(canonical)), BinaryRefs: cloneBinaryRefs(transformed.BinaryRefs)},
		Canonical: canonical, ExternalRefs: transformed.ExternalRefs,
	}, nil
}

func addEnvelopeCandidate(objects map[string]plainContentCandidate, candidate plainContentCandidate) error {
	key := hashHex(candidate.Object.Hash)
	if existing, ok := objects[key]; ok {
		defer clear(candidate.Canonical)
		if existing.Object.Kind != candidate.Object.Kind || existing.Object.PlaintextLength != candidate.Object.PlaintextLength || !EqualHash(existing.Object.SemanticHash, candidate.Object.SemanticHash) || !bytes.Equal(existing.Canonical, candidate.Canonical) {
			return ErrIntegrity
		}
		return nil
	}
	objects[key] = candidate
	return nil
}

func sealCandidates(cipher security.Cipher, encoder *contentEncoder, objects map[string]plainContentCandidate, binaryCandidates map[string]binaryCandidate, lookup ObjectLookup) ([]ContentObject, []BinaryObject, error) {
	objectKeys := make([]string, 0, len(objects))
	for key := range objects {
		objectKeys = append(objectKeys, key)
	}
	sort.Strings(objectKeys)
	binaryKeys := make([]string, 0, len(binaryCandidates))
	for key := range binaryCandidates {
		binaryKeys = append(binaryKeys, key)
	}
	sort.Strings(binaryKeys)
	existingContent := make(map[string]StoredContent)
	existingBinary := make(map[string]StoredBinary)
	if lookup != nil {
		contentHashes := make([][]byte, 0, len(objectKeys))
		for _, key := range objectKeys {
			contentHashes = append(contentHashes, append([]byte(nil), objects[key].Object.Hash...))
		}
		binaryHashes := make([][]byte, 0, len(binaryKeys))
		for _, key := range binaryKeys {
			binaryHashes = append(binaryHashes, append([]byte(nil), binaryCandidates[key].Hash...))
		}
		content, binaries, err := lookup(contentHashes, binaryHashes)
		if err != nil {
			return nil, nil, err
		}
		for _, value := range content {
			key := hashHex(value.Hash)
			if _, ok := objects[key]; !ok {
				return nil, nil, ErrIntegrity
			}
			if _, duplicate := existingContent[key]; duplicate {
				return nil, nil, ErrIntegrity
			}
			existingContent[key] = value
		}
		for _, value := range binaries {
			key := hashHex(value.Hash)
			if _, ok := binaryCandidates[key]; !ok {
				return nil, nil, ErrIntegrity
			}
			if _, duplicate := existingBinary[key]; duplicate {
				return nil, nil, ErrIntegrity
			}
			existingBinary[key] = value
		}
	}
	decoder := &contentDecoder{}
	result := make([]ContentObject, 0, len(objects))
	for _, key := range objectKeys {
		candidate := objects[key]
		object := candidate.Object
		if stored, ok := existingContent[key]; ok {
			if stored.Kind != object.Kind || stored.PlaintextLength != object.PlaintextLength || stored.EncodedLength < 0 || !EqualHash(stored.SemanticHash, object.SemanticHash) {
				return nil, nil, ErrIntegrity
			}
			aad, err := security.AAD("content_object", key, stored.Kind, stored.Compression)
			if err != nil || verifyStoredEncoding(cipher, decoder, aad, stored.DataEnc, stored.Compression, stored.EncodedLength, candidate.Canonical) != nil {
				return nil, nil, ErrIntegrity
			}
			object.Compression = stored.Compression
			object.EncodedLength = stored.EncodedLength
			object.DataEnc = append([]byte(nil), stored.DataEnc...)
		} else {
			compression, encrypted, length, err := sealContentWithEncoder(cipher, encoder, object.Hash, object.Kind, candidate.Canonical)
			if err != nil {
				return nil, nil, err
			}
			object.Compression = compression
			object.EncodedLength = length
			object.DataEnc = encrypted
		}
		external, err := sealExternalRefs(cipher, object.Hash, candidate.ExternalRefs)
		if err != nil {
			return nil, nil, err
		}
		object.ExternalRefs = external
		result = append(result, object)
	}
	binaries := make([]BinaryObject, 0, len(binaryCandidates))
	for _, key := range binaryKeys {
		candidate := binaryCandidates[key]
		if stored, ok := existingBinary[key]; ok {
			if stored.PlaintextLength != int64(len(candidate.Data)) || stored.EncodedLength < 0 || stored.MediaType != "application/octet-stream" {
				return nil, nil, ErrIntegrity
			}
			aad, err := security.AAD("binary_object", key, stored.Compression)
			if err != nil || verifyStoredEncoding(cipher, decoder, aad, stored.DataEnc, stored.Compression, stored.EncodedLength, candidate.Data) != nil {
				return nil, nil, ErrIntegrity
			}
			binaries = append(binaries, BinaryObject{Hash: append([]byte(nil), stored.Hash...), MediaType: stored.MediaType, Compression: stored.Compression, PlaintextLength: stored.PlaintextLength, EncodedLength: stored.EncodedLength, DataEnc: append([]byte(nil), stored.DataEnc...)})
		} else {
			sealed, err := sealBinaryWithEncoder(cipher, encoder, candidate)
			if err != nil {
				return nil, nil, err
			}
			binaries = append(binaries, sealed)
		}
	}
	return result, binaries, nil
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
