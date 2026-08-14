package auditmodel

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	contentHashDomain        = "llmapi-logger/content/v1\x00"
	binaryHashDomain         = "llmapi-logger/binary/v1\x00"
	sequenceHashDomain       = "llmapi-logger/sequence/v1\x00"
	reconstructionHashDomain = "llmapi-logger/rebuild/v1\x00"
	conversationKeyDomain    = "llmapi-logger/conversation-key/v1\x00"
	externalRefDomain        = "llmapi-logger/external-ref/v1\x00"
)

// DecodeJSON preserves JSON number spellings and rejects trailing values.
func DecodeJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("auditmodel: inspect trailing JSON: %w", err)
	}
	return errors.New("auditmodel: trailing JSON value")
}

func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("auditmodel: canonical JSON: %w", err)
	}
	return encoded, nil
}

func ContentHash(canonical []byte) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(contentHashDomain))
	_, _ = digest.Write(canonical)
	return digest.Sum(nil)
}

func BinaryHash(data []byte) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(binaryHashDomain))
	_, _ = digest.Write(data)
	return digest.Sum(nil)
}

func ReconstructionHash(canonical []byte) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(reconstructionHashDomain))
	_, _ = digest.Write(canonical)
	return digest.Sum(nil)
}

func ConversationKeyHash(value string) []byte {
	if value == "" {
		return nil
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(conversationKeyDomain))
	_, _ = digest.Write([]byte(value))
	return digest.Sum(nil)
}

func ExternalValueHash(kind, value string) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(externalRefDomain))
	_, _ = digest.Write([]byte(kind))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(value))
	return digest.Sum(nil)
}

func SequenceHash(refs []ObjectRef) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(sequenceHashDomain))
	var length [8]byte
	for _, ref := range refs {
		putUint64(length[:], uint64(len(ref.Slot)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(ref.Slot))
		putUint64(length[:], uint64(len(ref.ObjectHash)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(ref.ObjectHash)
	}
	return digest.Sum(nil)
}

func EqualHash(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func hashHex(value []byte) string { return hex.EncodeToString(value) }

func putUint64(destination []byte, value uint64) {
	for index := 7; index >= 0; index-- {
		destination[index] = byte(value)
		value >>= 8
	}
}

func CloneJSON(value any) (any, error) {
	encoded, err := CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	var cloned any
	if err := DecodeJSON(encoded, &cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}

// CheckReservedMarkers is called before a normalizer inserts internal markers.
func CheckReservedMarkers(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		if _, exists := typed[ItemMarkerKey]; exists {
			return ErrReservedMarker
		}
		if _, exists := typed[BinaryMarkerKey]; exists {
			return ErrReservedMarker
		}
		for _, child := range typed {
			if err := CheckReservedMarkers(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := CheckReservedMarkers(child); err != nil {
				return err
			}
		}
	}
	return nil
}
