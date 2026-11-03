package insights

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"strconv"
)

// CipherDetailCodec encrypts Detail JSON with the audit cipher under AAD
// (audit_id, "analysis_detail", analysis_version).
type CipherDetailCodec struct {
	Cipher security.Cipher
}

func detailAAD(auditID string, version int) ([]byte, error) {
	return security.AAD(auditID, "analysis_detail", strconv.Itoa(version))
}

// SealDetail encrypts detail for the current AnalysisVersion. The plaintext
// JSON is cleared before returning.
func (codec CipherDetailCodec) SealDetail(auditID string, detail Detail) ([]byte, error) {
	if codec.Cipher == nil {
		return nil, errors.New("insights: nil detail cipher")
	}
	aad, err := detailAAD(auditID, AnalysisVersion)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(detail)
	if err != nil {
		return nil, fmt.Errorf("insights: encode detail: %w", err)
	}
	defer clear(plaintext)
	encoded, err := encodeDetailPayload(plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return codec.Cipher.Encrypt(aad, encoded)
}

// OpenDetail decrypts and decodes one stored detail blob.
func (codec CipherDetailCodec) OpenDetail(auditID string, version int, sealed []byte) (Detail, error) {
	if codec.Cipher == nil {
		return Detail{}, errors.New("insights: nil detail cipher")
	}
	if len(sealed) == 0 {
		return Detail{}, errors.New("insights: empty detail")
	}
	aad, err := detailAAD(auditID, version)
	if err != nil {
		return Detail{}, err
	}
	plaintext, err := codec.Cipher.Decrypt(aad, sealed)
	if err != nil {
		return Detail{}, fmt.Errorf("insights: decrypt detail: %w", err)
	}
	defer clear(plaintext)
	decoded, err := decodeDetailPayload(plaintext)
	if err != nil {
		return Detail{}, err
	}
	defer clear(decoded)
	var detail Detail
	if err := json.Unmarshal(decoded, &detail); err != nil {
		return Detail{}, fmt.Errorf("insights: decode detail: %w", err)
	}
	return detail, nil
}

// The codec version is independent of the analysis vocabulary version. The
// header is inside AES-GCM, so neither compression metadata nor lengths are
// trusted before authentication. Historical headerless JSON remains readable.
var detailMagic = []byte{'A', 'I', 'D', 1}

const maxDetailPayload = 64 << 20

func encodeDetailPayload(plain []byte) ([]byte, error) {
	if len(plain) > maxDetailPayload {
		return nil, errors.New("insights: detail exceeds limit")
	}
	compression, encoded, err := bodycodec.Encode(plain, "application/json")
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	result := make([]byte, 9, 9+len(encoded))
	copy(result, detailMagic)
	if compression == bodycodec.CompressionGZIP {
		result[4] = 1
	}
	binary.BigEndian.PutUint32(result[5:9], uint32(len(plain)))
	return append(result, encoded...), nil
}
func decodeDetailPayload(encoded []byte) ([]byte, error) {
	if len(encoded) > maxDetailPayload+9 {
		return nil, errors.New("insights: detail exceeds limit")
	}
	if !bytes.HasPrefix(encoded, []byte("AID")) {
		return append([]byte(nil), encoded...), nil
	}
	if len(encoded) < 9 || !bytes.Equal(encoded[:4], detailMagic) {
		return nil, errors.New("insights: unsupported detail codec")
	}
	size := int(binary.BigEndian.Uint32(encoded[5:9]))
	if size > maxDetailPayload {
		return nil, errors.New("insights: detail exceeds limit")
	}
	compression := bodycodec.CompressionNone
	switch encoded[4] {
	case 0:
	case 1:
		compression = bodycodec.CompressionGZIP
	default:
		return nil, errors.New("insights: unsupported detail compression")
	}
	return bodycodec.Decode(encoded[9:], compression, size)
}
