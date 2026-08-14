package auditmodel

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"time"

	"llmapi-logger/internal/security"
)

func sealContent(cipher security.Cipher, hash []byte, kind string, plaintext []byte) (string, []byte, int64, error) {
	compression, encoded, err := compressContent(plaintext)
	if err != nil {
		return "", nil, 0, err
	}
	aad, err := security.AAD("content_object", hashHex(hash), kind, compression)
	if err != nil {
		return "", nil, 0, err
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		return "", nil, 0, fmt.Errorf("auditmodel: encrypt content object: %w", err)
	}
	return compression, encrypted, int64(len(encoded)), nil
}

func sealBinary(cipher security.Cipher, candidate binaryCandidate) (BinaryObject, error) {
	compression := CompressionNone
	encoded := candidate.Data
	if shouldCompressBinary(candidate.MediaType, candidate.Data) {
		compressed, err := gzipBytes(candidate.Data)
		if err != nil {
			return BinaryObject{}, err
		}
		if worthwhileCompression(len(candidate.Data), len(compressed)) {
			compression = CompressionGZIP
			encoded = compressed
		}
	}
	aad, err := security.AAD("binary_object", hashHex(candidate.Hash), compression)
	if err != nil {
		return BinaryObject{}, err
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		return BinaryObject{}, fmt.Errorf("auditmodel: encrypt binary object: %w", err)
	}
	return BinaryObject{
		Hash: append([]byte(nil), candidate.Hash...),
		// The decoded bytes are the binary object's identity. The exact media
		// type remains occurrence metadata on BinaryReference, so alternate
		// but equivalent labels cannot defeat byte-level deduplication.
		MediaType:       "application/octet-stream",
		Compression:     compression,
		PlaintextLength: int64(len(candidate.Data)),
		EncodedLength:   int64(len(encoded)),
		DataEnc:         encrypted,
	}, nil
}

func compressContent(plaintext []byte) (string, []byte, error) {
	if len(plaintext) < 128 {
		return CompressionNone, append([]byte(nil), plaintext...), nil
	}
	compressed, err := gzipBytes(plaintext)
	if err != nil {
		return "", nil, err
	}
	if !worthwhileCompression(len(plaintext), len(compressed)) {
		return CompressionNone, append([]byte(nil), plaintext...), nil
	}
	return CompressionGZIP, compressed, nil
}

func gzipBytes(plaintext []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		return nil, fmt.Errorf("auditmodel: create gzip writer: %w", err)
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("auditmodel: gzip object: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("auditmodel: close gzip object: %w", err)
	}
	return output.Bytes(), nil
}

func worthwhileCompression(plainLength, compressedLength int) bool {
	return plainLength >= 128 && compressedLength+32 < plainLength
}

func shouldCompressBinary(_ string, data []byte) bool {
	// Compression is selected from the bytes, not a caller-controlled media
	// label, so the same binary hash always has the same stored representation.
	// Unknown formats may be trial-compressed, but are only retained compressed
	// when the size reduction is worthwhile.
	return !alreadyCompressedMagic(data)
}

func alreadyCompressedMagic(data []byte) bool {
	return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) ||
		bytes.HasPrefix(data, []byte("\xff\xd8\xff")) ||
		bytes.HasPrefix(data, []byte("GIF87a")) ||
		bytes.HasPrefix(data, []byte("GIF89a")) ||
		bytes.HasPrefix(data, []byte("PK\x03\x04")) ||
		bytes.HasPrefix(data, []byte("\x1f\x8b")) ||
		bytes.HasPrefix(data, []byte("%PDF-")) ||
		len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}

func openContent(cipher security.Cipher, stored StoredContent) ([]byte, error) {
	aad, err := security.AAD("content_object", hashHex(stored.Hash), stored.Kind, stored.Compression)
	if err != nil {
		return nil, ErrIntegrity
	}
	encoded, err := cipher.Decrypt(aad, stored.DataEnc)
	if err != nil {
		return nil, ErrIntegrity
	}
	if stored.EncodedLength > 0 && int64(len(encoded)) != stored.EncodedLength {
		clear(encoded)
		return nil, ErrIntegrity
	}
	plaintext, err := decompress(stored.Compression, encoded, stored.PlaintextLength)
	clear(encoded)
	if err != nil || int64(len(plaintext)) != stored.PlaintextLength || !EqualHash(ContentHash(plaintext), stored.Hash) {
		clear(plaintext)
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

func OpenObject(cipher security.Cipher, stored StoredContent) (DecodedObject, error) {
	if stored.EncodedLength < 0 || stored.PlaintextLength < 0 {
		return DecodedObject{}, ErrIntegrity
	}
	plaintext, err := openContent(cipher, stored)
	if err != nil {
		return DecodedObject{}, err
	}
	defer clear(plaintext)
	var object DecodedObject
	if err := DecodeJSON(plaintext, &object); err != nil || object.SchemaVersion != SchemaVersion || object.Kind != stored.Kind {
		return DecodedObject{}, ErrIntegrity
	}
	return object, nil
}

func OpenBinary(cipher security.Cipher, stored StoredBinary) ([]byte, error) {
	aad, err := security.AAD("binary_object", hashHex(stored.Hash), stored.Compression)
	if err != nil {
		return nil, ErrIntegrity
	}
	encoded, err := cipher.Decrypt(aad, stored.DataEnc)
	if err != nil {
		return nil, ErrIntegrity
	}
	if stored.EncodedLength > 0 && int64(len(encoded)) != stored.EncodedLength {
		clear(encoded)
		return nil, ErrIntegrity
	}
	plaintext, err := decompress(stored.Compression, encoded, stored.PlaintextLength)
	clear(encoded)
	if err != nil || int64(len(plaintext)) != stored.PlaintextLength || !EqualHash(BinaryHash(plaintext), stored.Hash) {
		clear(plaintext)
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

func decompress(compression string, encoded []byte, expectedLength int64) ([]byte, error) {
	switch compression {
	case CompressionNone:
		return append([]byte(nil), encoded...), nil
	case CompressionGZIP:
		reader, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		limit := expectedLength + 1
		if limit <= 0 {
			limit = 1
		}
		plaintext, readErr := io.ReadAll(io.LimitReader(reader, limit))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return nil, errorsJoin(readErr, closeErr)
		}
		if int64(len(plaintext)) > expectedLength {
			return nil, ErrIntegrity
		}
		return plaintext, nil
	default:
		return nil, ErrIntegrity
	}
}

func errorsJoin(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
