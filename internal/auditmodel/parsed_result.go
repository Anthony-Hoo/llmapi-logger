package auditmodel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
)

// parsed_results.parsed_json_enc is sealed under AAD (audit_id, "parsed_json",
// parser_name). Rows written before compression hold the JSON itself; newer
// rows may hold a gzip stream of it. The two are told apart by the decrypted
// bytes alone: a JSON text never starts with the gzip magic 0x1f 0x8b, so no
// column, AAD or digest input changes and old rows stay readable as they are.
const (
	// MaxParsedResultBytes bounds decompression on read. The fallback
	// conversation comes from a request and a response that the parser decodes
	// up to 64 MiB each (parser.MaxDecodedBodyBytes), so twice that covers what
	// the writer normally produces. Larger results are stored plain, exactly as
	// before, so the bound never makes a written row unreadable.
	MaxParsedResultBytes = 128 << 20
	// Below this size gzip saves little and would allocate a writer for every
	// compact summary row.
	minCompressedParsedResult = 4096
	// gzip header (10) plus trailer (8); anything shorter is not a stream.
	minGzipStream = 18
)

var (
	// ErrParsedResultAAD reports parser names or audit IDs that cannot form an AAD.
	ErrParsedResultAAD = errors.New("auditmodel: parsed result AAD failed")
	// ErrParsedResult is returned for every failure to open a stored parsed
	// result: decryption, a malformed or oversized gzip stream, or a length
	// mismatch. Callers map it to the same integrity error as before.
	ErrParsedResult = errors.New("auditmodel: parsed result integrity check failed")

	gzipMagic = []byte{0x1f, 0x8b}
)

func parsedResultAAD(auditID, parserName string) ([]byte, error) {
	aad, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		return nil, ErrParsedResultAAD
	}
	return aad, nil
}

// SealParsedResult encrypts one parsed result JSON for parsed_json_enc,
// gzip-compressing it first when that makes the stored value smaller. The
// caller keeps ownership of plaintext.
func SealParsedResult(cipher security.Cipher, auditID, parserName string, plaintext []byte) ([]byte, error) {
	aad, err := parsedResultAAD(auditID, parserName)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(plaintext, gzipMagic) {
		// Such a value could not be told apart from a compressed one.
		return nil, errors.New("auditmodel: parsed result is not JSON")
	}
	payload := plaintext
	if len(plaintext) >= minCompressedParsedResult && len(plaintext) <= MaxParsedResultBytes {
		compression, encoded, encodeErr := bodycodec.Encode(plaintext, "application/json")
		// Compression is only an optimization; on failure the plain form is
		// still a valid row.
		if encodeErr == nil {
			defer clear(encoded)
			if compression == bodycodec.CompressionGZIP {
				payload = encoded
			}
		}
	}
	encrypted, err := cipher.Encrypt(aad, payload)
	if err != nil {
		return nil, fmt.Errorf("auditmodel: encrypt parsed result: %w", err)
	}
	return encrypted, nil
}

// OpenParsedResult decrypts parsed_json_enc and returns the JSON it holds,
// whichever form the row was written in. The caller must clear the result.
func OpenParsedResult(cipher security.Cipher, auditID, parserName string, sealed []byte) ([]byte, error) {
	aad, err := parsedResultAAD(auditID, parserName)
	if err != nil {
		return nil, err
	}
	payload, err := cipher.Decrypt(aad, sealed)
	if err != nil {
		return nil, ErrParsedResult
	}
	if !bytes.HasPrefix(payload, gzipMagic) {
		return payload, nil
	}
	defer clear(payload)
	return decodeParsedResultGzip(payload)
}

func decodeParsedResultGzip(payload []byte) ([]byte, error) {
	if len(payload) < minGzipStream {
		return nil, ErrParsedResult
	}
	// ISIZE is the plaintext length mod 2^32. The writer only compresses up to
	// MaxParsedResultBytes, so it is exact for every valid row. It is checked
	// before any allocation; bodycodec.Decode then reads at most size+1 bytes
	// and requires the stream to produce exactly size, so a wrong ISIZE can
	// only cause a rejection, never a larger allocation.
	size := binary.LittleEndian.Uint32(payload[len(payload)-4:])
	if size > MaxParsedResultBytes {
		return nil, ErrParsedResult
	}
	plaintext, err := bodycodec.Decode(payload, bodycodec.CompressionGZIP, int(size))
	if err != nil {
		clear(plaintext)
		return nil, ErrParsedResult
	}
	return plaintext, nil
}
