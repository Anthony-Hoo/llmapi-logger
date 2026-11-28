package staging

import (
	"fmt"
	"strconv"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// OpenChunk authenticates and decodes one sealed body chunk, staged or not,
// and returns its plaintext. It is the check the import makes on every staged
// record and the read-back a stage uses when the bytes it borrows from its
// source were staged.
func OpenChunk(cipher security.Cipher, chunk storage.BodyChunk) ([]byte, error) {
	if cipher == nil {
		return nil, fmt.Errorf("staging: nil cipher")
	}
	aad, err := security.AAD(chunk.AuditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), chunk.Compression)
	if err != nil {
		return nil, fmt.Errorf("staging: chunk AAD: %w", err)
	}
	encoded, err := cipher.Decrypt(aad, chunk.DataEnc)
	if err != nil {
		return nil, fmt.Errorf("staging: open chunk %s/%d: %w", chunk.Stage, chunk.Seq, err)
	}
	if len(encoded) != chunk.EncodedLength {
		clear(encoded)
		return nil, fmt.Errorf("staging: chunk %s/%d encoded length %d, recorded %d", chunk.Stage, chunk.Seq, len(encoded), chunk.EncodedLength)
	}
	plaintext, err := bodycodec.Decode(encoded, chunk.Compression, chunk.PlaintextLength)
	clear(encoded)
	if err != nil {
		return nil, fmt.Errorf("staging: decode chunk %s/%d: %w", chunk.Stage, chunk.Seq, err)
	}
	if len(plaintext) != chunk.PlaintextLength {
		return nil, fmt.Errorf("staging: chunk %s/%d plaintext length %d, recorded %d", chunk.Stage, chunk.Seq, len(plaintext), chunk.PlaintextLength)
	}
	return plaintext, nil
}
