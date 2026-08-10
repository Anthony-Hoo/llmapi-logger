package query

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// StreamRaw authenticates and decrypts each owning chunk before writing it.
// It never materializes the complete Body in memory.
func (service *Service) StreamRaw(ctx context.Context, auditID string, side Side, destination io.Writer) error {
	if ctx == nil {
		return invalid("nil context")
	}
	if destination == nil {
		return invalid("nil destination")
	}
	if err := validateAuditID(auditID); err != nil {
		return err
	}
	stage, err := stageForSide(side)
	if err != nil {
		return err
	}
	metadata, err := service.store.RawBodyMeta(ctx, auditID, stage)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query: read raw metadata: %w", err)
	}
	if metadata.State == sqlite.StageStateStreaming {
		return ErrNotReady
	}

	digest := sha256.New()
	var written int64
	var expectedSequence int64
	var expectedOffset int64
	complete := metadata.State == sqlite.StageStateComplete && metadata.HashComplete && metadata.EOFSeen && metadata.StoredLength == metadata.ObservedLength
	err = service.store.StreamBodyChunks(ctx, auditID, stage, func(chunk sqlite.BodyChunk) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if chunk.Seq != expectedSequence || chunk.Offset != expectedOffset {
			return ErrIntegrity
		}
		aad, err := security.AAD(auditID, "body_chunk", stage, strconv.FormatInt(chunk.Seq, 10))
		if err != nil {
			return ErrIntegrity
		}
		plaintext, err := service.cipher.Decrypt(aad, chunk.DataEnc)
		if err != nil || len(plaintext) != chunk.PlaintextLength {
			return ErrIntegrity
		}
		if complete {
			_, _ = digest.Write(plaintext)
		}
		count, err := destination.Write(plaintext)
		written += int64(count)
		if err != nil {
			return err
		}
		if count != len(plaintext) {
			return io.ErrShortWrite
		}
		expectedSequence = chunk.Seq + 1
		expectedOffset = chunk.Offset + int64(len(plaintext))
		return nil
	})
	if err != nil {
		return fmt.Errorf("query: stream raw body: %w", err)
	}
	if written != metadata.StoredLength {
		return ErrIntegrity
	}
	if complete {
		if len(metadata.SHA256) != sha256.Size || !equalBytes(digest.Sum(nil), metadata.SHA256) {
			return ErrIntegrity
		}
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
