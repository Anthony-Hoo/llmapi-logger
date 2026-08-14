package query

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"

	"llmapi-logger/internal/bodycodec"
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
	stage, metadata, err := service.selectRawBody(ctx, auditID, side)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query: read raw metadata: %w", err)
	}
	if metadata.State == sqlite.StageStateStreaming {
		return ErrNotReady
	}
	if metadata.RetentionState == sqlite.RetentionPending {
		return ErrNotReady
	}
	if metadata.RetentionState == sqlite.RetentionMetadata {
		return ErrNotRetained
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
		compression := chunk.Compression
		if compression == "" {
			compression = bodycodec.CompressionNone
		}
		aad, err := security.AAD(auditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), compression)
		if err != nil {
			return ErrIntegrity
		}
		encoded, err := service.cipher.Decrypt(aad, chunk.DataEnc)
		if err != nil && compression == bodycodec.CompressionNone {
			legacyAAD, legacyErr := security.AAD(auditID, "body_chunk", chunk.Stage, strconv.FormatInt(chunk.Seq, 10))
			if legacyErr == nil {
				encoded, err = service.cipher.Decrypt(legacyAAD, chunk.DataEnc)
			}
		}
		if err != nil || chunk.EncodedLength > 0 && len(encoded) != chunk.EncodedLength {
			clear(encoded)
			return ErrIntegrity
		}
		plaintext, decodeErr := bodycodec.Decode(encoded, compression, chunk.PlaintextLength)
		clear(encoded)
		if decodeErr != nil {
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

// selectRawBody prefers the provider-side stage used for ordinary request and
// response evidence. Locally rejected requests and locally generated proxy
// responses never reach that stage, so raw evidence falls back to the matching
// client-facing observation point when the preferred stage does not exist.
func (service *Service) selectRawBody(ctx context.Context, auditID string, side Side) (string, sqlite.RawBodyMetadata, error) {
	stages, err := rawStagesForSide(side)
	if err != nil {
		return "", sqlite.RawBodyMetadata{}, err
	}
	for _, stage := range stages {
		metadata, err := service.store.RawBodyMeta(ctx, auditID, stage)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return "", sqlite.RawBodyMetadata{}, err
		}
		return stage, metadata, nil
	}
	return "", sqlite.RawBodyMetadata{}, sql.ErrNoRows
}

func rawStagesForSide(side Side) ([]string, error) {
	switch side {
	case SideRequest:
		return []string{sqlite.StageRequestSent, sqlite.StageRequestReceived}, nil
	case SideResponse:
		return []string{sqlite.StageResponseReceived, sqlite.StageResponseSent}, nil
	default:
		return nil, ErrInvalidQuery
	}
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
