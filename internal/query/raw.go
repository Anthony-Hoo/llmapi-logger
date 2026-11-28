package query

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
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
	verifier, err := newRawVerifier(metadata)
	if err != nil {
		return err
	}
	err = service.store.StreamBodyChunks(ctx, auditID, stage, func(chunk storage.BodyChunk) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifier.accept(chunk.Seq, chunk.Offset, chunk.PlaintextLength); err != nil {
			return err
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
		return verifier.write(destination, chunk.Seq, chunk.Offset, plaintext)
	})
	if err != nil {
		return fmt.Errorf("query: stream raw body: %w", err)
	}
	return verifier.finish()
}

// rawVerifier is the part of StreamRaw that needs no decryption: the state
// gate, chunk continuity, the written length and, for a complete body, the
// SHA-256 of what was written.
type rawVerifier struct {
	metadata         storage.RawBodyMetadata
	digest           hash.Hash
	written          int64
	expectedSequence int64
	expectedOffset   int64
	complete         bool
	missingChunks    bool
}

// newRawVerifier refuses a body that is still streaming, pending or not
// retained, before any chunk is read.
func newRawVerifier(metadata storage.RawBodyMetadata) (*rawVerifier, error) {
	if metadata.State == storage.StageStateStreaming {
		return nil, ErrNotReady
	}
	if metadata.RetentionState == storage.RetentionPending {
		return nil, ErrNotReady
	}
	if metadata.RetentionState == storage.RetentionMetadata {
		return nil, ErrNotRetained
	}
	return &rawVerifier{
		metadata:      metadata,
		digest:        sha256.New(),
		complete:      metadata.State == storage.StageStateComplete && metadata.HashComplete && metadata.EOFSeen && metadata.StoredLength == metadata.ObservedLength,
		missingChunks: rawHasMissingChunks(metadata),
	}, nil
}

// accept checks the position of the next chunk before it is opened.
func (verifier *rawVerifier) accept(sequence, offset int64, plaintextLength int) error {
	if sequence != verifier.expectedSequence || offset != verifier.expectedOffset {
		// Only a capture-time, explicitly recorded loss permits a forward
		// gap. Keep original sequence/AAD and offsets; never renumber or
		// fabricate missing bytes. Other gaps still mean corruption.
		if !verifier.missingChunks || sequence <= verifier.expectedSequence || offset < verifier.expectedOffset {
			return ErrIntegrity
		}
	}
	observed := verifier.metadata.ObservedLength
	if verifier.missingChunks && (plaintextLength < 0 || offset > observed || int64(plaintextLength) > observed-offset) {
		return ErrIntegrity
	}
	return nil
}

// write hashes and writes one opened chunk that accept let through.
func (verifier *rawVerifier) write(destination io.Writer, sequence, offset int64, plaintext []byte) error {
	if verifier.complete {
		_, _ = verifier.digest.Write(plaintext)
	}
	count, err := destination.Write(plaintext)
	verifier.written += int64(count)
	if err != nil {
		return err
	}
	if count != len(plaintext) {
		return io.ErrShortWrite
	}
	verifier.expectedSequence = sequence + 1
	verifier.expectedOffset = offset + int64(len(plaintext))
	return nil
}

// finish checks the written length and, for a complete body, its digest.
func (verifier *rawVerifier) finish() error {
	if verifier.written != verifier.metadata.StoredLength {
		return ErrIntegrity
	}
	if verifier.complete {
		if len(verifier.metadata.SHA256) != sha256.Size || !equalBytes(verifier.digest.Sum(nil), verifier.metadata.SHA256) {
			return ErrIntegrity
		}
	}
	return nil
}

func rawHasMissingChunks(metadata storage.RawBodyMetadata) bool {
	return metadata.State == storage.StageStatePartial && metadata.RetentionState == storage.RetentionFull &&
		metadata.ErrorCode != nil && *metadata.ErrorCode == storage.CaptureChunkMissing
}

// selectRawBody prefers the provider-side stage used for ordinary request and
// response evidence. Locally rejected requests and locally generated proxy
// responses never reach that stage, so raw evidence falls back to the matching
// client-facing observation point when the preferred stage does not exist.
func (service *Service) selectRawBody(ctx context.Context, auditID string, side Side) (string, storage.RawBodyMetadata, error) {
	stages, err := rawStagesForSide(side)
	if err != nil {
		return "", storage.RawBodyMetadata{}, err
	}
	for _, stage := range stages {
		metadata, err := service.store.RawBodyMeta(ctx, auditID, stage)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return "", storage.RawBodyMetadata{}, err
		}
		return stage, metadata, nil
	}
	return "", storage.RawBodyMetadata{}, sql.ErrNoRows
}

func rawStagesForSide(side Side) ([]string, error) {
	switch side {
	case SideRequest:
		return []string{storage.StageRequestSent, storage.StageRequestReceived}, nil
	case SideResponse:
		return []string{storage.StageResponseReceived, storage.StageResponseSent}, nil
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
