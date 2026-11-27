package headerblock

import (
	"errors"
	"fmt"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const blockAADPurpose = "header_block_v1"

// BlockAAD is the associated data of a sealed block:
// security.AAD(auditID, "header_block_v1", compression).
func BlockAAD(auditID, compression string) ([]byte, error) {
	if auditID == "" {
		return nil, errors.New("headerblock: empty audit id")
	}
	return security.AAD(auditID, blockAADPurpose, compression)
}

// Seal compresses a block plaintext through bodycodec and encrypts it with
// AES-GCM. The three results are the stored columns compression,
// plaintext_length and block_enc.
func Seal(c security.Cipher, auditID string, plaintext []byte) (compression string, length int64, enc []byte, err error) {
	if c == nil {
		return "", 0, nil, errors.New("headerblock: nil cipher")
	}
	if len(plaintext) > MaxPlaintextLength {
		return "", 0, nil, errors.New("headerblock: block exceeds the plaintext limit")
	}
	compression, encoded, err := bodycodec.Encode(plaintext, ContentType)
	if err != nil {
		return "", 0, nil, fmt.Errorf("headerblock: compress block: %w", err)
	}
	defer clear(encoded)
	aad, err := BlockAAD(auditID, compression)
	if err != nil {
		return "", 0, nil, err
	}
	enc, err = c.Encrypt(aad, encoded)
	if err != nil {
		return "", 0, nil, fmt.Errorf("headerblock: encrypt block: %w", err)
	}
	return compression, int64(len(plaintext)), enc, nil
}

// Open authenticates and decrypts a stored block, decompresses it and checks
// its length. It returns the plaintext, which Decode parses; the caller
// clears it when done.
func Open(c security.Cipher, auditID, compression string, length int64, enc []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("headerblock: nil cipher")
	}
	if compression != bodycodec.CompressionNone && compression != bodycodec.CompressionGZIP {
		return nil, fmt.Errorf("%w: unknown block compression", ErrIntegrity)
	}
	if length < 0 || length > MaxPlaintextLength {
		return nil, fmt.Errorf("%w: invalid block length", ErrIntegrity)
	}
	aad, err := BlockAAD(auditID, compression)
	if err != nil {
		return nil, err
	}
	encoded, err := c.Decrypt(aad, enc)
	if err != nil {
		return nil, fmt.Errorf("%w: block does not authenticate", ErrIntegrity)
	}
	defer clear(encoded)
	plaintext, err := bodycodec.Decode(encoded, compression, int(length))
	if err != nil {
		return nil, fmt.Errorf("%w: block length or compression mismatch", ErrIntegrity)
	}
	return plaintext, nil
}

// SealBlock encodes and seals the given stages into the stored triple.
func SealBlock(c security.Cipher, auditID string, stages []Stage) (storage.HeaderBlock, error) {
	plaintext, err := Encode(stages)
	if err != nil {
		return storage.HeaderBlock{}, err
	}
	defer clear(plaintext)
	compression, length, enc, err := Seal(c, auditID, plaintext)
	if err != nil {
		return storage.HeaderBlock{}, err
	}
	return storage.HeaderBlock{Compression: compression, PlaintextLength: length, DataEnc: enc}, nil
}

// OpenBlock opens and strictly decodes a stored block.
func OpenBlock(c security.Cipher, auditID string, block storage.HeaderBlockEvidence) ([]Stage, error) {
	plaintext, err := Open(c, auditID, block.Compression, block.PlaintextLength, block.DataEnc)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return Decode(plaintext)
}
