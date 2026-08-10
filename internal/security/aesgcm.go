package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const NonceSize = 12

// Cipher is the minimal authenticated-encryption surface used by storage.
type Cipher interface {
	Encrypt(aad, plaintext []byte) ([]byte, error)
	Decrypt(aad, blob []byte) ([]byte, error)
}

// AESGCM encrypts each value independently using AES-256-GCM. The value is
// immutable after construction and safe for concurrent use.
type AESGCM struct {
	aead cipher.AEAD
}

// NewAESGCM constructs an AES-256-GCM cipher from one raw 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("security: AES-256 key must be exactly %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: create GCM cipher: %w", err)
	}
	if aead.NonceSize() != NonceSize {
		return nil, fmt.Errorf("security: unexpected GCM nonce size %d", aead.NonceSize())
	}
	return &AESGCM{aead: aead}, nil
}

// Encrypt returns nonce[12] || ciphertext || authentication-tag. A fresh
// cryptographically random nonce is generated for every call.
func (ciphertext *AESGCM) Encrypt(aad, plaintext []byte) ([]byte, error) {
	if ciphertext == nil || ciphertext.aead == nil {
		return nil, errors.New("security: nil AES-GCM cipher")
	}

	blob := make([]byte, NonceSize, NonceSize+len(plaintext)+ciphertext.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, blob); err != nil {
		return nil, fmt.Errorf("security: generate GCM nonce: %w", err)
	}
	nonce := blob[:NonceSize]
	blob = ciphertext.aead.Seal(blob, nonce, plaintext, aad)
	return blob, nil
}

// Decrypt authenticates and opens a nonce-prefixed blob. Authentication
// failure never returns partial plaintext.
func (ciphertext *AESGCM) Decrypt(aad, blob []byte) ([]byte, error) {
	if ciphertext == nil || ciphertext.aead == nil {
		return nil, errors.New("security: nil AES-GCM cipher")
	}
	minimumSize := NonceSize + ciphertext.aead.Overhead()
	if len(blob) < minimumSize {
		return nil, fmt.Errorf("security: encrypted blob is too short: got %d bytes, need at least %d", len(blob), minimumSize)
	}

	nonce := blob[:NonceSize]
	plaintext, err := ciphertext.aead.Open(nil, nonce, blob[NonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("security: decrypt authentication failed: %w", err)
	}
	return plaintext, nil
}

// AAD encodes controlled fields with a NUL separator. Rejecting NUL in each
// field makes the encoding unambiguous for a fixed field sequence.
func AAD(parts ...string) ([]byte, error) {
	for index, part := range parts {
		if strings.ContainsRune(part, '\x00') {
			return nil, fmt.Errorf("security: AAD part %d contains NUL", index)
		}
	}
	return []byte(strings.Join(parts, "\x00")), nil
}
