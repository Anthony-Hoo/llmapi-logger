package security

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewAESGCMRequiresAES256Key(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := NewAESGCM(make([]byte, size)); err == nil {
			t.Errorf("NewAESGCM() accepted %d-byte key", size)
		}
	}
	if _, err := NewAESGCM(make([]byte, KeySize)); err != nil {
		t.Fatalf("NewAESGCM(32 bytes) error = %v", err)
	}
}

func TestAESGCMRoundTripUsesRandomNonce(t *testing.T) {
	ciphertext := newTestCipher(t)
	aad, err := AAD("audit-1", "body_chunk", "request", "0")
	if err != nil {
		t.Fatalf("AAD() error = %v", err)
	}
	plaintext := []byte("sensitive request body")

	first, err := ciphertext.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}
	second, err := ciphertext.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two encryptions produced the same blob")
	}
	if bytes.Equal(first[:NonceSize], second[:NonceSize]) {
		t.Fatal("two encryptions produced the same nonce")
	}
	if len(first) != NonceSize+len(plaintext)+16 {
		t.Fatalf("blob length = %d, want %d", len(first), NonceSize+len(plaintext)+16)
	}

	for index, blob := range [][]byte{first, second} {
		decrypted, err := ciphertext.Decrypt(aad, blob)
		if err != nil {
			t.Fatalf("Decrypt(blob %d) error = %v", index, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("Decrypt(blob %d) = %q, want %q", index, decrypted, plaintext)
		}
	}
}

func TestAESGCMRejectsTamperingAndWrongAAD(t *testing.T) {
	ciphertext := newTestCipher(t)
	aad := []byte("audit-1\x00header")
	blob, err := ciphertext.Encrypt(aad, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	for name, position := range map[string]int{
		"nonce":      0,
		"ciphertext": NonceSize,
		"tag":        len(blob) - 1,
	} {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), blob...)
			tampered[position] ^= 0x80
			plaintext, err := ciphertext.Decrypt(aad, tampered)
			if err == nil || plaintext != nil {
				t.Fatalf("Decrypt() = %q, %v; want nil, error", plaintext, err)
			}
		})
	}

	plaintext, err := ciphertext.Decrypt([]byte("audit-2\x00header"), blob)
	if err == nil || plaintext != nil {
		t.Fatalf("Decrypt(wrong AAD) = %q, %v; want nil, error", plaintext, err)
	}
	if _, err := ciphertext.Decrypt(aad, blob[:NonceSize+15]); err == nil {
		t.Fatal("Decrypt(short blob) error = nil")
	}
}

func TestAESGCMHandlesEmptyPlaintext(t *testing.T) {
	ciphertext := newTestCipher(t)
	blob, err := ciphertext.Encrypt(nil, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	plaintext, err := ciphertext.Decrypt(nil, blob)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("plaintext length = %d, want 0", len(plaintext))
	}
}

func TestNilAESGCMReturnsErrors(t *testing.T) {
	var ciphertext *AESGCM
	if _, err := ciphertext.Encrypt(nil, nil); err == nil {
		t.Fatal("Encrypt() error = nil")
	}
	if _, err := ciphertext.Decrypt(nil, make([]byte, NonceSize+16)); err == nil {
		t.Fatal("Decrypt() error = nil")
	}
}

func TestAADSeparatesPartsAndRejectsNUL(t *testing.T) {
	aad, err := AAD("audit-1", "header", "request", "authorization", "0")
	if err != nil {
		t.Fatalf("AAD() error = %v", err)
	}
	want := []byte("audit-1\x00header\x00request\x00authorization\x000")
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD() = %q, want %q", aad, want)
	}
	if aad, err := AAD("audit-1", "bad\x00part"); err == nil || aad != nil {
		t.Fatalf("AAD(NUL) = %q, %v; want nil, error", aad, err)
	}
}

func newTestCipher(t *testing.T) *AESGCM {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	ciphertext, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM() error = %v", err)
	}
	return ciphertext
}
