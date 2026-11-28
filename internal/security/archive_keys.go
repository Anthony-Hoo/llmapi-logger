package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const (
	archiveEncryptionKeyDomain            = "llmapi-logger/archive-encryption-key/v1\x00"
	archiveSigningKeyDomain               = "llmapi-logger/archive-signing-key/v1\x00"
	archiveCredentialFingerprintKeyDomain = "llmapi-logger/archive-credential-fingerprint-key/v1\x00"
	archiveKeyFingerprintDomain           = "llmapi-logger/archive-key-fingerprint/v1\x00"
	archiveCredentialValueDomain          = "llmapi-logger/archive-credential-value/v1\x00"
)

// ArchiveKeys owns the three cold-archive subkeys derived from the audit master
// key (doc/design/issue-59-stage4-cold-archive.md F.3): the bundle encryption
// key, the manifest signing key and the credential fingerprint key. Like
// IntegritySigner it holds only derived material and never the master key.
//
// Every subkey is HMAC-SHA-256(master, domain) with a domain distinct from
// each other and from the integrity, credential fingerprint and analysis
// fingerprint subkeys, so all six keys are independent.
type ArchiveKeys struct {
	encryption  [sha256.Size]byte
	signing     [sha256.Size]byte
	fingerprint [sha256.Size]byte
}

// DeriveArchiveKeys derives the archive subkeys. The master key must be
// exactly KeySize bytes, as for the package's other subkey constructors.
func DeriveArchiveKeys(master []byte) (*ArchiveKeys, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("security: archive master key must be exactly %d bytes", KeySize)
	}
	keys := &ArchiveKeys{}
	deriveArchiveSubkey(&keys.encryption, master, archiveEncryptionKeyDomain)
	deriveArchiveSubkey(&keys.signing, master, archiveSigningKeyDomain)
	deriveArchiveSubkey(&keys.fingerprint, master, archiveCredentialFingerprintKeyDomain)
	return keys, nil
}

func deriveArchiveSubkey(destination *[sha256.Size]byte, master []byte, domain string) {
	derivation := hmac.New(sha256.New, master)
	_, _ = derivation.Write([]byte(domain))
	derived := derivation.Sum(nil)
	copy(destination[:], derived)
	clear(derived)
}

// EncryptionKey returns a fresh copy of K_enc for the bundle stream cipher.
// The caller owns the copy and should clear it when done.
func (keys *ArchiveKeys) EncryptionKey() []byte {
	key := make([]byte, sha256.Size)
	copy(key, keys.encryption[:])
	return key
}

// SignManifest returns HMAC-SHA-256(K_sign, message). It MACs exactly the
// bytes given: the caller supplies the manifest domain string followed by the
// canonical manifest encoding (F.2). Keeping the domain with the encoder
// keeps the format version in one place.
func (keys *ArchiveKeys) SignManifest(message []byte) [32]byte {
	mac := hmac.New(sha256.New, keys.signing[:])
	_, _ = mac.Write(message)
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}

// VerifyManifest reports in constant time whether mac is SignManifest(message).
func (keys *ArchiveKeys) VerifyManifest(message []byte, mac []byte) bool {
	if len(mac) != sha256.Size {
		return false
	}
	want := keys.SignManifest(message)
	return hmac.Equal(want[:], mac)
}

// KeyFingerprint returns HMAC-SHA-256(K_sign, key-fingerprint domain). A
// manifest records it so a reader can report a key mismatch before trying to
// verify or decrypt anything.
func (keys *ArchiveKeys) KeyFingerprint() [32]byte {
	mac := hmac.New(sha256.New, keys.signing[:])
	_, _ = mac.Write([]byte(archiveKeyFingerprintDomain))
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}

// CredentialFingerprint returns the value_fpr of one omitted credential value
// (D.4): HMAC-SHA-256(K_fpr, domain || value) over the raw value bytes, with no
// name and no normalization. An empty value is fingerprinted like any other.
// One fixed domain prefix followed by one variable-length field cannot be
// ambiguous, so no length framing is needed.
func (keys *ArchiveKeys) CredentialFingerprint(value []byte) [32]byte {
	mac := hmac.New(sha256.New, keys.fingerprint[:])
	_, _ = mac.Write([]byte(archiveCredentialValueDomain))
	_, _ = mac.Write(value)
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}
