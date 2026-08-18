package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
)

const (
	credentialFingerprintKeyDomain = "llmapi-logger/credential-fingerprint-key/v1\x00"
	credentialFingerprintDomain    = "llmapi-logger/credential-fingerprint/v1\x00"
)

// CredentialFingerprinter owns a domain-separated HMAC-SHA-256 key derived from
// the audit encryption key. It maps an inbound API credential to a stable tag so
// a developer session can be scoped to the records its own key produced.
//
// The tag is keyed, not a plain digest: without the master key it can neither be
// verified nor reversed, which is what allows storing it while the project
// continues to store no plaintext or masked API key. It is an access-control
// index rather than evidence, so it stays out of the integrity event chain and
// is never returned by any API, log or error message.
type CredentialFingerprinter struct {
	key [sha256.Size]byte
}

func NewCredentialFingerprinter(masterKey []byte) (*CredentialFingerprinter, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("security: fingerprint master key must be exactly %d bytes", KeySize)
	}
	derivation := hmac.New(sha256.New, masterKey)
	_, _ = derivation.Write([]byte(credentialFingerprintKeyDomain))
	derived := derivation.Sum(nil)
	fingerprinter := &CredentialFingerprinter{}
	copy(fingerprinter.key[:], derived)
	clear(derived)
	return fingerprinter, nil
}

// Fingerprint returns the tag of one credential, or nil when the credential is
// absent or normalizes to nothing. A nil tag stores as NULL and matches no
// developer session.
func (fingerprinter *CredentialFingerprinter) Fingerprint(rawCredential string) []byte {
	if fingerprinter == nil {
		return nil
	}
	normalized := NormalizeNewAPIKey(rawCredential)
	if normalized == "" {
		return nil
	}
	// One fixed domain prefix followed by one variable-length field cannot be
	// ambiguous, so no length framing is needed here.
	mac := hmac.New(sha256.New, fingerprinter.key[:])
	_, _ = mac.Write([]byte(credentialFingerprintDomain))
	_, _ = mac.Write([]byte(normalized))
	return mac.Sum(nil)
}

// FingerprintRequest tags whichever credential transport the request used, so
// the same key matches across Authorization, X-Api-Key, X-Goog-Api-Key and the
// Gemini query parameter.
func (fingerprinter *CredentialFingerprinter) FingerprintRequest(header http.Header, query url.Values) []byte {
	if fingerprinter == nil {
		return nil
	}
	return fingerprinter.Fingerprint(ExtractCredential(header, query))
}
