package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const analysisFingerprintKeyDomain = "llmapi-logger/analysis-fingerprint-key/v1\x00"

// AnalysisFingerprinter owns the domain-separated HMAC-SHA-256 subkey used by
// derived context analysis (doc/features/20-context-insights.md). It tags item
// content, system prompts, tool sets, session keys and raw agent IDs so that
// audit_analysis can compare and group them in plaintext without storing them.
//
// The subkey is derived from the audit master key like the credential and
// integrity subkeys, with its own label, so analysis tags can neither be
// verified nor reversed without the master key and never collide with an
// api_key_fpr or an integrity MAC. Like api_key_fpr the tags are an index, not
// evidence, and stay out of the integrity event chain.
type AnalysisFingerprinter struct {
	key [sha256.Size]byte
}

// NewAnalysisFingerprinter derives the analysis subkey from the master key.
func NewAnalysisFingerprinter(masterKey []byte) (*AnalysisFingerprinter, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("security: analysis fingerprint master key must be exactly %d bytes", KeySize)
	}
	derivation := hmac.New(sha256.New, masterKey)
	_, _ = derivation.Write([]byte(analysisFingerprintKeyDomain))
	derived := derivation.Sum(nil)
	fingerprinter := &AnalysisFingerprinter{}
	copy(fingerprinter.key[:], derived)
	clear(derived)
	return fingerprinter, nil
}

// Fingerprint returns HMAC(subkey, domain ‖ 0x00 ‖ value), 32 bytes. Domain
// labels are fixed package constants without NUL bytes, so the separator keeps
// one domain's tags from colliding with another's. A nil fingerprinter returns
// nil.
func (fingerprinter *AnalysisFingerprinter) Fingerprint(domain string, value []byte) []byte {
	if fingerprinter == nil {
		return nil
	}
	mac := hmac.New(sha256.New, fingerprinter.key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
