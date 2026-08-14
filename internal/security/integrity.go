package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	integrityKeyDomain   = "llmapi-logger/integrity-key/v1\x00"
	integrityEventDomain = "llmapi-logger/integrity-event/v1\x00"
)

// IntegritySigner owns a domain-separated HMAC-SHA-256 key derived from the
// audit encryption key. It never exposes the derived key.
type IntegritySigner struct {
	key [sha256.Size]byte
}

func NewIntegritySigner(masterKey []byte) (*IntegritySigner, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("security: integrity master key must be exactly %d bytes", KeySize)
	}
	derivation := hmac.New(sha256.New, masterKey)
	_, _ = derivation.Write([]byte(integrityKeyDomain))
	derived := derivation.Sum(nil)
	signer := &IntegritySigner{}
	copy(signer.key[:], derived)
	clear(derived)
	return signer, nil
}

// MAC authenticates one ordered integrity event. previousMAC is empty only
// for the first event in a database.
func (signer *IntegritySigner) MAC(previousMAC []byte, auditID, eventType string, payloadDigest []byte, createdAtNS int64) ([]byte, error) {
	if signer == nil || auditID == "" || eventType == "" || createdAtNS <= 0 || len(payloadDigest) != sha256.Size ||
		(len(previousMAC) != 0 && len(previousMAC) != sha256.Size) {
		return nil, errors.New("security: invalid integrity event")
	}
	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write([]byte(integrityEventDomain))
	writeIntegrityField(mac, previousMAC)
	writeIntegrityField(mac, []byte(auditID))
	writeIntegrityField(mac, []byte(eventType))
	writeIntegrityField(mac, payloadDigest)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(createdAtNS))
	_, _ = mac.Write(timestamp[:])
	return mac.Sum(nil), nil
}

func (signer *IntegritySigner) Verify(previousMAC []byte, auditID, eventType string, payloadDigest, eventMAC []byte, createdAtNS int64) bool {
	want, err := signer.MAC(previousMAC, auditID, eventType, payloadDigest, createdAtNS)
	if err != nil || len(eventMAC) != sha256.Size {
		return false
	}
	return hmac.Equal(want, eventMAC)
}

type integrityWriter interface {
	Write([]byte) (int, error)
}

func writeIntegrityField(destination integrityWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}
