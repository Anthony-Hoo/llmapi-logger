package security

import (
	"bytes"
	"testing"
)

func TestIntegritySignerUsesOrderedDomainSeparatedMAC(t *testing.T) {
	t.Parallel()
	signer, err := NewIntegritySigner(bytes.Repeat([]byte{0x42}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x11}, 32)
	first, err := signer.MAC(nil, "audit-one", "capture_finalized", payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.MAC(first, "audit-one", "semantic_compacted", payload, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Verify(nil, "audit-one", "capture_finalized", payload, first, 1) ||
		!signer.Verify(first, "audit-one", "semantic_compacted", payload, second, 2) {
		t.Fatal("valid integrity event did not verify")
	}
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 0xff
	if signer.Verify(first, "audit-one", "semantic_compacted", tampered, second, 2) ||
		signer.Verify(nil, "audit-one", "semantic_compacted", payload, second, 2) {
		t.Fatal("tampered or reordered integrity event verified")
	}
}
