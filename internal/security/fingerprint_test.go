package security

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/url"
	"testing"
)

func testMasterKey(fill byte) []byte {
	key := make([]byte, KeySize)
	for index := range key {
		key[index] = fill
	}
	return key
}

func TestCredentialFingerprinterRequiresFullMasterKey(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		if _, err := NewCredentialFingerprinter(make([]byte, size)); err == nil {
			t.Fatalf("NewCredentialFingerprinter accepted a %d byte key", size)
		}
	}
	if _, err := NewCredentialFingerprinter(testMasterKey(0x11)); err != nil {
		t.Fatalf("NewCredentialFingerprinter: %v", err)
	}
}

func TestFingerprintIsDeterministicAndNormalizes(t *testing.T) {
	fingerprinter, err := NewCredentialFingerprinter(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}

	want := fingerprinter.Fingerprint("sk-abc123")
	if len(want) != sha256.Size {
		t.Fatalf("fingerprint length = %d, want %d", len(want), sha256.Size)
	}
	// Every spelling NewAPI resolves to the same token must share one tag, or a
	// developer would fail to see records their own key produced.
	for _, raw := range []string{"sk-abc123", "sk-abc123-channelsuffix", "Bearer sk-abc123", "abc123"} {
		if got := fingerprinter.Fingerprint(raw); !bytes.Equal(got, want) {
			t.Fatalf("Fingerprint(%q) differs from the canonical tag", raw)
		}
	}

	if got := fingerprinter.Fingerprint("sk-other"); bytes.Equal(got, want) {
		t.Fatal("distinct keys produced the same fingerprint")
	}
	for _, raw := range []string{"", "   ", "sk-"} {
		if got := fingerprinter.Fingerprint(raw); got != nil {
			t.Fatalf("Fingerprint(%q) = %x, want nil", raw, got)
		}
	}
}

func TestFingerprintIsSeparatedByMasterKey(t *testing.T) {
	first, err := NewCredentialFingerprinter(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCredentialFingerprinter(testMasterKey(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Fingerprint("sk-abc123"), second.Fingerprint("sk-abc123")) {
		t.Fatal("fingerprints must not be portable across audit master keys")
	}

	// A different domain string must also keep the fingerprint key independent
	// from the integrity signer derived from the same master key.
	signer, err := NewIntegritySigner(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.key[:], signer.key[:]) {
		t.Fatal("fingerprint and integrity subkeys must be domain separated")
	}
}

func TestFingerprintRequestCoversEveryTransport(t *testing.T) {
	fingerprinter, err := NewCredentialFingerprinter(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	want := fingerprinter.Fingerprint("sk-abc123")

	transports := []struct {
		name   string
		header http.Header
		query  url.Values
	}{
		{name: "authorization", header: http.Header{"Authorization": []string{"Bearer sk-abc123"}}},
		{name: "anthropic", header: http.Header{"X-Api-Key": []string{"sk-abc123"}}},
		{name: "gemini header", header: http.Header{"X-Goog-Api-Key": []string{"sk-abc123"}}},
		{name: "gemini query", query: url.Values{"key": []string{"sk-abc123"}}},
	}
	for _, transport := range transports {
		t.Run(transport.name, func(t *testing.T) {
			if got := fingerprinter.FingerprintRequest(transport.header, transport.query); !bytes.Equal(got, want) {
				t.Fatal("transport produced a different fingerprint for the same key")
			}
		})
	}

	if got := fingerprinter.FingerprintRequest(http.Header{}, url.Values{}); got != nil {
		t.Fatalf("FingerprintRequest without a credential = %x, want nil", got)
	}
}

func TestNilFingerprinterYieldsNoTag(t *testing.T) {
	// A nil fingerprinter is the disabled state, and must stay allocation free
	// and panic free on the capture path.
	var fingerprinter *CredentialFingerprinter
	if got := fingerprinter.Fingerprint("sk-abc123"); got != nil {
		t.Fatalf("Fingerprint on nil fingerprinter = %x, want nil", got)
	}
	if got := fingerprinter.FingerprintRequest(http.Header{"Authorization": []string{"Bearer sk-abc123"}}, nil); got != nil {
		t.Fatalf("FingerprintRequest on nil fingerprinter = %x, want nil", got)
	}
}
