package security

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestAnalysisFingerprinterRequiresFullMasterKey(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		if _, err := NewAnalysisFingerprinter(make([]byte, size)); err == nil {
			t.Fatalf("NewAnalysisFingerprinter accepted a %d byte key", size)
		}
	}
	if _, err := NewAnalysisFingerprinter(testMasterKey(0x11)); err != nil {
		t.Fatalf("NewAnalysisFingerprinter: %v", err)
	}
}

func TestAnalysisFingerprintMatchesSpecifiedConstruction(t *testing.T) {
	master := testMasterKey(0x11)
	fingerprinter, err := NewAnalysisFingerprinter(master)
	if err != nil {
		t.Fatal(err)
	}
	derivation := hmac.New(sha256.New, master)
	_, _ = derivation.Write([]byte("llmapi-logger/analysis-fingerprint-key/v1\x00"))
	subkey := derivation.Sum(nil)
	mac := hmac.New(sha256.New, subkey)
	_, _ = mac.Write([]byte("insights/item\x00value-example"))
	want := mac.Sum(nil)

	got := fingerprinter.Fingerprint("insights/item", []byte("value-example"))
	if len(got) != sha256.Size || !bytes.Equal(got, want) {
		t.Fatalf("Fingerprint = %x, want %x", got, want)
	}
	if again := fingerprinter.Fingerprint("insights/item", []byte("value-example")); !bytes.Equal(again, got) {
		t.Fatal("Fingerprint is not deterministic")
	}
}

func TestAnalysisFingerprintSeparatesDomainsAndKeys(t *testing.T) {
	first, err := NewAnalysisFingerprinter(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAnalysisFingerprinter(testMasterKey(0x22))
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("value-example")
	if bytes.Equal(first.Fingerprint("insights/item", value), first.Fingerprint("insights/hint", value)) {
		t.Fatal("different domains produced the same fingerprint")
	}
	// The separator keeps "a" + "b\x00c" apart from "a\x00b" + "c".
	if bytes.Equal(first.Fingerprint("insights/a", []byte("b")), first.Fingerprint("insights", []byte("a\x00b"))) {
		t.Fatal("domain and value boundaries are ambiguous")
	}
	if bytes.Equal(first.Fingerprint("insights/item", value), second.Fingerprint("insights/item", value)) {
		t.Fatal("fingerprints must not be portable across audit master keys")
	}

	credential, err := NewCredentialFingerprinter(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewIntegritySigner(testMasterKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.key[:], credential.key[:]) || bytes.Equal(first.key[:], signer.key[:]) {
		t.Fatal("analysis subkey must be domain separated from the credential and integrity subkeys")
	}
}

func TestNilAnalysisFingerprinterYieldsNoTag(t *testing.T) {
	var fingerprinter *AnalysisFingerprinter
	if got := fingerprinter.Fingerprint("insights/item", []byte("value")); got != nil {
		t.Fatalf("Fingerprint on nil fingerprinter = %x, want nil", got)
	}
}
