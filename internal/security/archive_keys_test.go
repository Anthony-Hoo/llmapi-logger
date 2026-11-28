package security

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// archiveTestMaster is a synthetic master key (bytes 0x00 to 0x1f) used only
// for these vectors. The expected values below were computed outside Go with
// .NET's HMACSHA256, so the test does not certify the implementation against
// its own output.
func archiveTestMaster() []byte {
	master := make([]byte, KeySize)
	for i := range master {
		master[i] = byte(i)
	}
	return master
}

const (
	archiveVectorEncryptionKey  = "0df110b3a61eae3ba2d519007b27236673a8449386f6cf47bbae4fbcd9ba18cd"
	archiveVectorSigningKey     = "4fbeecfe16f46d811839e4394d762f4505c6acd9f9fec4e45649141c2c156631"
	archiveVectorFingerprintKey = "6c9486caf63a70955a3e520fdf08d2c0eb4766c2aaac8c1a4289d6fd7e1f0c89"
	archiveVectorKeyFingerprint = "0c8bba6a5885ad44085662606f3b0e132dac071a100904c1b0537491dd611b33"
	// HMAC(K_sign, "llmapi-logger/archive-manifest/v1\x00example manifest encoding")
	archiveVectorManifestMAC = "b00d3d340bd58abba1cd8046521627b928bb344df53b01478567de11affab267"
	// HMAC(K_fpr, "llmapi-logger/archive-credential-value/v1\x00Bearer sk-example-0000")
	archiveVectorCredentialFingerprint = "b4023273ef3cc1ec165ef09947eff805059db3d3b87435ded5dcdcf738886d66"
	// HMAC(K_fpr, "llmapi-logger/archive-credential-value/v1\x00")
	archiveVectorEmptyCredentialFingerprint = "75fb9946699dbc6b6e9ddf513bb6b77484be974af0b05a81e32bba25b9fb1f03"

	// The existing subkeys under the same master key.
	archiveVectorIntegrityKey   = "31cce945dc61e09ff92d9a2a5d9e58f8d8c28467db0896153e4b45f18365b46b"
	archiveVectorCredentialKey  = "3501d605da5fe1bec2ab6514aa20d4e4875318a3e19999c41385792eb3f464dd"
	archiveVectorAnalysisKey    = "5c976886f152932e3bd4804fed50ba78726c4125f13779b6b914285b262efdeb"
	archiveVectorManifestPrefix = "llmapi-logger/archive-manifest/v1\x00"
)

func mustDeriveArchiveKeys(t *testing.T, master []byte) *ArchiveKeys {
	t.Helper()
	keys, err := DeriveArchiveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestArchiveKeysFixedVectors(t *testing.T) {
	t.Parallel()
	keys := mustDeriveArchiveKeys(t, archiveTestMaster())
	fingerprint := keys.KeyFingerprint()
	manifestMAC := keys.SignManifest([]byte(archiveVectorManifestPrefix + "example manifest encoding"))
	credential := keys.CredentialFingerprint([]byte("Bearer sk-example-0000"))
	empty := keys.CredentialFingerprint(nil)
	for _, check := range []struct {
		name string
		got  []byte
		want string
	}{
		{"K_enc", keys.EncryptionKey(), archiveVectorEncryptionKey},
		{"K_sign", keys.signing[:], archiveVectorSigningKey},
		{"K_fpr", keys.fingerprint[:], archiveVectorFingerprintKey},
		{"key fingerprint", fingerprint[:], archiveVectorKeyFingerprint},
		{"manifest MAC", manifestMAC[:], archiveVectorManifestMAC},
		{"credential fingerprint", credential[:], archiveVectorCredentialFingerprint},
		{"empty credential fingerprint", empty[:], archiveVectorEmptyCredentialFingerprint},
	} {
		if got := hex.EncodeToString(check.got); got != check.want {
			t.Errorf("%s = %s, want %s", check.name, got, check.want)
		}
	}
}

func TestArchiveKeysIndependentOfExistingSubkeys(t *testing.T) {
	t.Parallel()
	master := archiveTestMaster()
	keys := mustDeriveArchiveKeys(t, master)
	integrity, err := NewIntegritySigner(master)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredentialFingerprinter(master)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := NewAnalysisFingerprinter(master)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := keys.KeyFingerprint()
	all := map[string][]byte{
		"master":          master,
		"K_enc":           keys.EncryptionKey(),
		"K_sign":          keys.signing[:],
		"K_fpr":           keys.fingerprint[:],
		"key fingerprint": fingerprint[:],
		"integrity":       integrity.key[:],
		"credential":      credential.key[:],
		"analysis":        analysis.key[:],
	}
	for name, want := range map[string]string{
		"integrity":  archiveVectorIntegrityKey,
		"credential": archiveVectorCredentialKey,
		"analysis":   archiveVectorAnalysisKey,
	} {
		if got := hex.EncodeToString(all[name]); got != want {
			t.Errorf("%s subkey = %s, want %s", name, got, want)
		}
	}
	seen := map[string]string{}
	for name, value := range all {
		if other, ok := seen[string(value)]; ok {
			t.Errorf("%s equals %s", name, other)
		}
		seen[string(value)] = name
	}
}

func TestArchiveKeysDependOnMaster(t *testing.T) {
	t.Parallel()
	first := mustDeriveArchiveKeys(t, archiveTestMaster())
	other := archiveTestMaster()
	other[KeySize-1] ^= 0x01
	second := mustDeriveArchiveKeys(t, other)
	message := []byte(archiveVectorManifestPrefix + "example manifest encoding")
	value := []byte("sk-example")
	firstMAC, secondMAC := first.SignManifest(message), second.SignManifest(message)
	firstFpr, secondFpr := first.KeyFingerprint(), second.KeyFingerprint()
	firstCred, secondCred := first.CredentialFingerprint(value), second.CredentialFingerprint(value)
	if bytes.Equal(first.EncryptionKey(), second.EncryptionKey()) || first.signing == second.signing ||
		first.fingerprint == second.fingerprint || firstMAC == secondMAC || firstFpr == secondFpr ||
		firstCred == secondCred {
		t.Fatal("a different master key produced an equal archive output")
	}
	if second.VerifyManifest(message, firstMAC[:]) {
		t.Fatal("manifest MAC verified under another master key")
	}
}

func TestArchiveKeysManifestVerification(t *testing.T) {
	t.Parallel()
	keys := mustDeriveArchiveKeys(t, archiveTestMaster())
	message := []byte(archiveVectorManifestPrefix + "example manifest encoding")
	mac := keys.SignManifest(message)
	if !keys.VerifyManifest(message, mac[:]) {
		t.Fatal("valid manifest MAC did not verify")
	}
	tampered := append([]byte(nil), message...)
	tampered[len(tampered)-1] ^= 0x01
	flipped := mac
	flipped[0] ^= 0x80
	if keys.VerifyManifest(tampered, mac[:]) || keys.VerifyManifest(message, flipped[:]) ||
		keys.VerifyManifest(message, mac[:31]) || keys.VerifyManifest(message, nil) ||
		keys.VerifyManifest(message, append(mac[:], 0)) {
		t.Fatal("tampered manifest or MAC verified")
	}
}

func TestArchiveKeysEncryptionKeyIsACopy(t *testing.T) {
	t.Parallel()
	keys := mustDeriveArchiveKeys(t, archiveTestMaster())
	key := keys.EncryptionKey()
	clear(key)
	if hex.EncodeToString(keys.EncryptionKey()) != archiveVectorEncryptionKey {
		t.Fatal("clearing a returned key changed the held key")
	}
}

func TestDeriveArchiveKeysRejectsWrongLengthMaster(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 1, KeySize - 1, KeySize + 1, 64} {
		if keys, err := DeriveArchiveKeys(make([]byte, length)); err == nil || keys != nil {
			t.Errorf("length %d: got keys %v, err %v", length, keys, err)
		}
	}
}
