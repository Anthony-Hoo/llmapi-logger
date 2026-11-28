package security_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/security"
)

// The manifest MAC vector's prefix is the real manifest domain of archive
// format version 1, not a sample: internal/archive puts exactly that prefix
// in front of the canonical manifest encoding, and the archive signing key
// derived from the test master signs the real version 1 vector manifest to
// the value computed outside Go.
func TestArchiveManifestVectorUsesTheRealDomain(t *testing.T) {
	t.Parallel()
	testdata := filepath.Join("..", "archive", "testdata")
	data, err := os.ReadFile(filepath.Join(testdata, "manifest_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := archive.DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	encodingHex, err := os.ReadFile(filepath.Join(testdata, "manifest_v1.encoding.hex"))
	if err != nil {
		t.Fatal(err)
	}
	encoding, err := hex.DecodeString(string(bytes.TrimSpace(encodingHex)))
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte(security.ArchiveVectorManifestPrefix)
	input := archive.ManifestMACInput(manifest)
	if !bytes.HasPrefix(input, prefix) || !bytes.Equal(input[len(prefix):], encoding) || !bytes.Equal(encoding, archive.ManifestEncoding(manifest)) {
		t.Fatalf("the MAC input of the version 1 vector manifest is not %q followed by its encoding", prefix)
	}
	keys, err := security.DeriveArchiveKeys(security.ArchiveTestMaster())
	if err != nil {
		t.Fatal(err)
	}
	if mac := keys.SignManifest(input); hex.EncodeToString(mac[:]) != security.ArchiveVectorRealManifestMAC {
		t.Fatalf("MAC of the vector manifest = %x, want %s", mac, security.ArchiveVectorRealManifestMAC)
	}
	// Sign uses the same prefix: re-signed under these keys, the manifest's
	// MAC is HMAC(K_sign, prefix || its new encoding).
	if err := manifest.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if want := keys.SignManifest(append(bytes.Clone(prefix), archive.ManifestEncoding(manifest)...)); manifest.MAC != want || manifest.Verify(keys) != nil {
		t.Fatal("Sign does not MAC the manifest domain followed by the encoding")
	}
}
