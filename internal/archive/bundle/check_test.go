package bundle

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
)

// CheckFiles (the check before a removal) passes on an intact bundle and
// returns the SHA-256 of the manifest bytes, and names the reason for a
// missing manifest or data file, a truncated data file, an edited manifest
// and a manifest signed with another key.
func TestCheckFiles(t *testing.T) {
	for name, test := range map[string]struct {
		damage func(t *testing.T, manifest string, data []string)
		other  bool
		reason string
	}{
		"intact": {},
		"manifest missing": {damage: func(t *testing.T, manifest string, _ []string) {
			mustRemove(t, manifest)
		}, reason: ReasonNotFound},
		"objects file missing": {damage: func(t *testing.T, _ string, data []string) {
			mustRemove(t, objectsFile(t, data))
		}, reason: ReasonFileMissing},
		"data file truncated": {damage: func(t *testing.T, _ string, data []string) {
			path := objectsFile(t, data)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, info.Size()-1); err != nil {
				t.Fatal(err)
			}
		}, reason: ReasonFileMismatch},
		"manifest edited": {damage: func(t *testing.T, manifest string, _ []string) {
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			edited := strings.ReplaceAll(string(data), "conv_check", "conv_chekk")
			if edited == string(data) {
				t.Fatal("nothing to edit")
			}
			if err := os.WriteFile(manifest, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
		}, reason: ReasonMACMismatch},
		"another key": {other: true, reason: ReasonKeyMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			root := t.TempDir()
			sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_check", Index: 1},
				f.conversation("conv_check", "c", 0)...)
			manifestPath := sealed.ManifestPath()
			want, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var data []string
			for _, file := range listFiles(t, root) {
				if !strings.HasSuffix(file, ManifestSuffix) {
					data = append(data, filepath.Join(root, filepath.FromSlash(file)))
				}
			}
			if test.damage != nil {
				test.damage(t, manifestPath, data)
			}
			signer := f.keys
			if test.other {
				signer = testKeys(t, 0x43)
			}
			manifest, digest, err := CheckFiles(context.Background(), manifestPath, signer)
			if test.reason != "" {
				wantReason(t, err, test.reason)
				return
			}
			if err != nil || manifest.SegmentID != sealed.Manifest().SegmentID || digest != sha256.Sum256(want) {
				t.Fatalf("intact bundle: %v", err)
			}
		})
	}
	if _, _, err := CheckFiles(context.Background(), filepath.Join(t.TempDir(), "x.manifest.json"), nil); ReasonOf(err) != ReasonKeyRequired {
		t.Fatalf("no signer: %v", err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func objectsFile(t *testing.T, data []string) string {
	t.Helper()
	for _, path := range data {
		if strings.Contains(filepath.Base(path), ".objects.") {
			return path
		}
	}
	t.Fatalf("no objects file in %v", data)
	return ""
}
