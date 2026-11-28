package runner

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trialFixture is the archive directory the trial format version 0 wrote
// (internal/archive/testdata/trial/v0, see internal/archivecli/frozen_test.go).
var trialFixture = filepath.Join("..", "testdata", "trial", "v0")

// copyTree copies the regular files under from to the same relative paths
// under to and returns their contents by relative path.
func copyTree(t *testing.T, from, to string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		files[relative] = data
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no files under %s", from)
	}
	return files
}

// Bundles of the trial format version 0 left in the archive directory (a
// deployment that exported before the freeze) are refused by reconciliation
// as unsupported, never registered and never touched: no file is renamed
// .orphan or .rejected, every byte stays, and the warning counts them apart.
// The run itself exports and removes as usual.
func TestTrialFormatBundlesInTheDirectoryAreLeftAlone(t *testing.T) {
	h := newRemovalHarness(t)
	trial := filepath.Join(h.dir, "trial")
	files := copyTree(t, trialFixture, trial)
	h.addConversation("conv-trial", "openai", 2, baseTimeNS)
	result := h.mustRun()
	if result.Counts.ExportedAudits != 2 || result.Removal.Removed != 2 || result.ReconciledSealed != 0 {
		t.Fatalf("run %+v", result)
	}
	for relative, data := range files {
		got, err := os.ReadFile(filepath.Join(trial, relative))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s changed (%v)", relative, err)
		}
	}
	err := filepath.WalkDir(trial, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			relative, _ := filepath.Rel(trial, path)
			if _, ok := files[relative]; !ok {
				t.Errorf("new file %s", relative)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, segment := range h.store.segments {
		if segment.FormatVersion != 1 {
			t.Fatalf("segment %+v registered", segment)
		}
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `"error_category":"archive_manifest_unusable","manifests":3,"unsupported_format_version":3`) {
		t.Fatalf("logs %s", logs)
	}
}
