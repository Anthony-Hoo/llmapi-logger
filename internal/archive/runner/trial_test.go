package runner

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
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

// A run at the trial version 0 stopped after publishing a segment, before
// sealing it, leaves a version 0 segment publishing; its manifest is
// relabelled version 0, as the trial writer wrote it. The first run at the
// built-in version cannot verify it (the reader refuses version 0), so
// reconciliation treats it as a bundle that does not verify: the manifest is
// renamed .rejected, its data files .orphan, the intent rows are dropped.
// Nothing is deleted, and the audits are exported again at version 1 and
// removed by virtue of those members.
func TestTrialFormatSegmentLeftPublishingIsRejected(t *testing.T) {
	h := newRemovalHarness(t)
	h.options.FormatVersionOverride = int64Pointer(0)
	conversation := h.addConversation("conv_publishing", protocolChat, 3, baseTimeNS)
	h.options.Step = func(name string) error {
		if name == StepAfterPublish {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := h.run(); !errors.Is(err, errCrash) {
		t.Fatalf("run error %v", err)
	}
	publishing := 0
	for _, segment := range h.store.segments {
		if segment.State == storage.ArchiveSegmentPublishing && segment.FormatVersion == 0 {
			publishing++
		}
	}
	if publishing != 1 {
		t.Fatalf("%d version 0 segments publishing", publishing)
	}
	before := h.files()
	relabelled := 0
	for _, file := range before {
		if !strings.HasSuffix(file, bundle.ManifestSuffix) {
			continue
		}
		path := filepath.Join(h.dir, filepath.FromSlash(file))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.Replace(data, []byte(`"format_version": "1"`), []byte(`"format_version": "0"`), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		relabelled++
	}
	if relabelled != 1 {
		t.Fatalf("%d manifests in %q", relabelled, before)
	}

	h.options.Step, h.options.FormatVersionOverride = nil, nil
	result := h.mustRun()
	if result.ReconciledSealed != 0 || result.Counts.ExportedAudits != int64(len(conversation)) || result.Removal.Removed != int64(len(conversation)) {
		t.Fatalf("run %+v", result)
	}
	after := h.files()
	rejected, orphaned := 0, 0
	for _, file := range after {
		switch {
		case strings.HasSuffix(file, bundle.ManifestSuffix+bundle.RejectedSuffix):
			rejected++
		case strings.HasSuffix(file, bundle.OrphanSuffix):
			orphaned++
		}
	}
	if rejected != 1 || orphaned != len(before)-1 {
		t.Fatalf("%d rejected, %d orphaned of %q; now %q", rejected, orphaned, before, after)
	}
	for _, segment := range h.store.segments {
		if segment.FormatVersion == 0 {
			t.Fatalf("version 0 segment %+v kept", segment)
		}
	}
}
