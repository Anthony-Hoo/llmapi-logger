package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

// segmentOf finds the sealed segment of one conversation bundle, its
// manifest path and its data files.
func (h *harness) segmentOf(conversationID string) (storage.ArchiveSegment, string, []string) {
	h.t.Helper()
	for _, entry := range h.bundles() {
		for _, id := range entry.Manifest.Conversations {
			if id != conversationID || entry.Manifest.BundleKind != archive.BundleConversation {
				continue
			}
			segment := *h.store.segments[entry.Manifest.SegmentID]
			var data []string
			for _, file := range entry.Manifest.Files {
				data = append(data, filepath.Join(filepath.Dir(entry.ManifestPath), file.Name))
			}
			return segment, entry.ManifestPath, data
		}
	}
	h.t.Fatalf("no bundle of %s", conversationID)
	return storage.ArchiveSegment{}, "", nil
}

// Option B of R.9: before its first removal batch each segment's bundle is
// checked once per run. A bundle that is gone, a truncated data file, an
// edited manifest and a manifest other than the one the catalog sealed each
// hold back exactly that segment's members, which stay sealed and in the hot
// store, while the other segments are removed; the run completes and its
// result and log say so with a stable code. The next run, with the bundle
// restored, removes them.
func TestBundleCheckHoldsBackOneSegment(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
		damage func(t *testing.T, h *harness, segment storage.ArchiveSegment, manifest string, data []string) (restore func())
	}{
		{"bundle missing", bundle.ReasonNotFound, func(t *testing.T, h *harness, _ storage.ArchiveSegment, manifest string, data []string) func() {
			aside := t.TempDir()
			files := append(append([]string{}, data...), manifest)
			for _, path := range files {
				if err := os.Rename(path, filepath.Join(aside, filepath.Base(path))); err != nil {
					t.Fatal(err)
				}
			}
			return func() {
				for _, path := range files {
					if err := os.Rename(filepath.Join(aside, filepath.Base(path)), path); err != nil {
						t.Fatal(err)
					}
				}
			}
		}},
		{"data file truncated", bundle.ReasonFileMismatch, func(t *testing.T, h *harness, _ storage.ArchiveSegment, _ string, data []string) func() {
			original, err := os.ReadFile(data[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(data[0], original[:len(original)-1], 0o600); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.WriteFile(data[0], original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"manifest edited", bundle.ReasonMACMismatch, func(t *testing.T, h *harness, _ storage.ArchiveSegment, manifest string, data []string) func() {
			original, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			edited := bytes.ReplaceAll(original, []byte("conv-held"), []byte("conv-hold"))
			if bytes.Equal(edited, original) {
				t.Fatal("nothing to edit")
			}
			if err := os.WriteFile(manifest, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.WriteFile(manifest, original, 0o600); err != nil {
					t.Fatal(err)
				}
				unorphan(t, data)
			}
		}},
		{"manifest differs from the catalog", ReasonManifestDigestMismatch, func(t *testing.T, h *harness, segment storage.ArchiveSegment, _ string, _ []string) func() {
			h.store.mu.Lock()
			stored := h.store.segments[segment.SegmentID]
			original := stored.ManifestSHA256
			stored.ManifestSHA256 = bytes.Repeat([]byte{0x01}, 32)
			h.store.mu.Unlock()
			return func() {
				h.store.mu.Lock()
				stored.ManifestSHA256 = original
				h.store.mu.Unlock()
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRemovalHarness(t)
			h.options.Mode = storage.ArchiveModeExportOnly
			held := h.addConversation("conv-held", "openai", 3, baseTimeNS)
			others := h.addConversation("conv-other", "openai", 3, baseTimeNS+int64(60e9))
			h.addTurnless("turnless-1", "openai", baseTimeNS+5)
			h.mustRun()
			segment, manifest, data := h.segmentOf("conv-held")
			restore := test.damage(t, h, segment, manifest, data)

			h.options.Mode = storage.ArchiveModeArchiveThenDelete
			h.store.segmentLookups = nil
			runner := h.runner()
			oneAtATime(runner)
			result, err := runner.RunOnce(context.Background())
			if err != nil || result.Status != storage.ArchiveRunCompleted {
				t.Fatalf("run %+v, %v", result, err)
			}
			removal := result.Removal
			if removal.BundleCheckFailedSegments != 1 || removal.HeldBackMembers != int64(len(held)) ||
				removal.Removed != int64(len(others)+1) || removal.Stale != 0 || removal.Skipped != 0 {
				t.Fatalf("removal %+v", removal)
			}
			for _, audit := range held {
				if _, hot := h.store.audits[audit.id]; !hot || h.store.memberStates(audit.id)[1] != storage.ArchiveMemberSealed {
					t.Fatalf("%s left the hot store or its member changed: %v", audit.id, h.store.memberStates(audit.id))
				}
			}
			for _, audit := range others {
				if _, hot := h.store.audits[audit.id]; hot {
					t.Fatalf("%s was held back", audit.id)
				}
			}
			for _, batch := range h.store.removalBatches {
				for _, id := range batch {
					if strings.HasPrefix(id, "conv-held") {
						t.Fatalf("%s was sent to the store", id)
					}
				}
			}
			// One check per segment per run: removal looks each segment up
			// once (reconciliation once more for every bundle it indexes),
			// although the batches are one audit each.
			for id, lookups := range h.store.segmentLookups {
				if lookups > 2 {
					t.Fatalf("segment %s looked up %d times", id, lookups)
				}
			}
			logs := h.logs.String()
			if strings.Count(logs, `"error_category":"archive_bundle_check_failed"`) != 1 || !strings.Contains(logs, `"reason":"`+test.reason+`"`) ||
				!strings.Contains(logs, `"bundle_check_failed_segments":1`) || !strings.Contains(logs, `"held_back_members":3`) ||
				strings.Contains(logs, "conv-held") || strings.Contains(logs, h.dir) {
				t.Fatalf("logs %s", logs)
			}

			restore()
			next := h.mustRun()
			if next.Removal.Removed != int64(len(held)) || next.Removal.BundleCheckFailedSegments != 0 || len(h.store.audits) != 0 {
				t.Fatalf("next run %+v, %d left", next.Removal, len(h.store.audits))
			}
		})
	}
}

// The gaps of a gaps segment whose bundle fails the check stay; the audits
// are removed.
func TestBundleCheckHoldsBackGaps(t *testing.T) {
	h := newRemovalHarness(t)
	h.options.Mode = storage.ArchiveModeExportOnly
	h.addTurnless("turnless-1", "openai", baseTimeNS+5)
	h.store.gaps = []archive.Gap{
		{ID: 1, StartedAtNS: baseTimeNS, EndedAtNS: baseTimeNS + 10, Reason: "queue_full", RequestCount: 1, CreatedAtNS: baseTimeNS + 11},
		{ID: 2, StartedAtNS: baseTimeNS + 20, EndedAtNS: baseTimeNS + 30, Reason: "queue_full", RequestCount: 1, CreatedAtNS: baseTimeNS + 31},
	}
	h.mustRun()
	var manifest string
	var data []string
	for _, entry := range h.bundles() {
		if entry.Manifest.BundleKind == archive.BundleGaps {
			manifest = entry.ManifestPath
			for _, file := range entry.Manifest.Files {
				data = append(data, filepath.Join(filepath.Dir(manifest), file.Name))
			}
		}
	}
	if err := os.Rename(manifest, manifest+".moved"); err != nil {
		t.Fatal(err)
	}
	h.options.Mode = storage.ArchiveModeArchiveThenDelete
	result := h.mustRun()
	if result.Removal.Removed != 1 || result.Removal.RemovedGaps != 0 || result.Removal.HeldBackGaps != 2 ||
		result.Removal.BundleCheckFailedSegments != 1 || len(h.store.gaps) != 2 {
		t.Fatalf("removal %+v, %d gaps", result.Removal, len(h.store.gaps))
	}
	if err := os.Rename(manifest+".moved", manifest); err != nil {
		t.Fatal(err)
	}
	unorphan(t, data)
	if next := h.mustRun(); next.Removal.RemovedGaps != 2 || len(h.store.gaps) != 0 {
		t.Fatalf("next run %+v", next.Removal)
	}
}

// unorphan undoes what reconciliation does to the data files of a bundle
// whose manifest no longer verifies (H.6 item 3): it renames them .orphan,
// so restoring the manifest alone does not restore the bundle.
func unorphan(t *testing.T, data []string) {
	t.Helper()
	for _, path := range data {
		if _, err := os.Stat(path + bundle.OrphanSuffix); err == nil {
			if err := os.Rename(path+bundle.OrphanSuffix, path); err != nil {
				t.Fatal(err)
			}
		}
	}
}
