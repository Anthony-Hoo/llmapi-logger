package bundle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/storage"
)

// The index over a directory with a conversation bundle, two revisions of
// one audit in two buckets, a gap bundle, a rejected bundle, an orphaned
// data file, a temporary file, a manifest whose objects file is missing and
// a manifest that does not parse.
func TestIndex(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	options := f.options(root, true)

	conversation := f.writeSegment(options, Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_idx", Index: 1},
		f.conversation("conv_idx", "ix", 0)...)

	loose := canonical(t, f.audit("loose-1", "openai", minute(30), storage.CaptureVersion2))
	bucketTurns := f.conversation("conv_bkt", "bk", 20)[:1]
	first := f.writeSegment(options, Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, append(bucketTurns, loose)...)
	second := *loose
	second.Revision = 2
	again := f.options(root, true)
	again.RunID = "fedcba9876543210fedcba9876543210"
	revised := f.writeSegment(again, Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, &second)

	gaps, err := NewGapSegment(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := gaps.Add(archive.Gap{ID: 3, StartedAtNS: minute(100), EndedAtNS: minute(101), Reason: "r", Detail: "{}"}); err != nil {
		t.Fatal(err)
	}
	gapSealed, err := gaps.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := gapSealed.Publish(); err != nil {
		t.Fatal(err)
	}

	rejected := f.writeSegment(options, Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_rej", Index: 1},
		f.conversation("conv_rej", "rj", 40)...)
	if err := Reject(rejected.ManifestPath()); err != nil {
		t.Fatal(err)
	}

	broken := f.writeSegment(options, Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_miss", Index: 1},
		f.conversation("conv_miss", "ms", 60)...)
	missingObjects := filepath.Join(filepath.Dir(broken.ManifestPath()), broken.Manifest().Files[1].Name)
	if err := os.Remove(missingObjects); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(conversation.ManifestPath())
	lines := filepath.Join(dir, conversation.Manifest().Files[0].Name)
	orphan := filepath.Join(dir, "orphaned"+EncryptedSuffix)
	if err := os.WriteFile(orphan, readAll(t, lines), 0o600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(root, SessionsDir, tempName(strings.Repeat("ab", 16), roleLines, strings.Repeat("cd", 8)))
	if err := os.WriteFile(temp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unparsable := filepath.Join(dir, "unparsable"+ManifestSuffix)
	if err := os.WriteFile(unparsable, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unparsable"+EncryptedSuffix), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	index, err := BuildIndex(context.Background(), root, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if bundles := index.Bundles(); len(bundles) != 5 {
		t.Fatalf("bundles = %d, want 5 (conversation, two buckets, gaps, the one with a missing file)", len(bundles))
	}
	if problems := index.Problems(); len(problems) != 1 || problems[0].Path != unparsable || problems[0].Reason != ReasonManifestInvalid {
		t.Fatalf("problems = %+v", problems)
	}

	location, ok := index.Audit("loose-1")
	if !ok || location.Member.Revision != 2 || location.Entry.ManifestPath != revised.ManifestPath() || location.Line != 0 {
		t.Fatalf("audit = %+v", location)
	}
	if revisions := index.AuditRevisions("loose-1"); len(revisions) != 2 || revisions[1].Entry.ManifestPath != first.ManifestPath() || revisions[1].Line != 1 {
		t.Fatalf("revisions = %+v", revisions)
	}
	if location, ok := index.Audit("ix-2"); !ok || location.Line != 1 || location.Entry.ManifestPath != conversation.ManifestPath() {
		t.Fatalf("ix-2 = %+v", location)
	}
	if _, ok := index.Audit("rj-1"); ok {
		t.Fatal("rejected bundle is indexed")
	}
	if entries := index.Conversation("conv_bkt"); len(entries) != 1 || entries[0].ManifestPath != first.ManifestPath() {
		t.Fatalf("conversation in a bucket = %+v", entries)
	}
	if entries := index.Conversation("conv_rej"); len(entries) != 0 {
		t.Fatal("rejected conversation found")
	}
	if entries := index.InRange(minute(100), minute(100)); len(entries) != 1 || entries[0].Manifest.BundleKind != archive.BundleGaps {
		t.Fatalf("range = %+v", entries)
	}
	if entries := index.InRange(minute(0), minute(70)); len(entries) != 4 {
		t.Fatalf("range = %d entries", len(entries))
	}

	leftovers := index.Leftovers()
	if len(leftovers.DataWithoutManifest) != 1 || leftovers.DataWithoutManifest[0] != orphan {
		t.Fatalf("orphans = %v", leftovers.DataWithoutManifest)
	}
	if len(leftovers.Temporary) != 1 || leftovers.Temporary[0] != temp {
		t.Fatalf("temporary = %v", leftovers.Temporary)
	}
	if len(leftovers.MissingData) != 1 || leftovers.MissingData[0].ManifestPath != broken.ManifestPath() || leftovers.MissingData[0].Files[0] != missingObjects {
		t.Fatalf("missing = %+v", leftovers.MissingData)
	}

	renamed, err := MarkOrphan(orphan)
	if err != nil || renamed != orphan+OrphanSuffix {
		t.Fatalf("orphan rename = %q, %v", renamed, err)
	}
	index, err = BuildIndex(context.Background(), root, nil)
	if err != nil || len(index.Leftovers().DataWithoutManifest) != 0 {
		t.Fatalf("after the orphan rename: %v %+v", err, index.Leftovers())
	}

	// Under another key every manifest is a problem and nothing is indexed.
	index, err = BuildIndex(context.Background(), root, testKeys(t, 0x43))
	if err != nil || len(index.Bundles()) != 0 {
		t.Fatalf("wrong key: %v, %d bundles", err, len(index.Bundles()))
	}
	for _, problem := range index.Problems() {
		if problem.Reason != ReasonKeyMismatch && problem.Path != unparsable {
			t.Fatalf("problem = %+v", problem)
		}
	}
}

// A symlinked archive root is indexed through the directory it points to,
// and every path is reported under the root as given: the frozen v1 fixture
// has three bundles through its real path and through a symlink to it.
func TestIndexFollowsASymlinkedRoot(t *testing.T) {
	target, err := filepath.Abs(filepath.Join("..", "testdata", "frozen", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "archive")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a directory symlink here (%v); this test runs on Linux", err)
	}
	for _, root := range []string{target, link} {
		index, err := BuildIndex(context.Background(), root, nil)
		if err != nil {
			t.Fatal(err)
		}
		bundles := index.Bundles()
		if len(bundles) != 3 || len(index.Problems()) != 0 {
			t.Fatalf("%s: %d bundles, problems %+v", root, len(bundles), index.Problems())
		}
		for _, entry := range bundles {
			if relative, err := filepath.Rel(root, entry.ManifestPath); err != nil || strings.HasPrefix(relative, "..") {
				t.Fatalf("%s: manifest path %s is not under the root", root, entry.ManifestPath)
			}
		}
	}
}
