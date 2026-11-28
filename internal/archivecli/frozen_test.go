package archivecli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

// The compatibility promise of the archive format (plan 4.4, design N.1 and
// R.10, doc/features/26-cold-archive.md §2): every published format version
// stays readable by the current reader. internal/archive/testdata/frozen/v<N>/
// is a small archive directory that format version N wrote when it was
// published; TestFrozenFixturesRead opens, verifies and reads every one of
// them with this build's reader, and the record digests and raw bodies must
// be the ones pinned below.
//
// Adding the fixture of a new published version N, in the change that
// publishes it:
//
//  1. ARCHIVE_WRITE_FIXTURE=<repo>/internal/archive/testdata/frozen/vN \
//     go test ./internal/archivecli -run TestWriteFrozenFixture -count=1
//     (frozen_write_test.go; it refuses a directory that exists);
//  2. add frozenExpectations["N"] with the digests the generator logs and the
//     raw body digests;
//  3. commit the files as written; .gitattributes keeps them byte-exact.
//
// The reader of version N must keep reading v1 and every other directory
// here: a later reader that cannot is a broken promise, not a fixture to
// update. Existing fixture files are never regenerated or edited, even when
// the generator changes; they are what the published writer produced (the
// generator cannot reproduce them byte for byte anyway: segment ids and
// encryption salts are random).
//
// internal/archive/testdata/trial/v0/ is the same content written by the
// trial format version 0 (this generator at commit 61d06d8, the last commit
// before the freeze, with ARCHIVE_FIXTURE_REVISION=2). Version 0 was never
// published: the reader refuses it (TestTrialAndFutureFormatVersionsAreRefused).

// frozenExpectation is what a published fixture must read as.
type frozenExpectation struct {
	// digests are the record digests by "audit_id/revision".
	digests map[string]string
	// raw are the SHA-256 of exported raw bodies by "audit_id/kind".
	raw map[string]string
}

var frozenExpectations = map[string]frozenExpectation{
	"1": {
		digests: map[string]string{
			"frozen-a1/1":    "7a5a37e19a489422b33e767559b925c2d42d0490126026a70480a667f92549f7",
			"frozen-a2/1":    "6ae57dfe545576d1d74fcfb0e12c7f0b31e3299f977069f962558a7bc232f502",
			"frozen-a3/1":    "fdf98c8c5d57eb2b204ef073317a647352c022a2f1ed3578a265a31f63a412eb",
			"frozen-a4/1":    "ddd73382a44a233342364f8ce6b3e882afbdba186ffc49c171552391d1c19cba",
			"frozen-loose/1": "04449be614cb0c56413358dec1ad21bffdecde2d7c187117c37cc464887c34c8",
		},
		raw: map[string]string{
			"frozen-a1/raw-request":    "7b0262a9927663a73d749cb3b7b6c736dcddaae8e005d0ed5bf50244058ec8e3",
			"frozen-loose/raw-request": "ccdbc666e7e0f13af8df08856db4682de8ddb436ca2a08f55b4935dfd3e95be0",
		},
	},
}

var (
	frozenRoot = filepath.Join("..", "archive", "testdata", "frozen")
	trialRoot  = filepath.Join("..", "archive", "testdata", "trial", "v0")
)

// frozenKeyFile writes the fixtures' master key to a temporary key file.
func frozenKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(path, frozenMaster(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFrozenFixturesRead(t *testing.T) {
	entries, err := os.ReadDir(frozenRoot)
	if err != nil {
		t.Fatal(err)
	}
	versions := 0
	for _, entry := range entries {
		version, ok := strings.CutPrefix(entry.Name(), "v")
		if !entry.IsDir() || !ok {
			t.Fatalf("unexpected %s in %s", entry.Name(), frozenRoot)
		}
		want, ok := frozenExpectations[version]
		if !ok {
			t.Fatalf("frozen fixture v%s has no expectations", version)
		}
		versions++
		t.Run("v"+version, func(t *testing.T) { readFrozenFixture(t, filepath.Join(frozenRoot, entry.Name()), version, want) })
	}
	if versions != len(frozenExpectations) || frozenExpectations[archive.FormatVersion].digests == nil {
		t.Fatalf("%d fixtures for %d expectations; the version this build writes (%s) needs one", versions, len(frozenExpectations), archive.FormatVersion)
	}
}

func readFrozenFixture(t *testing.T, dir, version string, want frozenExpectation) {
	ctx := context.Background()
	keys, err := NewKeys(frozenMaster())
	if err != nil {
		t.Fatal(err)
	}
	index, err := bundle.BuildIndex(ctx, dir, keys.Archive)
	if err != nil {
		t.Fatal(err)
	}
	if problems := index.Problems(); len(problems) != 0 || len(index.Bundles()) != 3 {
		t.Fatalf("problems %+v, %d bundles", problems, len(index.Bundles()))
	}
	digests := map[string]string{}
	kinds := map[string]bool{}
	for _, entry := range index.Bundles() {
		if entry.Manifest.FormatVersion != version {
			t.Fatalf("%s is format version %q", entry.ManifestPath, entry.Manifest.FormatVersion)
		}
		kinds[entry.Manifest.BundleKind+map[bool]string{true: "/encrypted", false: "/plain"}[entry.Manifest.Encrypted]] = true
		opened, err := bundle.Open(entry.ManifestPath, bundle.ReadOptions{Signer: keys.Archive, EncryptionKey: keys.Archive.EncryptionKey(), Events: keys.Events})
		if err != nil {
			t.Fatalf("open %s: %v (%v)", entry.ManifestPath, err, errors.Unwrap(err))
		}
		report, err := opened.Verify(ctx)
		if err != nil {
			t.Fatalf("verify %s: %v (%v)", entry.ManifestPath, err, errors.Unwrap(err))
		}
		for _, member := range report.Members {
			digests[member.AuditID+"/"+strconv.FormatInt(member.Revision, 10)] = hex.EncodeToString(member.Digest[:])
		}
	}
	if !reflect.DeepEqual(digests, want.digests) {
		t.Fatalf("record digests %v\nwant %v", digests, want.digests)
	}
	if !reflect.DeepEqual(kinds, map[string]bool{"conversation/encrypted": true, "bucket/plain": true, "gaps/plain": true}) {
		t.Fatalf("bundle kinds %v", kinds)
	}

	// The reader tool.
	key := frozenKeyFile(t)
	run(t, "verify", "--dir", dir, "--key", key).want(t, ExitOK)
	listed := run(t, "list", "--dir", dir, "--key", key, "--json").want(t, ExitOK)
	if lines := listed.lines(); len(lines) != 3 || strings.Count(listed.stdout, `"format_version":"`+version+`"`) != 3 || strings.Count(listed.stdout, `"auth":"ok"`) != 3 {
		t.Fatalf("list:\n%s", listed.stdout)
	}
	if cat := run(t, "cat", "--dir", dir, "--key", key).want(t, ExitOK); len(cat.lines()) != len(want.digests)+1 {
		t.Fatalf("cat: %d lines", len(cat.lines()))
	}
	for name, digest := range want.raw {
		auditID, kind, _ := strings.Cut(name, "/")
		out := run(t, "export", "--dir", dir, "--key", key, "--audit", auditID, "--what", kind).want(t, ExitOK)
		if sum := sha256.Sum256([]byte(out.stdout)); hex.EncodeToString(sum[:]) != digest {
			t.Fatalf("%s: SHA-256 %x, want %s", name, sum, digest)
		}
	}
	// The renderings may change from one reader to the next; what they are
	// built from may not. Each carries what the fixture put in.
	for name, needles := range map[string][]string{
		"frozen-a1/headers":           {"Authorization", "value_fpr", "X-Trace"},
		"frozen-a1/timeline-response": {"points"},
		"frozen-a2/request":           {"first question", "answer to first question", "second question"},
		"frozen-a2/response":          {"answer to second question"},
		"frozen-a3/conversation":      {"first question", "second question", "third question", "answer to third question"},
		"frozen-a4/conversation":      {"unanswered question", "half an answer"},
		"frozen-loose/conversation":   {"first question"},
		"frozen-loose/detail":         {"normalization_failed", "frozen-loose"},
	} {
		auditID, kind, _ := strings.Cut(name, "/")
		out := run(t, "export", "--dir", dir, "--key", key, "--audit", auditID, "--what", kind).want(t, ExitOK)
		for _, needle := range needles {
			if !strings.Contains(out.stdout, needle) {
				t.Fatalf("%s lacks %q:\n%s", name, needle, out.stdout)
			}
		}
	}
	if turns := run(t, "export", "--dir", dir, "--key", key, "--conversation", frozenConversation).want(t, ExitOK).lines(); len(turns) != 3 {
		t.Fatalf("conversation export: %d turns", len(turns))
	}
	match := runWith(t, authKey("frozen-a1")+"\n", nil, "fpr", "--key", key, "--dir", dir).want(t, ExitOK)
	if !strings.Contains(match.stdout, "match frozen-a1 revision 1 header "+storage.StageRequestReceived+" header Authorization bearer") {
		t.Fatalf("fpr:\n%s", match.stdout)
	}
}

// wantBundleReason fails unless err carries the bundle reason code.
func wantBundleReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := bundle.ReasonOf(err); got != reason {
		t.Fatalf("reason %q (%v), want %q", got, err, reason)
	}
}

// copyFixture copies the regular files under from to the same relative paths
// under to.
func copyFixture(t *testing.T, from, to string) []string {
	t.Helper()
	var copied []string
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
		copied = append(copied, target)
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(copied)
	return copied
}

// futureFixture writes the version 1 fixture with its manifests turned into
// a format version 2 the reader has never seen: the version changed and a
// key added. Data files are copied as they are.
func futureFixture(t *testing.T, to string) {
	t.Helper()
	for _, path := range copyFixture(t, filepath.Join(frozenRoot, "v1"), to) {
		if !strings.HasSuffix(path, bundle.ManifestSuffix) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(string(data), `"format_version": "1"`, `"format_version": "2"`, 1)
		changed = strings.Replace(changed, `"line_count"`, `"shared_objects": [], "line_count"`, 1)
		if changed == string(data) {
			t.Fatal("manifest not rewritten")
		}
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// The reader refuses a bundle of the trial version 0 and of a future version
// with the stable code unsupported_format_version and the manifest's version,
// before any signature check (a version 0 signature does not verify under
// the version 1 domain, which must not read as tampering). list names every
// such bundle with its version; verify fails them; Open, VerifyFiles and
// CheckFiles refuse them. In a directory that also holds the version 1
// fixture, the trial bundles' higher revisions never shadow the version 1
// members, and cat and export print the version 1 content and exit 1
// (incomplete), since a refused bundle may hold part of the answer.
func TestTrialAndFutureFormatVersionsAreRefused(t *testing.T) {
	ctx := context.Background()
	key := frozenKeyFile(t)
	keys, err := NewKeys(frozenMaster())
	if err != nil {
		t.Fatal(err)
	}
	future := t.TempDir()
	futureFixture(t, future)
	for _, test := range []struct {
		name, dir, version string
	}{
		{"trial version 0", trialRoot, "0"},
		{"future version 2", future, "2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := `unsupported_format_version (format_version "` + test.version + `"; this reader reads format version ` + archive.FormatVersion + `)`
			listed := run(t, "list", "--dir", test.dir, "--key", key).want(t, ExitOK)
			if strings.Count(listed.stderr, "unreadable manifest") != 3 || strings.Count(listed.stderr, text) != 3 || len(listed.lines()) != 1 {
				t.Fatalf("list:\n%s\n%s", listed.stdout, listed.stderr)
			}
			verified := run(t, "verify", "--dir", test.dir, "--key", key, "--json").want(t, ExitFailed)
			if strings.Count(verified.stdout, `"result":"unsupported_format_version"`) != 3 || strings.Contains(verified.stdout, "mac_mismatch") {
				t.Fatalf("verify:\n%s", verified.stdout)
			}
			run(t, "verify", "--dir", test.dir, "--json").want(t, ExitFailed)
			index, err := bundle.BuildIndex(ctx, test.dir, keys.Archive)
			if err != nil {
				t.Fatal(err)
			}
			if len(index.Bundles()) != 0 || len(index.Problems()) != 3 || len(index.Leftovers().DataWithoutManifest) != 0 {
				t.Fatalf("index: %d bundles, problems %+v, leftovers %+v", len(index.Bundles()), index.Problems(), index.Leftovers())
			}
			for _, problem := range index.Problems() {
				if problem.Reason != bundle.ReasonUnsupportedFormatVersion || problem.FormatVersion != test.version {
					t.Fatalf("problem %+v", problem)
				}
				_, err := bundle.Open(problem.Path, bundle.ReadOptions{Signer: keys.Archive, EncryptionKey: keys.Archive.EncryptionKey()})
				wantBundleReason(t, err, bundle.ReasonUnsupportedFormatVersion)
				_, err = bundle.Open(problem.Path, bundle.ReadOptions{Unauthenticated: true, EncryptionKey: keys.Archive.EncryptionKey()})
				wantBundleReason(t, err, bundle.ReasonUnsupportedFormatVersion)
				_, err = bundle.VerifyFiles(ctx, problem.Path)
				wantBundleReason(t, err, bundle.ReasonUnsupportedFormatVersion)
				_, _, err = bundle.CheckFiles(ctx, problem.Path, keys.Archive)
				wantBundleReason(t, err, bundle.ReasonUnsupportedFormatVersion)
			}
		})
	}

	t.Run("beside version 1", func(t *testing.T) {
		root := t.TempDir()
		copyFixture(t, filepath.Join(frozenRoot, "v1"), filepath.Join(root, "published"))
		copyFixture(t, trialRoot, filepath.Join(root, "trial"))
		futureFixture(t, filepath.Join(root, "future"))
		reader, err := OpenReader(ctx, root, ReaderOptions{Keys: keys})
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		for _, id := range []string{"frozen-a1", "frozen-a2", "frozen-a3", "frozen-a4", "frozen-loose"} {
			revisions := reader.Index().AuditRevisions(id)
			if len(revisions) != 1 || revisions[0].Member.Revision != 1 || revisions[0].Entry.Manifest.FormatVersion != "1" {
				t.Fatalf("%s revisions %+v", id, revisions)
			}
			audit, err := reader.Audit(ctx, id)
			if err != nil || audit.Record.Revision != 1 {
				t.Fatalf("%s: %+v (%v)", id, audit, err)
			}
		}
		cat := run(t, "cat", "--dir", root, "--key", key).want(t, ExitFailed)
		if len(cat.lines()) != len(frozenExpectations["1"].digests)+1 || !strings.Contains(cat.stderr, "incomplete") || strings.Count(cat.stderr, "unsupported_format_version") != 6 {
			t.Fatalf("cat: %d lines\n%s", len(cat.lines()), cat.stderr)
		}
		raw := run(t, "export", "--dir", root, "--key", key, "--audit", "frozen-a1", "--what", "raw-request").want(t, ExitFailed)
		if sum := sha256.Sum256([]byte(raw.stdout)); hex.EncodeToString(sum[:]) != frozenExpectations["1"].raw["frozen-a1/raw-request"] || !strings.Contains(raw.stderr, "incomplete") {
			t.Fatalf("export: %x\n%s", sum, raw.stderr)
		}
	})
}
