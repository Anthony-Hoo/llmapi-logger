package bundle

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"llmapi-logger/internal/archive"
)

// Entry is one indexed bundle.
type Entry struct {
	ManifestPath string
	Manifest     *archive.Manifest
}

// Problem is a manifest the index could not use, with the reason code. For
// ReasonUnsupportedFormatVersion, FormatVersion is the manifest's version.
type Problem struct {
	Path          string
	Reason        string
	FormatVersion string
}

// Location is one revision of an audit: the bundle and the line that holds
// it. Line is the member's position, which is the line's.
type Location struct {
	Entry  Entry
	Line   int
	Member archive.ManifestMember
}

// MissingData is a manifest whose listed data files are not all there.
type MissingData struct {
	ManifestPath string
	Files        []string
}

// Leftovers is what reconciliation (H.6) acts on.
type Leftovers struct {
	// DataWithoutManifest are lines and objects files no manifest lists
	// (H.6 step 3: renamed with OrphanSuffix, never deleted).
	DataWithoutManifest []string
	// Temporary are files of this package's temporary naming (IsTempName),
	// the only files reconciliation removes.
	Temporary []string
	// MissingData are manifests whose data files are missing.
	MissingData []MissingData
}

// Index is the K.2 index of an archive directory, built from manifests only.
type Index struct {
	entries       []Entry
	problems      []Problem
	audits        map[string][]Location
	conversations map[string][]int
	leftovers     Leftovers
}

// BuildIndex walks root, reads every *.manifest.json (a rejected or orphaned
// manifest no longer has that suffix) and checks its schema; with a signer
// it also checks the key fingerprint and MAC. A manifest that fails is
// reported in Problems and left out of every lookup. Lookups use the
// manifests' contents only, never file names. Data files are matched to
// manifests through files[].name in the manifest's directory.
func BuildIndex(ctx context.Context, root string, signer archive.ManifestSigner) (*Index, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, fail(ReasonNotFound, errors.New("archive root is not a directory"))
	}
	// WalkDir does not follow a symlink given as its root: a symlinked
	// archive directory would index as empty. The walk goes through the
	// resolved directory, and every path it reports is put back under root,
	// so callers see the paths they would through root itself.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fail(ReasonNotFound, errors.New("archive root is not a directory"))
	}
	index := &Index{audits: map[string][]Location{}, conversations: map[string][]int{}}
	var manifests, data []string
	err = filepath.WalkDir(resolved, func(path string, entry fs.DirEntry, err error) error {
		if relative, relErr := filepath.Rel(resolved, path); relErr == nil {
			path = filepath.Join(root, relative)
		}
		if err != nil {
			index.problems = append(index.problems, Problem{Path: path, Reason: ReasonReadFailed})
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		name := entry.Name()
		switch {
		case IsTempName(name):
			index.leftovers.Temporary = append(index.leftovers.Temporary, path)
		case strings.HasSuffix(name, ManifestSuffix):
			manifests = append(manifests, path)
		case IsDataName(name):
			data = append(data, path)
		}
		return nil
	})
	if err != nil {
		return nil, keep(ReasonReadFailed, err)
	}
	sort.Strings(manifests)
	listed := map[string]bool{}
	var unreadable []string
	for _, path := range manifests {
		manifest, files, err := readManifest(path)
		if err != nil {
			problem := Problem{Path: path, Reason: ReasonOf(err)}
			var unsupported *archive.UnsupportedFormatVersionError
			if errors.As(err, &unsupported) {
				problem.FormatVersion = unsupported.Version
			}
			index.problems = append(index.problems, problem)
			unreadable = append(unreadable, strings.TrimSuffix(path, ManifestSuffix)+".")
			continue
		}
		dir := filepath.Dir(path)
		var missing []string
		for _, file := range files {
			full := filepath.Join(dir, file.Name)
			listed[full] = true
			if info, err := os.Stat(full); err != nil || !info.Mode().IsRegular() {
				missing = append(missing, full)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			index.leftovers.MissingData = append(index.leftovers.MissingData, MissingData{ManifestPath: path, Files: missing})
		}
		if signer != nil {
			if err := manifest.Verify(signer); err != nil {
				reason := ReasonMACMismatch
				if errors.Is(err, archive.ErrKeyMismatch) {
					reason = ReasonKeyMismatch
				}
				index.problems = append(index.problems, Problem{Path: path, Reason: reason})
				continue
			}
		}
		index.add(Entry{ManifestPath: path, Manifest: manifest})
	}
	for _, path := range data {
		if listed[path] {
			continue
		}
		// The data files of a manifest that does not parse are not orphans:
		// the manifest exists and is reported as a problem instead.
		owned := false
		for _, prefix := range unreadable {
			if strings.HasPrefix(path, prefix) {
				owned = true
				break
			}
		}
		if !owned {
			index.leftovers.DataWithoutManifest = append(index.leftovers.DataWithoutManifest, path)
		}
	}
	sort.Strings(index.leftovers.DataWithoutManifest)
	sort.Strings(index.leftovers.Temporary)
	return index, nil
}

func (index *Index) add(entry Entry) {
	position := len(index.entries)
	index.entries = append(index.entries, entry)
	conversations := map[string]bool{}
	for _, conversation := range entry.Manifest.Conversations {
		conversations[conversation] = true
	}
	for line, member := range entry.Manifest.Members {
		index.audits[member.AuditID] = append(index.audits[member.AuditID], Location{Entry: entry, Line: line, Member: member})
		if member.ConversationID != nil {
			conversations[*member.ConversationID] = true
		}
	}
	for conversation := range conversations {
		index.conversations[conversation] = append(index.conversations[conversation], position)
	}
}

// Bundles is every indexed bundle, by manifest path.
func (index *Index) Bundles() []Entry { return append([]Entry(nil), index.entries...) }

// Problems is every manifest left out, by path.
func (index *Index) Problems() []Problem { return append([]Problem(nil), index.problems...) }

// Leftovers is what reconciliation needs.
func (index *Index) Leftovers() Leftovers { return index.leftovers }

// InRange is every bundle whose [first_started_at_ns, last_ended_at_ns]
// overlaps [fromNS, toNS].
func (index *Index) InRange(fromNS, toNS int64) []Entry {
	var out []Entry
	for _, entry := range index.entries {
		if entry.Manifest.FirstStartedAtNS <= toNS && entry.Manifest.LastEndedAtNS >= fromNS {
			out = append(out, entry)
		}
	}
	return out
}

// Conversation is every segment that holds a line of the conversation, by
// manifest path. A conversation can span conversation bundles and buckets.
func (index *Index) Conversation(conversationID string) []Entry {
	var out []Entry
	for _, position := range index.conversations[conversationID] {
		out = append(out, index.entries[position])
	}
	return out
}

// AuditRevisions is every indexed revision of the audit, highest revision
// first; equal revisions are ordered by the later manifest created_at_ns,
// then by manifest path.
func (index *Index) AuditRevisions(auditID string) []Location {
	locations := append([]Location(nil), index.audits[auditID]...)
	sort.SliceStable(locations, func(left, right int) bool {
		a, b := locations[left], locations[right]
		if a.Member.Revision != b.Member.Revision {
			return a.Member.Revision > b.Member.Revision
		}
		if a.Entry.Manifest.CreatedAtNS != b.Entry.Manifest.CreatedAtNS {
			return a.Entry.Manifest.CreatedAtNS > b.Entry.Manifest.CreatedAtNS
		}
		return a.Entry.ManifestPath < b.Entry.ManifestPath
	})
	return locations
}

// Audit is the location of the audit's highest revision (K.2 item 3).
func (index *Index) Audit(auditID string) (Location, bool) {
	locations := index.AuditRevisions(auditID)
	if len(locations) == 0 {
		return Location{}, false
	}
	return locations[0], true
}

// Reject voids a bundle (H.2 step 6, P.11): the manifest is renamed with
// RejectedSuffix first, so no index sees the bundle any more, then each data
// file it lists. Nothing is deleted and no file is replaced. A manifest that
// does not parse is renamed alone.
func Reject(manifestPath string) error {
	manifest, _, readErr := readManifest(manifestPath)
	if _, err := renameAside(manifestPath, RejectedSuffix); err != nil {
		return err
	}
	if readErr != nil {
		return nil
	}
	dir := filepath.Dir(manifestPath)
	var first error
	for _, file := range manifest.Files {
		path := filepath.Join(dir, file.Name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if _, err := renameAside(path, RejectedSuffix); err != nil && first == nil {
			first = err
		}
	}
	_ = syncDirectory(dir)
	return first
}

// MarkOrphan renames a data file without a manifest with OrphanSuffix
// (H.6 steps 1 and 3) and returns the new path.
func MarkOrphan(path string) (string, error) {
	target, err := renameAside(path, OrphanSuffix)
	if err == nil {
		_ = syncDirectory(filepath.Dir(path))
	}
	return target, err
}
