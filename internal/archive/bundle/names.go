package bundle

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"llmapi-logger/internal/archive"
)

// Directories under the archive root (C.1, P.6): segments go to
// sessions/<YYYY>/<MM> by the UTC month of their earliest started_at_ns, gap
// bundles to gaps.
const (
	SessionsDir = "sessions"
	GapsDir     = "gaps"
)

// File name suffixes. A segment named N has N + LinesSuffix(encrypted),
// N + ".objects" + LinesSuffix(encrypted) and N + ManifestSuffix. A rejected
// or orphaned file keeps its name and gains RejectedSuffix or OrphanSuffix
// (P.11), so no manifest pattern matches it any more.
const (
	ManifestSuffix  = ".manifest.json"
	PlainSuffix     = ".jsonl.gz"
	EncryptedSuffix = ".jsonl.gz.enc"
	RejectedSuffix  = ".rejected"
	OrphanSuffix    = ".orphan"
)

// Temporary file roles.
const (
	roleLines    = archive.FileLines
	roleObjects  = archive.FileObjects
	roleManifest = "manifest"
)

const timestampLayout = "20060102T150405Z"

// safeComponent is what a conversation id or protocol may look like to be
// put into a file name. Anything else is refused rather than escaped: the
// name is only for people, and a refused name is a visible error.
var safeComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// tempPattern is the only naming of temporary files this package uses:
// "." + segment_id + "." + role + ".tmp-" + 16 random hex digits. The final
// name is not known while the files are written (its timestamps come from
// the members), so the segment id stands in for it.
var tempPattern = regexp.MustCompile(`^\.[0-9a-f]{32}\.(lines|objects|manifest)\.tmp-[0-9a-f]{16}$`)

// IsTempName reports whether a base file name is a temporary file of this
// package (H.6 step 3): only those may be removed by reconciliation.
func IsTempName(name string) bool { return tempPattern.MatchString(name) }

// IsDataName reports whether a base file name is a lines or objects file
// name of a live bundle: it ends in PlainSuffix or EncryptedSuffix.
func IsDataName(name string) bool {
	return strings.HasSuffix(name, PlainSuffix) || strings.HasSuffix(name, EncryptedSuffix)
}

func tempName(segmentID, role, random string) string {
	return "." + segmentID + "." + role + ".tmp-" + random
}

func formatTimestamp(ns int64) string { return time.Unix(0, ns).UTC().Format(timestampLayout) }

// segmentBase is the name of a segment without suffix (C.1, P.6):
// <first>_<last>_<conversation_id>-<run_id[:8]>_s<NNNN> or
// <first>_<last>_bucket-<protocol>-<run_id[:8]>_s<NNNN>.
//
// Both kinds carry the run disambiguator P.6 gives buckets: re-exporting the
// same members in a later run (a stale member at a higher revision) yields
// the same time range, and without it the new segment could not be
// published next to the old one. Names are for people only; lookups go
// through the manifests.
func segmentBase(kind, protocol, conversationID, runID string, first, last int64, index int) (string, error) {
	var middle string
	switch kind {
	case archive.BundleConversation:
		if !safeComponent.MatchString(conversationID) {
			return "", fail(ReasonUnsafeName, fmt.Errorf("conversation id is not usable in a file name"))
		}
		middle = conversationID + "-" + runID[:8]
	case archive.BundleBucket:
		if !safeComponent.MatchString(protocol) {
			return "", fail(ReasonUnsafeName, fmt.Errorf("protocol is not usable in a file name"))
		}
		middle = "bucket-" + protocol + "-" + runID[:8]
	default:
		return "", fail(ReasonInvalidOptions, fmt.Errorf("unknown bundle kind"))
	}
	return fmt.Sprintf("%s_%s_%s_s%04d", formatTimestamp(first), formatTimestamp(last), middle, index), nil
}

// gapBase is gaps-<first_id>-<last_id>-<run_id[:8]>: the same gap range
// exported again by a later run (for example after the catalog was restored
// from a backup) gets its own name.
func gapBase(firstID, lastID int64, runID string) string {
	return fmt.Sprintf("gaps-%d-%d-%s", firstID, lastID, runID[:8])
}

func dataSuffix(encrypted bool) string {
	if encrypted {
		return EncryptedSuffix
	}
	return PlainSuffix
}

func linesName(base string, encrypted bool) string { return base + dataSuffix(encrypted) }
func objectsName(base string, encrypted bool) string {
	return base + ".objects" + dataSuffix(encrypted)
}
func manifestName(base string) string { return base + ManifestSuffix }

// monthDir is sessions/<YYYY>/<MM> of the UTC month of ns.
func monthDir(root string, ns int64) string {
	at := time.Unix(0, ns).UTC()
	return filepath.Join(root, SessionsDir, fmt.Sprintf("%04d", at.Year()), fmt.Sprintf("%02d", int(at.Month())))
}

// plainFileName reports whether a manifest file name is a bare base name.
func plainFileName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name &&
		!strings.ContainsAny(name, `/\:`) && !strings.HasPrefix(name, ".")
}
