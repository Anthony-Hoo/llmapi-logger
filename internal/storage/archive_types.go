package storage

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The cold archive catalog (doc/design/issue-59-stage4-cold-archive.md, I):
// runs, segments and their members, exported gaps and deferred audits. It is
// management data outside the integrity chain. The types here are what a
// store's catalog operations take and return; the snapshot reader that turns
// hot rows into archive records lives with the PostgreSQL store, because the
// record type (internal/archive) itself depends on this package.

// Archive run modes (archive.mode without off).
const (
	ArchiveModeExportOnly        = "export_only"
	ArchiveModeArchiveThenDelete = "archive_then_delete"
)

// Archive run statuses.
const (
	ArchiveRunRunning     = "running"
	ArchiveRunCompleted   = "completed"
	ArchiveRunFailed      = "archive_failed"
	ArchiveRunInterrupted = "interrupted"
)

// Archive bundle kinds; the same strings as the manifest's bundle_kind.
const (
	ArchiveBundleConversation = "conversation"
	ArchiveBundleBucket       = "bucket"
	ArchiveBundleGaps         = "gaps"
)

// Archive segment states: an intent is publishing until its files are
// published and checked, then sealed; hot_removed once no member is sealed.
const (
	ArchiveSegmentPublishing = "publishing"
	ArchiveSegmentSealed     = "sealed"
	ArchiveSegmentHotRemoved = "hot_removed"
)

// Archive member states. A stale member is never a reason to delete hot data.
const (
	ArchiveMemberSealed     = "sealed"
	ArchiveMemberHotRemoved = "hot_removed"
	ArchiveMemberStale      = "stale"
)

// Reasons an audit behind the watermark is deferred (Q8, H.4).
const (
	ArchiveDeferredOpen            = "open"
	ArchiveDeferredParsePending    = "parse_pending"
	ArchiveDeferredCallerPending   = "caller_pending"
	ArchiveDeferredIntegrityFailed = "integrity_failed"
)

// ArchiveDigestSize is the length of a record digest, change stamp, manifest
// SHA-256 and key fingerprint.
const ArchiveDigestSize = 32

// ArchiveRunCounts are the counters of one run.
type ArchiveRunCounts struct {
	ExportedAudits        int64
	IntegrityFailedAudits int64
	StaleAudits           int64
	RemovedAudits         int64
	RemovedGaps           int64
	DeferredAudits        int64
	Segments              int64
	DiskBytes             int64
}

// ArchivePosition is a point of the selection order (started_at_ns,
// audit_id): the watermark is the last audit a completed pass looked at.
type ArchivePosition struct {
	StartedAtNS int64
	AuditID     string
}

// ArchiveRun is one archive_runs row.
type ArchiveRun struct {
	RunID         string
	Mode          string
	CutoffNS      int64
	StartedAtNS   int64
	FinishedAtNS  *int64
	Status        string
	Counts        ArchiveRunCounts
	FormatVersion int64
	Watermark     *ArchivePosition
}

// ArchiveRunFinish ends a running run with its final status and counters.
type ArchiveRunFinish struct {
	RunID        string
	FinishedAtNS int64
	Status       string
	Counts       ArchiveRunCounts
}

// ArchivePass is what a run records after a pass whose segments are all
// sealed (or that wrote none): the new watermark, the counters so far, the
// audits to defer (inserted, or updated keeping first_seen_at_ns) and the
// deferred audits to forget because they were exported or are gone. Every
// field is optional; an empty pass is a no-op.
type ArchivePass struct {
	RunID     string
	Watermark *ArchivePosition
	Counts    *ArchiveRunCounts
	Deferred  []ArchiveDeferred
	Resolved  []string
}

// ArchiveDeferred is one archive_deferred row.
type ArchiveDeferred struct {
	AuditID         string
	Reason          string
	FirstSeenAtNS   int64
	LastCheckedAtNS int64
}

// ArchiveSegment is one archive_segments row. MemberCount is the number of
// member rows the segment has: archive_members for a conversation or bucket
// segment, archive_gap_members for a gaps segment.
type ArchiveSegment struct {
	SegmentID        string
	RunID            string
	BundleKind       string
	FormatVersion    int64
	ManifestName     string
	ManifestSHA256   []byte
	KeyFingerprint   []byte
	Encrypted        bool
	MemberCount      int64
	DiskBytes        int64
	FirstStartedAtNS *int64
	LastEndedAtNS    *int64
	State            string
	CreatedAtNS      int64
	SealedAtNS       *int64
	RemovedAtNS      *int64
}

// ArchiveMember is one archive_members row. ChangeStamp is nil only for a
// stale member registered from a bundle the catalog did not know.
type ArchiveMember struct {
	AuditID          string
	Revision         int64
	SegmentID        string
	RecordDigest     []byte
	ChangeStamp      []byte
	State            string
	StartedAtNS      int64
	TurnCreatedAtNS  *int64
	StateChangedAtNS int64
}

// ArchiveMemberKey names one member row.
type ArchiveMemberKey struct {
	AuditID  string
	Revision int64
}

// ArchiveGapMember is one archive_gap_members row.
type ArchiveGapMember struct {
	GapID     int64
	SegmentID string
	State     string
}

// ArchiveIntent registers a sealed but unpublished segment (H.2 step 4):
// the segment in state publishing and its members, each with the record
// digest and the change stamp computed in the export snapshot. Members carry
// no state and no segment id; the store sets both. GapIDs are the gaps of a
// gaps segment.
type ArchiveIntent struct {
	Segment ArchiveSegment
	Members []ArchiveMember
	GapIDs  []int64
}

// ArchiveIntentResult reports what registering an intent did beyond
// inserting rows. Stale lists the members registered as stale because their
// audit changed after the snapshot or is gone, or because the audit already
// has a removed member; Superseded the older sealed rows of the same audits
// that the operation marked stale (Q12 item 5).
type ArchiveIntentResult struct {
	Stale      []ArchiveMemberKey
	Superseded []ArchiveMemberKey
}

// ArchiveSeal marks a publishing segment sealed once its files are
// published and checked (H.2 step 7).
type ArchiveSeal struct {
	SegmentID      string
	ManifestSHA256 []byte
	DiskBytes      int64
	SealedAtNS     int64
}

// ArchiveReconciled registers a verified bundle the catalog did not know
// (H.6 item 2): a sealed segment whose members are all stale and carry no
// change stamp. RunID of the segment is the reconciling run.
type ArchiveReconciled struct {
	Segment ArchiveSegment
	Members []ArchiveMember
	GapIDs  []int64
}

// ArchiveReconciledResult lists the rows a reconciliation did not insert
// because the catalog already had them: a member with the same (audit_id,
// revision), a gap already exported in another segment.
type ArchiveReconciledResult struct {
	SkippedMembers []ArchiveMemberKey
	SkippedGaps    []int64
}

// ArchiveCandidate is one audit the export snapshot looked at for selection
// (B.1). Deferral is empty when the audit meets conditions 1 to 3, otherwise
// one of the ArchiveDeferred* reasons; Current reports a current member
// (condition 4). NextRevision is one more than the highest revision any
// member of the audit has. ConversationID and TurnCreatedAtNS are the turn's,
// nil without one.
type ArchiveCandidate struct {
	AuditID         string
	StartedAtNS     int64
	Protocol        string
	ConversationID  *string
	TurnCreatedAtNS *int64
	Deferral        string
	Current         bool
	NextRevision    int64
}

// Due reports whether the candidate is to be exported now.
func (candidate ArchiveCandidate) Due() bool { return candidate.Deferral == "" && !candidate.Current }

// ArchiveDuePage is one page of the selection along audit_records_started_idx
// after a watermark. Candidates holds every audit of the page in order, due
// or not; Last is the last audit looked at (the next watermark), nil when
// the page is empty; More reports that the limit cut the page short.
type ArchiveDuePage struct {
	Candidates []ArchiveCandidate
	Last       *ArchivePosition
	More       bool
}

var archiveIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidArchiveID reports whether id is a run or segment id: 32 lowercase hex
// digits.
func ValidArchiveID(id string) bool { return archiveIDPattern.MatchString(id) }

func validArchiveMode(mode string) bool {
	return mode == ArchiveModeExportOnly || mode == ArchiveModeArchiveThenDelete
}

func validArchiveDeferredReason(reason string) bool {
	switch reason {
	case ArchiveDeferredOpen, ArchiveDeferredParsePending, ArchiveDeferredCallerPending, ArchiveDeferredIntegrityFailed:
		return true
	}
	return false
}

func validArchiveAuditID(id string) bool {
	return id != "" && len(id) <= 256 && strings.TrimSpace(id) == id
}

func validArchiveDigest(value []byte) bool { return len(value) == ArchiveDigestSize }

func validArchiveCounts(counts ArchiveRunCounts) bool {
	return counts.ExportedAudits >= 0 && counts.IntegrityFailedAudits >= 0 && counts.StaleAudits >= 0 &&
		counts.RemovedAudits >= 0 && counts.RemovedGaps >= 0 && counts.DeferredAudits >= 0 &&
		counts.Segments >= 0 && counts.DiskBytes >= 0
}

func validateArchivePosition(position *ArchivePosition) error {
	if position != nil && !validArchiveAuditID(position.AuditID) {
		return errors.New("storage: invalid archive watermark")
	}
	return nil
}

// ValidateArchiveRun checks a run to begin: a new running run without a
// finish time.
func ValidateArchiveRun(run ArchiveRun) error {
	switch {
	case !ValidArchiveID(run.RunID):
		return errors.New("storage: invalid archive run id")
	case !validArchiveMode(run.Mode):
		return errors.New("storage: invalid archive mode")
	case run.CutoffNS <= 0 || run.StartedAtNS <= 0:
		return errors.New("storage: invalid archive run time")
	case run.Status != ArchiveRunRunning || run.FinishedAtNS != nil:
		return errors.New("storage: a new archive run must be running")
	case !validArchiveCounts(run.Counts):
		return errors.New("storage: invalid archive run counts")
	case run.FormatVersion < 0:
		return errors.New("storage: invalid archive format version")
	}
	return validateArchivePosition(run.Watermark)
}

// ValidateArchiveRunFinish checks the end of a run.
func ValidateArchiveRunFinish(finish ArchiveRunFinish) error {
	switch {
	case !ValidArchiveID(finish.RunID):
		return errors.New("storage: invalid archive run id")
	case finish.FinishedAtNS <= 0:
		return errors.New("storage: invalid archive run finish time")
	case finish.Status != ArchiveRunCompleted && finish.Status != ArchiveRunFailed:
		return errors.New("storage: invalid archive run final status")
	case !validArchiveCounts(finish.Counts):
		return errors.New("storage: invalid archive run counts")
	}
	return nil
}

// ValidateArchivePass checks what a pass records.
func ValidateArchivePass(pass ArchivePass) error {
	if !ValidArchiveID(pass.RunID) {
		return errors.New("storage: invalid archive run id")
	}
	if err := validateArchivePosition(pass.Watermark); err != nil {
		return err
	}
	if pass.Counts != nil && !validArchiveCounts(*pass.Counts) {
		return errors.New("storage: invalid archive run counts")
	}
	seen := make(map[string]bool, len(pass.Deferred)+len(pass.Resolved))
	for _, deferred := range pass.Deferred {
		if err := ValidateArchiveDeferred(deferred); err != nil {
			return err
		}
		if seen[deferred.AuditID] {
			return errors.New("storage: archive audit listed twice")
		}
		seen[deferred.AuditID] = true
	}
	for _, auditID := range pass.Resolved {
		if !validArchiveAuditID(auditID) || seen[auditID] {
			return errors.New("storage: invalid or repeated resolved archive audit")
		}
		seen[auditID] = true
	}
	return nil
}

// ValidateArchiveDeferred checks one deferred row.
func ValidateArchiveDeferred(deferred ArchiveDeferred) error {
	switch {
	case !validArchiveAuditID(deferred.AuditID):
		return errors.New("storage: invalid deferred archive audit id")
	case !validArchiveDeferredReason(deferred.Reason):
		return errors.New("storage: invalid archive deferral reason")
	case deferred.FirstSeenAtNS <= 0 || deferred.LastCheckedAtNS < deferred.FirstSeenAtNS:
		return errors.New("storage: invalid archive deferral time")
	}
	return nil
}

// validateArchiveSegment checks the segment row common to an intent and a
// reconciliation; state is the state the row will be inserted with.
func validateArchiveSegment(segment ArchiveSegment, state string, members, gaps int) error {
	switch {
	case !ValidArchiveID(segment.SegmentID) || !ValidArchiveID(segment.RunID):
		return errors.New("storage: invalid archive segment or run id")
	case segment.BundleKind != ArchiveBundleConversation && segment.BundleKind != ArchiveBundleBucket && segment.BundleKind != ArchiveBundleGaps:
		return errors.New("storage: invalid archive bundle kind")
	case segment.FormatVersion < 0:
		return errors.New("storage: invalid archive format version")
	case segment.ManifestName == "" || len(segment.ManifestName) > 1024 || strings.HasPrefix(segment.ManifestName, "/") ||
		strings.Contains(segment.ManifestName, "\\") || strings.Contains(segment.ManifestName, "\x00") || hasDotDotSegment(segment.ManifestName):
		return errors.New("storage: archive manifest name must be relative with forward slashes")
	case segment.ManifestSHA256 != nil && !validArchiveDigest(segment.ManifestSHA256):
		return errors.New("storage: invalid archive manifest digest")
	case !validArchiveDigest(segment.KeyFingerprint):
		return errors.New("storage: invalid archive key fingerprint")
	case segment.DiskBytes < 0 || segment.CreatedAtNS <= 0:
		return errors.New("storage: invalid archive segment size or time")
	case segment.State != state:
		return fmt.Errorf("storage: archive segment must be registered %s", state)
	case segment.RemovedAtNS != nil:
		return errors.New("storage: a registered archive segment cannot be removed")
	case segment.BundleKind == ArchiveBundleGaps && members != 0:
		return errors.New("storage: a gaps segment has no audit members")
	case segment.BundleKind != ArchiveBundleGaps && gaps != 0:
		return errors.New("storage: only a gaps segment has gap members")
	case segment.MemberCount != int64(members+gaps):
		return errors.New("storage: archive segment member count differs from its members")
	}
	if state == ArchiveSegmentSealed && (segment.ManifestSHA256 == nil || segment.SealedAtNS == nil || *segment.SealedAtNS <= 0) {
		return errors.New("storage: a sealed archive segment needs its manifest digest and seal time")
	}
	if state == ArchiveSegmentPublishing && segment.SealedAtNS != nil {
		return errors.New("storage: a publishing archive segment is not sealed")
	}
	return nil
}

func hasDotDotSegment(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || part == "" {
			return true
		}
	}
	return false
}

func validateArchiveMembers(members []ArchiveMember, requireStamp bool) error {
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		switch {
		case !validArchiveAuditID(member.AuditID):
			return errors.New("storage: invalid archive member audit id")
		case seen[member.AuditID]:
			return errors.New("storage: archive audit listed twice in one segment")
		case member.Revision < 1:
			return errors.New("storage: invalid archive member revision")
		case !validArchiveDigest(member.RecordDigest):
			return errors.New("storage: invalid archive record digest")
		case requireStamp && !validArchiveDigest(member.ChangeStamp):
			return errors.New("storage: invalid archive change stamp")
		case !requireStamp && member.ChangeStamp != nil:
			return errors.New("storage: a reconciled archive member has no change stamp")
		case member.StateChangedAtNS <= 0:
			return errors.New("storage: invalid archive member time")
		case member.SegmentID != "" || member.State != "":
			return errors.New("storage: the store sets an archive member's segment and state")
		}
		seen[member.AuditID] = true
	}
	return nil
}

func validateArchiveGaps(gaps []int64) error {
	seen := make(map[int64]bool, len(gaps))
	for _, id := range gaps {
		if id <= 0 || seen[id] {
			return errors.New("storage: invalid or repeated archive gap id")
		}
		seen[id] = true
	}
	return nil
}

// ValidateArchiveIntent checks a segment intent.
func ValidateArchiveIntent(intent ArchiveIntent) error {
	if err := validateArchiveSegment(intent.Segment, ArchiveSegmentPublishing, len(intent.Members), len(intent.GapIDs)); err != nil {
		return err
	}
	if err := validateArchiveMembers(intent.Members, true); err != nil {
		return err
	}
	return validateArchiveGaps(intent.GapIDs)
}

// ValidateArchiveSeal checks a seal.
func ValidateArchiveSeal(seal ArchiveSeal) error {
	switch {
	case !ValidArchiveID(seal.SegmentID):
		return errors.New("storage: invalid archive segment id")
	case !validArchiveDigest(seal.ManifestSHA256):
		return errors.New("storage: invalid archive manifest digest")
	case seal.DiskBytes < 0 || seal.SealedAtNS <= 0:
		return errors.New("storage: invalid archive seal size or time")
	}
	return nil
}

// ValidateArchiveReconciled checks a reconciled bundle.
func ValidateArchiveReconciled(reconciled ArchiveReconciled) error {
	if err := validateArchiveSegment(reconciled.Segment, ArchiveSegmentSealed, len(reconciled.Members), len(reconciled.GapIDs)); err != nil {
		return err
	}
	if err := validateArchiveMembers(reconciled.Members, false); err != nil {
		return err
	}
	return validateArchiveGaps(reconciled.GapIDs)
}
