package runner

import (
	"bytes"
	"path/filepath"
	"sort"
	"time"

	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/retention"
	"llmapi-logger/internal/storage"
)

// RemovalResult is what one removal phase did (design M.2).
type RemovalResult struct {
	// Removed counts the audits deleted from the hot store, Stale the
	// members whose audit changed since the export (kept, re-exported by a
	// later pass at a higher revision), AlreadyGone the members whose audit
	// was no longer in the hot store, Skipped the members the store found no
	// longer removable when their batch ran.
	Removed     int64
	Stale       int64
	AlreadyGone int64
	Skipped     int64
	// RemovedGaps counts the gap members removed, RemovedSegments the
	// segments that had no sealed member left.
	RemovedGaps     int64
	RemovedSegments int64
	Batches         int64
	GapBatches      int64
	// BundleCheckFailedSegments counts the segments whose bundle failed the
	// check before removal (checkBundle); their members (HeldBackMembers)
	// and gaps (HeldBackGaps) stay sealed in the hot store for a later run.
	BundleCheckFailedSegments int64
	HeldBackMembers           int64
	HeldBackGaps              int64
	Duration                  time.Duration
}

// Reasons of a failed bundle check that are not the bundle package's.
const (
	// ReasonManifestDigestMismatch: the manifest verifies but is not the one
	// whose SHA-256 the catalog recorded when the segment was sealed.
	ReasonManifestDigestMismatch = "manifest_digest_mismatch"
	// ReasonSegmentMismatch: the manifest at the catalog's name describes
	// another segment.
	ReasonSegmentMismatch = "segment_mismatch"
)

// RemovalOrder returns the members in the order removal takes them (M.2,
// decision 5.2 item 2): turn_created_at_ns descending, members without a
// turn first, then audit_id descending (byte order, the catalog's "C"
// collation). A turn's parent is always created strictly before it
// (chooseTurnParent only considers earlier turns), so every child comes
// before its parent and no batch deletes a parent whose child a later batch
// still has to remove: the checkpoint of a retained child never rewrites a
// member that is still to be removed, which would make it stale. The input
// is not changed.
func RemovalOrder(members []storage.ArchiveRemovable) []storage.ArchiveRemovable {
	ordered := append([]storage.ArchiveRemovable(nil), members...)
	sort.SliceStable(ordered, func(left, right int) bool {
		a, b := ordered[left], ordered[right]
		switch {
		case a.TurnCreatedAtNS == nil && b.TurnCreatedAtNS != nil:
			return true
		case a.TurnCreatedAtNS != nil && b.TurnCreatedAtNS == nil:
			return false
		case a.TurnCreatedAtNS != nil && *a.TurnCreatedAtNS != *b.TurnCreatedAtNS:
			return *a.TurnCreatedAtNS > *b.TurnCreatedAtNS
		}
		return a.AuditID > b.AuditID
	})
	return ordered
}

// checkBundle checks a segment's bundle once per run before its first
// removal batch (design R.9, the maintainer's option B): the manifest and
// every data file it lists exist, the manifest's key fingerprint and MAC
// verify with the archive signing key, each data file's size and SHA-256
// equal the manifest's (bundle.CheckFiles: nothing is decrypted or
// decompressed), and the manifest's SHA-256 equals the one the catalog
// stored when the segment was sealed. It reports whether the segment's
// members may be removed. A failure is logged once with a stable code and
// counted; the members stay sealed. The check is outside the removal
// transaction, so a file can still go between it and the delete: that
// window is accepted. It is a condition in addition to the store's, never in
// place of them. A segment the catalog does not know or that is no longer
// sealed is left to the store, which skips its members.
func (current *run) checkBundle(checked map[string]bool, segmentID string) (bool, error) {
	if ok, done := checked[segmentID]; done {
		return ok, nil
	}
	options := current.options()
	segment, found, err := options.Store.Segment(current.ctx, segmentID)
	if err != nil {
		return false, current.removalFailure(err)
	}
	if !found || segment.State != storage.ArchiveSegmentSealed {
		checked[segmentID] = true
		return true, nil
	}
	reason := ""
	path := filepath.Join(options.Dir, filepath.FromSlash(segment.ManifestName))
	manifest, digest, err := bundle.CheckFiles(current.ctx, path, options.Keys)
	switch {
	case err != nil && current.ctx.Err() != nil:
		return false, current.ctx.Err()
	case err != nil:
		if reason = bundle.ReasonOf(err); reason == "" {
			reason = "check_failed"
		}
	case !bytes.Equal(digest[:], segment.ManifestSHA256):
		reason = ReasonManifestDigestMismatch
	case manifest.SegmentID != segmentID:
		reason = ReasonSegmentMismatch
	}
	checked[segmentID] = reason == ""
	if reason != "" {
		current.result.Removal.BundleCheckFailedSegments++
		options.Logger.Warn("archive bundle check failed before removal: its members stay in the hot store",
			"error_category", "archive_bundle_check_failed", "reason", reason, "bundle_kind", segment.BundleKind)
	}
	return reason == "", nil
}

// remove is the removal phase: every removable member in RemovalOrder, in
// batches sized by the retention Batcher (from one audit, doubling after a
// full batch within half a second, shrinking above a second), each followed
// by a pause as long as it took, at most five seconds; then the exported
// gaps, in batches of storage.RetentionBatchLimit. It stops at the run's
// deadline or when ctx ends. A failed batch fails the run (removal_failed);
// what was committed stays committed, and the next run continues with the
// members still sealed.
func (current *run) remove() error {
	options := current.options()
	stats := &current.result.Removal
	started := current.now()
	defer func() { stats.Duration = current.now().Sub(started) }()
	batcher := current.runner.batcher
	batcher.BeginRun()

	members, err := options.Store.RemovableMembers(current.ctx)
	if err != nil {
		return current.removalFailure(err)
	}
	ordered := RemovalOrder(members)
	checked := map[string]bool{}
	var last time.Duration
	ran := false
	// between runs before each batch but the first: the crash point of M.3
	// between batches, the pause, and the stop conditions.
	between := func() (bool, error) {
		if err := current.ctx.Err(); err != nil {
			return false, err
		}
		if ran {
			if err := current.step(StepBetweenRemovalBatches); err != nil {
				return false, err
			}
			current.runner.pause(current.ctx, retention.PauseAfter(last))
			if err := current.ctx.Err(); err != nil {
				return false, err
			}
		}
		if !current.now().Before(current.deadline) {
			current.result.DeadlineReached = true
			return false, nil
		}
		return true, nil
	}
	for len(ordered) > 0 {
		proceed, err := between()
		if err != nil || !proceed {
			return current.endRemoval(err, proceed, started)
		}
		size := batcher.Size()
		// The batch takes the next members in order whose bundle passed its
		// check; the members of a segment that failed are held back.
		batch := make([]storage.ArchiveRemoval, 0, size)
		for len(ordered) > 0 && len(batch) < size {
			member := ordered[0]
			ordered = ordered[1:]
			ok, err := current.checkBundle(checked, member.SegmentID)
			if err != nil {
				return err
			}
			if !ok {
				stats.HeldBackMembers++
				continue
			}
			batch = append(batch, member.ArchiveRemoval)
		}
		if len(batch) == 0 {
			break
		}
		take := len(batch)
		begin := current.now()
		result, err := options.Store.RemoveArchived(current.ctx, batch, begin.UnixNano())
		elapsed := current.now().Sub(begin)
		if err != nil {
			if batcher.Failed(current.ctx, take, elapsed) {
				options.Logger.Info("archive removal batch reduced to one audit", "failed_audit_batch", take)
			}
			return current.removalFailure(err)
		}
		current.tally(result)
		batcher.Done(size, take, take, elapsed)
		ran, last = true, elapsed
	}
	// P item 16: the gaps after the audits, one gaps segment at a time, each
	// after the same bundle check.
	sealedSegments, err := options.Store.Segments(current.ctx, storage.ArchiveSegmentSealed)
	if err != nil {
		return current.removalFailure(err)
	}
	for _, segment := range sealedSegments {
		if segment.BundleKind != storage.ArchiveBundleGaps || segment.FormatVersion < storage.ArchiveRemovalMinFormatVersion {
			continue
		}
		for {
			proceed, err := between()
			if err != nil || !proceed {
				return current.endRemoval(err, proceed, started)
			}
			ok, err := current.checkBundle(checked, segment.SegmentID)
			if err != nil {
				return err
			}
			if !ok {
				stats.HeldBackGaps += segment.MemberCount
				break
			}
			begin := current.now()
			result, err := options.Store.RemoveArchivedGaps(current.ctx, segment.SegmentID, storage.RetentionBatchLimit, begin.UnixNano())
			if err != nil {
				return current.removalFailure(err)
			}
			ran, last = true, current.now().Sub(begin)
			stats.GapBatches++
			stats.RemovedGaps += result.RemovedGaps
			stats.RemovedSegments += result.RemovedSegments
			current.result.Counts.RemovedGaps += result.RemovedGaps
			if result.RemovedGaps < storage.RetentionBatchLimit {
				break
			}
		}
	}
	batcher.EndRun()
	if err := current.step(StepAfterRemoval); err != nil {
		return err
	}
	current.logRemoval(started)
	return nil
}

// tally adds one batch's outcomes to the run.
func (current *run) tally(result storage.ArchiveRemovalResult) {
	stats := &current.result.Removal
	stats.Batches++
	stats.RemovedSegments += result.RemovedSegments
	for _, outcome := range result.Outcomes {
		switch outcome.Outcome {
		case storage.ArchiveRemovalRemoved:
			stats.Removed++
			current.result.Counts.RemovedAudits++
		case storage.ArchiveRemovalStale:
			stats.Stale++
			current.result.Counts.StaleAudits++
		case storage.ArchiveRemovalAlreadyGone:
			stats.AlreadyGone++
		default:
			stats.Skipped++
		}
	}
}

// endRemoval ends a removal phase stopped before its work was done: by ctx
// or a crash step (err), or by the deadline (proceed false, err nil).
func (current *run) endRemoval(err error, proceed bool, started time.Time) error {
	if err != nil {
		return err
	}
	if !proceed {
		current.runner.batcher.EndRun()
		current.logRemoval(started)
	}
	return nil
}

// removalFailure is the run error of a failed removal step.
func (current *run) removalFailure(err error) error {
	if current.ctx.Err() != nil {
		return current.ctx.Err()
	}
	return fail("removal_failed", err)
}

// logRemoval writes the removal phase's completion line: stable codes and
// counts only, no audit id, segment id or path.
func (current *run) logRemoval(started time.Time) {
	stats := current.result.Removal
	attributes := []any{
		"event", "archive_removal_completed",
		"removed_audits", stats.Removed,
		"stale_audits", stats.Stale,
		"already_gone_audits", stats.AlreadyGone,
		"skipped_audits", stats.Skipped,
		"removed_gaps", stats.RemovedGaps,
		"removed_segments", stats.RemovedSegments,
		"bundle_check_failed_segments", stats.BundleCheckFailedSegments,
		"held_back_members", stats.HeldBackMembers,
		"held_back_gaps", stats.HeldBackGaps,
		"batches", stats.Batches + stats.GapBatches,
		"duration_ms", current.now().Sub(started).Milliseconds(),
	}
	if current.result.DeadlineReached {
		attributes = append(attributes, "deadline_reached", true)
	}
	current.runner.options.Logger.Info("archive removal completed", attributes...)
}
