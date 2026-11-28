package runner

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

// reconcile brings the catalog and the archive directory together at the
// start of a run (H.6). It only reads, renames and registers; the only files
// it removes are the bundle writer's own temporary files.
//
//  1. A segment left publishing whose manifest is published and passes the
//     re-read checks against its intent rows is sealed; any other has its
//     intent dropped, and a manifest that fails is rejected (renamed).
//  2. A verified bundle the catalog does not know is registered sealed, its
//     members stale (never a reason to delete) unless the audit already has
//     a current member.
//  3. Temporary files of the writer's naming are removed; data files no
//     manifest lists are renamed .orphan.
//
// Item 4 of H.6 (continuing removal) belongs to the removal phase.
func (current *run) reconcile() error {
	options := current.options()
	publishing, err := options.Store.Segments(current.ctx, storage.ArchiveSegmentPublishing)
	if err != nil {
		return fail("catalog_failed", err)
	}
	for _, segment := range publishing {
		if err := current.reconcilePublishing(segment); err != nil {
			return err
		}
	}
	index, err := bundle.BuildIndex(current.ctx, options.Dir, options.Keys)
	if err != nil {
		if current.ctx.Err() != nil {
			return current.ctx.Err()
		}
		return fail("", err)
	}
	for _, entry := range index.Bundles() {
		if err := current.reconcileUnknown(entry); err != nil {
			return err
		}
	}
	leftovers := index.Leftovers()
	for _, path := range leftovers.Temporary {
		if bundle.IsTempName(filepath.Base(path)) {
			_ = os.Remove(path)
		}
	}
	for _, path := range leftovers.DataWithoutManifest {
		_, _ = bundle.MarkOrphan(path)
	}
	if problems := len(index.Problems()); problems > 0 {
		options.Logger.Warn("archive directory has manifests that do not verify", "error_category", "archive_manifest_unusable", "manifests", problems)
	}
	return nil
}

func (current *run) reconcilePublishing(segment storage.ArchiveSegment) error {
	options := current.options()
	path := filepath.Join(options.Dir, filepath.FromSlash(segment.ManifestName))
	if _, err := os.Lstat(path); err != nil {
		// Never published (or already rejected): its data files, if linked,
		// are orphans for step 3.
		return current.dropReconciled(segment.SegmentID)
	}
	ok, err := current.verifyAgainstCatalog(path, segment)
	if err != nil {
		return err
	}
	if !ok {
		_ = bundle.Reject(path)
		return current.dropReconciled(segment.SegmentID)
	}
	digest, size, err := fileDigest(path)
	if err != nil {
		return fail("seal_failed", err)
	}
	if err := options.Store.SealSegment(current.ctx, storage.ArchiveSeal{
		SegmentID: segment.SegmentID, ManifestSHA256: digest[:], DiskBytes: segment.DiskBytes + size, SealedAtNS: current.now().UnixNano(),
	}); err != nil {
		return current.catalogFailure(err)
	}
	current.result.ReconciledSealed++
	return nil
}

func (current *run) dropReconciled(segmentID string) error {
	if _, err := current.options().Store.DropIntent(current.ctx, segmentID); err != nil {
		return current.catalogFailure(err)
	}
	return nil
}

func (current *run) catalogFailure(err error) error {
	if current.ctx.Err() != nil {
		return current.ctx.Err()
	}
	return fail("catalog_failed", err)
}

// verifyAgainstCatalog re-reads a publishing segment's bundle (J.2) and
// compares it with its intent rows: the same segment, the same members with
// the same revisions and digests, or the same gaps.
func (current *run) verifyAgainstCatalog(path string, segment storage.ArchiveSegment) (bool, error) {
	options := current.options()
	read, release := current.readOptions()
	defer release()
	opened, err := bundle.Open(path, read)
	if err != nil {
		return false, nil
	}
	report, err := opened.Verify(current.ctx)
	if err != nil {
		if current.ctx.Err() != nil {
			return false, current.ctx.Err()
		}
		return false, nil
	}
	if report.Manifest.SegmentID != segment.SegmentID {
		return false, nil
	}
	if segment.BundleKind == storage.ArchiveBundleGaps {
		gaps, err := options.Store.SegmentGaps(current.ctx, segment.SegmentID)
		if err != nil {
			return false, current.catalogFailure(err)
		}
		return report.Gaps == int64(len(gaps)), nil
	}
	members, err := options.Store.SegmentMembers(current.ctx, segment.SegmentID)
	if err != nil {
		return false, current.catalogFailure(err)
	}
	if len(members) != len(report.Members) {
		return false, nil
	}
	byKey := make(map[storage.ArchiveMemberKey][]byte, len(members))
	for _, member := range members {
		byKey[storage.ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision}] = member.RecordDigest
	}
	for _, member := range report.Members {
		digest, ok := byKey[storage.ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision}]
		if !ok || !bytes.Equal(digest, member.Digest[:]) {
			return false, nil
		}
	}
	return true, nil
}

// reconcileUnknown registers a bundle on disk that the catalog does not
// know (H.6 item 2), once it verifies.
func (current *run) reconcileUnknown(entry bundle.Entry) error {
	options := current.options()
	manifest := entry.Manifest
	if _, found, err := options.Store.Segment(current.ctx, manifest.SegmentID); err != nil {
		return current.catalogFailure(err)
	} else if found {
		return nil
	}
	read, release := current.readOptions()
	defer release()
	opened, err := bundle.Open(entry.ManifestPath, read)
	if err != nil {
		return nil
	}
	report, err := opened.Verify(current.ctx)
	if err != nil {
		if current.ctx.Err() != nil {
			return current.ctx.Err()
		}
		options.Logger.Warn("archive bundle unknown to the catalog does not verify", "error_category", "archive_manifest_unusable", "reason", bundle.ReasonOf(err))
		return nil
	}
	relative, err := filepath.Rel(options.Dir, entry.ManifestPath)
	if err != nil {
		return nil
	}
	nowNS := current.now().UnixNano()
	digest, size, err := fileDigest(entry.ManifestPath)
	if err != nil {
		return nil
	}
	var diskBytes int64
	for _, file := range manifest.Files {
		diskBytes += file.Bytes
	}
	formatVersion, err := formatVersionOf(manifest)
	if err != nil {
		return nil
	}
	fingerprint := manifest.KeyFingerprint
	first, last := manifest.FirstStartedAtNS, manifest.LastEndedAtNS
	reconciled := storage.ArchiveReconciled{Segment: storage.ArchiveSegment{
		SegmentID: manifest.SegmentID, RunID: current.id, BundleKind: manifest.BundleKind, FormatVersion: formatVersion,
		ManifestName: filepath.ToSlash(relative), ManifestSHA256: digest[:], KeyFingerprint: fingerprint[:], Encrypted: manifest.Encrypted,
		DiskBytes: diskBytes + size, FirstStartedAtNS: &first, LastEndedAtNS: &last, State: storage.ArchiveSegmentSealed,
		CreatedAtNS: nowNS, SealedAtNS: &nowNS,
	}}
	if manifest.BundleKind == archive.BundleGaps {
		err := opened.Gaps(current.ctx, func(gap archive.Gap) error {
			reconciled.GapIDs = append(reconciled.GapIDs, gap.ID)
			return nil
		})
		if err != nil {
			return nil
		}
	} else {
		for _, member := range report.Members {
			hasCurrent, err := options.Store.HasCurrentMember(current.ctx, member.AuditID)
			if err != nil {
				return current.catalogFailure(err)
			}
			if hasCurrent {
				continue
			}
			var started int64
			for _, listed := range manifest.Members {
				if listed.AuditID == member.AuditID && listed.Revision == member.Revision {
					started = listed.StartedAtNS
				}
			}
			reconciled.Members = append(reconciled.Members, storage.ArchiveMember{
				AuditID: member.AuditID, Revision: member.Revision, RecordDigest: bytes.Clone(member.Digest[:]),
				StartedAtNS: started, StateChangedAtNS: nowNS,
			})
		}
	}
	reconciled.Segment.MemberCount = int64(len(reconciled.Members) + len(reconciled.GapIDs))
	if _, err := options.Store.RegisterReconciled(current.ctx, reconciled); err != nil {
		return current.catalogFailure(err)
	}
	options.Logger.Info("archive bundle registered from the directory", "bundle_kind", manifest.BundleKind, "members", reconciled.Segment.MemberCount)
	return nil
}

var errFormatVersion = errors.New("archive runner: manifest format version is not a number")

func formatVersionOf(manifest *archive.Manifest) (int64, error) {
	var version int64
	for _, char := range manifest.FormatVersion {
		if char < '0' || char > '9' {
			return 0, errFormatVersion
		}
		version = version*10 + int64(char-'0')
	}
	if manifest.FormatVersion == "" {
		return 0, errFormatVersion
	}
	return version, nil
}
