package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"llmapi-logger/internal/storage"
)

// The cold archive catalog of migration 008 (design I). Every write goes
// through the single writer as one archiveWrite, alone in its transaction;
// every read uses the read-only pool. The export snapshot has its own
// selection queries (archive_snapshot.go).

// archiveWrite is one catalog write executed by the writer inside its
// per-operation savepoint (writeArchive).
type archiveWrite func(dbTransaction) error

func (store *Store) submitArchive(ctx context.Context, write archiveWrite) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeArchive, data: write})
}

func archiveInvalid(err error) error { return localWriteError("postgres: " + err.Error()) }

// archiveListLimit bounds one page of a catalog listing.
const archiveListLimit = 10000

func validArchiveLimit(limit int) bool { return limit >= 1 && limit <= archiveListLimit }

// BeginArchiveRun inserts a running run. Any other run still marked running
// was left by a process that stopped mid-run (M.3): the same operation marks
// it interrupted, with the new run's start as its finish time, and returns
// how many it marked.
func (store *Store) BeginArchiveRun(ctx context.Context, run ArchiveRun) (int64, error) {
	if err := storage.ValidateArchiveRun(run); err != nil {
		return 0, archiveInvalid(err)
	}
	var interrupted int64
	err := store.submitArchive(ctx, func(transaction dbTransaction) error {
		interrupted = 0
		result, err := transaction.Exec(`
UPDATE archive_runs SET status = 'interrupted', finished_at_ns = GREATEST($1, started_at_ns)
WHERE status = 'running'`, run.StartedAtNS)
		if err != nil {
			return fmt.Errorf("postgres archive: interrupt stale runs: %w", err)
		}
		if interrupted, err = result.RowsAffected(); err != nil {
			return fmt.Errorf("postgres archive: count stale runs: %w", err)
		}
		var watermarkStarted any
		var watermarkAudit any
		if run.Watermark != nil {
			watermarkStarted, watermarkAudit = run.Watermark.StartedAtNS, run.Watermark.AuditID
		}
		counts := run.Counts
		if _, err := transaction.Exec(`
INSERT INTO archive_runs (
    run_id, mode, cutoff_ns, started_at_ns, status,
    exported_audits, integrity_failed_audits, stale_audits, removed_audits, removed_gaps,
    deferred_audits, segments, disk_bytes, format_version, watermark_started_at_ns, watermark_audit_id
) VALUES ($1, $2, $3, $4, 'running', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			run.RunID, run.Mode, run.CutoffNS, run.StartedAtNS,
			counts.ExportedAudits, counts.IntegrityFailedAudits, counts.StaleAudits, counts.RemovedAudits, counts.RemovedGaps,
			counts.DeferredAudits, counts.Segments, counts.DiskBytes, run.FormatVersion, watermarkStarted, watermarkAudit); err != nil {
			return fmt.Errorf("postgres archive: insert run: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return interrupted, nil
}

// FinishArchiveRun ends a running run. A run that is not running is
// sql.ErrNoRows.
func (store *Store) FinishArchiveRun(ctx context.Context, finish ArchiveRunFinish) error {
	if err := storage.ValidateArchiveRunFinish(finish); err != nil {
		return archiveInvalid(err)
	}
	return store.submitArchive(ctx, func(transaction dbTransaction) error {
		counts := finish.Counts
		result, err := transaction.Exec(`
UPDATE archive_runs
SET status = $1, finished_at_ns = GREATEST($2, started_at_ns),
    exported_audits = $3, integrity_failed_audits = $4, stale_audits = $5, removed_audits = $6,
    removed_gaps = $7, deferred_audits = $8, segments = $9, disk_bytes = $10
WHERE run_id = $11 AND status = 'running'`,
			finish.Status, finish.FinishedAtNS, counts.ExportedAudits, counts.IntegrityFailedAudits, counts.StaleAudits,
			counts.RemovedAudits, counts.RemovedGaps, counts.DeferredAudits, counts.Segments, counts.DiskBytes, finish.RunID)
		if err != nil {
			return fmt.Errorf("postgres archive: finish run: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("postgres archive: count finished run: %w", err)
		}
		if affected != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
}

// RecordArchivePass records a pass in one operation: the run's new
// watermark and counters, the deferred audits and the resolved ones. The run
// must be running (sql.ErrNoRows otherwise). The runner calls it only after
// every segment of the pass is sealed, so an audit behind the watermark is
// always either a current member, deferred, or in a segment the catalog
// knows (R.6).
func (store *Store) RecordArchivePass(ctx context.Context, pass ArchivePass) error {
	if err := storage.ValidateArchivePass(pass); err != nil {
		return archiveInvalid(err)
	}
	owned := cloneArchivePass(pass)
	return store.submitArchive(ctx, func(transaction dbTransaction) error {
		var running bool
		if err := transaction.QueryRow(`SELECT status = 'running' FROM archive_runs WHERE run_id = $1 FOR UPDATE`, owned.RunID).Scan(&running); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return sql.ErrNoRows
			}
			return fmt.Errorf("postgres archive: read run: %w", err)
		}
		if !running {
			return sql.ErrNoRows
		}
		if owned.Watermark != nil {
			if _, err := transaction.Exec(`
UPDATE archive_runs SET watermark_started_at_ns = $1, watermark_audit_id = $2 WHERE run_id = $3`,
				owned.Watermark.StartedAtNS, owned.Watermark.AuditID, owned.RunID); err != nil {
				return fmt.Errorf("postgres archive: update watermark: %w", err)
			}
		}
		if counts := owned.Counts; counts != nil {
			if _, err := transaction.Exec(`
UPDATE archive_runs
SET exported_audits = $1, integrity_failed_audits = $2, stale_audits = $3, removed_audits = $4,
    removed_gaps = $5, deferred_audits = $6, segments = $7, disk_bytes = $8
WHERE run_id = $9`, counts.ExportedAudits, counts.IntegrityFailedAudits, counts.StaleAudits, counts.RemovedAudits,
				counts.RemovedGaps, counts.DeferredAudits, counts.Segments, counts.DiskBytes, owned.RunID); err != nil {
				return fmt.Errorf("postgres archive: update run counts: %w", err)
			}
		}
		if err := upsertArchiveDeferred(transaction, owned.Deferred); err != nil {
			return err
		}
		return deleteArchiveDeferred(transaction, owned.Resolved)
	})
}

// UpsertArchiveDeferred inserts deferred audits, or updates the reason and
// last check of ones already deferred, keeping their first_seen_at_ns.
func (store *Store) UpsertArchiveDeferred(ctx context.Context, deferred []ArchiveDeferred) error {
	if len(deferred) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(deferred))
	for _, row := range deferred {
		if err := storage.ValidateArchiveDeferred(row); err != nil {
			return archiveInvalid(err)
		}
		if seen[row.AuditID] {
			return localWriteError("postgres: archive audit listed twice")
		}
		seen[row.AuditID] = true
	}
	owned := append([]ArchiveDeferred(nil), deferred...)
	return store.submitArchive(ctx, func(transaction dbTransaction) error {
		return upsertArchiveDeferred(transaction, owned)
	})
}

// DeleteArchiveDeferred forgets deferred audits; unknown ids are ignored.
func (store *Store) DeleteArchiveDeferred(ctx context.Context, auditIDs []string) error {
	if len(auditIDs) == 0 {
		return nil
	}
	for _, auditID := range auditIDs {
		if auditID == "" {
			return localWriteError("postgres: empty deferred archive audit id")
		}
	}
	owned := append([]string(nil), auditIDs...)
	return store.submitArchive(ctx, func(transaction dbTransaction) error {
		return deleteArchiveDeferred(transaction, owned)
	})
}

func upsertArchiveDeferred(transaction dbTransaction, deferred []ArchiveDeferred) error {
	for _, row := range deferred {
		if _, err := transaction.Exec(`
INSERT INTO archive_deferred (audit_id, reason, first_seen_at_ns, last_checked_at_ns)
VALUES ($1, $2, $3, $4)
ON CONFLICT (audit_id) DO UPDATE
SET reason = EXCLUDED.reason,
    last_checked_at_ns = GREATEST(archive_deferred.last_checked_at_ns, EXCLUDED.last_checked_at_ns)`,
			row.AuditID, row.Reason, row.FirstSeenAtNS, row.LastCheckedAtNS); err != nil {
			return fmt.Errorf("postgres archive: upsert deferred audit: %w", err)
		}
	}
	return nil
}

func deleteArchiveDeferred(transaction dbTransaction, auditIDs []string) error {
	for start := 0; start < len(auditIDs); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(auditIDs))
		arguments := stringsToAny(auditIDs[start:end])
		if _, err := transaction.Exec(`DELETE FROM archive_deferred WHERE audit_id IN (`+placeholders(len(arguments))+`)`, arguments...); err != nil {
			return fmt.Errorf("postgres archive: delete deferred audits: %w", err)
		}
	}
	return nil
}

func cloneArchivePass(pass ArchivePass) ArchivePass {
	owned := pass
	if pass.Watermark != nil {
		watermark := *pass.Watermark
		owned.Watermark = &watermark
	}
	if pass.Counts != nil {
		counts := *pass.Counts
		owned.Counts = &counts
	}
	owned.Deferred = append([]ArchiveDeferred(nil), pass.Deferred...)
	owned.Resolved = append([]string(nil), pass.Resolved...)
	return owned
}

// RegisterArchiveIntent registers a segment in state publishing with its
// members and gap members (H.2 step 4). For each member, in one operation:
//   - its change stamp is recomputed in this transaction with the function
//     the export snapshot used. A member whose audit is gone or whose stamp
//     differs from the snapshot's is registered stale: the audit changed after
//     the export and will be selected again;
//   - an older sealed row of the same audit is marked stale first, so the
//     partial unique index archive_members_current_idx holds (Q12 item 5); if
//     the audit already has a hot_removed row, the new member is stale;
//   - the revision must be above every revision the audit has.
//
// The run must exist. The result lists the stale and superseded rows.
func (store *Store) RegisterArchiveIntent(ctx context.Context, intent ArchiveIntent) (ArchiveIntentResult, error) {
	if err := storage.ValidateArchiveIntent(intent); err != nil {
		return ArchiveIntentResult{}, archiveInvalid(err)
	}
	owned := cloneArchiveIntent(intent)
	var result ArchiveIntentResult
	err := store.submitArchive(ctx, func(transaction dbTransaction) error {
		result = ArchiveIntentResult{}
		if err := insertArchiveSegment(transaction, owned.Segment); err != nil {
			return err
		}
		members := append([]ArchiveMember(nil), owned.Members...)
		sort.Slice(members, func(left, right int) bool { return members[left].AuditID < members[right].AuditID })
		known, err := readIntentMemberState(transaction, members)
		if err != nil {
			return err
		}
		for _, member := range members {
			state, superseded, err := registerIntentMember(transaction, owned.Segment.SegmentID, member, known[member.AuditID])
			if err != nil {
				return err
			}
			if state == ArchiveMemberStale {
				result.Stale = append(result.Stale, ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision})
			}
			if superseded != nil {
				result.Superseded = append(result.Superseded, *superseded)
			}
		}
		for _, gapID := range owned.GapIDs {
			if _, err := transaction.Exec(`
INSERT INTO archive_gap_members (gap_id, segment_id, state) VALUES ($1, $2, 'sealed')`, gapID, owned.Segment.SegmentID); err != nil {
				return fmt.Errorf("postgres archive: insert gap member: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return ArchiveIntentResult{}, err
	}
	return result, nil
}

const (
	ArchiveMemberSealed     = storage.ArchiveMemberSealed
	ArchiveMemberHotRemoved = storage.ArchiveMemberHotRemoved
	ArchiveMemberStale      = storage.ArchiveMemberStale
)

// intentMemberState is what the catalog and the hot store already hold for
// one audit of an intent, read in batches before the members are inserted.
type intentMemberState struct {
	highestRevision int64
	hasCurrent      bool
	currentRevision int64
	currentState    string
	stamp           archiveStamp
}

// readIntentMemberState reads, for every member and a few hundred at a time,
// the highest revision, the current (not stale) row locked FOR UPDATE, and
// the change stamp recomputed in this transaction, so the writer does not pay
// a round trip per table and member.
func readIntentMemberState(transaction dbTransaction, members []ArchiveMember) (map[string]*intentMemberState, error) {
	known := make(map[string]*intentMemberState, len(members))
	ids := make([]string, 0, len(members))
	for _, member := range members {
		known[member.AuditID] = &intentMemberState{}
		ids = append(ids, member.AuditID)
	}
	for start := 0; start < len(ids); start += archiveStampBatch {
		end := min(start+archiveStampBatch, len(ids))
		arguments := stringsToAny(ids[start:end])
		rows, err := transaction.Query(`
SELECT audit_id, MAX(revision) FROM archive_members
WHERE audit_id IN (`+placeholders(len(arguments))+`) GROUP BY audit_id`, arguments...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read member revisions: %w", err)
		}
		for rows.Next() {
			var auditID string
			var revision int64
			if err := rows.Scan(&auditID, &revision); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan member revision: %w", err)
			}
			known[auditID].highestRevision = revision
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read member revisions: %w", err)
		}
		rows, err = transaction.Query(`
SELECT audit_id, revision, state FROM archive_members
WHERE audit_id IN (`+placeholders(len(arguments))+`) AND state <> 'stale'
ORDER BY audit_id
FOR UPDATE`, arguments...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read current members: %w", err)
		}
		for rows.Next() {
			var auditID, state string
			var revision int64
			if err := rows.Scan(&auditID, &revision, &state); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan current member: %w", err)
			}
			entry := known[auditID]
			entry.hasCurrent, entry.currentRevision, entry.currentState = true, revision, state
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read current members: %w", err)
		}
	}
	stamps, err := archiveChangeStamps(context.Background(), transaction, ids)
	if err != nil {
		return nil, err
	}
	for id, stamp := range stamps {
		known[id].stamp = stamp
	}
	return known, nil
}

func registerIntentMember(transaction dbTransaction, segmentID string, member ArchiveMember, known *intentMemberState) (string, *ArchiveMemberKey, error) {
	if member.Revision <= known.highestRevision {
		return "", nil, localWriteError("postgres: archive member revision is not above the audit's existing revisions")
	}
	state := ArchiveMemberSealed
	if !known.stamp.exists || !bytes.Equal(known.stamp.stamp[:], member.ChangeStamp) {
		state = ArchiveMemberStale
	}
	var superseded *ArchiveMemberKey
	if known.hasCurrent {
		switch known.currentState {
		case ArchiveMemberSealed:
			if _, err := transaction.Exec(`
UPDATE archive_members SET state = 'stale', state_changed_at_ns = $1
WHERE audit_id = $2 AND revision = $3`, member.StateChangedAtNS, member.AuditID, known.currentRevision); err != nil {
				return "", nil, fmt.Errorf("postgres archive: supersede member: %w", err)
			}
			superseded = &ArchiveMemberKey{AuditID: member.AuditID, Revision: known.currentRevision}
		default:
			// A removed audit cannot be exported again; whatever was read is
			// not a current member.
			state = ArchiveMemberStale
		}
	}
	if _, err := transaction.Exec(`
INSERT INTO archive_members (
    audit_id, revision, segment_id, record_digest, change_stamp, state,
    started_at_ns, turn_created_at_ns, state_changed_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		member.AuditID, member.Revision, segmentID, member.RecordDigest, member.ChangeStamp, state,
		member.StartedAtNS, member.TurnCreatedAtNS, member.StateChangedAtNS); err != nil {
		return "", nil, fmt.Errorf("postgres archive: insert member: %w", err)
	}
	return state, superseded, nil
}
func insertArchiveSegment(transaction dbTransaction, segment ArchiveSegment) error {
	if _, err := transaction.Exec(`
INSERT INTO archive_segments (
    segment_id, run_id, bundle_kind, format_version, manifest_name, manifest_sha256,
    key_fingerprint, encrypted, member_count, disk_bytes, first_started_at_ns,
    last_ended_at_ns, state, created_at_ns, sealed_at_ns
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		segment.SegmentID, segment.RunID, segment.BundleKind, segment.FormatVersion, segment.ManifestName,
		nullableBytes(segment.ManifestSHA256), segment.KeyFingerprint, boolInteger(segment.Encrypted),
		segment.MemberCount, segment.DiskBytes, segment.FirstStartedAtNS, segment.LastEndedAtNS,
		segment.State, segment.CreatedAtNS, segment.SealedAtNS); err != nil {
		return fmt.Errorf("postgres archive: insert segment: %w", err)
	}
	return nil
}

func cloneArchiveSegment(segment ArchiveSegment) ArchiveSegment {
	segment.ManifestSHA256 = cloneBytes(segment.ManifestSHA256)
	segment.KeyFingerprint = cloneBytes(segment.KeyFingerprint)
	segment.FirstStartedAtNS = cloneInt64(segment.FirstStartedAtNS)
	segment.LastEndedAtNS = cloneInt64(segment.LastEndedAtNS)
	segment.SealedAtNS = cloneInt64(segment.SealedAtNS)
	segment.RemovedAtNS = cloneInt64(segment.RemovedAtNS)
	return segment
}

func cloneArchiveMembers(members []ArchiveMember) []ArchiveMember {
	owned := make([]ArchiveMember, len(members))
	for index, member := range members {
		member.RecordDigest = cloneBytes(member.RecordDigest)
		member.ChangeStamp = cloneBytes(member.ChangeStamp)
		member.TurnCreatedAtNS = cloneInt64(member.TurnCreatedAtNS)
		owned[index] = member
	}
	return owned
}

func cloneArchiveIntent(intent ArchiveIntent) ArchiveIntent {
	return ArchiveIntent{Segment: cloneArchiveSegment(intent.Segment), Members: cloneArchiveMembers(intent.Members), GapIDs: append([]int64(nil), intent.GapIDs...)}
}

// SealArchiveSegment marks a publishing segment sealed (H.2 step 7) with its
// manifest digest and disk size. Sealing a segment that is already sealed
// with the same manifest digest succeeds, so a retry after a lost
// acknowledgement is harmless; any other state is sql.ErrNoRows.
func (store *Store) SealArchiveSegment(ctx context.Context, seal ArchiveSeal) error {
	if err := storage.ValidateArchiveSeal(seal); err != nil {
		return archiveInvalid(err)
	}
	digest := cloneBytes(seal.ManifestSHA256)
	return store.submitArchive(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`
UPDATE archive_segments
SET state = 'sealed', manifest_sha256 = $1, disk_bytes = $2, sealed_at_ns = $3
WHERE segment_id = $4 AND state = 'publishing'`, digest, seal.DiskBytes, seal.SealedAtNS, seal.SegmentID)
		if err != nil {
			return fmt.Errorf("postgres archive: seal segment: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected == 1 {
			return err
		}
		var state string
		var stored []byte
		if err := transaction.QueryRow(`SELECT state, manifest_sha256 FROM archive_segments WHERE segment_id = $1`, seal.SegmentID).Scan(&state, &stored); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return sql.ErrNoRows
			}
			return fmt.Errorf("postgres archive: read segment: %w", err)
		}
		if state == storage.ArchiveSegmentSealed && bytes.Equal(stored, digest) {
			return nil
		}
		return sql.ErrNoRows
	})
}

// DropArchiveIntent deletes a publishing segment and, by cascade, its member
// and gap member rows (H.2 step 6 failure, H.6 item 1). It reports whether a
// row was deleted; an unknown segment is not an error, a segment in any other
// state is refused. Rows the intent marked superseded stay stale: stale is
// never a reason to delete, and the audit is selected again.
func (store *Store) DropArchiveIntent(ctx context.Context, segmentID string) (bool, error) {
	if !storage.ValidArchiveID(segmentID) {
		return false, localWriteError("postgres: invalid archive segment id")
	}
	var dropped bool
	err := store.submitArchive(ctx, func(transaction dbTransaction) error {
		dropped = false
		result, err := transaction.Exec(`DELETE FROM archive_segments WHERE segment_id = $1 AND state = 'publishing'`, segmentID)
		if err != nil {
			return fmt.Errorf("postgres archive: drop intent: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("postgres archive: count dropped intent: %w", err)
		}
		if affected == 1 {
			dropped = true
			return nil
		}
		var exists bool
		if err := transaction.QueryRow(`SELECT EXISTS (SELECT 1 FROM archive_segments WHERE segment_id = $1)`, segmentID).Scan(&exists); err != nil {
			return fmt.Errorf("postgres archive: read segment: %w", err)
		}
		if exists {
			return localWriteError("postgres: only a publishing archive segment can be dropped")
		}
		return nil
	})
	return dropped, err
}

// RegisterReconciledArchive registers a verified bundle the catalog did not
// know (H.6 item 2): a sealed segment, its members stale without a change
// stamp, its gaps sealed. A member whose (audit_id, revision) the catalog
// already has, or a gap already in another segment, is skipped and listed in
// the result; the segment row is always inserted. A segment or manifest name
// the catalog already has is an error.
func (store *Store) RegisterReconciledArchive(ctx context.Context, reconciled ArchiveReconciled) (ArchiveReconciledResult, error) {
	if err := storage.ValidateArchiveReconciled(reconciled); err != nil {
		return ArchiveReconciledResult{}, archiveInvalid(err)
	}
	owned := ArchiveReconciled{Segment: cloneArchiveSegment(reconciled.Segment), Members: cloneArchiveMembers(reconciled.Members), GapIDs: append([]int64(nil), reconciled.GapIDs...)}
	var result ArchiveReconciledResult
	err := store.submitArchive(ctx, func(transaction dbTransaction) error {
		result = ArchiveReconciledResult{}
		if err := insertArchiveSegment(transaction, owned.Segment); err != nil {
			return err
		}
		for _, member := range owned.Members {
			inserted, err := transaction.Exec(`
INSERT INTO archive_members (
    audit_id, revision, segment_id, record_digest, change_stamp, state,
    started_at_ns, turn_created_at_ns, state_changed_at_ns
) VALUES ($1, $2, $3, $4, NULL, 'stale', $5, $6, $7)
ON CONFLICT (audit_id, revision) DO NOTHING`,
				member.AuditID, member.Revision, owned.Segment.SegmentID, member.RecordDigest,
				member.StartedAtNS, member.TurnCreatedAtNS, member.StateChangedAtNS)
			if err != nil {
				return fmt.Errorf("postgres archive: insert reconciled member: %w", err)
			}
			if affected, err := inserted.RowsAffected(); err != nil {
				return fmt.Errorf("postgres archive: count reconciled member: %w", err)
			} else if affected == 0 {
				result.SkippedMembers = append(result.SkippedMembers, ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision})
			}
		}
		for _, gapID := range owned.GapIDs {
			inserted, err := transaction.Exec(`
INSERT INTO archive_gap_members (gap_id, segment_id, state) VALUES ($1, $2, 'sealed')
ON CONFLICT (gap_id) DO NOTHING`, gapID, owned.Segment.SegmentID)
			if err != nil {
				return fmt.Errorf("postgres archive: insert reconciled gap: %w", err)
			}
			if affected, err := inserted.RowsAffected(); err != nil {
				return fmt.Errorf("postgres archive: count reconciled gap: %w", err)
			} else if affected == 0 {
				result.SkippedGaps = append(result.SkippedGaps, gapID)
			}
		}
		return nil
	})
	if err != nil {
		return ArchiveReconciledResult{}, err
	}
	return result, nil
}

// --- Reads (read-only pool) ---

func (store *Store) archiveReadable(ctx context.Context) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return nil
}

const archiveSegmentColumns = `segment_id, run_id, bundle_kind, format_version, manifest_name, manifest_sha256,
       key_fingerprint, encrypted, member_count, disk_bytes, first_started_at_ns, last_ended_at_ns,
       state, created_at_ns, sealed_at_ns, removed_at_ns`

func scanArchiveSegment(row rowScanner) (ArchiveSegment, error) {
	var segment ArchiveSegment
	var encrypted int64
	var first, last, sealed, removed sql.NullInt64
	if err := row.Scan(&segment.SegmentID, &segment.RunID, &segment.BundleKind, &segment.FormatVersion,
		&segment.ManifestName, &segment.ManifestSHA256, &segment.KeyFingerprint, &encrypted, &segment.MemberCount,
		&segment.DiskBytes, &first, &last, &segment.State, &segment.CreatedAtNS, &sealed, &removed); err != nil {
		return ArchiveSegment{}, err
	}
	segment.ManifestSHA256 = cloneBytes(segment.ManifestSHA256)
	segment.KeyFingerprint = cloneBytes(segment.KeyFingerprint)
	segment.Encrypted = encrypted != 0
	segment.FirstStartedAtNS, segment.LastEndedAtNS = nullInt64Pointer(first), nullInt64Pointer(last)
	segment.SealedAtNS, segment.RemovedAtNS = nullInt64Pointer(sealed), nullInt64Pointer(removed)
	return segment, nil
}

// ArchiveSegment returns one segment, sql.ErrNoRows when unknown.
func (store *Store) ArchiveSegment(ctx context.Context, segmentID string) (ArchiveSegment, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return ArchiveSegment{}, err
	}
	segment, err := scanArchiveSegment(store.readerDB.QueryRowContext(ctx, `SELECT `+archiveSegmentColumns+` FROM archive_segments WHERE segment_id = $1`, segmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return ArchiveSegment{}, sql.ErrNoRows
	}
	if err != nil {
		return ArchiveSegment{}, fmt.Errorf("postgres archive: read segment: %w", err)
	}
	return segment, nil
}

// ListArchiveSegments returns the segments in state (publishing, sealed or
// hot_removed) in segment_id order, at most limit after the segment id after.
func (store *Store) ListArchiveSegments(ctx context.Context, state, after string, limit int) ([]ArchiveSegment, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres: invalid archive list limit")
	}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+archiveSegmentColumns+`
FROM archive_segments WHERE state = $1 AND segment_id > $2 ORDER BY segment_id LIMIT $3`, state, after, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: list segments: %w", err)
	}
	var segments []ArchiveSegment
	for rows.Next() {
		segment, err := scanArchiveSegment(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan segment: %w", err)
		}
		segments = append(segments, segment)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: list segments: %w", err)
	}
	return segments, nil
}

// ArchiveMemberQuery selects members: by State when set, by SegmentID when
// set, in (audit_id, revision) order after After, at most Limit.
type ArchiveMemberQuery struct {
	State     string
	SegmentID string
	After     *ArchiveMemberKey
	Limit     int
}

// ListArchiveMembers returns one page of members.
func (store *Store) ListArchiveMembers(ctx context.Context, query ArchiveMemberQuery) ([]ArchiveMember, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if !validArchiveLimit(query.Limit) {
		return nil, errors.New("postgres: invalid archive list limit")
	}
	afterAudit, afterRevision := "", int64(0)
	if query.After != nil {
		afterAudit, afterRevision = query.After.AuditID, query.After.Revision
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, revision, segment_id, record_digest, change_stamp, state,
       started_at_ns, turn_created_at_ns, state_changed_at_ns
FROM archive_members
WHERE ($1 = '' OR state = $1) AND ($2 = '' OR segment_id = $2) AND (audit_id, revision) > ($3, $4)
ORDER BY audit_id, revision
LIMIT $5`, query.State, query.SegmentID, afterAudit, afterRevision, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: list members: %w", err)
	}
	var members []ArchiveMember
	for rows.Next() {
		var member ArchiveMember
		var turnCreated sql.NullInt64
		if err := rows.Scan(&member.AuditID, &member.Revision, &member.SegmentID, &member.RecordDigest, &member.ChangeStamp,
			&member.State, &member.StartedAtNS, &turnCreated, &member.StateChangedAtNS); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan member: %w", err)
		}
		member.RecordDigest, member.ChangeStamp = cloneBytes(member.RecordDigest), cloneBytes(member.ChangeStamp)
		member.TurnCreatedAtNS = nullInt64Pointer(turnCreated)
		members = append(members, member)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: list members: %w", err)
	}
	return members, nil
}

// ListArchiveGapMembers returns the gap members of a segment, or of every
// segment when segmentID is empty, in state when set, after gap id after.
func (store *Store) ListArchiveGapMembers(ctx context.Context, segmentID, state string, after int64, limit int) ([]ArchiveGapMember, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres: invalid archive list limit")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT gap_id, segment_id, state FROM archive_gap_members
WHERE ($1 = '' OR segment_id = $1) AND ($2 = '' OR state = $2) AND gap_id > $3
ORDER BY gap_id LIMIT $4`, segmentID, state, after, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: list gap members: %w", err)
	}
	var gaps []ArchiveGapMember
	for rows.Next() {
		var gap ArchiveGapMember
		if err := rows.Scan(&gap.GapID, &gap.SegmentID, &gap.State); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan gap member: %w", err)
		}
		gaps = append(gaps, gap)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: list gap members: %w", err)
	}
	return gaps, nil
}

// ArchiveCurrentRevision returns the highest revision any member of the
// audit has, 0 when the catalog has none.
func (store *Store) ArchiveCurrentRevision(ctx context.Context, auditID string) (int64, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return 0, err
	}
	var revision int64
	if err := store.readerDB.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM archive_members WHERE audit_id = $1`, auditID).Scan(&revision); err != nil {
		return 0, fmt.Errorf("postgres archive: read revision: %w", err)
	}
	return revision, nil
}

// ListArchiveDeferred returns deferred audits in audit_id order after after.
func (store *Store) ListArchiveDeferred(ctx context.Context, after string, limit int) ([]ArchiveDeferred, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres: invalid archive list limit")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT audit_id, reason, first_seen_at_ns, last_checked_at_ns FROM archive_deferred
WHERE audit_id > $1 ORDER BY audit_id LIMIT $2`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: list deferred audits: %w", err)
	}
	var deferred []ArchiveDeferred
	for rows.Next() {
		var row ArchiveDeferred
		if err := rows.Scan(&row.AuditID, &row.Reason, &row.FirstSeenAtNS, &row.LastCheckedAtNS); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan deferred audit: %w", err)
		}
		deferred = append(deferred, row)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: list deferred audits: %w", err)
	}
	return deferred, nil
}

const archiveRunColumns = `run_id, mode, cutoff_ns, started_at_ns, finished_at_ns, status,
       exported_audits, integrity_failed_audits, stale_audits, removed_audits, removed_gaps,
       deferred_audits, segments, disk_bytes, format_version, watermark_started_at_ns, watermark_audit_id`

func scanArchiveRun(row rowScanner) (ArchiveRun, error) {
	var run ArchiveRun
	var finished, watermarkStarted sql.NullInt64
	var watermarkAudit sql.NullString
	counts := &run.Counts
	if err := row.Scan(&run.RunID, &run.Mode, &run.CutoffNS, &run.StartedAtNS, &finished, &run.Status,
		&counts.ExportedAudits, &counts.IntegrityFailedAudits, &counts.StaleAudits, &counts.RemovedAudits, &counts.RemovedGaps,
		&counts.DeferredAudits, &counts.Segments, &counts.DiskBytes, &run.FormatVersion, &watermarkStarted, &watermarkAudit); err != nil {
		return ArchiveRun{}, err
	}
	run.FinishedAtNS = nullInt64Pointer(finished)
	if watermarkStarted.Valid && watermarkAudit.Valid {
		run.Watermark = &ArchivePosition{StartedAtNS: watermarkStarted.Int64, AuditID: watermarkAudit.String}
	}
	return run, nil
}

// LastArchiveRun returns the run that started last, among the runs in
// status when it is set, or nil when there is none. The catch-up of H.1
// asks for the last completed run.
func (store *Store) LastArchiveRun(ctx context.Context, status string) (*ArchiveRun, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	run, err := scanArchiveRun(store.readerDB.QueryRowContext(ctx, `SELECT `+archiveRunColumns+`
FROM archive_runs WHERE ($1 = '' OR status = $1) ORDER BY started_at_ns DESC, run_id DESC LIMIT 1`, status))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read last run: %w", err)
	}
	return &run, nil
}

// ArchiveWatermark returns the selection watermark of a format version: the
// watermark of the latest run of that version that recorded one, nil when
// none did (B.1: a new format version starts from the beginning).
func (store *Store) ArchiveWatermark(ctx context.Context, formatVersion int64) (*ArchivePosition, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	var position ArchivePosition
	err := store.readerDB.QueryRowContext(ctx, `
SELECT watermark_started_at_ns, watermark_audit_id FROM archive_runs
WHERE format_version = $1 AND watermark_audit_id IS NOT NULL
ORDER BY started_at_ns DESC, run_id DESC LIMIT 1`, formatVersion).Scan(&position.StartedAtNS, &position.AuditID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read watermark: %w", err)
	}
	return &position, nil
}
