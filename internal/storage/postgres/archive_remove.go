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

// The cold archive's verified removal (doc/design/issue-59-stage4-cold-archive.md
// M.2): the only path that deletes archived evidence from the hot store. Each
// batch is one writer operation alone in its transaction, so a member is
// marked hot_removed exactly when its audit was deleted, never one without
// the other (M.3).

// archiveRemovalRequest is one writeRemoveArchived operation.
type archiveRemovalRequest struct {
	Batch       []ArchiveRemoval
	RemovedAtNS int64
	Result      ArchiveRemovalResult
}

// archiveGapRemovalRequest is one writeRemoveArchivedGaps operation.
type archiveGapRemovalRequest struct {
	Limit       int
	RemovedAtNS int64
	Result      ArchiveGapRemovalResult
}

// RemoveArchived removes one batch of archived audits from the hot store
// (M.2) and returns an outcome per member, in the order given. In one
// transaction alone on the writer:
//
//  1. the members' catalog rows are locked; only a member still sealed, in a
//     segment that is sealed and of format version
//     storage.ArchiveRemovalMinFormatVersion or later, whose segment id,
//     revision and change stamp are those given, is considered. Any other is
//     skipped, which is what makes a repeated batch harmless;
//  2. the change stamp of each is recomputed in the transaction with the
//     function the export used (archiveChangeStamps). An audit no longer in
//     the hot store is only marked hot_removed; a stamp that differs from
//     the one the member stores marks the member stale and deletes nothing;
//  3. the audits whose stamps are unchanged are deleted by deleteAuditBatch,
//     unchanged from retention: checkpoints of retained children, leaf to
//     root deletion, pruning of derived detail, object GC;
//  4. those members are marked hot_removed at removedAtNS, and every segment
//     of the batch with no sealed member left is marked hot_removed.
func (store *Store) RemoveArchived(ctx context.Context, batch []ArchiveRemoval, removedAtNS int64) (ArchiveRemovalResult, error) {
	if err := storage.ValidateArchiveRemovals(batch); err != nil {
		return ArchiveRemovalResult{}, archiveInvalid(err)
	}
	if removedAtNS <= 0 {
		return ArchiveRemovalResult{}, localWriteError("postgres: invalid archive removal time")
	}
	if ctx == nil {
		return ArchiveRemovalResult{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ArchiveRemovalResult{}, ErrClosed
	}
	owned := make([]ArchiveRemoval, len(batch))
	for index, removal := range batch {
		removal.ChangeStamp = cloneBytes(removal.ChangeStamp)
		owned[index] = removal
	}
	request := &archiveRemovalRequest{Batch: owned, RemovedAtNS: removedAtNS}
	if err := store.submitSync(ctx, writeRequest{kind: writeRemoveArchived, data: request}); err != nil {
		return ArchiveRemovalResult{}, err
	}
	return request.Result, nil
}

// removableMember is a locked catalog row of a removal batch.
type removableMember struct {
	segmentID string
	revision  int64
	stamp     []byte
}

func removeArchived(transaction dbTransaction, request *archiveRemovalRequest) error {
	if request == nil || storage.ValidateArchiveRemovals(request.Batch) != nil || request.RemovedAtNS <= 0 {
		return errors.New("postgres writer: invalid archive removal request")
	}
	request.Result = ArchiveRemovalResult{}
	ids := make([]string, len(request.Batch))
	for index, removal := range request.Batch {
		ids[index] = removal.AuditID
	}
	locked, err := lockRemovableMembers(transaction, ids)
	if err != nil {
		return err
	}
	outcomes := make(map[string]string, len(request.Batch))
	var candidates []string
	for _, removal := range request.Batch {
		row, ok := locked[removal.AuditID]
		if !ok || row.segmentID != removal.SegmentID || row.revision != removal.Revision || !bytes.Equal(row.stamp, removal.ChangeStamp) {
			outcomes[removal.AuditID] = storage.ArchiveRemovalSkipped
			continue
		}
		candidates = append(candidates, removal.AuditID)
	}
	stamps, err := archiveChangeStamps(context.Background(), transaction, candidates)
	if err != nil {
		return err
	}
	var deleteIDs []string
	for _, id := range candidates {
		current := stamps[id]
		switch {
		case !current.exists:
			outcomes[id] = storage.ArchiveRemovalAlreadyGone
		case !bytes.Equal(current.stamp[:], locked[id].stamp):
			outcomes[id] = storage.ArchiveRemovalStale
		default:
			outcomes[id] = storage.ArchiveRemovalRemoved
			deleteIDs = append(deleteIDs, id)
		}
	}
	// Every stamp is computed before anything is deleted: a checkpoint of a
	// child in this batch must not count as a change of that child.
	sort.Strings(deleteIDs)
	if err := deleteAuditBatch(transaction, deleteIDs); err != nil {
		return err
	}
	segments := map[string]bool{}
	for _, id := range candidates {
		state := storage.ArchiveMemberHotRemoved
		if outcomes[id] == storage.ArchiveRemovalStale {
			state = storage.ArchiveMemberStale
		}
		row := locked[id]
		result, err := transaction.Exec(`
UPDATE archive_members SET state = $1, state_changed_at_ns = $2
WHERE audit_id = $3 AND revision = $4 AND state = 'sealed'`, state, request.RemovedAtNS, id, row.revision)
		if err != nil {
			return fmt.Errorf("postgres archive: mark removed member: %w", err)
		}
		if err := requireOneRow(result, "mark removed member"); err != nil {
			return err
		}
		segments[row.segmentID] = true
	}
	removedSegments, err := markRemovedSegments(transaction, segments, "archive_members", request.RemovedAtNS)
	if err != nil {
		return err
	}
	request.Result.RemovedSegments = removedSegments
	request.Result.Outcomes = make([]ArchiveRemovalOutcome, len(request.Batch))
	for index, removal := range request.Batch {
		request.Result.Outcomes[index] = ArchiveRemovalOutcome{AuditID: removal.AuditID, Revision: removal.Revision, Outcome: outcomes[removal.AuditID]}
	}
	return nil
}

// lockRemovableMembers locks, FOR UPDATE, the removable member rows of the
// audits together with their segments: sealed members of sealed segments of
// a format version that may serve as the basis for a removal. The format
// gate is part of this statement, so no caller can remove on the basis of a
// trial bundle.
func lockRemovableMembers(transaction dbTransaction, auditIDs []string) (map[string]removableMember, error) {
	arguments := append(stringsToAny(auditIDs), storage.ArchiveRemovalMinFormatVersion)
	rows, err := transaction.Query(`
SELECT m.audit_id, m.revision, m.segment_id, m.change_stamp
FROM archive_members AS m
JOIN archive_segments AS s ON s.segment_id = m.segment_id
WHERE m.audit_id IN (`+placeholders(len(auditIDs))+`)
  AND m.state = 'sealed'
  AND s.state = 'sealed'
  AND s.format_version >= $`+fmt.Sprint(len(auditIDs)+1)+`
  AND s.bundle_kind <> 'gaps'
  AND m.change_stamp IS NOT NULL
ORDER BY m.audit_id
FOR UPDATE OF m, s`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: lock removable members: %w", err)
	}
	locked := make(map[string]removableMember, len(auditIDs))
	for rows.Next() {
		var auditID string
		var row removableMember
		if err := rows.Scan(&auditID, &row.revision, &row.segmentID, &row.stamp); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan removable member: %w", err)
		}
		row.stamp = cloneBytes(row.stamp)
		locked[auditID] = row
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: lock removable members: %w", err)
	}
	return locked, nil
}

// markRemovedSegments marks hot_removed every sealed segment of the set that
// has no sealed row left in members (archive_members or archive_gap_members)
// and returns how many it marked.
func markRemovedSegments(transaction dbTransaction, segments map[string]bool, members string, removedAtNS int64) (int64, error) {
	if len(segments) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(segments))
	for id := range segments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result, err := transaction.Exec(`
UPDATE archive_segments AS s SET state = 'hot_removed', removed_at_ns = GREATEST($1, s.sealed_at_ns)
WHERE s.segment_id IN (`+placeholders(len(ids), 1)+`)
  AND s.state = 'sealed'
  AND NOT EXISTS (SELECT 1 FROM `+members+` AS m WHERE m.segment_id = s.segment_id AND m.state = 'sealed')`,
		append([]any{removedAtNS}, stringsToAny(ids)...)...)
	if err != nil {
		return 0, fmt.Errorf("postgres archive: mark removed segments: %w", err)
	}
	marked, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres archive: count removed segments: %w", err)
	}
	return marked, nil
}

// RemoveArchivedGaps removes up to limit exported gaps from the hot store
// (M.2), in one transaction alone on the writer: the sealed gap members of
// sealed gaps segments of format version storage.ArchiveRemovalMinFormatVersion
// or later are locked in gap id order, their audit_gaps rows deleted, the
// members marked hot_removed, and the segments left without a sealed gap
// marked hot_removed. Gaps are only ever inserted (C.6), so they carry no
// change stamp. A result below limit means none is left.
func (store *Store) RemoveArchivedGaps(ctx context.Context, limit int, removedAtNS int64) (ArchiveGapRemovalResult, error) {
	if limit < 1 || limit > RetentionBatchLimit {
		return ArchiveGapRemovalResult{}, localWriteError(fmt.Sprintf("postgres: an archive gap removal batch holds 1 to %d gaps", RetentionBatchLimit))
	}
	if removedAtNS <= 0 {
		return ArchiveGapRemovalResult{}, localWriteError("postgres: invalid archive removal time")
	}
	if ctx == nil {
		return ArchiveGapRemovalResult{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ArchiveGapRemovalResult{}, ErrClosed
	}
	request := &archiveGapRemovalRequest{Limit: limit, RemovedAtNS: removedAtNS}
	if err := store.submitSync(ctx, writeRequest{kind: writeRemoveArchivedGaps, data: request}); err != nil {
		return ArchiveGapRemovalResult{}, err
	}
	return request.Result, nil
}

func removeArchivedGaps(transaction dbTransaction, request *archiveGapRemovalRequest) error {
	if request == nil || request.Limit < 1 || request.Limit > RetentionBatchLimit || request.RemovedAtNS <= 0 {
		return errors.New("postgres writer: invalid archive gap removal request")
	}
	request.Result = ArchiveGapRemovalResult{}
	rows, err := transaction.Query(`
SELECT g.gap_id, g.segment_id
FROM archive_gap_members AS g
JOIN archive_segments AS s ON s.segment_id = g.segment_id
WHERE g.state = 'sealed'
  AND s.state = 'sealed'
  AND s.format_version >= $1
  AND s.bundle_kind = 'gaps'
ORDER BY g.gap_id
LIMIT $2
FOR UPDATE OF g, s`, storage.ArchiveRemovalMinFormatVersion, request.Limit)
	if err != nil {
		return fmt.Errorf("postgres archive: lock removable gaps: %w", err)
	}
	var gapIDs []any
	segments := map[string]bool{}
	for rows.Next() {
		var gapID int64
		var segmentID string
		if err := rows.Scan(&gapID, &segmentID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres archive: scan removable gap: %w", err)
		}
		gapIDs = append(gapIDs, gapID)
		segments[segmentID] = true
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres archive: lock removable gaps: %w", err)
	}
	if len(gapIDs) == 0 {
		return nil
	}
	deleted, err := transaction.Exec(`DELETE FROM audit_gaps WHERE id IN (`+placeholders(len(gapIDs))+`)`, gapIDs...)
	if err != nil {
		return fmt.Errorf("postgres archive: delete removed gaps: %w", err)
	}
	if request.Result.DeletedRows, err = deleted.RowsAffected(); err != nil {
		return fmt.Errorf("postgres archive: count removed gaps: %w", err)
	}
	marked, err := transaction.Exec(`UPDATE archive_gap_members SET state = 'hot_removed' WHERE gap_id IN (`+placeholders(len(gapIDs))+`) AND state = 'sealed'`, gapIDs...)
	if err != nil {
		return fmt.Errorf("postgres archive: mark removed gaps: %w", err)
	}
	if request.Result.RemovedGaps, err = marked.RowsAffected(); err != nil {
		return fmt.Errorf("postgres archive: count marked gaps: %w", err)
	}
	if request.Result.RemovedGaps != int64(len(gapIDs)) {
		return errors.New("postgres archive: gap members changed during removal")
	}
	request.Result.RemovedSegments, err = markRemovedSegments(transaction, segments, "archive_gap_members", request.RemovedAtNS)
	return err
}

// ListRemovableArchiveMembers returns one page, in (audit_id, revision)
// order after after, of the members a removal may take: sealed members of
// sealed conversation or bucket segments of format version
// storage.ArchiveRemovalMinFormatVersion or later. The removal orders them
// itself (M.2); the writer checks every condition again under lock.
func (store *Store) ListRemovableArchiveMembers(ctx context.Context, after *ArchiveMemberKey, limit int) ([]ArchiveRemovable, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres: invalid archive list limit")
	}
	afterAudit, afterRevision := "", int64(0)
	if after != nil {
		afterAudit, afterRevision = after.AuditID, after.Revision
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT m.segment_id, m.audit_id, m.revision, m.change_stamp, m.started_at_ns, m.turn_created_at_ns
FROM archive_members AS m
JOIN archive_segments AS s ON s.segment_id = m.segment_id
WHERE m.state = 'sealed'
  AND s.state = 'sealed'
  AND s.format_version >= $1
  AND s.bundle_kind <> 'gaps'
  AND m.change_stamp IS NOT NULL
  AND (m.audit_id, m.revision) > ($2, $3)
ORDER BY m.audit_id, m.revision
LIMIT $4`, storage.ArchiveRemovalMinFormatVersion, afterAudit, afterRevision, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: list removable members: %w", err)
	}
	var members []ArchiveRemovable
	for rows.Next() {
		var member ArchiveRemovable
		var turnCreated sql.NullInt64
		if err := rows.Scan(&member.SegmentID, &member.AuditID, &member.Revision, &member.ChangeStamp, &member.StartedAtNS, &turnCreated); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan removable member: %w", err)
		}
		member.ChangeStamp = cloneBytes(member.ChangeStamp)
		member.TurnCreatedAtNS = nullInt64Pointer(turnCreated)
		members = append(members, member)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: list removable members: %w", err)
	}
	return members, nil
}
