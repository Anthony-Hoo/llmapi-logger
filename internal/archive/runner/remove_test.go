package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/storage"
)

// --- The fake store's removal, with the semantics of postgres.RemoveArchived
// as far as the runner relies on them: the format and state gates, the stamp
// check before any deletion, and the checkpoint of a retained child, which
// changes the child's stamp. ---

func (store *fakeStore) removableLocked(member *storage.ArchiveMember) bool {
	segment := store.segments[member.SegmentID]
	return member.State == storage.ArchiveMemberSealed && segment != nil && segment.State == storage.ArchiveSegmentSealed &&
		segment.FormatVersion >= storage.ArchiveRemovalMinFormatVersion && segment.BundleKind != storage.ArchiveBundleGaps
}

func (store *fakeStore) RemovableMembers(context.Context) ([]storage.ArchiveRemovable, error) {
	if err := store.injected("RemovableMembers"); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, "RemovableMembers")
	var out []storage.ArchiveRemovable
	for _, member := range store.members {
		if store.removableLocked(member) {
			out = append(out, storage.ArchiveRemovable{
				ArchiveRemoval: storage.ArchiveRemoval{SegmentID: member.SegmentID, AuditID: member.AuditID, Revision: member.Revision, ChangeStamp: bytes.Clone(member.ChangeStamp)},
				StartedAtNS:    member.StartedAtNS, TurnCreatedAtNS: member.TurnCreatedAtNS,
			})
		}
	}
	// The store lists in (audit_id, revision) order; the runner orders.
	sort.Slice(out, func(left, right int) bool { return out[left].AuditID < out[right].AuditID })
	return out, nil
}

func (store *fakeStore) RemoveArchived(_ context.Context, batch []storage.ArchiveRemoval, removedAtNS int64) (storage.ArchiveRemovalResult, error) {
	if err := store.injected("RemoveArchived"); err != nil {
		return storage.ArchiveRemovalResult{}, err
	}
	if err := storage.ValidateArchiveRemovals(batch); err != nil {
		return storage.ArchiveRemovalResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, "RemoveArchived")
	var ids []string
	for _, removal := range batch {
		ids = append(ids, removal.AuditID)
	}
	store.removalBatches = append(store.removalBatches, ids)
	result := storage.ArchiveRemovalResult{}
	var deleted []string
	segments := map[string]bool{}
	for _, removal := range batch {
		outcome := storage.ArchiveRemovalSkipped
		var target *storage.ArchiveMember
		for _, member := range store.members {
			if member.AuditID == removal.AuditID && member.Revision == removal.Revision {
				target = member
			}
		}
		if target != nil && store.removableLocked(target) && target.SegmentID == removal.SegmentID && bytes.Equal(target.ChangeStamp, removal.ChangeStamp) {
			audit, exists := store.audits[removal.AuditID]
			switch {
			case !exists:
				outcome = storage.ArchiveRemovalAlreadyGone
				target.State = storage.ArchiveMemberHotRemoved
			case !bytes.Equal(audit.stamp[:], target.ChangeStamp):
				outcome = storage.ArchiveRemovalStale
				target.State = storage.ArchiveMemberStale
			default:
				outcome = storage.ArchiveRemovalRemoved
				target.State = storage.ArchiveMemberHotRemoved
				deleted = append(deleted, removal.AuditID)
			}
			target.StateChangedAtNS = removedAtNS
			segments[target.SegmentID] = true
		}
		result.Outcomes = append(result.Outcomes, storage.ArchiveRemovalOutcome{AuditID: removal.AuditID, Revision: removal.Revision, Outcome: outcome})
	}
	gone := map[string]bool{}
	for _, id := range deleted {
		gone[id] = true
		delete(store.audits, id)
	}
	// checkpointRetainedChildren: a child that stays hot is rewritten.
	for _, audit := range store.audits {
		if audit.parent != "" && gone[audit.parent] {
			store.checkpoints++
			audit.parent = ""
			audit.stamp = stampOf(audit.id, 1000+store.checkpoints)
		}
	}
	for id := range segments {
		if store.segmentEmptyLocked(id) {
			store.segments[id].State = storage.ArchiveSegmentHotRemoved
			result.RemovedSegments++
		}
	}
	return result, nil
}

func (store *fakeStore) segmentEmptyLocked(segmentID string) bool {
	if store.segments[segmentID].State != storage.ArchiveSegmentSealed {
		return false
	}
	for _, member := range store.members {
		if member.SegmentID == segmentID && member.State == storage.ArchiveMemberSealed {
			return false
		}
	}
	for gapID, owner := range store.gapMembers {
		if owner == segmentID && !store.removedGaps[gapID] {
			return false
		}
	}
	return true
}

func (store *fakeStore) RemoveArchivedGaps(_ context.Context, segmentID string, limit int, _ int64) (storage.ArchiveGapRemovalResult, error) {
	if err := store.injected("RemoveArchivedGaps"); err != nil {
		return storage.ArchiveGapRemovalResult{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls = append(store.calls, "RemoveArchivedGaps")
	var ids []int64
	for gapID, owner := range store.gapMembers {
		segment := store.segments[owner]
		if owner == segmentID && !store.removedGaps[gapID] && segment.State == storage.ArchiveSegmentSealed && segment.FormatVersion >= storage.ArchiveRemovalMinFormatVersion {
			ids = append(ids, gapID)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	if len(ids) > limit {
		ids = ids[:limit]
	}
	var result storage.ArchiveGapRemovalResult
	segments := map[string]bool{}
	for _, id := range ids {
		store.removedGaps[id] = true
		segments[store.gapMembers[id]] = true
		result.RemovedGaps++
		kept := store.gaps[:0]
		for _, gap := range store.gaps {
			if gap.ID == id {
				result.DeletedRows++
				continue
			}
			kept = append(kept, gap)
		}
		store.gaps = kept
	}
	for id := range segments {
		if store.segmentEmptyLocked(id) {
			store.segments[id].State = storage.ArchiveSegmentHotRemoved
			result.RemovedSegments++
		}
	}
	return result, nil
}

func (store *fakeStore) memberStates(auditID string) map[int64]string {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := map[int64]string{}
	for _, member := range store.members {
		if member.AuditID == auditID {
			out[member.Revision] = member.State
		}
	}
	return out
}

// newRemovalHarness is a harness in archive_then_delete at the built-in
// format version, which removal accepts (version 1 and later).
func newRemovalHarness(t *testing.T) *harness {
	h := newHarness(t)
	h.options.Mode = storage.ArchiveModeArchiveThenDelete
	return h
}

// oneAtATime makes the runner's removal batches one audit each for good: a
// slow failure of a batch of several sets the size and its ceiling to one,
// and a run that does not complete keeps that ceiling.
func oneAtATime(runner *Runner) {
	runner.batcher.BeginRun()
	runner.batcher.Failed(context.Background(), 2, 2*time.Second)
}

func int64Pointer(value int64) *int64 { return &value }

// The order of M.2: members without a turn first, then turn_created_at_ns
// descending, ties by audit_id descending; the input is not changed.
func TestRemovalOrder(t *testing.T) {
	member := func(id string, started int64, created *int64) storage.ArchiveRemovable {
		return storage.ArchiveRemovable{ArchiveRemoval: storage.ArchiveRemoval{AuditID: id}, StartedAtNS: started, TurnCreatedAtNS: created}
	}
	input := []storage.ArchiveRemovable{
		member("b", 1, int64Pointer(20)), member("a", 2, nil), member("d", 3, int64Pointer(20)), member("c", 4, int64Pointer(30)),
		member("e", 5, nil), member("f", 6, int64Pointer(10)),
	}
	kept := append([]storage.ArchiveRemovable(nil), input...)
	var got []string
	for _, m := range RemovalOrder(input) {
		got = append(got, m.AuditID)
	}
	if want := []string{"e", "a", "c", "d", "b", "f"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if !reflect.DeepEqual(input, kept) {
		t.Fatal("RemovalOrder changed its input")
	}
}

// startedDescending is the order M.2 rejects, kept here only as the
// counter-example: started_at_ns descending.
func startedDescending(members []storage.ArchiveRemovable) []storage.ArchiveRemovable {
	ordered := append([]storage.ArchiveRemovable(nil), members...)
	sort.SliceStable(ordered, func(left, right int) bool { return ordered[left].StartedAtNS > ordered[right].StartedAtNS })
	return ordered
}

// The A/B case of M.2: A starts at 0 s and ends at 100 s, B starts at 10 s
// and ends at 20 s. B is parsed first and becomes A's parent, so A's turn is
// created after B's although A started first. Turn creation descending
// takes the child A first; start descending takes the parent B first.
func TestRemovalOrderPutsTheChildFirstWhereStartOrderDoesNot(t *testing.T) {
	second := int64(time.Second)
	a := storage.ArchiveRemovable{ArchiveRemoval: storage.ArchiveRemoval{AuditID: "a-child"}, StartedAtNS: 0, TurnCreatedAtNS: int64Pointer(100 * second)}
	b := storage.ArchiveRemovable{ArchiveRemoval: storage.ArchiveRemoval{AuditID: "b-parent"}, StartedAtNS: 10 * second, TurnCreatedAtNS: int64Pointer(20 * second)}
	if got := RemovalOrder([]storage.ArchiveRemovable{b, a}); got[0].AuditID != "a-child" {
		t.Fatalf("removal order takes %s first", got[0].AuditID)
	}
	if got := startedDescending([]storage.ArchiveRemovable{a, b}); got[0].AuditID != "b-parent" {
		t.Fatalf("the counter-example takes %s first", got[0].AuditID)
	}
}

// archive_then_delete at format version 1: one run exports, then removes
// every member one audit per batch in the order of M.2 (children before
// parents, turnless first), and then the gaps. No checkpoint is written and
// no member turns stale because of the removal's own work; every member and
// segment is hot_removed. A second run removes nothing.
func TestArchiveThenDeleteRemovesChildrenBeforeParents(t *testing.T) {
	h := newRemovalHarness(t)
	chain := h.addConversation("conv-chain", "openai", 4, baseTimeNS)
	other := h.addConversation("conv-other", "anthropic", 2, baseTimeNS+int64(time.Minute))
	h.addTurnless("turnless-1", "openai", baseTimeNS+5)
	// A branch: a second child of the chain's second turn, created last.
	branchStarted := baseTimeNS + 10*int64(time.Second)
	branchRecord := h.fixture.withTurn(h.fixture.audit("conv-chain-branch", "openai", branchStarted), "conv-chain", chain[1].build(), branchStarted+10, "branch message")
	branchConversation, branchCreated := "conv-chain", branchStarted+10
	h.store.audits["conv-chain-branch"] = &fakeAudit{id: "conv-chain-branch", startedNS: branchStarted, protocol: "openai", conversation: &branchConversation,
		turnCreatedNS: &branchCreated, stamp: stampOf("conv-chain-branch", 0), build: func() *archive.Record { return branchRecord }, parent: chain[1].id}
	h.store.gaps = []archive.Gap{{ID: 1, StartedAtNS: baseTimeNS, EndedAtNS: baseTimeNS + 10, Reason: "queue_full", RequestCount: 1, CreatedAtNS: baseTimeNS + 11}}
	runner := h.runner()
	oneAtATime(runner)
	result, err := runner.RunOnce(context.Background())
	if err != nil || result.Status != storage.ArchiveRunCompleted {
		t.Fatalf("run %+v, %v", result, err)
	}
	total := len(chain) + len(other) + 2
	removal := result.Removal
	if removal.Removed != int64(total) || removal.Stale != 0 || removal.AlreadyGone != 0 || removal.Skipped != 0 ||
		removal.Batches != int64(total) || removal.RemovedGaps != 1 || result.Counts.RemovedAudits != int64(total) || result.Counts.RemovedGaps != 1 {
		t.Fatalf("removal %+v counts %+v", removal, result.Counts)
	}
	if h.store.checkpoints != 0 {
		t.Fatalf("%d checkpoints", h.store.checkpoints)
	}
	var order []string
	for _, batch := range h.store.removalBatches {
		if len(batch) != 1 {
			t.Fatalf("batch of %d", len(batch))
		}
		order = append(order, batch[0])
	}
	position := map[string]int{}
	for index, id := range order {
		position[id] = index
	}
	if position["turnless-1"] != 0 || position["conv-chain-branch"] > position[chain[1].id] {
		t.Fatalf("order %v", order)
	}
	for _, audits := range [][]*fakeAudit{chain, other} {
		for index := 1; index < len(audits); index++ {
			if position[audits[index].id] > position[audits[index-1].id] {
				t.Fatalf("parent %s removed before child %s: %v", audits[index-1].id, audits[index].id, order)
			}
		}
	}
	if len(h.store.audits) != 0 || len(h.store.gaps) != 0 {
		t.Fatalf("left %d audits, %d gaps", len(h.store.audits), len(h.store.gaps))
	}
	for _, segment := range h.store.segments {
		if segment.State != storage.ArchiveSegmentHotRemoved {
			t.Fatalf("segment %s is %s", segment.BundleKind, segment.State)
		}
	}
	// RemoveArchivedGaps comes after the last RemoveArchived.
	calls := strings.Join(h.store.calls, ",")
	if !strings.HasSuffix(calls, "RemoveArchived,RemoveArchivedGaps") {
		t.Fatalf("calls %s", calls)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"archive removal completed"`) || !strings.Contains(logs, fmt.Sprintf(`"removed_audits":%d`, total)) ||
		strings.Contains(logs, "conv-chain") || strings.Contains(logs, h.dir) {
		t.Fatalf("logs %s", logs)
	}
	again := h.mustRun()
	if again.Removal.Removed != 0 || again.Counts.ExportedAudits != 0 {
		t.Fatalf("second run %+v", again)
	}
}

// The counter-example of M.2 on the same fake: removing in start order
// takes a parent while its child is still to be removed; the checkpoint
// rewrites the child, which then turns stale. RemovalOrder avoids exactly
// this (the test above). This drives the store directly, not the runner.
func TestStartOrderMakesFalseStaleMembers(t *testing.T) {
	h := newRemovalHarness(t)
	h.options.Mode = storage.ArchiveModeExportOnly
	chain := h.addConversation("conv-ab", "openai", 3, baseTimeNS)
	h.mustRun()
	members, err := h.store.RemovableMembers(context.Background())
	if err != nil || len(members) != len(chain) {
		t.Fatalf("members %d, %v", len(members), err)
	}
	stale := 0
	for _, member := range startedDescending(reverseStarted(members)) {
		result, err := h.store.RemoveArchived(context.Background(), []storage.ArchiveRemoval{member.ArchiveRemoval}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if result.Outcomes[0].Outcome == storage.ArchiveRemovalStale {
			stale++
		}
	}
	if h.store.checkpoints == 0 || stale == 0 {
		t.Fatalf("checkpoints %d stale %d", h.store.checkpoints, stale)
	}
}

// reverseStarted gives the members the start times of the A/B case: the
// later a turn was created, the earlier its request started.
func reverseStarted(members []storage.ArchiveRemovable) []storage.ArchiveRemovable {
	out := append([]storage.ArchiveRemovable(nil), members...)
	for index := range out {
		out[index].StartedAtNS = -*out[index].TurnCreatedAtNS
	}
	return out
}

// M.4: a member whose audit changed after the export is not removed; it
// turns stale, and the next run re-exports it at revision 2 (the existing
// stale re-inclusion) and removes it then.
func TestStaleMemberIsExportedAgainAndRemoved(t *testing.T) {
	h := newRemovalHarness(t)
	audit := h.addTurnless("changed-1", "openai", baseTimeNS)
	h.addTurnless("plain-1", "openai", baseTimeNS+1)
	h.options.Step = func(step string) error {
		if step == StepAfterPublish {
			audit.stamp = stampOf("changed-1", 1)
		}
		return nil
	}
	first := h.mustRun()
	if first.Removal.Removed != 1 || first.Removal.Stale != 1 || first.Counts.StaleAudits != 1 {
		t.Fatalf("first run %+v", first)
	}
	if states := h.store.memberStates("changed-1"); !reflect.DeepEqual(states, map[int64]string{1: storage.ArchiveMemberStale}) {
		t.Fatalf("states %v", states)
	}
	if _, hot := h.store.audits["changed-1"]; !hot {
		t.Fatal("the changed audit was removed")
	}
	h.options.Step = nil
	second := h.mustRun()
	if second.Counts.ExportedAudits != 1 || second.Removal.Removed != 1 || second.Removal.Stale != 0 {
		t.Fatalf("second run %+v", second)
	}
	if states := h.store.memberStates("changed-1"); !reflect.DeepEqual(states, map[int64]string{1: storage.ArchiveMemberStale, 2: storage.ArchiveMemberHotRemoved}) {
		t.Fatalf("states %v", states)
	}
}

// M.3 and H.6 item 4: a run that stops between two removal batches, or
// whose batch fails, leaves the committed batches hot_removed and the rest
// sealed; the next run removes the rest, each audit once. A crash after the
// last batch leaves the run record running for the next run to mark
// interrupted, with the member states complete.
func TestRemovalContinuesAfterACrashOrAFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(h *harness)
		clear func(h *harness)
	}{
		{"crash between batches", func(h *harness) {
			calls := 0
			h.options.Step = func(step string) error {
				if step == StepBetweenRemovalBatches {
					if calls++; calls == 2 {
						return errors.New("crash")
					}
				}
				return nil
			}
		}, func(h *harness) { h.options.Step = nil }},
		{"failed batch", func(h *harness) {
			h.options.Step = func(step string) error {
				if step == StepBetweenRemovalBatches {
					h.store.mu.Lock()
					h.store.fail["RemoveArchived"] = errors.New("storage failure")
					h.store.mu.Unlock()
				}
				return nil
			}
		}, func(h *harness) {
			h.options.Step = nil
			delete(h.store.fail, "RemoveArchived")
		}},
		{"crash after the last batch", func(h *harness) {
			h.options.Step = func(step string) error {
				if step == StepAfterRemoval {
					return errors.New("crash")
				}
				return nil
			}
		}, func(h *harness) { h.options.Step = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRemovalHarness(t)
			audits := h.addConversation("conv-crash", "openai", 4, baseTimeNS)
			test.setup(h)
			runner := h.runner()
			oneAtATime(runner)
			first, err := runner.RunOnce(context.Background())
			if err == nil && first.Status == storage.ArchiveRunCompleted {
				t.Fatalf("the first run completed: %+v", first)
			}
			if test.name == "failed batch" && (first.Status != storage.ArchiveRunFailed || first.Reason != "removal_failed") {
				t.Fatalf("failed run %+v", first)
			}
			removedFirst := 4 - len(h.store.audits)
			if test.name == "crash after the last batch" {
				if removedFirst != 4 || h.store.runs[0].Status != storage.ArchiveRunRunning {
					t.Fatalf("removed %d, run %s", removedFirst, h.store.runs[0].Status)
				}
			} else if removedFirst < 1 || removedFirst >= 4 {
				t.Fatalf("first run removed %d of 4", removedFirst)
			}
			for _, audit := range audits {
				_, hot := h.store.audits[audit.id]
				state := h.store.memberStates(audit.id)[1]
				if hot != (state == storage.ArchiveMemberSealed) || (!hot && state != storage.ArchiveMemberHotRemoved) {
					t.Fatalf("%s: hot %v, member %s", audit.id, hot, state)
				}
			}
			test.clear(h)
			second := h.mustRun()
			if second.Removal.Removed != int64(4-removedFirst) || second.Removal.AlreadyGone != 0 || second.Removal.Stale != 0 || len(h.store.audits) != 0 {
				t.Fatalf("second run %+v, %d left", second.Removal, len(h.store.audits))
			}
			if test.name != "failed batch" && h.store.runs[0].Status != storage.ArchiveRunInterrupted {
				t.Fatalf("first run %s", h.store.runs[0].Status)
			}
		})
	}
}

// export_only never removes; archive_then_delete at the built-in format
// version 0 exports and removes nothing (no segment qualifies); a run past
// its deadline does not start removing.
func TestRemovalGates(t *testing.T) {
	t.Run("export_only", func(t *testing.T) {
		h := newRemovalHarness(t)
		h.options.Mode = storage.ArchiveModeExportOnly
		h.addConversation("conv-gate", "openai", 2, baseTimeNS)
		result := h.mustRun()
		if result.Removal != (RemovalResult{}) || len(h.store.audits) != 2 || strings.Contains(strings.Join(h.store.calls, ","), "Remove") {
			t.Fatalf("export_only removal %+v calls %v", result.Removal, h.store.calls)
		}
	})
	// Catalog rows of the trial format version 0 (the seam registers the
	// segments at 0) are never a basis for removal. The first run at the
	// built-in version exports the audits again at revision 2, the version 0
	// members turn stale, and removal goes by the new members only. A gap
	// exported at version 0 is never exported again (a gap has one catalog
	// row, keyed by its id) and so never removed.
	t.Run("format version 0", func(t *testing.T) {
		h := newRemovalHarness(t)
		h.options.FormatVersionOverride = int64Pointer(0)
		h.addConversation("conv-gate", "openai", 2, baseTimeNS)
		h.store.gaps = []archive.Gap{{ID: 1, StartedAtNS: baseTimeNS, EndedAtNS: baseTimeNS + 10, Reason: "queue_full", RequestCount: 1, CreatedAtNS: baseTimeNS + 11}}
		result := h.mustRun()
		if h.runner().FormatVersion() != 0 || result.Counts.ExportedAudits != 2 || result.Removal.Removed != 0 || result.Removal.RemovedGaps != 0 ||
			len(h.store.audits) != 2 || len(h.store.gaps) != 1 || len(h.store.removalBatches) != 0 {
			t.Fatalf("format 0: %+v, %d audits", result, len(h.store.audits))
		}
		if again := h.mustRun(); again.Counts.ExportedAudits != 0 || again.Removal.Removed != 0 || len(h.store.audits) != 2 {
			t.Fatalf("second run at format 0: %+v", again)
		}

		h.options.FormatVersionOverride = nil
		upgraded := h.mustRun()
		if h.runner().FormatVersion() != 1 || upgraded.Counts.ExportedAudits != 2 || upgraded.Removal.Removed != 2 || upgraded.Removal.Stale != 0 ||
			upgraded.ExportedGaps != 0 || upgraded.Removal.RemovedGaps != 0 || len(h.store.audits) != 0 || len(h.store.gaps) != 1 {
			t.Fatalf("first run at format 1: %+v", upgraded)
		}
		audits := map[string]bool{}
		for _, member := range h.store.members {
			audits[member.AuditID] = true
		}
		if len(audits) != 2 {
			t.Fatalf("members of %d audits", len(audits))
		}
		for id := range audits {
			if states := h.store.memberStates(id); !reflect.DeepEqual(states, map[int64]string{1: storage.ArchiveMemberStale, 2: storage.ArchiveMemberHotRemoved}) {
				t.Fatalf("%s members %v", id, states)
			}
		}
		for _, segment := range h.store.segments {
			if segment.FormatVersion == 0 && segment.State == storage.ArchiveSegmentHotRemoved {
				t.Fatalf("a version 0 segment was removed: %+v", segment)
			}
		}
	})
	t.Run("deadline", func(t *testing.T) {
		h := newRemovalHarness(t)
		h.addConversation("conv-gate", "openai", 2, baseTimeNS)
		h.options.Step = func(step string) error {
			if step == StepBeforeRecordPass {
				h.clock.advance(2 * time.Hour)
			}
			return nil
		}
		result := h.mustRun()
		if !result.DeadlineReached || result.Removal.Removed != 0 || len(h.store.audits) != 2 {
			t.Fatalf("deadline %+v", result)
		}
		h.options.Step = nil
		if next := h.mustRun(); next.Removal.Removed != 2 {
			t.Fatalf("next run %+v", next.Removal)
		}
	})
}
