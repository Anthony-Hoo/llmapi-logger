package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"llmapi-logger/internal/storage"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

func testArchiveRun(runID string, startedAt int64) ArchiveRun {
	return ArchiveRun{RunID: runID, Mode: storage.ArchiveModeExportOnly, CutoffNS: startedAt, StartedAtNS: startedAt,
		Status: storage.ArchiveRunRunning, FormatVersion: 0}
}

func testArchiveSegment(segmentID, runID, manifest string, members int) ArchiveSegment {
	first, last := int64(1000), int64(2000)
	return ArchiveSegment{SegmentID: segmentID, RunID: runID, BundleKind: storage.ArchiveBundleBucket, FormatVersion: 0,
		ManifestName: manifest, KeyFingerprint: bytes.Repeat([]byte{0x11}, 32), Encrypted: true, MemberCount: int64(members),
		FirstStartedAtNS: &first, LastEndedAtNS: &last, State: storage.ArchiveSegmentPublishing, CreatedAtNS: 3000}
}

// archiveStampOf computes an audit's change stamp in a read-only snapshot.
func archiveStampOf(t *testing.T, store *Store, auditID string) []byte {
	t.Helper()
	transaction, err := store.readerDB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	stamp, exists, err := archiveChangeStamp(context.Background(), transaction, auditID)
	if err != nil || !exists {
		t.Fatalf("stamp of %s: exists %v, %v", auditID, exists, err)
	}
	return stamp[:]
}

func testArchiveMember(auditID string, revision int64, stamp []byte) ArchiveMember {
	return ArchiveMember{AuditID: auditID, Revision: revision, RecordDigest: bytes.Repeat([]byte{0x22}, 32),
		ChangeStamp: stamp, StartedAtNS: 1000, StateChangedAtNS: 3000}
}

func memberStates(t *testing.T, store *Store) map[ArchiveMemberKey]string {
	t.Helper()
	members, err := store.ListArchiveMembers(context.Background(), ArchiveMemberQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	states := map[ArchiveMemberKey]string{}
	for _, member := range members {
		states[ArchiveMemberKey{AuditID: member.AuditID, Revision: member.Revision}] = member.State
	}
	return states
}

func TestArchiveCatalogRunsIntentsAndSeal(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	for _, id := range []string{"catalog-a", "catalog-b", "catalog-c"} {
		writeV2Audit(t, store, cipher, v2Audit{id: id})
	}

	first := testArchiveRun("a0000000000000000000000000000001", 100)
	if interrupted, err := store.BeginArchiveRun(ctx, first); err != nil || interrupted != 0 {
		t.Fatalf("begin run = %d, %v", interrupted, err)
	}
	// A second run marks the first one interrupted.
	second := testArchiveRun("a0000000000000000000000000000002", 200)
	if interrupted, err := store.BeginArchiveRun(ctx, second); err != nil || interrupted != 1 {
		t.Fatalf("begin second run = %d, %v", interrupted, err)
	}
	if run, err := store.LastArchiveRun(ctx, storage.ArchiveRunInterrupted); err != nil || run == nil || run.RunID != first.RunID || run.FinishedAtNS == nil || *run.FinishedAtNS != 200 {
		t.Fatalf("interrupted run = %+v, %v", run, err)
	}

	stampA := archiveStampOf(t, store, "catalog-a")
	intent := ArchiveIntent{
		Segment: testArchiveSegment("b0000000000000000000000000000001", second.RunID, "sessions/2025/01/one.manifest.json", 4),
		Members: []ArchiveMember{
			testArchiveMember("catalog-a", 1, stampA),
			// Changed since the snapshot.
			testArchiveMember("catalog-b", 1, bytes.Repeat([]byte{0x99}, 32)),
			// Gone from the hot store.
			testArchiveMember("catalog-gone", 1, bytes.Repeat([]byte{0x98}, 32)),
			testArchiveMember("catalog-c", 1, archiveStampOf(t, store, "catalog-c")),
		},
	}
	result, err := store.RegisterArchiveIntent(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	wantStale := []ArchiveMemberKey{{AuditID: "catalog-b", Revision: 1}, {AuditID: "catalog-gone", Revision: 1}}
	if !reflect.DeepEqual(result.Stale, wantStale) || len(result.Superseded) != 0 {
		t.Fatalf("intent result = %+v", result)
	}
	states := memberStates(t, store)
	if states[ArchiveMemberKey{AuditID: "catalog-a", Revision: 1}] != ArchiveMemberSealed || states[ArchiveMemberKey{AuditID: "catalog-c", Revision: 1}] != ArchiveMemberSealed {
		t.Fatalf("member states = %v", states)
	}
	segment, err := store.ArchiveSegment(ctx, intent.Segment.SegmentID)
	if err != nil || segment.State != storage.ArchiveSegmentPublishing || segment.MemberCount != 4 || !segment.Encrypted {
		t.Fatalf("segment = %+v, %v", segment, err)
	}
	if publishing, err := store.ListArchiveSegments(ctx, storage.ArchiveSegmentPublishing, "", 10); err != nil || len(publishing) != 1 {
		t.Fatalf("publishing segments = %v, %v", publishing, err)
	}

	// A revision that is not above the audit's existing ones is refused and
	// leaves nothing behind.
	again := ArchiveIntent{
		Segment: testArchiveSegment("b0000000000000000000000000000002", second.RunID, "sessions/2025/01/two.manifest.json", 1),
		Members: []ArchiveMember{testArchiveMember("catalog-a", 1, stampA)},
	}
	if _, err := store.RegisterArchiveIntent(ctx, again); err == nil {
		t.Fatal("repeated revision accepted")
	}
	if _, err := store.ArchiveSegment(ctx, again.Segment.SegmentID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("refused intent left a segment: %v", err)
	}

	// Re-inclusion: revision 2 of catalog-a supersedes the sealed revision 1.
	again.Members = []ArchiveMember{testArchiveMember("catalog-a", 2, stampA)}
	result, err = store.RegisterArchiveIntent(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Stale) != 0 || !reflect.DeepEqual(result.Superseded, []ArchiveMemberKey{{AuditID: "catalog-a", Revision: 1}}) {
		t.Fatalf("re-inclusion result = %+v", result)
	}
	states = memberStates(t, store)
	if states[ArchiveMemberKey{AuditID: "catalog-a", Revision: 1}] != ArchiveMemberStale || states[ArchiveMemberKey{AuditID: "catalog-a", Revision: 2}] != ArchiveMemberSealed {
		t.Fatalf("member states after re-inclusion = %v", states)
	}
	if revision, err := store.ArchiveCurrentRevision(ctx, "catalog-a"); err != nil || revision != 2 {
		t.Fatalf("current revision = %d, %v", revision, err)
	}

	// Seal, idempotently; a different digest or an unknown segment is refused.
	digest := bytes.Repeat([]byte{0x44}, 32)
	seal := ArchiveSeal{SegmentID: intent.Segment.SegmentID, ManifestSHA256: digest, DiskBytes: 4096, SealedAtNS: 4000}
	for attempt := 0; attempt < 2; attempt++ {
		if err := store.SealArchiveSegment(ctx, seal); err != nil {
			t.Fatalf("seal %d: %v", attempt, err)
		}
	}
	other := seal
	other.ManifestSHA256 = bytes.Repeat([]byte{0x45}, 32)
	if err := store.SealArchiveSegment(ctx, other); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("seal with another digest = %v", err)
	}
	segment, err = store.ArchiveSegment(ctx, intent.Segment.SegmentID)
	if err != nil || segment.State != storage.ArchiveSegmentSealed || !bytes.Equal(segment.ManifestSHA256, digest) || segment.DiskBytes != 4096 ||
		segment.SealedAtNS == nil || *segment.SealedAtNS != 4000 {
		t.Fatalf("sealed segment = %+v, %v", segment, err)
	}
	// A sealed segment cannot be dropped; a publishing one can, with its
	// members, and an unknown one is a no-op.
	if _, err := store.DropArchiveIntent(ctx, intent.Segment.SegmentID); err == nil {
		t.Fatal("dropped a sealed segment")
	}
	if dropped, err := store.DropArchiveIntent(ctx, again.Segment.SegmentID); err != nil || !dropped {
		t.Fatalf("drop intent = %v, %v", dropped, err)
	}
	if dropped, err := store.DropArchiveIntent(ctx, again.Segment.SegmentID); err != nil || dropped {
		t.Fatalf("drop unknown intent = %v, %v", dropped, err)
	}
	states = memberStates(t, store)
	if _, ok := states[ArchiveMemberKey{AuditID: "catalog-a", Revision: 2}]; ok || states[ArchiveMemberKey{AuditID: "catalog-a", Revision: 1}] != ArchiveMemberStale {
		t.Fatalf("member states after drop = %v", states)
	}

	// Pass progress: watermark, counters and deferred rows in one operation.
	pass := ArchivePass{
		RunID:     second.RunID,
		Watermark: &ArchivePosition{StartedAtNS: 1000, AuditID: "catalog-c"},
		Counts:    &ArchiveRunCounts{ExportedAudits: 2, StaleAudits: 2, Segments: 1, DiskBytes: 4096},
		Deferred: []ArchiveDeferred{
			{AuditID: "deferred-1", Reason: storage.ArchiveDeferredParsePending, FirstSeenAtNS: 10, LastCheckedAtNS: 10},
			{AuditID: "deferred-2", Reason: storage.ArchiveDeferredOpen, FirstSeenAtNS: 10, LastCheckedAtNS: 10},
		},
	}
	if err := store.RecordArchivePass(ctx, pass); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertArchiveDeferred(ctx, []ArchiveDeferred{{AuditID: "deferred-1", Reason: storage.ArchiveDeferredCallerPending, FirstSeenAtNS: 20, LastCheckedAtNS: 20}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordArchivePass(ctx, ArchivePass{RunID: second.RunID, Resolved: []string{"deferred-2"}}); err != nil {
		t.Fatal(err)
	}
	deferred, err := store.ListArchiveDeferred(ctx, "", 10)
	if err != nil || !reflect.DeepEqual(deferred, []ArchiveDeferred{{AuditID: "deferred-1", Reason: storage.ArchiveDeferredCallerPending, FirstSeenAtNS: 10, LastCheckedAtNS: 20}}) {
		t.Fatalf("deferred = %+v, %v", deferred, err)
	}
	if watermark, err := store.ArchiveWatermark(ctx, 0); err != nil || watermark == nil || *watermark != *pass.Watermark {
		t.Fatalf("watermark = %+v, %v", watermark, err)
	}
	if watermark, err := store.ArchiveWatermark(ctx, 1); err != nil || watermark != nil {
		t.Fatalf("watermark of another format = %+v, %v", watermark, err)
	}
	if err := store.DeleteArchiveDeferred(ctx, []string{"deferred-1", "unknown"}); err != nil {
		t.Fatal(err)
	}

	finish := ArchiveRunFinish{RunID: second.RunID, FinishedAtNS: 5000, Status: storage.ArchiveRunCompleted,
		Counts: ArchiveRunCounts{ExportedAudits: 2, StaleAudits: 2, Segments: 1, DiskBytes: 4096}}
	if err := store.FinishArchiveRun(ctx, finish); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishArchiveRun(ctx, finish); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("finishing a finished run = %v", err)
	}
	if err := store.RecordArchivePass(ctx, ArchivePass{RunID: second.RunID, Resolved: []string{"x"}}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("pass on a finished run = %v", err)
	}
	run, err := store.LastArchiveRun(ctx, storage.ArchiveRunCompleted)
	if err != nil || run == nil || run.RunID != second.RunID || run.Counts != finish.Counts || run.Watermark == nil {
		t.Fatalf("completed run = %+v, %v", run, err)
	}
	if !store.Healthy() {
		t.Fatal("refused catalog writes left the store unhealthy")
	}
}

func TestArchiveCatalogReconciledBundle(t *testing.T) {
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	writeV2Audit(t, store, cipher, v2Audit{id: "reconcile-a"})
	run := testArchiveRun("c0000000000000000000000000000001", 100)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	intent := ArchiveIntent{
		Segment: testArchiveSegment("d0000000000000000000000000000001", run.RunID, "sessions/known.manifest.json", 1),
		Members: []ArchiveMember{testArchiveMember("reconcile-a", 1, archiveStampOf(t, store, "reconcile-a"))},
	}
	if _, err := store.RegisterArchiveIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	gaps := testArchiveSegment("d0000000000000000000000000000002", run.RunID, "gaps/known.manifest.json", 2)
	gaps.BundleKind = storage.ArchiveBundleGaps
	if _, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: gaps, GapIDs: []int64{7, 8}}); err != nil {
		t.Fatal(err)
	}

	sealedAt := int64(4000)
	segment := testArchiveSegment("d0000000000000000000000000000003", run.RunID, "sessions/found.manifest.json", 2)
	segment.State, segment.ManifestSHA256, segment.SealedAtNS = storage.ArchiveSegmentSealed, bytes.Repeat([]byte{0x55}, 32), &sealedAt
	reconciled := ArchiveReconciled{Segment: segment, Members: []ArchiveMember{
		// The catalog already has this (audit_id, revision).
		testArchiveMember("reconcile-a", 1, nil),
		testArchiveMember("reconcile-a-elsewhere", 3, nil),
	}}
	result, err := store.RegisterReconciledArchive(ctx, reconciled)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.SkippedMembers, []ArchiveMemberKey{{AuditID: "reconcile-a", Revision: 1}}) || len(result.SkippedGaps) != 0 {
		t.Fatalf("reconciled result = %+v", result)
	}
	states := memberStates(t, store)
	if states[ArchiveMemberKey{AuditID: "reconcile-a", Revision: 1}] != ArchiveMemberSealed || states[ArchiveMemberKey{AuditID: "reconcile-a-elsewhere", Revision: 3}] != ArchiveMemberStale {
		t.Fatalf("member states = %v", states)
	}
	gapSegment := testArchiveSegment("d0000000000000000000000000000004", run.RunID, "gaps/found.manifest.json", 2)
	gapSegment.BundleKind, gapSegment.State, gapSegment.ManifestSHA256, gapSegment.SealedAtNS = storage.ArchiveBundleGaps, storage.ArchiveSegmentSealed, bytes.Repeat([]byte{0x56}, 32), &sealedAt
	result, err = store.RegisterReconciledArchive(ctx, ArchiveReconciled{Segment: gapSegment, GapIDs: []int64{8, 9}})
	if err != nil || !reflect.DeepEqual(result.SkippedGaps, []int64{8}) {
		t.Fatalf("reconciled gaps = %+v, %v", result, err)
	}
	gapMembers, err := store.ListArchiveGapMembers(ctx, "", "", 0, 10)
	if err != nil || len(gapMembers) != 3 || gapMembers[2].GapID != 9 || gapMembers[2].SegmentID != gapSegment.SegmentID {
		t.Fatalf("gap members = %+v, %v", gapMembers, err)
	}
	// The same manifest name again is refused.
	again := segment
	again.SegmentID = "d0000000000000000000000000000005"
	if _, err := store.RegisterReconciledArchive(ctx, ArchiveReconciled{Segment: again, Members: reconciled.Members}); err == nil {
		t.Fatal("duplicate manifest name accepted")
	}
}

func TestArchiveCatalogRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	run := testArchiveRun("e0000000000000000000000000000001", 100)
	bad := []func() error{
		func() error { r := run; r.RunID = "short"; _, err := store.BeginArchiveRun(ctx, r); return err },
		func() error { r := run; r.Mode = "off"; _, err := store.BeginArchiveRun(ctx, r); return err },
		func() error {
			r := run
			r.Status = storage.ArchiveRunCompleted
			_, err := store.BeginArchiveRun(ctx, r)
			return err
		},
		func() error {
			s := testArchiveSegment("f0000000000000000000000000000001", run.RunID, "../escape.manifest.json", 0)
			_, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: s})
			return err
		},
		func() error {
			s := testArchiveSegment("f0000000000000000000000000000001", run.RunID, "sessions/a.manifest.json", 2)
			_, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: s, Members: []ArchiveMember{testArchiveMember("x", 1, bytes.Repeat([]byte{1}, 32))}})
			return err
		},
		func() error {
			s := testArchiveSegment("f0000000000000000000000000000001", run.RunID, "sessions/a.manifest.json", 1)
			_, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: s, Members: []ArchiveMember{testArchiveMember("x", 1, nil)}})
			return err
		},
		func() error {
			s := testArchiveSegment("f0000000000000000000000000000001", run.RunID, "sessions/a.manifest.json", 1)
			_, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: s, GapIDs: []int64{1}})
			return err
		},
		func() error {
			return store.UpsertArchiveDeferred(ctx, []ArchiveDeferred{{AuditID: "x", Reason: "unknown", FirstSeenAtNS: 1, LastCheckedAtNS: 1}})
		},
		func() error {
			return store.SealArchiveSegment(ctx, ArchiveSeal{SegmentID: "f0000000000000000000000000000001", ManifestSHA256: []byte{1}, SealedAtNS: 1})
		},
	}
	for index, call := range bad {
		var local localWriteError
		if err := call(); !errors.As(err, &local) {
			t.Fatalf("invalid input %d = %v", index, err)
		}
	}
	// The run and segment reference rules are enforced by the database: an
	// intent for an unknown run fails without hurting the writer.
	s := testArchiveSegment("f0000000000000000000000000000002", "e0000000000000000000000000000009", "sessions/b.manifest.json", 0)
	if _, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: s}); err == nil {
		t.Fatal("intent for an unknown run accepted")
	}
	if !store.Healthy() {
		t.Fatal("a refused intent left the store unhealthy")
	}
}
