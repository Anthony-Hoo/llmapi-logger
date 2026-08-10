package sqlite

import (
	"bytes"
	"context"
	"testing"
)

func TestRecoverInterruptedAuditsRepairsCommittedEvidenceAndIsIdempotent(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("interrupted")
	record.StartedAtNS = 10
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	second := testAudit("interrupted-without-body")
	second.StartedAtNS = 20
	if err := store.BeginAudit(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := store.StartStage(ctx, HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 11,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, BodyStream{
		AuditID: record.AuditID, Stage: StageRequestReceived,
		ObservedLength: 99, StoredLength: 99, SHA256: bytes.Repeat([]byte{0x7a}, 32),
		HashComplete: true, EOFSeen: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []BodyChunk{
		{AuditID: record.AuditID, Stage: StageRequestReceived, Seq: 0, Offset: 0, PlaintextLength: 3, ObservedAtNS: 12, DataEnc: []byte{0x01}},
		{AuditID: record.AuditID, Stage: StageRequestReceived, Seq: 1, Offset: 5, PlaintextLength: 2, ObservedAtNS: 13, DataEnc: []byte{0x02}},
	} {
		if err := store.AddChunk(ctx, chunk); err != nil {
			t.Fatal(err)
		}
	}

	const recoveredAt = int64(100)
	recovered, err := store.RecoverInterruptedAudits(ctx, recoveredAt)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 2 {
		t.Fatalf("recovered = %d, want 2", recovered)
	}

	snapshot, err := store.Snapshot(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.EndedAtNS == nil || *snapshot.Audit.EndedAtNS != recoveredAt ||
		snapshot.Audit.ForwardStatus != ForwardInterrupted ||
		snapshot.Audit.CaptureStatus != CapturePartial ||
		snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != GapReasonProcessExit {
		t.Fatalf("unexpected recovered audit: %+v", snapshot.Audit)
	}
	if len(snapshot.Stages) != 1 || snapshot.Stages[0].State != StageStatePartial ||
		snapshot.Stages[0].EndedAtNS == nil || *snapshot.Stages[0].EndedAtNS != recoveredAt ||
		snapshot.Stages[0].ErrorCode == nil || *snapshot.Stages[0].ErrorCode != GapReasonProcessExit {
		t.Fatalf("unexpected recovered stages: %+v", snapshot.Stages)
	}
	if len(snapshot.Bodies) != 1 {
		t.Fatalf("body count = %d, want 1", len(snapshot.Bodies))
	}
	body := snapshot.Bodies[0]
	if body.StoredLength != 5 || body.ObservedLength != 7 || len(body.SHA256) != 0 ||
		body.HashComplete || body.EOFSeen || body.State != StageStatePartial ||
		body.ErrorCode == nil || *body.ErrorCode != GapReasonProcessExit {
		t.Fatalf("unexpected recovered body: %+v", body)
	}

	var gapCount, requestCount int
	var startedAt, endedAt, createdAt int64
	var reason, detail string
	if err := store.readerDB.QueryRow(`
SELECT COUNT(*), started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns
FROM audit_gaps
WHERE reason = ?`, GapReasonProcessExit).Scan(
		&gapCount, &startedAt, &endedAt, &reason, &requestCount, &detail, &createdAt,
	); err != nil {
		t.Fatal(err)
	}
	if gapCount != 1 || startedAt != record.StartedAtNS || endedAt != recoveredAt ||
		reason != GapReasonProcessExit || requestCount != 2 || detail != GapDetailProcessExit || createdAt != recoveredAt {
		t.Fatalf("unexpected recovery gap count=%d start=%d end=%d reason=%q requests=%d detail=%q created=%d",
			gapCount, startedAt, endedAt, reason, requestCount, detail, createdAt)
	}

	recovered, err = store.RecoverInterruptedAudits(ctx, recoveredAt+1)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 0 {
		t.Fatalf("second recovery = %d, want 0", recovered)
	}
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_gaps WHERE reason = ?", GapReasonProcessExit).Scan(&gapCount); err != nil {
		t.Fatal(err)
	}
	if gapCount != 1 {
		t.Fatalf("idempotent recovery left %d gaps, want 1", gapCount)
	}
}

func TestRecoverInterruptedAuditsRequiresValidTime(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	if _, err := store.RecoverInterruptedAudits(context.Background(), 0); err == nil {
		t.Fatal("expected invalid recovery time error")
	}
}
