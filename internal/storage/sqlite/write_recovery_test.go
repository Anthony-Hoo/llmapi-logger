package sqlite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/security"
)

func TestStorageRecoveryFinalizesWithoutNewTraffic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x19}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	insertRetentionAudit(t, store, "outage-finish", 1, int64Pointer(2), ParsePending, true)
	if _, err := store.writerDB.Exec("UPDATE audit_records SET ended_at_ns=NULL, forward_status='in_progress', capture_status='pending' WHERE audit_id='outage-finish'"); err != nil {
		t.Fatal(err)
	}
	setWriterReadOnly(t, store, true)
	status := 200
	requestID := "request-example"
	finish := AuditFinish{AuditID: "outage-finish", EndedAtNS: 3, StatusCode: &status, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending, NewAPIRequestID: &requestID}
	if _, err := store.FinishAuditWithResult(ctx, finish); ErrorClass(err) != "sqlite_read_only" {
		t.Fatalf("finish error=%v", err)
	}
	if store.Healthy() {
		t.Fatal("pending recovery reported healthy")
	}
	setWriterReadOnly(t, store, false)
	// No new writer request or artificial wake: the periodic recovery must run.
	waitForCaptureRecovery(t, store)
	snapshot, err := store.Snapshot(ctx, finish.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.EndedAtNS == nil || *snapshot.Audit.EndedAtNS != 3 || snapshot.Audit.ForwardStatus != ForwardCompleted || snapshot.Audit.CaptureStatus != CaptureFailed || snapshot.Audit.ParseStatus != ParsePending {
		t.Fatalf("recovered outcome=%+v", snapshot.Audit)
	}
	if len(snapshot.Chunks) != 1 || snapshot.Bodies[0].RetentionState != RetentionFull || !bytes.Equal(snapshot.Chunks[0].DataEnc, []byte{1}) {
		t.Fatal("recovery changed retained raw")
	}
	if snapshot.Audit.NewAPIRequestID == nil || *snapshot.Audit.NewAPIRequestID != requestID || snapshot.Audit.CallerStatus != CallerPending {
		t.Fatal("recovery lost caller lookup metadata")
	}
	ids, err := store.ListPendingParseIDs(ctx, 10)
	if err != nil || len(ids) != 1 || ids[0] != finish.AuditID {
		t.Fatalf("recovered audit not parseable: %v %v", ids, err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := store.DeleteExpired(ctx, 10, 200, 200)
	if err != nil || result.DeletedAudits != 1 {
		t.Fatalf("recovered audit not collectable: %+v %v", result, err)
	}
}

func TestGlobalHeaderFailureCannotFinalizeComplete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x29}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"lost-header", "unaffected"} {
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
	}
	stage := HTTPStage{AuditID: "lost-header", Stage: StageRequestReceived, StartedAtNS: 2}
	stage.defaults()
	if err := store.submitSync(ctx, writeRequest{kind: writeStartStage, data: stage}); err != nil {
		t.Fatal(err)
	}
	setWriterReadOnly(t, store, true)
	header := HTTPHeader{AuditID: stage.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader, Name: "content-type", ValueLength: 1, ValueEnc: []byte{1}}
	if err := store.submitSync(ctx, writeRequest{kind: writeAddHeaders, data: []HTTPHeader{header}}); ErrorClass(err) != "sqlite_read_only" {
		t.Fatalf("header error=%v", err)
	}
	setWriterReadOnly(t, store, false)
	// This finish may arrive before the background recovery ticker fires.
	if err := store.FinishStage(ctx, StageFinish{AuditID: stage.AuditID, Stage: stage.Stage, State: StageStateComplete, EndedAtNS: 3}); err != nil {
		t.Fatal(err)
	}
	finish := AuditFinish{AuditID: stage.AuditID, EndedAtNS: 4, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	actual, err := store.FinishAuditWithResult(ctx, finish)
	if err != nil || actual.CaptureStatus != CaptureFailed {
		t.Fatalf("lost header finalized complete: %+v %v", actual, err)
	}
	snapshot, err := store.Snapshot(ctx, stage.AuditID)
	if err != nil || len(snapshot.Headers) != 0 || len(snapshot.Stages) != 1 || snapshot.Stages[0].State != StageStatePartial || snapshot.Stages[0].ErrorCode == nil || *snapshot.Stages[0].ErrorCode != "capture_headers_failed" {
		t.Fatalf("header boundary not marked: %+v %v", snapshot, err)
	}
	finish.AuditID = "unaffected"
	actual, err = store.FinishAuditWithResult(ctx, finish)
	if err != nil || actual.CaptureStatus != CaptureComplete {
		t.Fatalf("unrelated capture changed: %+v %v", actual, err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQueueFullFinalizationWaitsForAcceptedStages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x39}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, testAudit("queued-finish")); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
	writer.integrity.Store(store.integrity.Load())
	if err := writer.StartStage(ctx, HTTPStage{AuditID: "queued-finish", Stage: StageRequestReceived, StartedAtNS: 2}); err != nil {
		t.Fatal(err)
	}
	finish := AuditFinish{AuditID: "queued-finish", EndedAtNS: 3, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	if _, err := writer.FinishAuditWithResult(ctx, finish); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("finish error=%v", err)
	}
	writer.recoverCaptureWrites()
	var ended *int64
	if err := store.readerDB.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id='queued-finish'").Scan(&ended); err != nil || ended != nil {
		t.Fatal("recovery overtook an accepted stage")
	}
	close(writer.queue)
	writer.runWriter()
	snapshot, err := store.Snapshot(ctx, finish.AuditID)
	if err != nil || snapshot.Audit.EndedAtNS == nil || len(snapshot.Stages) != 1 || snapshot.Stages[0].EndedAtNS == nil {
		t.Fatalf("queue drain did not precede recovery: %+v %v", snapshot, err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, store.readerDB, "integrity_events", 1)
}

func TestFinalizationRetryPreservesCommittedOutcome(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x49}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, testAudit("finish-once")); err != nil {
		t.Fatal(err)
	}
	status := 200
	finish := AuditFinish{AuditID: "finish-once", EndedAtNS: 3, StatusCode: &status, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	if _, err := store.FinishAuditWithResult(ctx, finish); err != nil {
		t.Fatal(err)
	}
	audit, err := store.LoadParserAudit(ctx, finish.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimPendingParse(ctx, finish.AuditID); err != nil || !claimed {
		t.Fatalf("claim=%v %v", claimed, err)
	}
	if err := store.SaveParsedResult(ctx, ParsedResult{AuditID: finish.AuditID, ParserName: audit.ParserName, ParserVersion: "1", Status: ParseOK, ParsedAtNS: 4}); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := store.readerDB.QueryRow("SELECT count(*) FROM integrity_events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	finish.EndedAtNS = 999
	finish.CaptureStatus = CaptureFailed
	actual, err := store.FinishAuditWithResult(ctx, finish)
	if err != nil || actual.EndedAtNS != 3 || actual.CaptureStatus != CaptureComplete || actual.ParseStatus != ParseOK {
		t.Fatalf("retry changed final outcome: %+v %v", actual, err)
	}
	assertTableCount(t, store.readerDB, "integrity_events", before)
	store.rememberFailedWrite(writeRequest{kind: writeFinishAudit, data: &finish}, 0)
	store.recoveryWake <- struct{}{}
	waitForCaptureRecovery(t, store)
	assertTableCount(t, store.readerDB, "integrity_events", before)
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureRecoveryOverflowIsBoundedAndFailClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.BeginAudit(ctx, testAudit("overflow-active")); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB}
	const secret = "private-header-ciphertext"
	for i := 0; i <= captureRecoveryLimit; i++ {
		id := fmt.Sprintf("outage-%d", i)
		writer.rememberFailedWrite(writeRequest{kind: writeAddHeaders, data: []HTTPHeader{{AuditID: id, Stage: StageRequestReceived, ValueEnc: []byte(secret)}}}, 0)
	}
	if len(writer.recoveries) != captureRecoveryLimit || !writer.recoveryOverflow.Load() || writer.Healthy() {
		t.Fatal("recovery overflow was not bounded and unhealthy")
	}
	if strings.Contains(fmt.Sprint(writer.recoveries), secret) {
		t.Fatal("recovery retained ciphertext")
	}
	record := testAudit("overflow-new")
	record.defaults()
	finish := AuditFinish{AuditID: "overflow-active", EndedAtNS: 3, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	results, _, err := writer.commitBatch([]writeRequest{{kind: writeBeginAudit, data: record}, {kind: writeFinishAudit, data: &finish}})
	if err != nil || !errors.Is(results[0], ErrRecoveryOverflow) || results[1] != nil || finish.CaptureStatus != CaptureFailed {
		t.Fatalf("overflow accepted new audit or complete capture: %v %v %+v", results, err, finish)
	}
	writer.recoverCaptureWrites()
	if writer.Healthy() || !writer.recoveryOverflow.Load() {
		t.Fatal("ordinary recovery cleared overflow without startup reconciliation")
	}
}

func TestRecoverySnapshotKeepsConcurrentFinalization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.BeginAudit(ctx, testAudit("concurrent-recovery")); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB}
	writer.rememberFailedWrite(writeRequest{kind: writeStartStage, data: HTTPStage{AuditID: "concurrent-recovery", Stage: StageRequestReceived}}, 0)
	conn, err := store.writerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	before := store.writerDB.Stats().WaitCount
	done := make(chan struct{})
	go func() { writer.recoverCaptureWrites(); close(done) }()
	deadline := time.Now().Add(time.Second)
	for store.writerDB.Stats().WaitCount == before {
		if time.Now().After(deadline) {
			t.Fatal("recovery did not snapshot before waiting for writer connection")
		}
		time.Sleep(time.Millisecond)
	}
	finish := AuditFinish{AuditID: "concurrent-recovery", EndedAtNS: 3, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	writer.rememberFailedWrite(writeRequest{kind: writeFinishAudit, data: &finish}, 0)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	if writer.recoveryPending.Load() != 1 {
		t.Fatal("old recovery snapshot discarded a newer finalization")
	}
	writer.recoverCaptureWrites()
	snapshot, err := store.Snapshot(ctx, finish.AuditID)
	if err != nil || snapshot.Audit.EndedAtNS == nil || writer.recoveryPending.Load() != 0 {
		t.Fatalf("new finalization was not recovered: %+v %v", snapshot, err)
	}
}

func TestRecoveryRotatesPastPermanentLocalFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB}
	for i := 0; i < captureRecoveryBatch; i++ {
		id := fmt.Sprintf("bad-%02d", i)
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
		writer.rememberFailedWrite(writeRequest{kind: writeStartStage, data: HTTPStage{AuditID: id, Stage: StageRequestReceived}}, 0)
	}
	if err := store.BeginAudit(ctx, testAudit("later-good")); err != nil {
		t.Fatal(err)
	}
	writer.rememberFailedWrite(writeRequest{kind: writeStartStage, data: HTTPStage{AuditID: "later-good", Stage: StageRequestReceived}}, 0)
	if _, err := store.writerDB.Exec(`CREATE TRIGGER block_recovery BEFORE UPDATE ON audit_records
WHEN OLD.audit_id LIKE 'bad-%' BEGIN SELECT RAISE(ABORT,'injected local failure'); END`); err != nil {
		t.Fatal(err)
	}
	writer.recoverCaptureWrites()
	if writer.recoveryPending.Load() != captureRecoveryBatch+1 {
		t.Fatal("first bounded recovery round did not preserve failures")
	}
	writer.recoverCaptureWrites()
	if writer.recoveryPending.Load() != captureRecoveryBatch {
		t.Fatal("later recoverable audit was starved by earlier local errors")
	}
	snapshot, err := store.Snapshot(ctx, "later-good")
	if err != nil || snapshot.Audit.CaptureStatus != CaptureFailed {
		t.Fatalf("later audit not marked: %+v %v", snapshot, err)
	}
}

func TestCaptureRecoveryRetainsEntriesUntilCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x59}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, testAudit("recovery-commit")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec(`CREATE TABLE fail_recovery_commit (audit_id TEXT REFERENCES audit_records(audit_id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER fail_recovery_finish AFTER UPDATE OF ended_at_ns ON audit_records
WHEN NEW.ended_at_ns IS NOT NULL BEGIN INSERT INTO fail_recovery_commit VALUES ('missing-parent'); END`); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB}
	writer.integrity.Store(store.integrity.Load())
	finish := AuditFinish{AuditID: "recovery-commit", EndedAtNS: 3, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	writer.rememberFailedWrite(writeRequest{kind: writeFinishAudit, data: &finish}, 0)
	writer.recoverCaptureWrites()
	if writer.recoveryPending.Load() != 1 {
		t.Fatal("failed commit discarded its recovery metadata")
	}
	snapshot, err := store.Snapshot(ctx, finish.AuditID)
	if err != nil || snapshot.Audit.EndedAtNS != nil || snapshot.Audit.CaptureStatus == CaptureFailed {
		t.Fatal("failed recovery transaction left partial mutations")
	}
	assertTableCount(t, store.readerDB, "integrity_events", 0)
	if _, err := store.writerDB.Exec("DROP TRIGGER fail_recovery_finish; DROP TABLE fail_recovery_commit"); err != nil {
		t.Fatal(err)
	}
	writer.recoverCaptureWrites()
	if writer.recoveryPending.Load() != 0 {
		t.Fatal("recovery did not complete after commit became writable")
	}
	assertTableCount(t, store.readerDB, "integrity_events", 1)
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGlobalChunkLossPreservesObservedBoundsAndRetainedBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	insertRetentionAudit(t, store, "lost-chunk", 1, int64Pointer(2), ParsePending, true)
	if _, err := store.writerDB.Exec("UPDATE audit_records SET ended_at_ns=NULL, forward_status='in_progress', capture_status='pending' WHERE audit_id='lost-chunk'"); err != nil {
		t.Fatal(err)
	}
	setWriterReadOnly(t, store, true)
	chunk := BodyChunk{AuditID: "lost-chunk", Stage: StageRequestReceived, Seq: 1, Offset: 1, PlaintextLength: 5, EncodedLength: 5, Compression: ChunkCompressionNone, ObservedAtNS: 3, DataEnc: []byte{2, 3, 4, 5, 6}}
	if err := store.submitSync(ctx, writeRequest{kind: writeAddChunk, data: chunk}); ErrorClass(err) != "sqlite_read_only" {
		t.Fatalf("chunk error=%v", err)
	}
	setWriterReadOnly(t, store, false)
	if err := store.FinishStage(ctx, StageFinish{AuditID: chunk.AuditID, Stage: chunk.Stage, State: StageStateComplete, EndedAtNS: 4, Body: &BodyFinish{ObservedLength: 6, StoredLength: 6, SHA256: bytes.Repeat([]byte{0x44}, 32), HashComplete: true, EOFSeen: true, State: StageStateComplete, RetentionState: RetentionPending, ChunkCount: 2}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishAuditWithResult(ctx, AuditFinish{AuditID: chunk.AuditID, EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx, chunk.AuditID)
	if err != nil || len(snapshot.Bodies) != 1 {
		t.Fatalf("snapshot=%+v %v", snapshot, err)
	}
	body := snapshot.Bodies[0]
	if body.ObservedLength != 6 || body.StoredLength != 1 || body.ChunkCount != 1 || body.HashComplete || body.RetentionState != RetentionFull || body.ErrorCode == nil || *body.ErrorCode != CaptureChunkMissing {
		t.Fatalf("lost chunk was not reconciled honestly: %+v", body)
	}
	if len(snapshot.Chunks) != 1 || !bytes.Equal(snapshot.Chunks[0].DataEnc, []byte{1}) {
		t.Fatal("recovery altered committed bytes")
	}
}

func setWriterReadOnly(t *testing.T, store *Store, enabled bool) {
	t.Helper()
	setting := "OFF"
	if enabled {
		setting = "ON"
	}
	if _, err := store.writerDB.Exec("PRAGMA query_only=" + setting); err != nil {
		t.Fatal(err)
	}
}

func waitForCaptureRecovery(t *testing.T, store *Store) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for store.recoveryPending.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("capture recovery did not drain: %d", store.recoveryPending.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
