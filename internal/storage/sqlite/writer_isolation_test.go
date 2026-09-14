package sqlite

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"llmapi-logger/internal/security"
)

func TestFinishAuditWithResultDoesNotReturnUncommittedOutcome(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.BeginAudit(ctx, testAudit("finish-result")); err != nil {
		t.Fatal(err)
	}
	// The finalization operation succeeds, but a deferred foreign-key violation
	// prevents the outer transaction from committing its effective outcome.
	if _, err := store.writerDB.Exec(`CREATE TABLE reject_commit (
    audit_id TEXT REFERENCES audit_records(audit_id) DEFERRABLE INITIALLY DEFERRED
)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec(`CREATE TRIGGER reject_finish_commit AFTER UPDATE OF ended_at_ns ON audit_records
BEGIN INSERT INTO reject_commit VALUES ('missing-audit'); END`); err != nil {
		t.Fatal(err)
	}
	finish := AuditFinish{AuditID: "finish-result", EndedAtNS: 2, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	result, err := store.FinishAuditWithResult(ctx, finish)
	if err == nil || result.AuditID != "" || result.CaptureStatus != "" {
		t.Fatal("failed commit returned a terminal outcome")
	}
	snapshot, err := store.Snapshot(ctx, finish.AuditID)
	if err != nil || snapshot.Audit.EndedAtNS != nil {
		t.Fatal("failed commit persisted a terminal audit")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	result, err = store.FinishAuditWithResult(cancelled, finish)
	if !errors.Is(err, context.Canceled) || result.AuditID != "" || result.CaptureStatus != "" {
		t.Fatal("cancelled finalization returned a terminal outcome")
	}
}

func TestCaptureFailureCannotBeFinalizedAsComplete(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"headers", "chunk", "start stage", "start body", "finish stage"} {
		for _, laterBatch := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/same batch", true: "/later batch"}[laterBatch], func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				store, _ := openTestStore(t)
				if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x25}, security.KeySize)); err != nil {
					t.Fatal(err)
				}
				for _, id := range []string{"failed-capture", "independent-capture"} {
					if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
						t.Fatal(err)
					}
				}
				stage := HTTPStage{AuditID: "failed-capture", Stage: StageRequestReceived, StartedAtNS: 2}
				stage.defaults()
				body := BodyStream{AuditID: stage.AuditID, Stage: stage.Stage}
				body.defaults()
				if err := store.submitSync(ctx, writeRequest{kind: writeStartStage, data: stage}); err != nil {
					t.Fatal(err)
				}
				if err := store.submitSync(ctx, writeRequest{kind: writeStartBody, data: body}); err != nil {
					t.Fatal(err)
				}
				chunk := BodyChunk{AuditID: stage.AuditID, Stage: stage.Stage, PlaintextLength: 1, ObservedAtNS: 3, DataEnc: []byte{1}}
				chunk.defaults()
				if err := store.submitSync(ctx, writeRequest{kind: writeAddChunk, data: chunk}); err != nil {
					t.Fatal(err)
				}
				stageFinish := StageFinish{AuditID: stage.AuditID, Stage: stage.Stage, State: StageStateComplete, EndedAtNS: 4,
					Body: &BodyFinish{ObservedLength: 1, StoredLength: 1, ChunkCount: 1, HashComplete: true, EOFSeen: true, State: StageStateComplete, RetentionState: RetentionPending}}
				duplicateHeader := HTTPHeader{AuditID: stage.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader, Name: "x-test", ValueLength: 1, ValueEnc: []byte{1}}
				failed := writeRequest{kind: writeAddHeaders, data: []HTTPHeader{duplicateHeader, duplicateHeader}}
				switch operation {
				case "chunk":
					if _, err := store.writerDB.Exec(`CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks
WHEN NEW.seq = 1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`); err != nil {
						t.Fatal(err)
					}
					chunk.Seq, chunk.Offset = 1, 1
					failed = writeRequest{kind: writeAddChunk, data: chunk}
					stageFinish.Body.ObservedLength, stageFinish.Body.StoredLength, stageFinish.Body.ChunkCount = 2, 2, 2
				case "start stage":
					failed = writeRequest{kind: writeStartStage, data: stage}
				case "start body":
					failed = writeRequest{kind: writeStartBody, data: body}
				case "finish stage":
					missing := stageFinish
					missing.Stage = StageResponseReceived
					failed = writeRequest{kind: writeFinishStage, data: missing}
				}
				status := 200
				finish := AuditFinish{AuditID: stage.AuditID, EndedAtNS: 5, StatusCode: &status, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
				independent := finish
				independent.AuditID = "independent-capture"
				batch := []writeRequest{failed, {kind: writeFinishStage, data: stageFinish}, {kind: writeFinishAudit, data: &finish}, {kind: writeFinishAudit, data: &independent}}
				if laterBatch {
					results, err := store.commitBatch(batch[:1])
					if err != nil || results[0] == nil {
						t.Fatalf("capture failure was not isolated: %v, %v", results, err)
					}
					batch = batch[1:]
				}
				results, err := store.commitBatch(batch)
				if err != nil {
					t.Fatal(err)
				}
				for i, result := range results {
					if (result != nil) != (!laterBatch && i == 0) {
						t.Fatalf("operation %d: %v", i, result)
					}
				}
				snapshot, err := store.Snapshot(ctx, stage.AuditID)
				if err != nil {
					t.Fatal(err)
				}
				if snapshot.Audit.CaptureStatus != CaptureFailed || snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != "capture_write_failed" {
					t.Fatalf("failed capture finalized with status %q and missing or incorrect failure code", snapshot.Audit.CaptureStatus)
				}
				if snapshot.Audit.ForwardStatus != ForwardCompleted || len(snapshot.Chunks) != 1 || snapshot.Bodies[0].RetentionState != RetentionFull {
					t.Fatal("failed capture changed forwarding or lost the remaining raw evidence")
				}
				other, err := store.Snapshot(ctx, independent.AuditID)
				if err != nil || other.Audit.CaptureStatus != CaptureComplete {
					t.Fatalf("independent audit status = %q, error = %v", other.Audit.CaptureStatus, err)
				}
				if err := store.VerifyIntegrityPayloads(ctx); err != nil {
					t.Fatalf("final capture failure was not signed consistently: %v", err)
				}
			})
		}
	}
}

func TestWriterIsolatesParsedSaveFailureFromQueuedCapture(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	request, response := graphObjectFixture()
	saveGraphTestTurn(t, store, cipher, "existing-turn", "", "response-existing", 100, request, response)
	parsed := buildGraphTestTurn(t, store, cipher, "failing-turn", "", "response-failing", 200, request, response)
	if _, err := store.writerDB.Exec("UPDATE binary_objects SET plaintext_length = plaintext_length + 1"); err != nil {
		t.Fatal(err)
	}
	record := testAudit("capture-alongside-parser")
	record.defaults()
	stage := HTTPStage{AuditID: record.AuditID, Stage: StageRequestReceived, StartedAtNS: 2}
	stage.defaults()
	body := BodyStream{AuditID: record.AuditID, Stage: stage.Stage}
	body.defaults()
	chunk := BodyChunk{AuditID: record.AuditID, Stage: stage.Stage, PlaintextLength: 1, ObservedAtNS: 3, DataEnc: []byte{1}}
	chunk.defaults()
	batch := []writeRequest{
		{kind: writeBeginAudit, data: record, ack: make(chan error, 1)},
		{kind: writeStartStage, data: stage},
		{kind: writeSaveParsedAudit, data: parsed, ack: make(chan error, 1)},
		{kind: writeStartBody, data: body},
		{kind: writeAddChunk, data: chunk},
		{kind: writeAddHeaders, data: []HTTPHeader{{AuditID: record.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader, Name: "x-test", ValueLength: 1, ValueEnc: []byte{2}}}},
		{kind: writeFinishStage, data: StageFinish{AuditID: record.AuditID, Stage: stage.Stage, State: StageStatePartial, EndedAtNS: 4}},
		{kind: writeFinishAudit, data: &AuditFinish{AuditID: record.AuditID, EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CapturePartial, ParseStatus: ParsePending}, ack: make(chan error, 1)},
	}
	// Preload a separate writer loop so all operations deterministically share
	// one batch, independent of scheduler timing and the 5 ms batch window.
	writer := &Store{writerDB: store.writerDB, queue: make(chan writeRequest, len(batch)), done: make(chan struct{})}
	for _, op := range batch {
		writer.queue <- op
	}
	close(writer.queue)
	writer.runWriter()
	for i, op := range batch {
		if op.ack != nil {
			if err := <-op.ack; (err != nil) != (i == 2) {
				t.Fatalf("operation %d error = %v", i, err)
			}
		}
	}
	if !writer.healthy.Load() {
		t.Fatal("isolated parser failure changed writer health")
	}
	if writer.Healthy() || writer.IntegrityPayloadState() != "failed" {
		t.Fatal("same-batch successful capture hid stored object corruption")
	}
	snapshot, err := store.Snapshot(context.Background(), record.AuditID)
	if err != nil || len(snapshot.Stages) != 1 || len(snapshot.Headers) != 1 || len(snapshot.Chunks) != 1 {
		t.Fatalf("capture batch was lost: %+v, %v", snapshot, err)
	}
	var parsedCount int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM parsed_results WHERE audit_id = ?", parsed.Result.AuditID).Scan(&parsedCount); err != nil || parsedCount != 0 {
		t.Fatalf("failed parser operation left partial rows: %d, %v", parsedCount, err)
	}
}

func TestWriterTransactionFailureRejectsEveryAcknowledgement(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	if _, err := store.writerDB.Exec(`CREATE TRIGGER fail_transaction BEFORE INSERT ON audit_records
WHEN NEW.audit_id = 'abort-batch' BEGIN SELECT RAISE(ROLLBACK, 'test transaction failure'); END`); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, queue: make(chan writeRequest, 2), done: make(chan struct{})}
	acks := []chan error{make(chan error, 1), make(chan error, 1)}
	for i, id := range []string{"rolled-back", "abort-batch"} {
		record := testAudit(id)
		record.defaults()
		writer.queue <- writeRequest{kind: writeBeginAudit, data: record, ack: acks[i]}
	}
	close(writer.queue)
	writer.runWriter()
	for _, ack := range acks {
		if err := <-ack; err == nil {
			t.Fatal("transaction failure acknowledged as successful")
		}
	}
	if writer.healthy.Load() {
		t.Fatal("transaction failure reported healthy")
	}
	assertTableCount(t, store.readerDB, "audit_records", 0)
}
