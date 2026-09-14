package sqlite

import (
	"context"
	"testing"
)

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
		{kind: writeFinishAudit, data: AuditFinish{AuditID: record.AuditID, EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CapturePartial, ParseStatus: ParsePending}, ack: make(chan error, 1)},
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
