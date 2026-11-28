package sqlite

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"llmapi-logger/internal/storage"
)

// drainWriter returns once every operation queued before it was processed.
func drainWriter(t *testing.T, store *Store) error {
	t.Helper()
	return store.ResetProcessingParses(context.Background())
}

// mismatchedRequest runs a request whose two request bodies differ, so the
// request pair never merges and request_sent has chunks of its own.
func mismatchedRequest(run *eqRun) {
	headers := requestHeaders("application/json")
	run.begin(http.MethodPost, headers, 3<<19, true)
	run.startRequestSent(headers, 3<<19, true)
	run.read(StageRequestReceived, eqNoise(3<<19, 50))
	run.read(StageRequestSent, eqNoise(3<<19, 52))
	run.requestEOF(http.Header{"X-Checksum": {"c"}})
}

func countRows(t *testing.T, store *Store, query string, args ...any) int {
	t.Helper()
	var count int
	if err := store.readerDB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// A checkpoint rejected by a trigger on any of its tables rolls back as a
// whole and fails the audit; CommitAudit then finalizes it as failed without
// an error, skipping the parts whose rows are missing. Legacy under the same
// trigger also ends failed; it only loses the one operation the trigger hit.
func TestCheckpointRejectedByTriggerFailsAudit(t *testing.T) {
	t.Parallel()
	for _, table := range []string{"http_stages", "http_headers", "body_streams", "body_chunks"} {
		t.Run(table, func(t *testing.T) {
			t.Parallel()
			run := newEqRun(t, "trigger-"+table)
			for _, store := range []*Store{run.legacy.store, run.unified.store} {
				if _, err := store.writerDB.Exec(`CREATE TRIGGER reject_request_sent BEFORE INSERT ON ` + table + `
WHEN NEW.stage = '` + StageRequestSent + `' BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			mismatchedRequest(run)
			jsonResponse(run, eqJSON(2000, 52), 4096)
			run.finish()
			for _, result := range []AuditFinish{run.commitResult, run.legacyResult} {
				if result.CaptureStatus != CaptureFailed || result.ErrorCode == nil || *result.ErrorCode != "capture_write_failed" {
					t.Fatalf("outcome = %+v", result)
				}
			}
			unified := run.unified.store
			// The whole checkpoint 1 is gone: request_sent's stage row, both
			// request bodies and the request trailers.
			if n := countRows(t, unified, "SELECT count(*) FROM http_stages WHERE audit_id = ? AND stage = ?", run.id, StageRequestSent); n != 0 {
				t.Fatalf("request_sent stage rows = %d", n)
			}
			if n := countRows(t, unified, "SELECT count(*) FROM body_streams WHERE audit_id = ? AND stage LIKE 'request%'", run.id); n != 0 {
				t.Fatalf("request body rows = %d", n)
			}
			// The trailers of request_received were in the lost checkpoint, so
			// its stage carries the header failure, as legacy marks a lost
			// AddHeaders.
			var state, code string
			if err := unified.readerDB.QueryRow("SELECT state, error_code FROM http_stages WHERE audit_id = ? AND stage = ?", run.id, StageRequestReceived).Scan(&state, &code); err != nil {
				t.Fatal(err)
			}
			if state != StageStatePartial || code != "capture_headers_failed" {
				t.Fatalf("request_received = %s %s", state, code)
			}
			if n := countRows(t, unified, "SELECT count(*) FROM http_stages WHERE audit_id = ? AND (state = 'streaming' OR ended_at_ns IS NULL)", run.id); n != 0 {
				t.Fatalf("unfinished stages = %d", n)
			}
			if n := countRows(t, unified, "SELECT count(*) FROM integrity_events WHERE audit_id = ?", run.id); n != 1 {
				t.Fatalf("integrity events = %d", n)
			}
			run.verifyIntegrity()
		})
	}
}

// A checkpoint whose batch fails at the storage level is remembered; the
// commit's pre-check persists the failure marker before it finalizes.
func TestCheckpointBatchFailureIsRecoveredBeforeCommit(t *testing.T) {
	t.Parallel()
	run := newEqRun(t, "checkpoint-batch")
	headers := requestHeaders("application/json")
	body := eqJSON(3000, 53)
	run.begin(http.MethodPost, headers, int64(len(body)), true)
	run.startRequestSent(headers, int64(len(body)), true)
	run.readBoth(body)
	unified := run.unified.store
	if err := drainWriter(t, unified); err != nil {
		t.Fatal(err)
	}
	setWriterReadOnly(t, unified, true)
	run.requestEOF(nil)
	if err := drainWriter(t, unified); ErrorClass(err) != "sqlite_read_only" {
		t.Fatalf("drain error = %v", err)
	}
	if unified.recoveryPending.Load() != 1 {
		t.Fatalf("pending recoveries = %d", unified.recoveryPending.Load())
	}
	setWriterReadOnly(t, unified, false)
	jsonResponse(run, eqJSON(500, 54), 4096)
	run.finish()
	if run.commitResult.CaptureStatus != CaptureFailed {
		t.Fatalf("outcome = %+v", run.commitResult)
	}
	if n := countRows(t, unified, "SELECT count(*) FROM http_stages WHERE audit_id = ? AND stage = ?", run.id, StageRequestSent); n != 0 {
		t.Fatalf("request_sent stage rows = %d", n)
	}
	waitForCaptureRecovery(t, unified)
	if err := unified.VerifyIntegrityPayloads(run.ctx); err != nil {
		t.Fatal(err)
	}
}

// A commit whose batch fails is returned wrapping ErrWriteBatchFailed with
// the SQLite cause, is not handed to recovery before its final attempt, and a
// retry writes the same rows as legacy.
func TestCommitAuditBatchFailureRetriesToLegacyRows(t *testing.T) {
	t.Parallel()
	run := newEqRun(t, "commit-retry")
	unified := run.unified.store
	attempts := 0
	run.unified.failCommit = func(commit AuditCommit) (AuditFinish, error) {
		if err := drainWriter(t, unified); err != nil {
			t.Fatal(err)
		}
		setWriterReadOnly(t, unified, true)
		_, err := unified.CommitAudit(run.ctx, commit)
		attempts++
		if !errors.Is(err, ErrWriteBatchFailed) || ErrorClass(err) != "sqlite_read_only" {
			t.Fatalf("first attempt error = %v", err)
		}
		if unified.recoveryPending.Load() != 0 {
			t.Fatal("a non-final failed commit was handed to recovery")
		}
		setWriterReadOnly(t, unified, false)
		attempts++
		return unified.CommitAudit(run.ctx, commit)
	}
	sendRequest(run, eqJSON(3000, 55), 1000, nil)
	streamResponse(run, 6, nil)
	run.finish()
	if attempts != 2 || run.commitResult.CaptureStatus != CaptureComplete {
		t.Fatalf("attempts = %d outcome = %+v", attempts, run.commitResult)
	}
	run.assertSameRows()
}

// The final attempt's batch failure leaves the outcome to write recovery,
// which finalizes the audit as failed and keeps the checkpoint rows.
func TestCommitAuditFinalAttemptFailureIsRecovered(t *testing.T) {
	t.Parallel()
	run := newEqRun(t, "commit-final")
	unified := run.unified.store
	run.unified.failCommit = func(commit AuditCommit) (AuditFinish, error) {
		commit.FinalAttempt = true
		if err := drainWriter(t, unified); err != nil {
			t.Fatal(err)
		}
		setWriterReadOnly(t, unified, true)
		if _, err := unified.CommitAudit(run.ctx, commit); !errors.Is(err, ErrWriteBatchFailed) {
			t.Fatalf("final attempt error = %v", err)
		}
		if unified.recoveryPending.Load() != 1 {
			t.Fatal("the final failed commit was not handed to recovery")
		}
		setWriterReadOnly(t, unified, false)
		unified.recoveryWake <- struct{}{}
		waitForCaptureRecovery(t, unified)
		return AuditFinish{}, nil
	}
	sendRequest(run, eqJSON(3000, 56), 1000, nil)
	streamResponse(run, 6, nil)
	run.finish()
	snapshot, err := unified.Snapshot(run.ctx, run.id)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.EndedAtNS == nil || snapshot.Audit.CaptureStatus != CaptureFailed {
		t.Fatalf("recovered audit = %+v", snapshot.Audit)
	}
	// Checkpoint 1 wrote the request side; it is still there, finalized.
	if len(snapshot.Chunks) == 0 || len(snapshot.Stages) != 4 {
		t.Fatalf("checkpoint rows lost: %d chunks, %d stages", len(snapshot.Chunks), len(snapshot.Stages))
	}
	for _, body := range snapshot.Bodies {
		if body.State == StageStateStreaming || body.RetentionState != RetentionFull {
			t.Fatalf("body left unfinished: %+v", body)
		}
	}
	if n := countRows(t, unified, "SELECT count(*) FROM integrity_events WHERE audit_id = ?", run.id); n != 1 {
		t.Fatalf("integrity events = %d", n)
	}
	if err := unified.VerifyIntegrityPayloads(run.ctx); err != nil {
		t.Fatal(err)
	}
}

// An operation-level commit failure is not retried and not wrapped: the
// audit is failed in the same batch and its outcome goes to recovery at once.
func TestCommitAuditConstraintFailureIsNotRetried(t *testing.T) {
	t.Parallel()
	run := newEqRun(t, "commit-constraint")
	unified := run.unified.store
	if _, err := unified.writerDB.Exec(`CREATE TRIGGER reject_body_finish BEFORE UPDATE OF state ON body_streams
BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END`); err != nil {
		t.Fatal(err)
	}
	run.unified.failCommit = func(commit AuditCommit) (AuditFinish, error) {
		_, err := unified.CommitAudit(run.ctx, commit)
		if err == nil || errors.Is(err, ErrWriteBatchFailed) || ErrorClass(err) != "sqlite_constraint" {
			t.Fatalf("commit error = %v", err)
		}
		if unified.recoveryPending.Load() != 1 {
			t.Fatal("an isolated commit failure was not handed to recovery")
		}
		var status, code string
		var ended *int64
		if err := unified.readerDB.QueryRow("SELECT capture_status, error_code, ended_at_ns FROM audit_records WHERE audit_id = ?", run.id).Scan(&status, &code, &ended); err != nil {
			t.Fatal(err)
		}
		if status != CaptureFailed || code != "capture_write_failed" || ended != nil {
			t.Fatalf("audit after failed commit = %s %s %v", status, code, ended)
		}
		if _, err := unified.writerDB.Exec("DROP TRIGGER reject_body_finish"); err != nil {
			t.Fatal(err)
		}
		unified.recoveryWake <- struct{}{}
		waitForCaptureRecovery(t, unified)
		return AuditFinish{}, nil
	}
	sendRequest(run, eqJSON(2000, 57), 1000, nil)
	jsonResponse(run, eqJSON(800, 58), 4096)
	run.finish()
	snapshot, err := unified.Snapshot(run.ctx, run.id)
	if err != nil || snapshot.Audit.EndedAtNS == nil || snapshot.Audit.CaptureStatus != CaptureFailed {
		t.Fatalf("recovered audit = %+v %v", snapshot.Audit, err)
	}
	if err := unified.VerifyIntegrityPayloads(run.ctx); err != nil {
		t.Fatal(err)
	}
}

// A commit or checkpoint for an audit already finalized reads back the
// committed outcome and changes nothing: no row and no second integrity event.
func TestFinalizedAuditIgnoresRepeatedWrites(t *testing.T) {
	t.Parallel()
	run := newEqRun(t, "finalized")
	sendRequest(run, eqJSON(2000, 59), 1000, nil)
	streamResponse(run, 4, nil)
	run.finish()
	unified := run.unified.store
	before := dumpDatabase(t, unified.writerDB, run.unified.cipher)

	repeat := run.unified.lastCommit
	repeat.Finish.EndedAtNS += 1000
	repeat.Finish.CaptureStatus = CapturePartial
	repeat.Finish.ErrorCode = stringPointer("audit_finalize_failed")
	repeat.FinalAttempt = true
	result, err := unified.CommitAudit(run.ctx, repeat)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFinish(result, run.commitResult) {
		t.Fatalf("repeated commit returned %+v, committed %+v", result, run.commitResult)
	}
	trailer := sealHeaders(t, run.unified.cipher, run.id, StageResponseSent, eqGroup{kind: HeaderKindTrailer, values: []eqValue{{name: "X-Late", value: "late"}}})
	if err := unified.Checkpoint(run.ctx, AuditCheckpoint{AuditID: run.id, Headers: trailer}); err != nil {
		t.Fatal(err)
	}
	if err := drainWriter(t, unified); err != nil {
		t.Fatal(err)
	}
	after := dumpDatabase(t, unified.writerDB, run.unified.cipher)
	if diffs := diffDumps(before, after); len(diffs) != 0 {
		t.Fatalf("finalized audit changed:\n%s", strings.Join(diffs, "\n"))
	}
	if unified.recoveryPending.Load() != 0 {
		t.Fatal("a repeated commit left a recovery entry")
	}
}

// A queue-full checkpoint is not remembered: the session folds its content
// into the next write. A queue-full commit is remembered only on its final
// attempt.
func TestQueueFullCheckpointAndCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if err := store.BeginAudit(ctx, testAudit("queue-full")); err != nil {
		t.Fatal(err)
	}
	writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{}), recoveryWake: make(chan struct{}, 1)}
	if err := writer.StartStage(ctx, HTTPStage{AuditID: "queue-full", Stage: StageRequestReceived, StartedAtNS: 2}); err != nil {
		t.Fatal(err)
	}
	checkpoint := AuditCheckpoint{AuditID: "queue-full", Stages: []HTTPStage{{AuditID: "queue-full", Stage: StageRequestSent, StartedAtNS: 3}}}
	if err := writer.Checkpoint(ctx, checkpoint); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("checkpoint error = %v", err)
	}
	ended := int64(4)
	commit := AuditCommit{
		Finish: AuditFinish{AuditID: "queue-full", EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending},
		Stages: []StageCommit{{Stage: HTTPStage{AuditID: "queue-full", Stage: StageRequestReceived, State: StageStateComplete, StartedAtNS: 2, EndedAtNS: &ended}, StageWritten: true}},
	}
	if _, err := writer.CommitAudit(ctx, commit); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("commit error = %v", err)
	}
	if writer.recoveryPending.Load() != 0 {
		t.Fatal("a queue-full checkpoint or non-final commit was remembered")
	}
	commit.FinalAttempt = true
	if _, err := writer.CommitAudit(ctx, commit); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("final commit error = %v", err)
	}
	if writer.recoveryPending.Load() != 1 {
		t.Fatal("a queue-full final commit was not remembered")
	}
}

// A chunk that fails validation inside the writer is a local error: only its
// checkpoint rolls back and the audit is failed; the batch commits.
func TestCheckpointInvalidChunkIsIsolated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	for _, id := range []string{"bad-chunk", "neighbour"} {
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
	}
	stage := HTTPStage{AuditID: "bad-chunk", Stage: StageRequestSent, StartedAtNS: 2}
	checkpoint := AuditCheckpoint{
		AuditID: "bad-chunk", Stages: []HTTPStage{stage},
		Bodies: []BodyStream{{AuditID: "bad-chunk", Stage: StageRequestSent}},
		Chunks: storage.ChunkList{{AuditID: "neighbour", Stage: StageRequestSent, PlaintextLength: 1, ObservedAtNS: 3, DataEnc: []byte{1}}},
	}
	if err := store.Checkpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx, AuditCheckpoint{AuditID: "neighbour", Stages: []HTTPStage{{AuditID: "neighbour", Stage: StageRequestSent, StartedAtNS: 2}}}); err != nil {
		t.Fatal(err)
	}
	if err := drainWriter(t, store); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, store, "SELECT count(*) FROM http_stages WHERE audit_id = 'bad-chunk'"); n != 0 {
		t.Fatalf("rolled back checkpoint left %d stage rows", n)
	}
	if n := countRows(t, store, "SELECT count(*) FROM http_stages WHERE audit_id = 'neighbour'"); n != 1 {
		t.Fatal("the neighbouring checkpoint in the batch was lost")
	}
	if n := countRows(t, store, "SELECT count(*) FROM audit_records WHERE audit_id = 'bad-chunk' AND capture_status = 'failed' AND error_code = 'capture_write_failed'"); n != 1 {
		t.Fatal("the audit was not failed")
	}
	if !store.Healthy() {
		t.Fatal("an isolated local error made the writer unhealthy")
	}
}

func TestUnifiedWritesRejectCaptureVersion2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	if store.SupportsHeaderBlock() {
		t.Fatal("the SQLite store claims header block support")
	}
	record := testAudit("version-2")
	record.CaptureVersion = storage.CaptureVersion2
	if err := store.BeginAudit(ctx, record); err == nil {
		t.Fatal("version 2 BeginAudit accepted")
	}
	if err := store.BeginAudit(ctx, testAudit("version-1")); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx, AuditCheckpoint{AuditID: "version-1", CaptureVersion: storage.CaptureVersion2}); err == nil {
		t.Fatal("version 2 checkpoint accepted")
	}
	commit := AuditCommit{CaptureVersion: storage.CaptureVersion2,
		Finish: AuditFinish{AuditID: "version-1", EndedAtNS: 5, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}}
	if _, err := store.CommitAudit(ctx, commit); err == nil {
		t.Fatal("version 2 commit accepted")
	}
	if n := countRows(t, store, "SELECT count(*) FROM audit_records"); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
}

// BeginAudit with the inbound stage writes the audit row, the stage row and
// its headers in one operation. A rejected stage row or header loses only
// that part: the start row commits, marked as legacy marks a failed
// StartStage or AddHeaders. A batch-level failure still fails BeginAudit.
func TestBeginAuditInboundStageKeepsStartRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	inbound := func(id string) AuditRecord {
		record := testAudit(id)
		record.Inbound = &InboundStage{
			Stage:   HTTPStage{AuditID: id, Stage: StageRequestReceived, Proto: "HTTP/1.1", Method: "POST", Host: "proxy.example.com", StartedAtNS: 2},
			Headers: []HTTPHeader{{AuditID: id, Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "Content-Type", ValueLength: 4, ValueEnc: []byte{1}}},
		}
		return record
	}
	if err := store.BeginAudit(ctx, inbound("inbound")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx, "inbound")
	if err != nil || len(snapshot.Stages) != 1 || snapshot.Stages[0].State != StageStateStreaming || len(snapshot.Headers) != 1 || snapshot.Audit.CaptureStatus != CapturePending {
		t.Fatalf("inbound snapshot = %+v %v", snapshot, err)
	}
	for _, testCase := range []struct {
		table, stageState, stageCode string
		stages                       int
		stageLost                    bool
	}{
		{table: "http_headers", stages: 1, stageState: StageStatePartial, stageCode: "capture_headers_failed"},
		{table: "http_stages", stages: 0, stageLost: true},
	} {
		id := "inbound-" + testCase.table
		if _, err := store.writerDB.Exec(`CREATE TRIGGER reject_inbound BEFORE INSERT ON ` + testCase.table + `
WHEN NEW.audit_id = '` + id + `' BEGIN SELECT RAISE(ABORT, 'injected inbound failure'); END`); err != nil {
			t.Fatal(err)
		}
		err := store.BeginAudit(ctx, inbound(id))
		if testCase.stageLost {
			// Only a lost stage row is reported, and not as a storage failure.
			if !errors.Is(err, storage.ErrInboundStageNotStored) || ErrorClass(err) != "inbound_stage_not_stored" {
				t.Fatalf("%s: BeginAudit error = %v", testCase.table, err)
			}
		} else if err != nil {
			t.Fatalf("%s: BeginAudit error = %v", testCase.table, err)
		}
		if _, err := store.writerDB.Exec("DROP TRIGGER reject_inbound"); err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.Snapshot(ctx, id)
		if err != nil || snapshot.Audit.CaptureStatus != CaptureFailed || snapshot.Audit.ErrorCode == nil || *snapshot.Audit.ErrorCode != "capture_write_failed" ||
			len(snapshot.Headers) != 0 || len(snapshot.Stages) != testCase.stages {
			t.Fatalf("%s: snapshot = %+v %v", testCase.table, snapshot, err)
		}
		if testCase.stages == 1 && (snapshot.Stages[0].State != testCase.stageState || snapshot.Stages[0].ErrorCode == nil || *snapshot.Stages[0].ErrorCode != testCase.stageCode) {
			t.Fatalf("%s: stage = %+v", testCase.table, snapshot.Stages[0])
		}
	}
	setWriterReadOnly(t, store, true)
	if err := store.BeginAudit(ctx, inbound("inbound-read-only")); ErrorClass(err) != "sqlite_read_only" || errors.Is(err, storage.ErrInboundStageNotStored) {
		t.Fatalf("batch failure error = %v", err)
	}
	setWriterReadOnly(t, store, false)
	if n := countRows(t, store, "SELECT count(*) FROM audit_records WHERE audit_id = 'inbound-read-only'"); n != 0 {
		t.Fatal("a failed batch committed the start row")
	}
	wrong := testAudit("inbound-wrong-stage")
	wrong.Inbound = &InboundStage{Stage: HTTPStage{AuditID: "inbound-wrong-stage", Stage: StageRequestSent, StartedAtNS: 2}}
	if err := store.BeginAudit(ctx, wrong); err == nil {
		t.Fatal("an inbound stage other than request_received was accepted")
	}
}

// The same trigger at BeginAudit time on both databases: legacy loses its
// StartStage or AddHeaders of request_received, the unified path loses the
// inbound part of BeginAudit. End to end through the checkpoints and
// CommitAudit, both end failed with the same rows. The request and response
// pairs are not mergeable here, because for a failed audit legacy never
// merges while the session decides a merge in memory (see the report).
func TestBeginAuditInboundFailureMatchesLegacyEndToEnd(t *testing.T) {
	t.Parallel()
	for _, trigger := range []struct {
		name, table, when string
		mergeableRequest  bool
	}{
		{"stage row", "http_stages", "NEW.stage = '" + StageRequestReceived + "'", false},
		{"header rows", "http_headers", "NEW.stage = '" + StageRequestReceived + "' AND NEW.kind = 'header'", false},
		// The session learned from BeginAudit that the stage row is lost and
		// sends request_sent unmerged with its chunks, with DedupInDB for the
		// request pair, so request_sent is stored as legacy stores it.
		{"stage row with a mergeable request pair", "http_stages", "NEW.stage = '" + StageRequestReceived + "'", true},
	} {
		t.Run(trigger.name, func(t *testing.T) {
			t.Parallel()
			run := newEqRun(t, "inbound-"+trigger.table)
			for _, store := range []*Store{run.legacy.store, run.unified.store} {
				if _, err := store.writerDB.Exec(`CREATE TRIGGER reject_inbound BEFORE INSERT ON ` + trigger.table + `
WHEN ` + trigger.when + ` BEGIN SELECT RAISE(ABORT, 'injected inbound failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if trigger.mergeableRequest {
				sendRequest(run, eqNoise(3<<19, 80), 256<<10, http.Header{"X-Checksum": {"c"}})
			} else {
				mismatchedRequest(run)
			}
			run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
			run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
			for _, event := range eqSSE(4) {
				run.read(StageResponseReceived, event)
				run.write(event, nil)
			}
			run.readError(StageResponseReceived)
			run.finish()
			if run.unified.checkpoints != 2 {
				t.Fatalf("checkpoints = %d", run.unified.checkpoints)
			}
			for _, result := range []AuditFinish{run.commitResult, run.legacyResult} {
				if result.CaptureStatus != CaptureFailed || result.ErrorCode == nil || *result.ErrorCode != "capture_write_failed" {
					t.Fatalf("outcome = %+v", result)
				}
			}
			if !sameFinish(run.commitResult, run.legacyResult) {
				t.Fatalf("committed outcome %+v, legacy %+v", run.commitResult, run.legacyResult)
			}
			run.assertSameRows()
			if n := countRows(t, run.unified.store, "SELECT count(*) FROM http_stages WHERE audit_id = ?", run.id); n < 3 {
				t.Fatalf("unified kept %d stage rows", n)
			}
			if run.unified.inboundLost != (trigger.table == "http_stages") {
				t.Fatalf("inbound lost = %v", run.unified.inboundLost)
			}
			if trigger.mergeableRequest {
				if run.unified.merged[StageRequestSent] || !run.unified.lastCommit.DedupInDB[0] {
					t.Fatal("the request pair was merged in memory after a lost inbound stage")
				}
				if body := bodyRow(t, run, StageRequestSent); body.SourceStage != StageRequestSent || body.StoredLength != 3<<19 {
					t.Fatalf("request_sent body = %+v", body)
				}
				if n := countRows(t, run.unified.store, "SELECT count(*) FROM body_chunks WHERE audit_id = ? AND stage = ?", run.id, StageRequestSent); n != 2 {
					t.Fatalf("request_sent chunks = %d", n)
				}
			}
		})
	}
}
