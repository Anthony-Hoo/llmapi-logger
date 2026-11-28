package proxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// largeStreamExchange is a streamed chat turn whose request body spans
// several 1 MiB chunks.
func largeStreamExchange(t *testing.T) *eqExchange {
	t.Helper()
	built, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 501, HistoryItems: 700, ItemBytes: 4000})
	if err != nil {
		t.Fatal(err)
	}
	exchange := fromFixture("large-stream", built[0], 128<<10)
	if len(exchange.body) < 2<<20 {
		t.Fatalf("request is only %d bytes", len(exchange.body))
	}
	return exchange
}

// sendAgainstOracle sends the exchange; the client must see what it saw on
// the legacy path (the legacy oracle's "view").
func sendAgainstOracle(t *testing.T, unified *eqRun, exchange *eqExchange) eqClientView {
	t.Helper()
	unifiedView, _ := unified.send(copyChunks(exchange))
	if view := frozen[eqFrozenView](t, "view"); view != frozenView(unifiedView) {
		t.Fatalf("client saw %+v, unified %+v %q", view, frozenView(unifiedView), unifiedView.body)
	}
	return unifiedView
}

// compareRuns compares the unified run's rows with the legacy oracle's:
// "captured", each audit's rows as committed, before any parse released raw
// chunks, and "final", the whole database at the end. delta turns the legacy
// rows into what the unified path stores by design.
func compareRuns(t *testing.T, unified *eqRun, delta func(map[string][]eqRow)) map[string][]eqRow {
	t.Helper()
	captured := frozen[map[string]map[string][]eqRow](t, "captured")
	if len(captured) != len(unified.captured) {
		t.Fatalf("%d audits, unified %d", len(captured), len(unified.captured))
	}
	for id, committed := range captured {
		if delta != nil {
			delta(committed)
		}
		if diffs := diffEqDumps(committed, unified.captured[id]); len(diffs) != 0 {
			t.Fatalf("committed rows differ:\n%s", strings.Join(diffs[:min(len(diffs), 30)], "\n"))
		}
	}
	unified.worker.Close()
	legacyDump := frozen[map[string][]eqRow](t, "final")
	unifiedDump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
	if delta != nil {
		delta(legacyDump)
	}
	if diffs := diffEqDumps(legacyDump, unifiedDump); len(diffs) != 0 {
		t.Fatalf("rows differ:\n%s", strings.Join(diffs[:min(len(diffs), 30)], "\n"))
	}
	return unifiedDump
}

// A checkpoint the queue refuses is folded into the next write: the stored
// rows are those of a run without the fault, no gap is recorded, and one
// stable log line says what happened (design B.8, K item 4).
func TestCheckpointQueueFullIsFoldedIntoTheNextWrite(t *testing.T) {
	for _, refuse := range []int{1, 2} {
		t.Run(fmt.Sprintf("checkpoint %d refused", refuse), func(t *testing.T) {
			var counting *countingStore
			unified := newEqRun(t, audit.Options{}, func(store *sqlite.Store) audit.Store {
				counting = &countingStore{Store: store}
				var calls atomic.Int64
				counting.checkpoint = func(storage.AuditCheckpoint) error {
					if calls.Add(1) == int64(refuse) {
						return storage.ErrQueueFull
					}
					return nil
				}
				return counting
			})
			sendAgainstOracle(t, unified, largeStreamExchange(t))
			dump := compareRuns(t, unified, nil)
			if len(dump["audit_gaps"]) != 0 || counting.checkpoints.Load() != 2 {
				t.Fatalf("gaps %d, checkpoints %d", len(dump["audit_gaps"]), counting.checkpoints.Load())
			}
			if !strings.Contains(string(unified.logs.Bytes()), `"error_code":"capture_checkpoint_deferred"`) {
				t.Fatal("deferred checkpoint was not logged")
			}
		})
	}
}

type commitScript struct {
	attempts []bool // FinalAttempt of each attempt
	fail     func(attempt int) error
}

func scriptedCommitRun(t *testing.T, retries int, script *commitScript, sleeps *[]time.Duration) *eqRun {
	t.Helper()
	options := audit.Options{CommitRetries: retries, Sleep: func(delay time.Duration) { *sleeps = append(*sleeps, delay) }}
	return newEqRun(t, options, func(store *sqlite.Store) audit.Store {
		counting := &countingStore{Store: store}
		counting.commit = func(commit sqlite.AuditCommit) (sqlite.AuditFinish, error, bool) {
			attempt := len(script.attempts)
			script.attempts = append(script.attempts, commit.FinalAttempt)
			if err := script.fail(attempt); err != nil {
				return sqlite.AuditFinish{}, err, true
			}
			return sqlite.AuditFinish{}, nil, false
		}
		return counting
	})
}

func TestCommitAuditRetries(t *testing.T) {
	batch := fmt.Errorf("commit: %w", storage.ErrWriteBatchFailed)
	constraint := errors.New("constraint failed")
	for _, test := range []struct {
		name       string
		retries    int
		fail       func(attempt int) error
		attempts   []bool
		sleeps     []time.Duration
		finalError bool
	}{
		{"batch failure once, then success", 3, func(attempt int) error {
			if attempt == 0 {
				return batch
			}
			return nil
		}, []bool{false, false}, []time.Duration{100 * time.Millisecond}, false},
		{"queue full once, then success", 3, func(attempt int) error {
			if attempt == 0 {
				return storage.ErrQueueFull
			}
			return nil
		}, []bool{false, false}, []time.Duration{100 * time.Millisecond}, false},
		{"batch failure every time", 3, func(int) error { return batch }, []bool{false, false, false, true},
			[]time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}, true},
		{"five retries cap at one second", 5, func(int) error { return storage.ErrQueueFull }, []bool{false, false, false, false, false, true},
			[]time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, time.Second}, true},
		{"constraint failure is not retried", 3, func(int) error { return constraint }, []bool{false}, nil, true},
		{"zero retries", 0, func(int) error { return storage.ErrQueueFull }, []bool{true}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := &commitScript{fail: test.fail}
			var sleeps []time.Duration
			unified := scriptedCommitRun(t, test.retries, script, &sleeps)
			unified.noParse = test.finalError
			view, id := unified.send(copyChunks(largeStreamExchange(t)))
			if view.status != 200 {
				t.Fatalf("status %d", view.status)
			}
			if fmt.Sprint(script.attempts) != fmt.Sprint(test.attempts) || fmt.Sprint(sleeps) != fmt.Sprint(test.sleeps) {
				t.Fatalf("attempts %v sleeps %v, want %v %v", script.attempts, sleeps, test.attempts, test.sleeps)
			}
			record := completionLogRecords(t, unified.logs.Bytes())[0]
			snapshot, err := unified.store.Snapshot(context.Background(), id)
			// A failed commit is no barrier: wait for the checkpoints.
			for deadline := time.Now().Add(5 * time.Second); err == nil && test.finalError && len(snapshot.Stages) < 4 && time.Now().Before(deadline); {
				time.Sleep(5 * time.Millisecond)
				snapshot, err = unified.store.Snapshot(context.Background(), id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.finalError {
				// The same outcome as a failed FinishAudit on the legacy path.
				assertLogField(t, record, "capture_status", "partial")
				assertLogField(t, record, "error_code", "audit_finalize_failed")
				if !strings.Contains(string(unified.logs.Bytes()), `"error_code":"finish_audit_failed"`) || snapshot.Audit.EndedAtNS != nil {
					t.Fatalf("final failure: log %s, ended %v", unified.logs.Bytes(), snapshot.Audit.EndedAtNS)
				}
				// The checkpoints' rows are in the database all the same.
				if len(snapshot.Stages) != 4 || len(snapshot.Chunks) == 0 {
					t.Fatalf("checkpointed rows: %d stages, %d chunks", len(snapshot.Stages), len(snapshot.Chunks))
				}
				return
			}
			assertLogField(t, record, "capture_status", "complete")
			if snapshot.Audit.CaptureStatus != "complete" || snapshot.Audit.EndedAtNS == nil {
				t.Fatalf("audit %+v", snapshot.Audit)
			}
		})
	}
}

// Content beyond the memory budget is not retained: the stage is partial
// with capture_budget_exhausted, the audit keeps raw in full for what it
// has, a queue_full gap is recorded and forwarding is unchanged (F.6).
func TestMemoryBudgetExhaustion(t *testing.T) {
	// No staging: the budget alone decides (design F.6).
	unified := newEqRun(t, audit.Options{StageBytes: 1 << 20, GlobalBytes: 1 << 20, Stager: refusingStager{}}, nil)
	// The forwarded bytes are legacy's (sendAgainstOracle).
	sendAgainstOracle(t, unified, largeStreamExchange(t))
	unified.manager.CloseGaps(context.Background())
	snapshot, err := unified.store.Snapshot(context.Background(), unified.lastAuditID())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.CaptureStatus != "partial" {
		t.Fatalf("capture status %s", snapshot.Audit.CaptureStatus)
	}
	exhausted := 0
	for _, body := range snapshot.Bodies {
		if body.ErrorCode != nil && *body.ErrorCode == "capture_budget_exhausted" {
			exhausted++
			if body.State != "partial" || body.StoredLength >= body.ObservedLength || body.RetentionState != "full" {
				t.Fatalf("exhausted body %+v", body)
			}
		}
	}
	if exhausted == 0 {
		t.Fatalf("no exhausted body: %+v", snapshot.Bodies)
	}
	for _, stage := range snapshot.Stages {
		if stage.Stage == storage.StageRequestReceived && (stage.State != "partial" || stage.ErrorCode == nil || *stage.ErrorCode != "capture_budget_exhausted") {
			t.Fatalf("request stage %+v", stage)
		}
	}
	dump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
	if len(dump["audit_gaps"]) != 1 || dump["audit_gaps"][0]["reason"] != `"queue_full"` {
		t.Fatalf("gaps %v", dump["audit_gaps"])
	}
	if used := unifiedBudgetUsed(unified); used != 0 {
		t.Fatalf("budget still holds %d bytes", used)
	}
}

func unifiedBudgetUsed(run *eqRun) int64 { return run.manager.MemoryInUse() }

// A start row committed without its inbound stage (a trigger rejects the
// request_received stage row on both paths): the audit is admitted, ends
// failed, and its rows equal legacy's except that the response pair is
// merged in memory where legacy, for a failed capture, keeps both copies.
func TestInboundStageNotStoredMatchesLegacy(t *testing.T) {
	unified := newEqRun(t, audit.Options{}, nil)
	execSQL(t, unified.dbPath, `CREATE TRIGGER reject_inbound BEFORE INSERT ON http_stages
		WHEN NEW.stage = 'request_for_newapi_received_from_nginx' BEGIN SELECT RAISE(ABORT, 'rejected by test'); END`)
	sendAgainstOracle(t, unified, largeStreamExchange(t))
	// Legacy, under the same trigger, logged completed and failed too.
	record := completionLogRecords(t, unified.logs.Bytes())[0]
	assertLogField(t, record, "forward_status", "completed")
	assertLogField(t, record, "capture_status", "failed")
	// The unified session learns of the lost stage from BeginAudit and says
	// so as legacy does for a StartStage it is told failed; a legacy session
	// whose StartStage is rejected inside the writer never learns of it.
	if !strings.Contains(string(unified.logs.Bytes()), `"error_code":"start_stage_failed"`) {
		t.Fatal("unified: no start_stage_failed log")
	}
	dump := compareRuns(t, unified, func(legacy map[string][]eqRow) {
		mergeResponsePair(t, legacy)
	})
	for _, row := range dump["body_streams"] {
		if row["stage"] == `"`+storage.StageRequestSent+`"` && row["source_stage"] != row["stage"] {
			t.Fatalf("request_sent merged: %v", row)
		}
	}
	if dump["audit_records"][0]["capture_status"] != `"failed"` {
		t.Fatalf("audit %v", dump["audit_records"][0])
	}
}

// mergeResponsePair rewrites legacy's unmerged response pair into the
// merged shape: response_sent points at response_received, takes its stored
// length and chunk count, and has no chunks of its own.
func mergeResponsePair(t *testing.T, dump map[string][]eqRow) {
	t.Helper()
	sent, received := `"`+storage.StageResponseSent+`"`, `"`+storage.StageResponseReceived+`"`
	var source eqRow
	for _, row := range dump["body_streams"] {
		if row["stage"] == received {
			source = row
		}
	}
	for _, row := range dump["body_streams"] {
		if row["stage"] == sent {
			row["source_stage"] = received
			for _, column := range []string{"stored_length", "chunk_count", "stream_event_count", "stream_timeline_complete"} {
				row[column] = source[column]
			}
		}
	}
	dropEqRows(dump, "body_chunks", func(row eqRow) bool { return row["stage"] == sent })
}

func dropEqRows(dump map[string][]eqRow, table string, match func(eqRow) bool) int {
	kept := dump[table][:0]
	dropped := 0
	for _, row := range dump[table] {
		if match(row) {
			dropped++
			continue
		}
		kept = append(kept, row)
	}
	dump[table] = kept
	return dropped
}

func execSQL(t *testing.T, path, statement string) {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

// freezingStore stops every write once frozen, as a process that dies does:
// what was enqueued before still commits, nothing after does.
type freezingStore struct {
	*sqlite.Store
	frozen atomic.Bool
}

func (store *freezingStore) Checkpoint(ctx context.Context, value sqlite.AuditCheckpoint) error {
	if store.frozen.Load() {
		return nil
	}
	return store.Store.Checkpoint(ctx, value)
}
func (store *freezingStore) CommitAudit(ctx context.Context, value sqlite.AuditCommit) (sqlite.AuditFinish, error) {
	if store.frozen.Load() {
		return sqlite.AuditFinish{}, storage.ErrClosed
	}
	return store.Store.CommitAudit(ctx, value)
}

func crashRun(t *testing.T, at func(event string, count int) bool) (*eqRun, *freezingStore) {
	t.Helper()
	var frozen *freezingStore
	run := newEqRun(t, audit.Options{}, func(store *sqlite.Store) audit.Store {
		frozen = &freezingStore{Store: store}
		return frozen
	})
	run.noParse = true
	run.upstream.hook = func(event string, count int) {
		if at(event, count) {
			frozen.frozen.Store(true)
		}
	}
	return run, frozen
}

// recoverRun discards the process state and runs the store's recovery, as a
// restart does.
func recoverRun(t *testing.T, run *eqRun) {
	t.Helper()
	run.worker.Close()
	if err := run.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlite.Open(context.Background(), run.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(context.Background(), eqKey); err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.RecoverInterruptedAudits(context.Background(), eqClockOrigin+10_000_000); err != nil || count != 1 {
		t.Fatalf("recovered %d: %v", count, err)
	}
	if err := reopened.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatalf("integrity after recovery: %v", err)
	}
	run.store = reopened
}

// Design I.2 without staging: at each crash point of B.7 the recovered audit
// has the rows the unified column promises and the shape of the legacy audit
// interrupted at the same point, apart from the listed differences.
func TestCrashPointsMatchLegacyAfterRecovery(t *testing.T) {
	stage := func(name string) string { return `"` + name + `"` }
	dropStage := func(dump map[string][]eqRow, table, name string) int {
		return dropEqRows(dump, table, func(row eqRow) bool { return row["stage"] == stage(name) })
	}
	mergedRequest := func(t *testing.T, dump map[string][]eqRow) {
		for _, row := range dump["body_streams"] {
			if row["stage"] == stage(storage.StageRequestSent) {
				row["source_stage"] = stage(storage.StageRequestReceived)
			}
		}
		if dropStage(dump, "body_chunks", storage.StageRequestSent) == 0 {
			t.Fatal("legacy request_sent had no chunks")
		}
	}
	for _, test := range []struct {
		name  string
		at    func(event string, count int) bool
		delta func(t *testing.T, legacy map[string][]eqRow)
		// stages and chunks the recovered unified audit has.
		stages, chunks int
	}{
		{
			// K item 1: BeginAudit wrote the inbound stage and its headers;
			// request_sent's row and headers are not written yet.
			name: "before the request body is read",
			at:   func(event string, _ int) bool { return event == "roundtrip" },
			delta: func(t *testing.T, legacy map[string][]eqRow) {
				dropStage(legacy, "http_stages", storage.StageRequestSent)
				dropStage(legacy, "http_headers", storage.StageRequestSent)
			},
			stages: 1,
		},
		{
			// B.7 row 2: a request body under the memory budget leaves nothing
			// while it is uploading.
			name: "while the request body is uploading",
			at:   func(event string, count int) bool { return event == "request-read" && count >= 1536<<10 },
			delta: func(t *testing.T, legacy map[string][]eqRow) {
				dropStage(legacy, "http_stages", storage.StageRequestSent)
				dropStage(legacy, "http_headers", storage.StageRequestSent)
				dropStage(legacy, "body_streams", storage.StageRequestSent)
				dropStage(legacy, "body_streams", storage.StageRequestReceived)
				dropStage(legacy, "body_chunks", storage.StageRequestSent)
				dropStage(legacy, "body_chunks", storage.StageRequestReceived)
			},
			stages: 1,
		},
		{
			// B.7 row 3: checkpoint 1 wrote the request side, merged.
			name:   "after the request, before the response headers",
			at:     func(event string, _ int) bool { return event == "request-done" },
			delta:  mergedRequest,
			stages: 2, chunks: 3,
		},
		{
			// B.7 row 4: checkpoint 2 wrote the response stages and headers;
			// the response bodies come only with the commit.
			name: "mid-stream",
			at:   func(event string, count int) bool { return event == "response-read" && count > 200 },
			delta: func(t *testing.T, legacy map[string][]eqRow) {
				mergedRequest(t, legacy)
				dropStage(legacy, "body_streams", storage.StageResponseReceived)
				dropStage(legacy, "body_streams", storage.StageResponseSent)
				dropStage(legacy, "body_chunks", storage.StageResponseReceived)
				dropStage(legacy, "body_chunks", storage.StageResponseSent)
			},
			stages: 4, chunks: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			unified, _ := crashRun(t, test.at)
			sendAgainstOracle(t, unified, largeStreamExchange(t))
			// Let the writes enqueued before the freeze commit, as they would
			// have within milliseconds of the crash.
			time.Sleep(50 * time.Millisecond)
			recoverRun(t, unified)
			// "recovered": the legacy database after the same crash and
			// recovery.
			legacyDump := frozen[map[string][]eqRow](t, "recovered")
			unifiedDump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
			test.delta(t, legacyDump)
			if diffs := diffEqDumps(legacyDump, unifiedDump); len(diffs) != 0 {
				t.Fatalf("recovered rows differ beyond B.7:\n%s", strings.Join(diffs[:min(len(diffs), 30)], "\n"))
			}
			if got := len(unifiedDump["http_stages"]); got != test.stages {
				t.Fatalf("unified stages %d, want %d", got, test.stages)
			}
			if got := len(unifiedDump["body_chunks"]); got != test.chunks {
				t.Fatalf("unified chunks %d, want %d", got, test.chunks)
			}
			if forward := unifiedDump["audit_records"][0]["forward_status"]; forward != `"interrupted"` {
				t.Fatalf("forward %s", forward)
			}
		})
	}
}

// largeResponseExchange is a streamed chat turn whose answer spans several
// 1 MiB chunks: the first delta event is repeated.
func largeResponseExchange(t *testing.T, size int) *eqExchange {
	t.Helper()
	built, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 777})
	if err != nil {
		t.Fatal(err)
	}
	exchange := fromFixture("large-response", built[0], 64<<10)
	delta := exchange.respChunks[1]
	chunks := [][]byte{exchange.respChunks[0]}
	total := 0
	for total < size {
		chunks = append(chunks, delta)
		total += len(delta)
	}
	exchange.respChunks = append(chunks, exchange.respChunks[1:]...)
	return exchange
}

// The request pair merged at checkpoint 1 no longer qualifies at Finish
// (Close fails after EOF): the commit points request_sent back at itself
// and writes its own chunks, sealed from the borrowed bytes (B.5, K item 3).
func TestRequestPairUnmergedAtFinish(t *testing.T) {
	var counting *countingStore
	var mergedAtCheckpoint atomic.Bool
	unified := newEqRun(t, audit.Options{}, func(store *sqlite.Store) audit.Store {
		counting = &countingStore{Store: store}
		counting.checkpoint = func(checkpoint storage.AuditCheckpoint) error {
			for _, body := range checkpoint.Bodies {
				if body.Stage == storage.StageRequestSent && body.SourceStage == storage.StageRequestReceived {
					mergedAtCheckpoint.Store(true)
				}
			}
			return nil
		}
		return counting
	})
	exchange := largeStreamExchange(t)
	exchange.closeErr = errors.New("close failed")
	sendAgainstOracle(t, unified, exchange)
	dump := compareRuns(t, unified, nil)
	if !mergedAtCheckpoint.Load() {
		t.Fatal("checkpoint 1 did not merge the request pair")
	}
	sent := 0
	for _, row := range dump["body_chunks"] {
		if row["stage"] == `"`+storage.StageRequestSent+`"` {
			sent++
		}
	}
	if sent < 3 {
		t.Fatalf("request_sent has %d chunks of its own", sent)
	}
}

// Responses over 1 MiB, complete and cut after the first chunk: the merged
// pair, and the duplicate sealed from borrowed bytes when the pair cannot
// merge.
func TestLargeResponsesMatchLegacy(t *testing.T) {
	for _, test := range []struct {
		name  string
		cut   int
		abort bool
	}{
		{name: "complete"},
		{name: "upstream cut after the first MiB", cut: 1<<20 + 4096, abort: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			unified := newEqRun(t, audit.Options{}, nil)
			// Compared before the parse releases the raw chunks.
			unified.manager.SetCompletionNotifier(nil)
			unified.noParse = true
			exchange := largeResponseExchange(t, 5<<19)
			exchange.cutAt, exchange.abort = test.cut, test.abort
			sendAgainstOracle(t, unified, exchange)
			dump := compareRuns(t, unified, nil)
			chunks := map[string]int{}
			for _, row := range dump["body_chunks"] {
				chunks[row["stage"]]++
			}
			if chunks[`"`+storage.StageResponseReceived+`"`] < 2 {
				t.Fatalf("response chunks %v", chunks)
			}
		})
	}
}

// A client that goes away during the upload: the forward is no longer in
// progress when the request body ends, so no checkpoint is written and the
// commit carries everything (B.1).
func TestClientCancelDuringUploadSkipsCheckpoints(t *testing.T) {
	var counting *countingStore
	unified := newEqRun(t, audit.Options{}, func(store *sqlite.Store) audit.Store {
		counting = &countingStore{Store: store}
		return counting
	})
	unified.noParse = true
	exchange := largeStreamExchange(t)
	exchange.cancelAfterRead = 1200 << 10
	sendAgainstOracle(t, unified, exchange)
	unified.waitParsed(unified.lastAuditID())
	dump := compareRuns(t, unified, nil)
	if counting.checkpoints.Load() != 0 || counting.commits.Load() != 1 {
		t.Fatalf("checkpoints %d, commits %d", counting.checkpoints.Load(), counting.commits.Load())
	}
	if forward := dump["audit_records"][0]["forward_status"]; forward != `"client_cancelled"` {
		t.Fatalf("forward %s", forward)
	}
}

// A CommitAudit the store rejects as an operation (a trigger on a table only
// the commit writes) is not retried; the writer records the outcome itself
// and finalizes the audit as failed.
func TestCommitConstraintFailureOnTheRealStore(t *testing.T) {
	var counting *countingStore
	unified := newEqRun(t, audit.Options{CommitRetries: 3, Sleep: func(time.Duration) { t.Error("retried") }},
		func(store *sqlite.Store) audit.Store {
			counting = &countingStore{Store: store}
			return counting
		})
	unified.noParse = true
	execSQL(t, unified.dbPath, `CREATE TRIGGER reject_timeline BEFORE INSERT ON stream_timelines BEGIN SELECT RAISE(ABORT, 'rejected by test'); END`)
	_, id := unified.send(copyChunks(largeStreamExchange(t)))
	if counting.commits.Load() != 1 {
		t.Fatalf("commit attempts %d", counting.commits.Load())
	}
	record := completionLogRecords(t, unified.logs.Bytes())[0]
	deadline := time.Now().Add(15 * time.Second)
	for {
		snapshot, err := unified.store.Snapshot(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Audit.EndedAtNS != nil {
			if snapshot.Audit.CaptureStatus != "failed" {
				t.Fatalf("finalized as %s", snapshot.Audit.CaptureStatus)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit was not finalized; completion log %v", record)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("completion log: capture_status=%v error_code=%v", record["capture_status"], record["error_code"])
}
