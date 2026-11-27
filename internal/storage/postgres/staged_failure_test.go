package postgres

// The store rows of the failure matrix in doc/design/issue-59-stage3-write-path.md
// I.3: a checkpoint rejected by a trigger on each table, a checkpoint batch
// that fails, a CommitAudit that fails once, fails every time, fails on a
// constraint, or commits while its caller sees an error.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// writerBarrier returns once every operation queued before it was processed.
func writerBarrier(t *testing.T, store *Store) {
	t.Helper()
	_ = store.submitSync(context.Background(), writeRequest{kind: writeOrg, data: orgWrite(func(dbTransaction) error { return nil })})
}

func buildHarness(t *testing.T, clock *harnessClock, id, scenario string) *harness {
	t.Helper()
	h := newHarness(t, clock, id)
	scenarioByName(t, scenario).build(h)
	return h
}

func injectInsertFailure(t *testing.T, store *Store, table, condition string) {
	t.Helper()
	if _, err := store.writerConn.ExecContext(context.Background(), fmt.Sprintf(`CREATE FUNCTION reject_staged_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected staged write failure' USING ERRCODE='23514'; END $$;
CREATE TRIGGER reject_staged BEFORE INSERT ON %s FOR EACH ROW WHEN (%s) EXECUTE FUNCTION reject_staged_fn()`, table, condition)); err != nil {
		t.Fatal(err)
	}
}

func dropInjectedFailure(t *testing.T, store *Store, table string) {
	t.Helper()
	if _, err := store.writerConn.ExecContext(context.Background(), `DROP TRIGGER reject_staged ON `+table+`; DROP FUNCTION reject_staged_fn()`); err != nil {
		t.Fatal(err)
	}
}

// mergeLegacyDuplicate turns a legacy duplicate body that kept its own
// chunks into the merged form the unified commit writes. A failed audit is
// never merged by the database (B.5 condition 8), but the session decides the
// response pair in memory and has no chunks of the duplicate to write.
func mergeLegacyDuplicate(t *testing.T, dump harnessDump, duplicate, source string) {
	t.Helper()
	var sourceRow, duplicateRow harnessRow
	for _, row := range dump["body_streams"] {
		switch row["stage"] {
		case source:
			sourceRow = row
		case duplicate:
			duplicateRow = row
		}
	}
	if sourceRow == nil || duplicateRow == nil || duplicateRow["source_stage"] != duplicate {
		t.Fatalf("legacy %s is not a separate body", duplicate)
	}
	duplicateRow["source_stage"] = source
	for _, column := range []string{"stored_length", "chunk_count", "stream_event_count", "stream_timeline_complete"} {
		duplicateRow[column] = sourceRow[column]
	}
	if dump.dropRows("body_chunks", stageIs(duplicate)) == 0 {
		t.Fatalf("legacy %s has no chunks", duplicate)
	}
}

func stageRow(dump harnessDump, table, stage string) harnessRow {
	for _, row := range dump[table] {
		if row["stage"] == stage {
			return row
		}
	}
	return nil
}

func TestCheckpointRejectedByTrigger(t *testing.T) {
	cases := []struct {
		table, condition, scenario string
		check                      func(t *testing.T, legacy, unified harnessDump)
	}{
		{"http_stages", "NEW.stage = 'request_sent_to_newapi'", "merged request pair unmerges at finish", func(t *testing.T, legacy, unified harnessDump) {
			// Checkpoint 1 is gone: request_sent's rows and both request
			// bodies. The commit's own request_sent chunks were dropped
			// with them instead of failing on the missing body row.
			if stageRow(unified, "http_stages", StageRequestSent) != nil || stageRow(unified, "body_streams", StageRequestReceived) != nil ||
				countRows(unified, "body_chunks") != countRows(legacy, "body_chunks")-countStage(legacy, "body_chunks", StageRequestReceived)-countStage(legacy, "body_chunks", StageResponseSent) {
				t.Fatalf("checkpoint rows survived: %v", summarizeRows(unified["body_chunks"]))
			}
		}},
		{"http_headers", "NEW.stage = 'request_sent_to_newapi'", "stream both pairs merged", func(t *testing.T, legacy, unified harnessDump) {
			if stageRow(legacy, "http_stages", StageRequestSent)["error_code"] != "capture_headers_failed" {
				t.Fatal("legacy did not mark the header stage")
			}
			if stageRow(unified, "http_stages", StageRequestSent) != nil {
				t.Fatal("rolled-back checkpoint left its stage row")
			}
		}},
		{"http_headers", "NEW.kind = 'trailer' AND NEW.stage = 'request_for_newapi_received_from_nginx'", "request and response trailers", func(t *testing.T, legacy, unified harnessDump) {
			// The checkpoint carrying the request trailers is rolled back,
			// but request_received's row came from BeginAudit: the header
			// marker lands on it, as legacy's AddHeaders failure does.
			for name, dump := range map[string]harnessDump{"legacy": legacy, "unified": unified} {
				if row := stageRow(dump, "http_stages", StageRequestReceived); row["error_code"] != "capture_headers_failed" || row["state"] != StageStatePartial {
					t.Fatalf("%s request_received not marked: %v", name, row)
				}
			}
		}},
		{"body_streams", "NEW.stage = 'request_sent_to_newapi'", "stream both pairs merged", func(t *testing.T, legacy, unified harnessDump) {
			if stageRow(unified, "body_streams", StageRequestReceived) != nil || stageRow(legacy, "body_streams", StageRequestReceived) == nil {
				t.Fatal("granularity differs from the design")
			}
		}},
		{"body_chunks", "NEW.stage = 'request_for_newapi_received_from_nginx' AND NEW.seq = 1", "upstream answers before the request ends", func(t *testing.T, legacy, unified harnessDump) {
			// Checkpoint 2 wrote both request bodies; checkpoint 1, carrying
			// their tail chunks, failed: the marker lands on both bodies.
			for _, stage := range []string{StageRequestReceived, StageRequestSent} {
				if row := stageRow(unified, "body_streams", stage); row == nil || row["error_code"] != CaptureChunkMissing {
					t.Fatalf("unified %s body not marked: %v", stage, row)
				}
			}
			if row := stageRow(legacy, "body_streams", StageRequestReceived); row["error_code"] != CaptureChunkMissing {
				t.Fatalf("legacy body not marked: %v", row)
			}
		}},
	}
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	for index, test := range cases {
		t.Run(fmt.Sprintf("%d %s", index, test.table), func(t *testing.T) {
			t.Parallel()
			legacyStore, unifiedStore := openHarnessStore(t), openHarnessStore(t)
			for _, store := range []*Store{legacyStore, unifiedStore} {
				injectInsertFailure(t, store, test.table, test.condition)
			}
			h := buildHarness(t, &harnessClock{now: 1_000_000}, "rejected-"+test.table, test.scenario)
			legacyOutcome := runHarnessOps(t, legacyStore, h.legacyOps(sealer))
			unifiedOutcome := runHarnessOps(t, unifiedStore, h.unifiedOps(sealer))
			for _, outcome := range []AuditFinish{legacyOutcome, unifiedOutcome} {
				if outcome.CaptureStatus != CaptureFailed || outcome.ErrorCode == nil || *outcome.ErrorCode != "capture_write_failed" {
					t.Fatalf("outcome %+v", derefFinish(outcome))
				}
			}
			legacy := dumpAudit(t, legacyStore.readerDB, cipher, h.id)
			unified := dumpAudit(t, unifiedStore.readerDB, cipher, h.id)
			if differences := diffDumps(harnessDump{"audit_records": legacy["audit_records"]}, harnessDump{"audit_records": unified["audit_records"]}); len(differences) != 0 {
				t.Fatalf("audit rows differ:\n%s", strings.Join(differences, "\n"))
			}
			test.check(t, legacy, unified)
			for _, row := range unified["body_streams"] {
				if row["retention_state"] != RetentionFull {
					t.Fatalf("failed audit body not retained: %v", row)
				}
			}
			for _, store := range []*Store{legacyStore, unifiedStore} {
				if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func countStage(dump harnessDump, table, stage string) int {
	count := 0
	for _, row := range dump[table] {
		if row["stage"] == stage {
			count++
		}
	}
	return count
}

// TestCheckpointBatchFailureMatchesLegacyBatchFailure fails the batch of
// checkpoint 1, and in the legacy store the batches of the operations it
// replaces, and compares the finalized rows.
func TestCheckpointBatchFailureMatchesLegacyBatchFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	legacyStore, unifiedStore := openHarnessStore(t), openHarnessStore(t)
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	h := buildHarness(t, &harnessClock{now: 1_000_000}, "checkpoint-batch", "stream both pairs merged")
	first := h.checkpoints[0].events[0]
	last := h.checkpoints[0].events[len(h.checkpoints[0].events)-1]

	run := func(store *Store, ops []hOp, failing func(hOp) bool) AuditFinish {
		var before, during, after []hOp
		for _, op := range ops {
			switch {
			case failing(op):
				during = append(during, op)
			case len(during) == 0:
				before = append(before, op)
			default:
				after = append(after, op)
			}
		}
		if len(during) == 0 {
			t.Fatal("no operation selected to fail")
		}
		runHarnessOps(t, store, before)
		writerBarrier(t, store)
		setWriterReadOnly(t, store, true)
		runHarnessOps(t, store, during)
		writerBarrier(t, store)
		// Recovery cannot run while the writer is read-only.
		if store.recoveryPending.Load() == 0 {
			t.Fatal("failed batch left no recovery entry")
		}
		setWriterReadOnly(t, store, false)
		return runHarnessOps(t, store, after)
	}
	legacyOutcome := run(legacyStore, h.legacyOps(sealer), func(op hOp) bool {
		return op.kind != writeBeginAudit && op.event >= first && op.event <= last && op.kind != writeFinishStage && op.kind != writeFinishAudit
	})
	unifiedOutcome := run(unifiedStore, h.unifiedOps(sealer), func(op hOp) bool { return op.kind == writeCheckpoint && op.event == 0 })
	if derefFinish(legacyOutcome) != derefFinish(unifiedOutcome) || unifiedOutcome.CaptureStatus != CaptureFailed {
		t.Fatalf("outcomes differ:\nlegacy  %+v\nunified %+v", derefFinish(legacyOutcome), derefFinish(unifiedOutcome))
	}
	legacy := dumpAudit(t, legacyStore.readerDB, cipher, h.id)
	unified := dumpAudit(t, unifiedStore.readerDB, cipher, h.id)
	mergeLegacyDuplicate(t, legacy, StageResponseSent, StageResponseReceived)
	if differences := diffDumps(legacy, unified); len(differences) != 0 {
		t.Fatalf("unified rows differ from legacy:\n%s", strings.Join(differences, "\n"))
	}
	if row := stageRow(unified, "http_stages", StageRequestReceived); row["error_code"] != "capture_storage_failed" {
		t.Fatalf("recovery marker missing: %v", row)
	}
	for _, store := range []*Store{legacyStore, unifiedStore} {
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// commitOf returns the harness's CommitAudit input and runs everything before
// it on the store.
func commitOf(t *testing.T, store *Store, ops []hOp) AuditCommit {
	t.Helper()
	last := ops[len(ops)-1]
	if last.kind != writeCommitAudit {
		t.Fatal("sequence does not end with a commit")
	}
	runHarnessOps(t, store, ops[:len(ops)-1])
	writerBarrier(t, store)
	return last.data.(AuditCommit)
}

func TestCommitRetriesAfterBatchFailure(t *testing.T) {
	cases := []struct {
		name, class string
		inject      func(t *testing.T, store *Store)
		clear       func(t *testing.T, store *Store)
	}{
		{"read-only transaction", "postgres_read_only",
			func(t *testing.T, store *Store) { setWriterReadOnly(t, store, true) },
			func(t *testing.T, store *Store) { setWriterReadOnly(t, store, false) }},
		{"failed COMMIT", "postgres_constraint",
			func(t *testing.T, store *Store) {
				if _, err := store.writerConn.ExecContext(context.Background(), `CREATE TABLE fail_commit_audit (audit_id TEXT REFERENCES audit_records(audit_id) DEFERRABLE INITIALLY DEFERRED);
CREATE FUNCTION fail_commit_audit_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO fail_commit_audit VALUES ('missing-parent'); RETURN NEW; END $$;
CREATE TRIGGER fail_commit_audit AFTER UPDATE OF ended_at_ns ON audit_records FOR EACH ROW WHEN (NEW.ended_at_ns IS NOT NULL) EXECUTE FUNCTION fail_commit_audit_fn()`); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, store *Store) {
				if _, err := store.writerConn.ExecContext(context.Background(), "DROP TRIGGER fail_commit_audit ON audit_records; DROP TABLE fail_commit_audit"); err != nil {
					t.Fatal(err)
				}
			}},
	}
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			legacyStore, unifiedStore := openHarnessStore(t), openHarnessStore(t)
			h := buildHarness(t, &harnessClock{now: 1_000_000}, "commit-retry", "stream both pairs merged")
			legacyOutcome := runHarnessOps(t, legacyStore, h.legacyOps(sealer))
			commit := commitOf(t, unifiedStore, h.unifiedOps(sealer))
			test.inject(t, unifiedStore)
			if _, err := unifiedStore.CommitAudit(ctx, commit); !errors.Is(err, ErrWriteBatchFailed) || ErrorClass(err) != test.class {
				t.Fatalf("first attempt error = %v (%s)", err, ErrorClass(err))
			}
			if unifiedStore.recoveryPending.Load() != 0 {
				t.Fatal("a non-final attempt handed the audit to recovery")
			}
			test.clear(t, unifiedStore)
			commit.FinalAttempt = true
			outcome, err := unifiedStore.CommitAudit(ctx, commit)
			if err != nil || derefFinish(outcome) != derefFinish(legacyOutcome) {
				t.Fatalf("retry = %+v, %v; legacy %+v", derefFinish(outcome), err, derefFinish(legacyOutcome))
			}
			legacy := dumpAudit(t, legacyStore.readerDB, cipher, h.id)
			unified := dumpAudit(t, unifiedStore.readerDB, cipher, h.id)
			// A rolled-back INSERT still consumes its identity value.
			for _, dump := range []harnessDump{legacy, unified} {
				for _, row := range dump["integrity_events"] {
					delete(row, "sequence")
				}
			}
			if differences := diffDumps(legacy, unified); len(differences) != 0 {
				t.Fatalf("retried commit differs from legacy:\n%s", strings.Join(differences, "\n"))
			}
			if err := unifiedStore.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommitFinalAttemptHandsOutcomeToRecovery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openHarnessStore(t)
	cipher := harnessCipher(t)
	h := buildHarness(t, &harnessClock{now: 1_000_000}, "commit-final", "stream both pairs merged")
	commit := commitOf(t, store, h.unifiedOps(harnessSealer{t: t, cipher: cipher}))
	setWriterReadOnly(t, store, true)
	for attempt := 1; attempt <= 3; attempt++ {
		commit.FinalAttempt = attempt == 3
		if _, err := store.CommitAudit(ctx, commit); !errors.Is(err, ErrWriteBatchFailed) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
		if pending := store.recoveryPending.Load(); pending != map[bool]int32{false: 0, true: 1}[commit.FinalAttempt] {
			t.Fatalf("attempt %d left %d recovery entries", attempt, pending)
		}
	}
	setWriterReadOnly(t, store, false)
	store.recoveryWake <- struct{}{}
	waitForCaptureRecovery(t, store)
	dump := dumpAudit(t, store.readerDB, cipher, h.id)
	audit := dump["audit_records"][0]
	if audit["capture_status"] != CaptureFailed || audit["error_code"] != "capture_write_failed" || audit["forward_status"] != ForwardCompleted ||
		audit["ended_at_ns"] != commit.Finish.EndedAtNS {
		t.Fatalf("recovered audit %v", audit)
	}
	// The checkpoints' evidence stays: both request stages and the request
	// body with its chunk; the response bodies never reached the database.
	if len(dump["http_stages"]) != 4 || stageRow(dump, "body_streams", StageRequestReceived) == nil ||
		countStage(dump, "body_chunks", StageRequestReceived) != 1 || stageRow(dump, "body_streams", StageResponseReceived) != nil {
		t.Fatalf("rows after final failure: stages %v bodies %v chunks %v", summarizeRows(dump["http_stages"]), summarizeRows(dump["body_streams"]), summarizeRows(dump["body_chunks"]))
	}
	// The lost commit is recorded as the FinishStage operations it replaces
	// would have been: every stage is marked as a storage loss.
	for _, row := range dump["http_stages"] {
		if row["state"] != StageStatePartial || row["ended_at_ns"] == nil || row["error_code"] != "capture_storage_failed" {
			t.Fatalf("stage not reconciled as a storage loss: %v", row)
		}
	}
	if countRows(dump, "integrity_events") != 1 {
		t.Fatal("recovery did not sign exactly once")
	}
	// A late retry only reads the committed outcome back.
	outcome, err := store.CommitAudit(ctx, commit)
	if err != nil || outcome.CaptureStatus != CaptureFailed {
		t.Fatalf("late retry = %+v, %v", derefFinish(outcome), err)
	}
	assertAuditEvents(t, store, h.id, 1)
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertAuditEvents(t *testing.T, store *Store, auditID string, want int) {
	t.Helper()
	var count int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM integrity_events WHERE audit_id = $1`, auditID).Scan(&count); err != nil || count != want {
		t.Fatalf("integrity events = %d (want %d), %v", count, want, err)
	}
}

func TestCommitConstraintFailureIsNotRetried(t *testing.T) {
	cases := []struct{ name, trigger string }{
		{"finish of a checkpointed body", `CREATE TRIGGER reject_commit BEFORE UPDATE OF state ON body_streams FOR EACH ROW EXECUTE FUNCTION reject_commit_fn()`},
		{"insert of a final body", `CREATE TRIGGER reject_commit BEFORE INSERT ON body_streams FOR EACH ROW WHEN (NEW.stage = 'response_received_from_newapi') EXECUTE FUNCTION reject_commit_fn()`},
	}
	cipher := harnessCipher(t)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := openHarnessStore(t)
			h := buildHarness(t, &harnessClock{now: 1_000_000}, "commit-constraint", "stream both pairs merged")
			commit := commitOf(t, store, h.unifiedOps(harnessSealer{t: t, cipher: cipher}))
			if _, err := store.writerConn.ExecContext(ctx, `CREATE FUNCTION reject_commit_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure' USING ERRCODE='23514'; END $$;
`+test.trigger); err != nil {
				t.Fatal(err)
			}
			_, err := store.CommitAudit(ctx, commit)
			if err == nil || errors.Is(err, ErrWriteBatchFailed) || ErrorClass(err) != "postgres_constraint" {
				t.Fatalf("constraint failure = %v (%s)", err, ErrorClass(err))
			}
			// Not FinalAttempt, yet the writer records the outcome at once and
			// marks the audit failed in the same transaction. (The periodic
			// recovery may already have finalized it when the trigger does
			// not block finalization.)
			store.recoveryMu.Lock()
			entry, recorded := store.recoveries[h.id]
			store.recoveryMu.Unlock()
			if recorded && entry.finish == nil || !recorded && !auditEnded(t, store, h.id) {
				t.Fatal("the outcome was not handed to recovery")
			}
			var captureStatus string
			var ended sql.NullInt64
			if err := store.readerDB.QueryRow(`SELECT capture_status, ended_at_ns FROM audit_records WHERE audit_id = $1`, h.id).Scan(&captureStatus, &ended); err != nil ||
				captureStatus != CaptureFailed {
				t.Fatalf("audit after isolated failure: %s %v %v", captureStatus, ended, err)
			}
			if _, err := store.writerConn.ExecContext(ctx, `DROP TRIGGER reject_commit ON body_streams; DROP FUNCTION reject_commit_fn()`); err != nil {
				t.Fatal(err)
			}
			store.recoveryWake <- struct{}{}
			waitForCaptureRecovery(t, store)
			if err := store.readerDB.QueryRow(`SELECT capture_status, ended_at_ns FROM audit_records WHERE audit_id = $1`, h.id).Scan(&captureStatus, &ended); err != nil ||
				captureStatus != CaptureFailed || !ended.Valid || ended.Int64 != commit.Finish.EndedAtNS {
				t.Fatalf("recovered audit: %s %v %v", captureStatus, ended, err)
			}
			assertAuditEvents(t, store, h.id, 1)
			if err := store.VerifyIntegrityPayloads(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCommitUncertainOutcomeIsReadBack lets a commit happen after its caller
// has given up, then retries it.
func TestCommitUncertainOutcomeIsReadBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	legacyStore := openHarnessStore(t)
	store, dsn := openTestStore(t)
	if err := store.EnableIntegrity(ctx, harnessIntegrityKey); err != nil {
		t.Fatal(err)
	}
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	h := buildHarness(t, &harnessClock{now: 1_000_000}, "commit-uncertain", "stream both pairs merged")
	legacyOutcome := runHarnessOps(t, legacyStore, h.legacyOps(sealer))
	commit := commitOf(t, store, h.unifiedOps(sealer))
	var pid int
	if err := store.writerConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	blocker, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	lock, err := blocker.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec(`SELECT audit_id FROM audit_records WHERE audit_id = $1 FOR UPDATE`, h.id); err != nil {
		t.Fatal(err)
	}
	attempt, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		_, err := store.CommitAudit(attempt, commit)
		result <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := blocker.QueryRow(`SELECT COALESCE(wait_event_type = 'Lock', false) FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("commit did not reach the locked row")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller error = %v", err)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	writerBarrier(t, store)
	assertAuditEvents(t, store, h.id, 1)
	outcome, err := store.CommitAudit(ctx, commit)
	if err != nil || derefFinish(outcome) != derefFinish(legacyOutcome) {
		t.Fatalf("retry = %+v, %v; legacy %+v", derefFinish(outcome), err, derefFinish(legacyOutcome))
	}
	assertAuditEvents(t, store, h.id, 1)
	legacy := dumpAudit(t, legacyStore.readerDB, cipher, h.id)
	unified := dumpAudit(t, store.readerDB, cipher, h.id)
	if differences := diffDumps(legacy, unified); len(differences) != 0 {
		t.Fatalf("rows differ from legacy:\n%s", strings.Join(differences, "\n"))
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestStagedWritesWithFullQueue uses a queue of capacity one: a checkpoint
// is refused at once, and only the final commit attempt hands its outcome to
// recovery, which waits for the accepted checkpoint.
func TestStagedWritesWithFullQueue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openHarnessStore(t)
	cipher := harnessCipher(t)
	h := buildHarness(t, &harnessClock{now: 1_000_000}, "queue-full", "stream both pairs merged")
	ops := h.unifiedOps(harnessSealer{t: t, cipher: cipher})
	runHarnessOps(t, store, ops[:1])
	writer := &Store{writerDB: store.writerDB, writerConn: store.writerConn, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
	writer.integrity.Store(store.integrity.Load())
	if err := writer.Checkpoint(ctx, ops[1].data.(AuditCheckpoint)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Checkpoint(ctx, ops[2].data.(AuditCheckpoint)); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("second checkpoint error = %v", err)
	}
	commit := ops[3].data.(AuditCommit)
	if _, err := writer.CommitAudit(ctx, commit); !errors.Is(err, ErrQueueFull) || len(writer.recoveries) != 0 {
		t.Fatalf("non-final commit = %v, recoveries %d", err, len(writer.recoveries))
	}
	commit.FinalAttempt = true
	if _, err := writer.CommitAudit(ctx, commit); !errors.Is(err, ErrQueueFull) || len(writer.recoveries) != 1 || writer.recoveries[h.id].finish == nil {
		t.Fatalf("final commit = %v, recoveries %v", err, writer.recoveries)
	}
	writer.recoverCaptureWrites()
	if ended := auditEnded(t, store, h.id); ended {
		t.Fatal("recovery overtook the accepted checkpoint")
	}
	close(writer.queue)
	writer.runWriter()
	dump := dumpAudit(t, store.readerDB, cipher, h.id)
	if dump["audit_records"][0]["capture_status"] != CaptureFailed || stageRow(dump, "http_stages", StageRequestSent) == nil ||
		stageRow(dump, "http_stages", StageResponseReceived) != nil {
		t.Fatalf("queue drain: audit %v stages %v", dump["audit_records"][0], summarizeRows(dump["http_stages"]))
	}
	assertAuditEvents(t, store, h.id, 1)
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

func auditEnded(t *testing.T, store *Store, auditID string) bool {
	t.Helper()
	var ended sql.NullInt64
	if err := store.readerDB.QueryRow(`SELECT ended_at_ns FROM audit_records WHERE audit_id = $1`, auditID).Scan(&ended); err != nil {
		t.Fatal(err)
	}
	return ended.Valid
}

// TestCommitDedupMaskLimitsTheDatabaseMerge clears DedupInDB for pairs whose
// bodies were written separately and are equal: they must stay separate,
// which shows the mask, not the data, decides.
func TestCommitDedupMaskLimitsTheDatabaseMerge(t *testing.T) {
	t.Parallel()
	store := openHarnessStore(t)
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	clock := &harnessClock{now: 1_000_000}
	for _, test := range []struct{ scenario, duplicate string }{
		{"duplicate ahead of its source", StageRequestSent},
		{"response pair merged in the database", StageResponseSent},
	} {
		h := buildHarness(t, clock, "dedup-mask-"+test.duplicate, test.scenario)
		ops := h.unifiedOps(sealer)
		commit := ops[len(ops)-1].data.(AuditCommit)
		if commit.DedupInDB == [2]bool{} {
			t.Fatalf("%s: scenario does not merge in the database", test.scenario)
		}
		commit.DedupInDB = [2]bool{}
		ops[len(ops)-1].data = commit
		runHarnessOps(t, store, ops)
		dump := dumpAudit(t, store.readerDB, cipher, h.id)
		if row := stageRow(dump, "body_streams", test.duplicate); row["source_stage"] != test.duplicate || countStage(dump, "body_chunks", test.duplicate) == 0 {
			t.Fatalf("%s merged despite the mask: %v", test.duplicate, row)
		}
	}
	if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestFailedCheckpointedAuditRecovers interrupts an audit whose checkpoint 1
// merged the request pair and whose checkpoint 2 failed: recovery reconciles
// the failed audit by source_stage without new logic (B.4).
func TestFailedCheckpointedAuditRecovers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openHarnessStore(t)
	injectInsertFailure(t, store, "http_stages", "NEW.stage = 'response_received_from_newapi'")
	cipher := harnessCipher(t)
	h := buildHarness(t, &harnessClock{now: 1_000_000}, "failed-interrupted", "interrupted after checkpoint 2")
	runHarnessOps(t, store, h.unifiedOps(harnessSealer{t: t, cipher: cipher}))
	dump := dumpAudit(t, store.readerDB, cipher, h.id)
	audit := dump["audit_records"][0]
	if audit["capture_status"] != CaptureFailed || audit["forward_status"] != ForwardInterrupted || audit["error_code"] != "capture_write_failed" {
		t.Fatalf("recovered audit %v", audit)
	}
	source := stageRow(dump, "body_streams", StageRequestReceived)
	duplicate := stageRow(dump, "body_streams", StageRequestSent)
	if duplicate["source_stage"] != StageRequestReceived || duplicate["state"] != StageStatePartial ||
		duplicate["stored_length"] != source["stored_length"] || duplicate["chunk_count"] != source["chunk_count"] ||
		duplicate["stored_length"] == int64(0) || countStage(dump, "body_chunks", StageRequestSent) != 0 {
		t.Fatalf("merged duplicate not reconciled from its source: %v / %v", duplicate, source)
	}
	if stageRow(dump, "http_stages", StageResponseReceived) != nil || len(dump["http_stages"]) != 2 {
		t.Fatalf("stages %v", summarizeRows(dump["http_stages"]))
	}
	assertAuditEvents(t, store, h.id, 1)
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestStagedWriteInputs needs no database: version 2 is refused until its
// migration, and large writes are sized for a transaction of their own.
func TestStagedWriteInputs(t *testing.T) {
	ctx := context.Background()
	store := &Store{}
	record := testAudit("version-two")
	record.CaptureVersion = storage.CaptureVersion2
	if err := store.BeginAudit(ctx, record); err == nil || !strings.Contains(err.Error(), "capture version 2") {
		t.Fatalf("version 2 BeginAudit = %v", err)
	}
	if err := store.Checkpoint(ctx, AuditCheckpoint{AuditID: "version-two", CaptureVersion: storage.CaptureVersion2}); err == nil {
		t.Fatal("version 2 checkpoint accepted")
	}
	finish := AuditFinish{AuditID: "version-two", EndedAtNS: 2, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}
	if _, err := store.CommitAudit(ctx, AuditCommit{Finish: finish, CaptureVersion: storage.CaptureVersion2}); err == nil {
		t.Fatal("version 2 commit accepted")
	}
	inbound := testAudit("bad-inbound")
	inbound.Inbound = &InboundStage{Stage: HTTPStage{AuditID: "bad-inbound", Stage: StageRequestSent, StartedAtNS: 2}}
	if err := store.BeginAudit(ctx, inbound); err == nil {
		t.Fatal("BeginAudit accepted a stage other than request_received")
	}
	large := storage.ChunkList{{DataEnc: make([]byte, 17<<20)}}
	if size := chunkPayloadBytes(large); size != 17<<20 || !(writeRequest{kind: writeCheckpoint, payloadBytes: size}).alone() {
		t.Fatalf("large checkpoint size %d", size)
	}
	if (writeRequest{kind: writeCommitAudit, payloadBytes: 1 << 20}).alone() {
		t.Fatal("small commit runs alone")
	}
	if size := chunkPayloadBytes(stagedSource{}); size <= aloneWritePayloadBytes {
		t.Fatal("a staged chunk source is not treated as large")
	}
}

type stagedSource struct{}

func (stagedSource) Each(func(BodyChunk) error) error { return nil }
