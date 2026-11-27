package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
)

// lostCheckpointAudit drives the case of a checkpoint lost to a batch-level
// storage failure: BeginAudit writes the inbound stage and its block;
// checkpoint 1 (request_sent and the block of both request stages) fails with
// its whole batch, so its failure mark is only in the writer's in-memory
// recovery table; checkpoint 2 (both response stages and the block of all four)
// is then written. The audit has stage rows for three stages and a block that
// names four.
func lostCheckpointAudit(t *testing.T, store *Store, cipher security.Cipher, auditID string) {
	t.Helper()
	ctx := context.Background()
	stages := v2TestStages()
	writeV2Audit(t, store, cipher, v2Audit{id: auditID, stopAfter: 1})
	setWriterReadOnly(t, store, true)
	if err := store.Checkpoint(ctx, AuditCheckpoint{
		AuditID: auditID, CaptureVersion: CaptureVersion2,
		Stages:      []HTTPStage{v2StageRow(auditID, stages[1], 1002)},
		Contents:    []StageContent{v2Content(stages[1])},
		HeaderBlock: sealV2Block(t, cipher, auditID, stages[:2], map[string]bool{StageRequestReceived: true}),
	}); err != nil {
		t.Fatal(err)
	}
	writerBarrier(t, store)
	if store.recoveryPending.Load() == 0 {
		t.Fatal("the failed batch left no recovery entry")
	}
	setWriterReadOnly(t, store, false)
	if err := store.Checkpoint(ctx, AuditCheckpoint{
		AuditID: auditID, CaptureVersion: CaptureVersion2,
		Stages:      []HTTPStage{v2StageRow(auditID, stages[2], 1003), v2StageRow(auditID, stages[3], 1004)},
		Contents:    []StageContent{v2Content(stages[2]), v2Content(stages[3])},
		HeaderBlock: sealV2Block(t, cipher, auditID, stages, map[string]bool{StageRequestReceived: true}),
	}); err != nil {
		t.Fatal(err)
	}
	writerBarrier(t, store)
}

func detailStages(t *testing.T, store *Store, auditID string) (rows int, captureStatus, forwardStatus string) {
	t.Helper()
	if err := store.readerDB.QueryRow(`SELECT (SELECT COUNT(*) FROM http_stages WHERE audit_id = $1), capture_status, forward_status FROM audit_records WHERE audit_id = $1`, auditID).
		Scan(&rows, &captureStatus, &forwardStatus); err != nil {
		t.Fatal(err)
	}
	return rows, captureStatus, forwardStatus
}

// The process exits before the failure mark is written: startup recovery
// finalizes the audit as interrupted and partial, not failed. Its block names
// a stage without a row, and the audit stays readable: the detail view and
// the parser's header read return the Headers of all four stages, the one
// whose row was lost included (the failed-capture rule).
func TestCaptureV2LostCheckpointMarkReadsAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, dsn := openSignedStore(t)
	lostCheckpointAudit(t, store, cipher, "v2-lost")
	// The exit: the in-memory recovery table goes with the process before
	// its mark is written. Close would write it, so it is emptied first.
	store.recoveryMu.Lock()
	clear(store.recoveries)
	store.recoveryPending.Store(0)
	store.recoveryMu.Unlock()
	if rows, capture, _ := detailStages(t, store, "v2-lost"); rows != 3 || capture == CaptureFailed {
		t.Fatalf("before the exit: %d stage rows, capture %s", rows, capture)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.EnableIntegrity(ctx, v2TestKey); err != nil {
		t.Fatal(err)
	}
	if recovered, err := restarted.RecoverInterruptedAudits(ctx, 5000); err != nil || recovered != 1 {
		t.Fatalf("recovered %d: %v", recovered, err)
	}
	rows, capture, forward := detailStages(t, restarted, "v2-lost")
	if rows != 3 || capture != CapturePartial || forward != ForwardInterrupted {
		t.Fatalf("after recovery: %d stage rows, capture %s, forward %s", rows, capture, forward)
	}
	if err := restarted.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	compareCaptureDigests(t, restarted, "v2-lost")

	service, err := query.New(restarted, cipher)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Get(ctx, "v2-lost", nil)
	if err != nil {
		t.Fatalf("detail of the interrupted audit: %v", err)
	}
	shown := map[string]int{}
	for _, header := range detail.Headers {
		shown[header.Stage]++
	}
	if len(shown) != 4 || shown[StageRequestSent] == 0 || len(detail.Stages) != 3 {
		t.Fatalf("detail headers per stage %v, %d stage rows", shown, len(detail.Stages))
	}
	source, err := restarted.LoadParserHeaderSource(ctx, "v2-lost", []string{"x-agent-id"})
	if err != nil || !source.Interrupted || source.CaptureFailed {
		t.Fatalf("parser header source %+v, %v", source, err)
	}
	values, err := headerblock.Expand(cipher, "v2-lost", source)
	if err != nil || len(values) != len(detail.Headers) {
		t.Fatalf("parser expand: %d values, %v", len(values), err)
	}
	// Without the interrupted marker the same rows are a mismatch: this is
	// the case the rule covers.
	source.Interrupted = false
	if _, err := headerblock.Expand(cipher, "v2-lost", source); !errors.Is(err, headerblock.ErrIntegrity) {
		t.Fatalf("strict expand = %v", err)
	}
}

// Reported, not covered by the rule: while the audit is still open and the
// recovery table has not written its mark yet (up to one recovery interval,
// five seconds), the audit is neither failed nor interrupted and its detail is
// an integrity error. Once the mark is written it reads as a failed capture.
func TestCaptureV2LostCheckpointIsUnreadableUntilMarked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := v2TestCipher(t)
	store, _ := openSignedStore(t)
	lostCheckpointAudit(t, store, cipher, "v2-unmarked")
	service, err := query.New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if _, capture, _ := detailStages(t, store, "v2-unmarked"); capture != CaptureFailed {
		if _, err := service.Get(ctx, "v2-unmarked", nil); !errors.Is(err, query.ErrIntegrity) {
			t.Fatalf("detail before the mark = %v", err)
		}
	}
	deadline := time.Now().Add(3 * captureRecoveryInterval)
	for {
		if _, capture, _ := detailStages(t, store, "v2-unmarked"); capture == CaptureFailed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the recovery table never marked the audit failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := service.Get(ctx, "v2-unmarked", nil); err != nil {
		t.Fatalf("detail after the mark = %v", err)
	}
}
