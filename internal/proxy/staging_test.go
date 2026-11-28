package proxy

// Local staging (design F) through the real proxy handler on SQLite: bodies
// over a small per-stage budget go to staging, and the stored audit is the
// legacy one; a process that stops with chunks staged leaves an audit that
// the start-up import and today's recovery finalize with them.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

const stagingTestBudget = 1 << 20

func openEqStager(t *testing.T, dir string, options staging.Options) *staging.Stager {
	t.Helper()
	cipher, err := security.NewAESGCM(eqKey)
	if err != nil {
		t.Fatal(err)
	}
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	stager, err := staging.Open(dir, cipher, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	return stager
}

func requireNoStagingFiles(t *testing.T, stager *staging.Stager) {
	t.Helper()
	stager.Flush()
	if entries, err := os.ReadDir(stager.Dir()); err != nil || len(entries) != 0 {
		t.Fatalf("staging directory holds %v (%v)", entries, err)
	}
}

// Request and response bodies over the budget, both pairs merged, a request
// pair that is unmerged at Finish (its duplicate seals its own chunks from
// bytes its source staged), and a request the body-limit interceptor reads
// before request_sent exists, and an upstream that answers before reading
// the whole request: every row equals legacy's, and so do the
// views and exports.
func TestStagedBodiesThroughProxyMatchLegacy(t *testing.T) {
	large := largeStreamExchange(t)
	unmerged := cloneExchange(large, "unmerged")
	unmerged.closeErr = errors.New("close failed")
	preRead := cloneExchange(large, "pre-read")
	preRead.path = "/v1/responses"
	preRead.body = preRead.body[:min(len(preRead.body), 5<<19)]
	// The upstream answers before the request is read: checkpoint 2 writes
	// request chunks while others are already staged.
	early := cloneExchange(large, "early-answer")
	early.earlyAnswer = 1300 << 10
	for _, exchange := range []*eqExchange{large, largeResponseExchange(t, 5<<19), unmerged, preRead, early} {
		t.Run(exchange.name, func(t *testing.T) {
			stager := openEqStager(t, filepath.Join(t.TempDir(), "staging"), staging.Options{})
			legacy := newEqRun(t, audit.WritePathLegacy, audit.Options{}, nil)
			unified := newEqRun(t, audit.WritePathUnified, audit.Options{StageBytes: stagingTestBudget, Stager: stager}, nil)
			sendBoth(t, legacy, unified, exchange)
			ids := make([]string, 0, 1)
			for id := range unified.captured {
				ids = append(ids, id)
			}
			for _, id := range ids {
				compareQueryViews(t, id, legacy, unified)
			}
			compareRuns(t, legacy, unified, nil)
			if stats := stager.Stats(); stats.Records == 0 {
				t.Fatal("nothing was staged")
			}
			requireNoStagingFiles(t, stager)
			if used := unified.manager.MemoryInUse(); used != 0 {
				t.Fatalf("budget holds %d bytes", used)
			}
			if err := unified.store.VerifyIntegrityPayloads(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Staging full (F.6, I.3): the stage stops retaining with
// capture_budget_exhausted, raw is kept in full, a queue_full gap is
// recorded and the client sees the same bytes.
func TestStagingFullThroughProxy(t *testing.T) {
	stager := openEqStager(t, filepath.Join(t.TempDir(), "staging"), staging.Options{MaxBytes: 600 << 10})
	legacy := newEqRun(t, audit.WritePathLegacy, audit.Options{}, nil)
	unified := newEqRun(t, audit.WritePathUnified, audit.Options{StageBytes: stagingTestBudget, Stager: stager}, nil)
	// The forwarded bytes are legacy's (sendBoth).
	sendBoth(t, legacy, unified, largeStreamExchange(t))
	unified.manager.CloseGaps(context.Background())
	snapshot, err := unified.store.Snapshot(context.Background(), unified.lastAuditID())
	if err != nil {
		t.Fatal(err)
	}
	exhausted := false
	for _, body := range snapshot.Bodies {
		if body.ErrorCode != nil && *body.ErrorCode == "capture_budget_exhausted" {
			exhausted = body.State == storage.StageStatePartial && body.RetentionState == storage.RetentionFull && body.StoredLength < body.ObservedLength
		}
	}
	if !exhausted || snapshot.Audit.CaptureStatus != storage.CapturePartial {
		t.Fatalf("audit %+v, bodies %+v", snapshot.Audit, snapshot.Bodies)
	}
	dump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
	if len(dump["audit_gaps"]) != 1 || dump["audit_gaps"][0]["reason"] != `"queue_full"` {
		t.Fatalf("gaps %v", dump["audit_gaps"])
	}
	requireNoStagingFiles(t, stager)
}

// stagedCrashRun is crashRun with staging: once frozen, neither the store
// nor the staging files receive anything more, as when the process dies.
func stagedCrashRun(t *testing.T, writePath string, at func(event string, count int) bool) (*eqRun, *staging.Stager, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "staging")
	var dead atomic.Bool
	stager := openEqStager(t, dir, staging.Options{Fault: func(string, string) error {
		if dead.Load() {
			return syscall.EIO
		}
		return nil
	}})
	var frozen *freezingStore
	options := audit.Options{}
	if writePath == audit.WritePathUnified {
		options = audit.Options{StageBytes: stagingTestBudget, Stager: keepingStager{stager}}
	}
	run := newEqRun(t, writePath, options, func(store *sqlite.Store) audit.Store {
		frozen = &freezingStore{Store: store}
		return frozen
	})
	run.noParse = true
	run.upstream.hook = func(event string, count int) {
		if !frozen.frozen.Load() && at(event, count) {
			// What was accepted before the crash reaches the disk and the
			// database within milliseconds; nothing after it does.
			stager.Flush()
			time.Sleep(50 * time.Millisecond)
			frozen.frozen.Store(true)
			dead.Store(true)
		}
	}
	return run, stager, dir
}

// keepingStager never removes a file: the process stops right after the
// commit, before the cleanup.
type keepingStager struct{ *staging.Stager }

func (stager keepingStager) Discard(auditID string) { stager.Stager.Keep(auditID) }

// restartWithImport discards the process state and starts again: integrity,
// the staging import, then today's recovery, then the payload check.
func restartWithImport(t *testing.T, run *eqRun, dir string, wantRecovered int) staging.ImportReport {
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
	stager := openEqStager(t, dir, staging.Options{})
	report, err := stager.Import(context.Background(), reopened)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.RecoverInterruptedAudits(context.Background(), eqClockOrigin+10_000_000); err != nil || count != wantRecovered {
		t.Fatalf("%s: recovered %d: %v", run.path, count, err)
	}
	if err := reopened.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatalf("%s: integrity after recovery: %v", run.path, err)
	}
	run.store = reopened
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("staging left %v", entries)
	}
	return report
}

// Design I.2 with staging (B.7 rows 2 and 4): the process dies with chunks
// staged. After the import and recovery the audit has those chunks, is
// partial with raw kept in full, and verifies. Each chunk it has is the
// chunk legacy, interrupted at the same point, has; the difference is that
// legacy also has the chunks unified still held in memory.
func TestCrashWithStagedChunksRecovers(t *testing.T) {
	for _, test := range []struct {
		name     string
		exchange func(t *testing.T) *eqExchange
		at       func(event string, count int) bool
		stage    string
	}{
		{"request body uploading", largeStreamExchange, func(event string, count int) bool { return event == "request-read" && count >= 1800<<10 }, storage.StageRequestReceived},
		{"response mid-stream", func(t *testing.T) *eqExchange { return largeResponseExchange(t, 6<<20) },
			func(event string, count int) bool { return event == "response-read" && count >= 5<<20 }, storage.StageResponseReceived},
	} {
		t.Run(test.name, func(t *testing.T) {
			legacy, _, legacyDir := stagedCrashRun(t, audit.WritePathLegacy, test.at)
			unified, stager, unifiedDir := stagedCrashRun(t, audit.WritePathUnified, test.at)
			sendBoth(t, legacy, unified, test.exchange(t))
			staged := stager.Stats().Records
			if staged == 0 {
				t.Fatal("nothing was staged before the crash")
			}
			_ = stager.Close()
			restartWithImport(t, legacy, legacyDir, 1)
			report := restartWithImport(t, unified, unifiedDir, 1)
			if report.Files != 1 || report.Removed != 1 || int64(report.Inserted) < 1 {
				t.Fatalf("import %+v of %d staged chunks", report, staged)
			}
			legacyDump := frozen(t, "recovered", legacy, func(run *eqRun) map[string][]eqRow { return dumpEqDatabase(t, run.dbPath, run.cipher) })
			unifiedDump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
			legacyChunks := map[string]bool{}
			for _, row := range legacyDump["body_chunks"] {
				legacyChunks[row.key()] = true
			}
			ofStage := 0
			for _, row := range unifiedDump["body_chunks"] {
				if !legacyChunks[row.key()] {
					t.Fatalf("unified chunk not in legacy: %s", row.key())
				}
				if row["stage"] == `"`+test.stage+`"` {
					ofStage++
				}
			}
			if ofStage < report.Inserted {
				t.Fatalf("%d %s chunks, %d imported", ofStage, test.stage, report.Inserted)
			}
			audit := unifiedDump["audit_records"][0]
			if audit["forward_status"] != `"interrupted"` || audit["capture_status"] != `"partial"` {
				t.Fatalf("audit %v", audit)
			}
			for _, body := range unifiedDump["body_streams"] {
				if body["retention_state"] != `"full"` || body["state"] != `"partial"` {
					t.Fatalf("body %v", body)
				}
				if body["stage"] == `"`+test.stage+`"` && body["chunk_count"] == "int64:0" {
					t.Fatalf("spilled body has no chunks: %v", body)
				}
			}
		})
	}
}

// The process stops after the commit and before the staging file is
// removed: the next start only removes the file, and the audit is unchanged.
func TestCrashAfterCommitBeforeCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "staging")
	stager := openEqStager(t, dir, staging.Options{})
	unified := newEqRun(t, audit.WritePathUnified, audit.Options{StageBytes: stagingTestBudget, Stager: keepingStager{stager}}, nil)
	unified.noParse = true
	_, id := unified.send(copyChunks(largeStreamExchange(t)))
	stager.Flush()
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("staging holds %v", entries)
	}
	_ = stager.Close()
	before := dumpEqAudit(t, unified.dbPath, unified.cipher, id)
	report := restartWithImport(t, unified, dir, 0)
	if report.Removed != 1 || report.Inserted != 0 {
		t.Fatalf("import %+v", report)
	}
	if diffs := diffEqDumps(before, dumpEqAudit(t, unified.dbPath, unified.cipher, id)); len(diffs) != 0 {
		t.Fatalf("finalized audit changed:\n%s", strings.Join(diffs, "\n"))
	}
}
