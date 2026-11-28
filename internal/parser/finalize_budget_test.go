package parser_test

import (
	"context"
	"fmt"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// Design F.2: the plaintext handed to the finalizer stays in the global
// memory budget until its job is done or dropped, and the session hands over
// an id-only job when the budget cannot admit the plaintext.
func TestHandedOverPlaintextStaysInTheBudgetUntilTheJobEnds(t *testing.T) {
	exchanges, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 3})
	if err != nil {
		t.Fatal(err)
	}
	exchange := exchanges[0]
	handOver := func(t *testing.T, options audit.Options, exchange protofixture.Exchange) (*finalizeHarness, handover.Job) {
		harness := newFinalizeHarness(t, finalizeStores(t)["sqlite"](t), options, builtin.All())
		harness.send(harness.handler, exchange)
		job := harness.next()
		return harness, job
	}
	held := func(t *testing.T, harness *finalizeHarness, job handover.Job) {
		t.Helper()
		if job.Evidence == nil || job.Evidence.Bytes() == 0 {
			t.Fatal("no plaintext was handed over")
		}
		if used := harness.manager.MemoryInUse(); used != job.Evidence.Bytes() {
			t.Fatalf("budget holds %d bytes after Finish, the job %d", used, job.Evidence.Bytes())
		}
	}

	t.Run("released when the job is done", func(t *testing.T) {
		harness, job := handOver(t, audit.Options{}, exchange)
		held(t, harness, job)
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		if err := harness.worker.Start(ctx); err != nil {
			t.Fatal(err)
		}
		submitAll(t, harness.worker, job)
		waitParsed(t, harness.store, job.Audit.AuditID)
		waitFor(t, func() bool { return harness.manager.MemoryInUse() == 0 })
	})
	t.Run("released when the queue is full", func(t *testing.T) {
		harness, job := handOver(t, audit.Options{}, exchange)
		held(t, harness, job)
		for index := range parser.FinalizeQueueCapacity {
			submitAll(t, harness.worker, handover.Job{Audit: storage.ParserAudit{AuditID: fmt.Sprintf("filler-%d", index)}})
		}
		if harness.worker.Submit(job) {
			t.Fatal("a full queue took the job")
		}
		if used := harness.manager.MemoryInUse(); used != 0 {
			t.Fatalf("a refused job holds %d bytes", used)
		}
	})
	t.Run("released when the worker is closed", func(t *testing.T) {
		harness, job := handOver(t, audit.Options{}, exchange)
		harness.worker.Close()
		if harness.worker.Submit(job) || harness.manager.MemoryInUse() != 0 {
			t.Fatalf("a closed worker took the job or kept %d bytes", harness.manager.MemoryInUse())
		}
	})
	t.Run("released when the worker stops before the job", func(t *testing.T) {
		harness, job := handOver(t, audit.Options{}, exchange)
		submitAll(t, harness.worker, job)
		held(t, harness, job)
		harness.worker.Close()
		if used := harness.manager.MemoryInUse(); used != 0 {
			t.Fatalf("a dropped job holds %d bytes", used)
		}
		if loaded, err := harness.store.LoadParserAudit(context.Background(), job.Audit.AuditID); err != nil || loaded.ParseStatus != storage.ParsePending {
			t.Fatalf("dropped audit is %+v, %v; want pending for the scan", loaded, err)
		}
	})
	t.Run("id-only when the budget cannot admit it", func(t *testing.T) {
		// A 1 MiB global budget holds the request while it is captured, but
		// not that plaintext a second time beside it.
		large, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
			protofixture.Options{Seed: 4, HistoryItems: 170, ItemBytes: 4000})
		if err != nil {
			t.Fatal(err)
		}
		if size := len(large[0].RequestBody); size <= 512<<10 || size >= 1<<20 {
			t.Fatalf("request is %d bytes", size)
		}
		options := audit.Options{StageBytes: 1 << 20, GlobalBytes: 1 << 20}
		harness, job := handOver(t, options, large[0])
		if job.Evidence != nil || job.Audit.AuditID == "" {
			t.Fatalf("job with %d bytes of evidence under a full budget", job.Evidence.Bytes())
		}
		if used := harness.manager.MemoryInUse(); used != 0 {
			t.Fatalf("budget holds %d bytes after an id-only hand-over", used)
		}
		// The control: a small request under the same budget is handed over.
		harness.send(harness.handler, exchange)
		small := harness.next()
		held(t, harness, small)
		small.Release()
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		if err := harness.worker.Start(ctx); err != nil {
			t.Fatal(err)
		}
		submitAll(t, harness.worker, job)
		waitParsed(t, harness.store, job.Audit.AuditID)
		if loaded, _ := harness.store.LoadParserAudit(ctx, job.Audit.AuditID); loaded.ParseStatus != storage.ParseOK {
			t.Fatalf("id-only job parsed as %q", loaded.ParseStatus)
		}
	})
}

// downgradingStore reports every committed audit as failed, as the store
// does when an earlier write of the audit was lost.
type downgradingStore struct {
	*sqlite.Store
}

func (store downgradingStore) CommitAudit(ctx context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	persisted, err := store.Store.CommitAudit(ctx, commit)
	persisted.CaptureStatus = storage.CaptureFailed
	return persisted, err
}

// Design G.2: when the committed outcome is not the one the session
// submitted, what was stored is not what the session holds, and it hands
// over an id-only job.
func TestDowngradedCommitHandsOverAnIDOnlyJob(t *testing.T) {
	exchanges, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic},
		protofixture.Options{Seed: 8})
	if err != nil {
		t.Fatal(err)
	}
	store := finalizeStores(t)["sqlite"](t).(*sqlite.Store)
	harness := newFinalizeHarness(t, downgradingStore{store}, audit.Options{}, builtin.All())
	harness.send(harness.handler, exchanges[0])
	job := harness.next()
	if job.Evidence != nil || job.Release != nil {
		t.Fatal("a downgraded commit handed over its plaintext")
	}
	if used := harness.manager.MemoryInUse(); used != 0 {
		t.Fatalf("budget holds %d bytes", used)
	}
}
