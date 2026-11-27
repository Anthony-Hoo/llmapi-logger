package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// readCountingStore is the parser worker's PostgreSQL store, counting the
// reads of stored evidence. It embeds the store, so the optional interfaces
// the worker looks for are all there.
type readCountingStore struct {
	*postgres.Store
	stages, chunks atomic.Int64
}

func (store *readCountingStore) LoadParserStage(ctx context.Context, auditID, stage string) (storage.ParserStage, error) {
	store.stages.Add(1)
	return store.Store.LoadParserStage(ctx, auditID, stage)
}

func (store *readCountingStore) ReadParserChunks(ctx context.Context, auditID, stage string, afterSeq int64, limit int) ([]storage.BodyChunk, error) {
	store.chunks.Add(1)
	return store.Store.ReadParserChunks(ctx, auditID, stage, afterSeq, limit)
}

// finalizeRun is one write path on its own PostgreSQL schema: the real proxy
// handler, the audit manager and a parser worker wired as internal/app wires
// them.
type finalizeRun struct {
	store    *postgres.Store
	reads    *readCountingStore
	handler  http.Handler
	upstream *protofixture.Upstream
	database *sql.DB
}

func newFinalizeRun(t *testing.T, writePath string) *finalizeRun {
	t.Helper()
	ctx := context.Background()
	dsn := newIntegrationDatabaseURL(t)
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key := bytes.Repeat([]byte{0x3c}, security.KeySize)
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := audit.NewManagerWithOptions(store, cipher, nil, audit.ModeAvailable, quiet, audit.Options{WritePath: writePath})
	if err != nil {
		t.Fatal(err)
	}
	run := &finalizeRun{store: store, reads: &readCountingStore{Store: store}, database: openAuditDatabase(t, dsn)}
	t.Cleanup(func() { _ = run.database.Close() })
	worker, err := parser.NewWorker(run.reads, cipher, builtin.All(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetCompletionNotifier(worker.Notify)
	if manager.WritePath() == audit.WritePathUnified {
		manager.SetHandover(worker.Submit)
	}
	workerCtx, stop := context.WithCancel(ctx)
	if err := worker.Start(workerCtx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(); worker.Close() })
	routes := []config.RouteConfig{{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"}}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := interceptor.NewEngine(map[string]config.InterceptorConfig{}, routes)
	if err != nil {
		t.Fatal(err)
	}
	run.upstream = protofixture.NewUpstream(writePath)
	server := httptest.NewServer(run.upstream)
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	run.handler = proxy.NewWithAudit(target, matcher, engine, manager, quiet)
	return run
}

// send runs one exchange and returns its audit id and the time from the end
// of the response (the handler returns after the commit) to a terminal parse
// status.
func (run *finalizeRun) send(t *testing.T, exchange protofixture.Exchange) (string, time.Duration) {
	t.Helper()
	id := run.upstream.Register(&exchange)
	request := httptest.NewRequest(exchange.Method, "http://proxy.example.com"+exchange.Path, bytes.NewReader(exchange.RequestBody))
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(protofixture.ExchangeHeader, id)
	recorder := httptest.NewRecorder()
	run.handler.ServeHTTP(recorder, request)
	ended := time.Now()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	ctx := context.Background()
	var auditID string
	deadline := ended.Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if auditID == "" {
			_ = run.database.QueryRowContext(ctx, `SELECT audit_id FROM audit_records WHERE newapi_request_id = $1`, id).Scan(&auditID)
		}
		if auditID != "" {
			loaded, err := run.store.LoadParserAudit(ctx, auditID)
			if err == nil && loaded.ParseStatus != storage.ParsePending && loaded.ParseStatus != storage.ParseProcessing {
				if loaded.ParseStatus != storage.ParseOK {
					t.Fatalf("audit %s parsed as %s", auditID, loaded.ParseStatus)
				}
				return auditID, time.Since(ended)
			}
		}
		time.Sleep(500 * time.Microsecond)
	}
	t.Fatalf("exchange %s was not parsed", id)
	return "", 0
}

// Design G on PostgreSQL with capture version 2: the parse of a normal
// request reads no stage and no body chunk back, where legacy reads them.
// It also measures, for the report, the time from the end of the response to
// a terminal parse status on both paths, for a small and a 1 MB request, one
// request at a time so the pending backlog stays far below 100 and the
// 30-second scan plays no part.
func TestUnifiedParseDoesNotReadBackOnPostgreSQL(t *testing.T) {
	small, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 21})
	if err != nil {
		t.Fatal(err)
	}
	large, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 22, HistoryItems: 250, ItemBytes: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if size := len(large[0].RequestBody); size < 900<<10 || size > 1200<<10 {
		t.Fatalf("large request is %d bytes", size)
	}
	legacy, unified := newFinalizeRun(t, audit.WritePathLegacy), newFinalizeRun(t, audit.WritePathUnified)
	rounds := 15
	if testing.Short() {
		rounds = 2
	}
	for _, size := range []struct {
		name     string
		exchange protofixture.Exchange
	}{{"small", small[0]}, {"1MB", large[0]}} {
		var legacyTimes, unifiedTimes []time.Duration
		for range rounds {
			_, elapsed := legacy.send(t, size.exchange)
			legacyTimes = append(legacyTimes, elapsed)
			_, elapsed = unified.send(t, size.exchange)
			unifiedTimes = append(unifiedTimes, elapsed)
		}
		t.Logf("%s request (%d bytes): end of response to parsed, legacy p50 %v p90 %v; unified p50 %v p90 %v",
			size.name, len(size.exchange.RequestBody), percentile(legacyTimes, 50), percentile(legacyTimes, 90),
			percentile(unifiedTimes, 50), percentile(unifiedTimes, 90))
	}
	if legacy.reads.chunks.Load() == 0 || legacy.reads.stages.Load() == 0 {
		t.Fatalf("legacy parse read %d stages and %d chunk pages", legacy.reads.stages.Load(), legacy.reads.chunks.Load())
	}
	if unified.reads.chunks.Load() != 0 || unified.reads.stages.Load() != 0 {
		t.Fatalf("unified parse read %d stages and %d chunk pages back", unified.reads.stages.Load(), unified.reads.chunks.Load())
	}
	t.Logf("parser reads of stored evidence: legacy %d stage loads and %d chunk pages, unified none",
		legacy.reads.stages.Load(), legacy.reads.chunks.Load())
}

func percentile(values []time.Duration, rank int) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[min(len(sorted)-1, len(sorted)*rank/100)]
}
