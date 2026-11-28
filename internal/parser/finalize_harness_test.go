package parser_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// finalizeStore is what the finalizer tests need of a real store: the
// capture session's surface and the parser's.
type finalizeStore interface {
	audit.Store
	parser.Store
}

var finalizeKey = bytes.Repeat([]byte{0x5a}, security.KeySize)

// finalizeStores returns the stores the finalizer tests run on: SQLite
// (capture version 1) always, and PostgreSQL (capture version 2) in a schema
// of its own when TEST_DATABASE_URL names a throwaway database.
func finalizeStores(t *testing.T) map[string]func(*testing.T) finalizeStore {
	stores := map[string]func(*testing.T) finalizeStore{
		"sqlite": func(t *testing.T) finalizeStore {
			store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.EnableIntegrity(context.Background(), finalizeKey); err != nil {
				t.Fatal(err)
			}
			return store
		},
	}
	if os.Getenv("TEST_DATABASE_URL") != "" {
		stores["postgres"] = func(t *testing.T) finalizeStore {
			store, err := postgres.Open(context.Background(), finalizeSchemaURL(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.EnableIntegrity(context.Background(), finalizeKey); err != nil {
				t.Fatal(err)
			}
			return store
		}
	}
	return stores
}

var finalizeSchemas atomic.Uint64

// finalizeSchemaURL creates a schema of its own in the test database and
// drops it when the test ends.
func finalizeSchemaURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open PostgreSQL test connection")
	}
	schema := fmt.Sprintf("logger_parser_%d_%d", time.Now().UnixNano(), finalizeSchemas.Add(1))
	if _, err := database.Exec("CREATE SCHEMA " + schema); err != nil {
		database.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		defer database.Close()
		if _, err := database.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL test URL")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// finalizeHarness is the unified write path through the real proxy handler,
// with a protofixture upstream, and a parser worker on the same store.
type finalizeHarness struct {
	t        *testing.T
	store    finalizeStore
	cipher   security.Cipher
	manager  *audit.Manager
	handler  http.Handler
	upstream *protofixture.Upstream
	worker   *parser.Worker
	// submit is the manager's hand-over callback; it defaults to keeping the
	// job in jobs.
	submit func(handover.Job) bool
	jobs   chan handover.Job
}

func finalizeRoutes() []config.RouteConfig {
	return []config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages"},
		{ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		{ID: "gemini-stream", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
	}
}

func newFinalizeHarness(t *testing.T, store finalizeStore, options audit.Options, parsers []parser.Parser) *finalizeHarness {
	t.Helper()
	harness := &finalizeHarness{t: t, store: store, jobs: make(chan handover.Job, 256)}
	var err error
	if harness.cipher, err = security.NewAESGCM(finalizeKey); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, closeManager, err := newTestManager(t.TempDir(), store, harness.cipher, nil, quiet, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeManager)
	harness.manager = manager
	harness.submit = func(job handover.Job) bool { harness.jobs <- job; return true }
	harness.manager.SetHandover(func(job handover.Job) bool { return harness.submit(job) })
	if harness.worker, err = parser.NewWorker(store, harness.cipher, parsers, quiet); err != nil {
		t.Fatal(err)
	}
	harness.worker.SetHeaderAllowlist([]string{"user-agent", "content-type", protofixture.ExchangeHeader, "x-missing"})
	t.Cleanup(harness.worker.Close)
	harness.upstream = protofixture.NewUpstream("fx")
	harness.upstream.CancelWait = 2 * time.Second
	server := httptest.NewServer(harness.upstream)
	t.Cleanup(server.Close)
	harness.handler = harness.proxyTo(server.URL)
	return harness
}

func (harness *finalizeHarness) proxyTo(target string) http.Handler {
	harness.t.Helper()
	routes := finalizeRoutes()
	matcher, err := routing.Compile(routes)
	if err != nil {
		harness.t.Fatal(err)
	}
	engine, err := interceptor.NewEngine(map[string]config.InterceptorConfig{}, routes)
	if err != nil {
		harness.t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		harness.t.Fatal(err)
	}
	return proxy.NewWithAudit(parsed, matcher, engine, harness.manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// cancelAt cancels the client request once the response body has reached
// cut bytes, which is where a client-cancel exchange gives up.
type cancelAt struct {
	*httptest.ResponseRecorder
	cut     int
	written int
	cancel  context.CancelFunc
}

func (writer *cancelAt) Write(data []byte) (int, error) {
	count, err := writer.ResponseRecorder.Write(data)
	writer.written += count
	if writer.cut > 0 && writer.written >= writer.cut {
		writer.cancel()
	}
	return count, err
}

// send runs one exchange through handler and returns the client's status.
func (harness *finalizeHarness) send(handler http.Handler, exchange protofixture.Exchange) int {
	harness.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, exchange.Method, "http://proxy.example.com"+exchange.Path, bytes.NewReader(exchange.RequestBody))
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set("User-Agent", "client-example/1.0")
	request.Header.Set(protofixture.ExchangeHeader, harness.upstream.Register(&exchange))
	writer := &cancelAt{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	if exchange.Response.ClientCancel {
		writer.cut = exchange.Response.CutAt
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				panic(recovered)
			}
		}()
		handler.ServeHTTP(writer, request)
	}()
	return writer.Code
}

// next returns the job the last Finish handed over.
func (harness *finalizeHarness) next() handover.Job {
	harness.t.Helper()
	select {
	case job := <-harness.jobs:
		return job
	case <-time.After(parser.PipelineWait):
		harness.t.Fatal("no job was handed over")
		return handover.Job{}
	}
}

// finalizeTraffic is the protofixture catalogue on all four protocols in
// both modes, plus a request body above 1 MiB.
func finalizeTraffic(t *testing.T) []protofixture.Exchange {
	t.Helper()
	var traffic []protofixture.Exchange
	for index, value := range protofixture.Catalog() {
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(index + 1)})
		if err != nil {
			t.Fatal(err)
		}
		traffic = append(traffic, built...)
	}
	large, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 91, HistoryItems: 600, ItemBytes: 4000, DeltaBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if len(large[0].RequestBody) <= 1<<20 {
		t.Fatalf("large request is only %d bytes", len(large[0].RequestBody))
	}
	return append(traffic, large[0])
}

func exchangeName(exchange protofixture.Exchange) string {
	mode := "json"
	if exchange.Stream {
		mode = "sse"
	}
	return strings.Join([]string{string(exchange.Protocol), string(exchange.Scenario), mode, fmt.Sprint(exchange.Turn)}, "/")
}
