package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

// The application hands committed audits to the parser worker's Submit with
// the plaintext their session held (design G): served before the worker
// runs, the request's plaintext stays in the capture budget with its queued
// job and is released once it is parsed.
func TestCommittedAuditsAreHandedToTheParser(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"id":"chatcmpl-test","object":"chat.completion","model":"model-example",`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	{
		{
			configuration := insightsTestConfig(t, upstream.URL, true, "")
			application, err := newSQLiteTest(configuration, logger)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = application.Close() })
			request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions",
				strings.NewReader(`{"model":"model-example","messages":[{"role":"user","content":"task"}]}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer sk-testinsightskey")
			response := httptest.NewRecorder()
			application.server.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("proxy status = %d", response.Code)
			}
			if held := application.auditManager.MemoryInUse(); held == 0 || application.parserWorker.QueueLength() != 1 {
				t.Fatalf("%d bytes held and %d jobs queued before the worker runs", held, application.parserWorker.QueueLength())
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := application.parserWorker.Start(ctx); err != nil {
				t.Fatal(err)
			}
			page, err := application.auditStore.ListAudits(ctx, sqlite.AuditQueryFilter{}, sqlite.AuditQueryCursor{}, 10)
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("%d audits, %v", len(page.Rows), err)
			}
			auditID := page.Rows[0].AuditID
			// The analysis row is written on the parser goroutine right after
			// the save.
			deadline := time.Now().Add(5 * time.Second)
			for {
				parsed, err := application.auditStore.LoadParserAudit(ctx, auditID)
				_, analysisErr := application.auditStore.LoadAnalysis(ctx, auditID)
				if err == nil && parsed.ParseStatus == sqlite.ParseOK && analysisErr == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("audit %+v, analysis %v", parsed, analysisErr)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if used := application.auditManager.MemoryInUse(); used != 0 {
				t.Fatalf("%d bytes held after the parse", used)
			}
		}
	}
}
