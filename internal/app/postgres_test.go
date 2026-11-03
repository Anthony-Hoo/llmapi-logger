package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
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
)

func TestPostgresApplicationHTTPPersistence(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL application integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := fmt.Sprintf("app_test_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	var count atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"test","object":"chat.completion","model":"lab-model","choices":[{"index":0,"message":{"role":"assistant","content":"safe reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}`)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.DatabaseURL = u.String()
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "synthetic-test-admin"
	cfg.NewAPI.URL = upstream.URL
	cfg.RetentionDays = 0
	cfg.Routes = []config.RouteConfig{{ID: "chat", Method: "POST", Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"}}
	app, err := NewContext(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.auditStore == nil || !app.auditStore.Healthy() {
		t.Fatal("PostgreSQL did not initialize")
	}
	if err := app.parserWorker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	data := httptest.NewServer(app.server.Handler)
	defer data.Close()
	admin := httptest.NewServer(app.adminServer.Handler())
	defer admin.Close()
	request := func(base, path, body string) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer synthetic-test-admin")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	status, b := request(admin.URL, "/api/v1/content-policy-rules", `{"name":"test","enabled":true,"action":"block","scan_scopes":["latest_user"],"keywords":["PG_BLOCK"]}`)
	if status != 201 {
		t.Fatalf("rule status %d: %s", status, b)
	}
	var rule struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(b, &rule); err != nil || rule.ID == 0 {
		t.Fatal("invalid created rule")
	}
	status, _ = request(data.URL, "/v1/chat/completions", `{"model":"lab-model","messages":[{"role":"user","content":"PG_BLOCK"}]}`)
	if status != 400 || count.Load() != 0 {
		t.Fatalf("block status %d, upstream %d", status, count.Load())
	}
	status, b = request(data.URL, "/v1/chat/completions", `{"model":"lab-model","messages":[{"role":"user","content":"safe hello"}]}`)
	if status != 200 || !bytes.Contains(b, []byte("safe reply")) {
		t.Fatalf("forward status %d: %s", status, b)
	}
	deadline := time.Now().Add(10 * time.Second)
	var page storage.AuditListPage
	for time.Now().Before(deadline) {
		page, err = app.auditStore.ListAudits(ctx, storage.AuditQueryFilter{}, storage.AuditQueryCursor{}, 10)
		if err == nil && len(page.Rows) == 2 {
			var ready bool
			for _, row := range page.Rows {
				if row.ParseStatus == "ok" {
					ready = true
				}
			}
			if ready {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("audit records: %v count=%d", err, len(page.Rows))
	}
	var blocked, parsed bool
	for _, row := range page.Rows {
		blocked = blocked || row.ForwardStatus == "rejected"
		parsed = parsed || row.ParseStatus == "ok"
	}
	if !blocked || !parsed {
		t.Fatal("missing persisted block or parsed success")
	}
	if err := app.auditStore.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewContext(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.auditStore == nil || len(reopened.contentPolicies.List()) != 1 || reopened.contentPolicies.List()[0].ID != rule.ID {
		t.Fatal("rule or PostgreSQL state lost on restart")
	}
	if err := reopened.auditStore.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}
