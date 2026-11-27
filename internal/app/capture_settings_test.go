package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
)

func captureSettingsCall(t *testing.T, application *App, token, method, body string) (int, string) {
	t.Helper()
	request := httptest.NewRequest(method, "/api/v1/settings/audit-capture", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(response, request)
	return response.Code, response.Body.String()
}

// The capture setting is assembled with the unavailable audit manager: the
// page reads the configuration file's value, and a write is refused because
// there is no store to save it in.
func TestCaptureSettingsWithTheUnavailableManager(t *testing.T) {
	configuration := insightsTestConfig(t, "http://192.0.2.1:3000", false, "")
	configuration.Mode = "available"
	configuration.Audit.CommitRetries = 4
	configuration.Audit.WritePath = config.AuditWritePathUnified
	application, err := newContextWithStore(context.Background(), configuration, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(context.Context, string, *slog.Logger) (runtimeStore, error) {
			return nil, errors.New("database unavailable")
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	if application.auditStore != nil || application.auditManager.Healthy() {
		t.Fatal("the audit manager is not the unavailable one")
	}
	if application.auditManager.CommitRetries() != 4 {
		t.Fatalf("manager retries = %d", application.auditManager.CommitRetries())
	}
	if status, body := captureSettingsCall(t, application, "app-test-admin-token", http.MethodGet, ""); status != http.StatusOK ||
		!strings.Contains(body, `"source":"file"`) || !strings.Contains(body, `"commit_retries":4`) ||
		// No session runs, so the page reports the path in use: legacy.
		!strings.Contains(body, `"write_path":"legacy"`) {
		t.Fatalf("GET = %d %s", status, body)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if status, body := captureSettingsCall(t, application, "app-test-admin-token", method, `{"commit_retries":1}`); status != http.StatusServiceUnavailable || !strings.Contains(body, "settings_unavailable") {
			t.Fatalf("%s = %d %s", method, status, body)
		}
	}
}

// A value saved from the page is applied to the manager at the next start.
func TestCaptureSettingsSavedValueAppliesAtStart(t *testing.T) {
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
	schema := fmt.Sprintf("app_capture_test_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	cfg := config.Default()
	cfg.DatabaseURL = u.String()
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "synthetic-test-admin"
	cfg.NewAPI.URL = "http://192.0.2.1:3000"
	cfg.RetentionDays = 0
	cfg.Audit.WritePath = config.AuditWritePathUnified
	cfg.Routes = []config.RouteConfig{{ID: "chat", Method: "POST", Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	first, err := NewContext(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	if first.auditStore == nil || first.auditManager.CommitRetries() != config.DefaultAuditCommitRetries {
		t.Fatalf("first start: store %v, retries %d", first.auditStore != nil, first.auditManager.CommitRetries())
	}
	if status, body := captureSettingsCall(t, first, cfg.AdminToken, http.MethodPut, `{"commit_retries":1}`); status != http.StatusOK || !strings.Contains(body, `"source":"saved"`) {
		t.Fatalf("PUT = %d %s", status, body)
	}
	if first.auditManager.CommitRetries() != 1 {
		t.Fatalf("after save: retries %d", first.auditManager.CommitRetries())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := NewContext(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.auditManager.CommitRetries() != 1 {
		t.Fatalf("after a restart: retries %d", second.auditManager.CommitRetries())
	}
	if status, body := captureSettingsCall(t, second, cfg.AdminToken, http.MethodGet, ""); status != http.StatusOK || !strings.Contains(body, `"commit_retries":1`) || !strings.Contains(body, `"source":"saved"`) {
		t.Fatalf("GET after a restart = %d %s", status, body)
	}
	if status, _ := captureSettingsCall(t, second, cfg.AdminToken, http.MethodDelete, ""); status != http.StatusOK || second.auditManager.CommitRetries() != config.DefaultAuditCommitRetries {
		t.Fatalf("reset = %d, retries %d", status, second.auditManager.CommitRetries())
	}
}
