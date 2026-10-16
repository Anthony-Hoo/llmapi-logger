package app

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage/sqlite"
)

func insightsTestConfig(t *testing.T, upstreamURL string, enabled bool, vocabularyFile string) config.Config {
	t.Helper()
	configuration := config.Default()
	configuration.NewAPI.URL = upstreamURL
	configuration.DBPath = filepath.Join(t.TempDir(), "audit.db")
	configuration.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	configuration.AdminToken = "app-test-admin-token"
	configuration.Insights = config.InsightsConfig{Enabled: enabled, VocabularyFile: vocabularyFile}
	configuration.Routes = []config.RouteConfig{{
		ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions",
	}}
	return configuration
}

// parseOneAudit proxies a request carrying custom agent headers, runs the
// parser worker and returns the audit id once it is parsed.
func parseOneAudit(t *testing.T, application *App) string {
	t.Helper()
	body := `{"model":"model-example","messages":[{"role":"user","content":"task"}]}`
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer sk-testinsightskey")
	request.Header.Set("X-Agent-Id", "agent-example")
	response := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("proxy status = %d", response.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := application.parserWorker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		page, err := application.auditStore.ListAudits(ctx, sqlite.AuditQueryFilter{}, sqlite.AuditQueryCursor{}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) == 1 {
			auditID := page.Rows[0].AuditID
			audit, err := application.auditStore.LoadParserAudit(ctx, auditID)
			if err != nil {
				t.Fatal(err)
			}
			if audit.ParseStatus == sqlite.ParseOK {
				return auditID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("audit was not parsed")
	return ""
}

func TestInsightsWiringFollowsConfiguration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"id":"chatcmpl-test","object":"chat.completion","model":"model-example",`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("enabled analyses parsed audits", func(t *testing.T) {
		application, err := New(insightsTestConfig(t, upstream.URL, true, ""), logger)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = application.Close() })
		auditID := parseOneAudit(t, application)
		deadline := time.Now().Add(5 * time.Second)
		for {
			row, err := application.auditStore.LoadAnalysis(context.Background(), auditID)
			if err == nil {
				if row.AgentClient == nil || *row.AgentClient != "custom" || len(row.AgentNodeFPR) != sqlite.AnalysisFingerprintSize {
					t.Fatalf("analysis agent = %v node=%x", row.AgentClient, row.AgentNodeFPR)
				}
				break
			}
			if !errors.Is(err, sql.ErrNoRows) || time.Now().After(deadline) {
				t.Fatalf("LoadAnalysis = %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("disabled writes no analysis and ignores the vocabulary file", func(t *testing.T) {
		// A disabled deployment never reads the override file, so even a
		// missing one cannot fail startup.
		missing := filepath.Join(t.TempDir(), "missing-vocabulary.yaml")
		application, err := New(insightsTestConfig(t, upstream.URL, false, missing), logger)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = application.Close() })
		auditID := parseOneAudit(t, application)
		// Analysis runs right after the parse save on the same goroutine;
		// closing the worker waits for it.
		application.parserWorker.Close()
		if _, err := application.auditStore.LoadAnalysis(context.Background(), auditID); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("LoadAnalysis with insights disabled = %v, want no rows", err)
		}
	})

	t.Run("enabled rejects an invalid vocabulary", func(t *testing.T) {
		invalid := filepath.Join(t.TempDir(), "vocabulary.yaml")
		if err := os.WriteFile(invalid, []byte("clients:\n  custom:\n    node_fallback: sideways\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		application, err := New(insightsTestConfig(t, upstream.URL, true, invalid), logger)
		if application != nil {
			_ = application.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "insights vocabulary") {
			t.Fatalf("New with invalid vocabulary = %v, want vocabulary error", err)
		}
	})
}

func TestValidateConfigChecksInsightsOverrides(t *testing.T) {
	write := func(t *testing.T, name, contents string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	malformed := write(t, "pricing.json", `{"models":`)
	valid := write(t, "valid-pricing.json", `{"models":{"x/model":{"input":0,"output":0}}}`)

	validate := func(t *testing.T, enabled bool, pricingFile string) error {
		t.Helper()
		configuration := insightsTestConfig(t, "http://upstream.example.com", enabled, "")
		configuration.Insights.PricingFile = pricingFile
		data, err := yaml.Marshal(configuration)
		if err != nil {
			t.Fatal(err)
		}
		return ValidateConfig(write(t, "config.yaml", string(data)))
	}

	if err := validate(t, true, valid); err != nil {
		t.Fatalf("valid pricing override rejected: %v", err)
	}
	if err := validate(t, true, malformed); err == nil || !strings.Contains(err.Error(), "insights pricing") {
		t.Fatalf("malformed pricing override = %v, want pricing error", err)
	}
	if err := validate(t, false, malformed); err != nil {
		t.Fatalf("disabled insights must not read the pricing override: %v", err)
	}
}
