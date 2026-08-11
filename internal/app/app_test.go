package app

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestNewAssemblesDataPlaneHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("created"))
	}))
	defer upstream.Close()

	configuration := config.Default()
	configuration.NewAPIURL = upstream.URL
	configuration.DBPath = filepath.Join(t.TempDir(), "audit.db")
	configuration.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	configuration.AdminToken = "app-test-admin-token"
	configuration.Routes = []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
	application, err := New(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new application: %v", err)
	}
	t.Cleanup(func() {
		if err := application.Close(); err != nil {
			t.Errorf("close application: %v", err)
		}
	})

	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	response := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if response.Body.String() != "created" {
		t.Fatalf("body = %q, want created", response.Body.String())
	}
}

func TestNewRoutesNewAPIRequestsThroughConfiguredProxy(t *testing.T) {
	observed := make(chan *http.Request, 1)
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed <- request.Clone(request.Context())
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte("proxied"))
	}))
	defer upstreamProxy.Close()

	configuration := config.Default()
	configuration.NewAPIURL = "http://newapi.invalid"
	configuration.NewAPIProxyURL = upstreamProxy.URL
	configuration.DBPath = filepath.Join(t.TempDir(), "audit.db")
	configuration.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	configuration.AdminToken = "app-test-admin-token"
	configuration.Routes = []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
	application, err := New(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new application: %v", err)
	}
	t.Cleanup(func() {
		if err := application.Close(); err != nil {
			t.Errorf("close application: %v", err)
		}
	})

	response := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody),
	)
	if response.Code != http.StatusAccepted || response.Body.String() != "proxied" {
		t.Fatalf("response = %d %q, want proxied 202", response.Code, response.Body.String())
	}

	request := <-observed
	if request.URL.Scheme != "http" || request.URL.Host != "newapi.invalid" {
		t.Fatalf("proxy request URL = %q, want NewAPI absolute URL", request.URL.String())
	}
	if request.URL.Path != "/v1/chat/completions" {
		t.Fatalf("proxy request path = %q", request.URL.Path)
	}
}

func TestNewRoutesPassthroughThroughConfiguredProxyWithoutAudit(t *testing.T) {
	observed := make(chan *http.Request, 1)
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed <- request.Clone(request.Context())
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"data":[{"id":"model"}]}`))
	}))
	defer upstreamProxy.Close()

	configuration := config.Default()
	configuration.NewAPIURL = "http://newapi.invalid"
	configuration.NewAPIProxyURL = upstreamProxy.URL
	configuration.DBPath = filepath.Join(t.TempDir(), "audit.db")
	configuration.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	configuration.AdminToken = "app-test-admin-token"
	configuration.Routes = []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
	application, err := New(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new application: %v", err)
	}
	t.Cleanup(func() {
		if err := application.Close(); err != nil {
			t.Errorf("close application: %v", err)
		}
	})

	response := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "http://audit-proxy/v1/models?group=all", http.NoBody),
	)
	if response.Code != http.StatusOK || response.Body.String() != `{"data":[{"id":"model"}]}` {
		t.Fatalf("response = %d %q, want models response", response.Code, response.Body.String())
	}

	request := <-observed
	if request.URL.Scheme != "http" || request.URL.Host != "newapi.invalid" {
		t.Fatalf("proxy request URL = %q, want NewAPI absolute URL", request.URL.String())
	}
	if request.Method != http.MethodGet || request.URL.Path != "/v1/models" || request.URL.RawQuery != "group=all" {
		t.Fatalf("passthrough request = %s %q, want GET /v1/models?group=all", request.Method, request.URL.RequestURI())
	}
	hasAudits, err := application.auditStore.HasAudits(context.Background())
	if err != nil {
		t.Fatalf("check audit rows: %v", err)
	}
	if hasAudits {
		t.Fatal("models passthrough unexpectedly created an audit record")
	}
}

func TestAssembleAuditTreatsStartupRecoveryFailureAsUnavailable(t *testing.T) {
	const recoveryErrorCanary = "recovery-error-secret-that-must-not-be-logged"
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "audit.db")
	keyPath := filepath.Join(directory, "audit.key")

	store, err := sqlite.Open(context.Background(), databasePath)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	if err := store.BeginAudit(context.Background(), sqlite.AuditRecord{
		AuditID:       "apx_interrupted",
		StartedAtNS:   time.Now().Add(-time.Minute).UnixNano(),
		RouteID:       "chat",
		Protocol:      "openai",
		ParserName:    "openai.chat_completions",
		Method:        http.MethodPost,
		Path:          "/v1/chat/completions",
		RequestURIEnc: []byte{1, 2, 3},
		Mode:          audit.ModeAvailable,
	}); err != nil {
		_ = store.Close()
		t.Fatalf("insert interrupted audit: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
	if _, err := security.LoadOrCreateKey(keyPath, true); err != nil {
		t.Fatalf("create audit key: %v", err)
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	if _, err := database.Exec(`
CREATE TRIGGER fail_interrupted_recovery
BEFORE UPDATE ON audit_records
WHEN OLD.ended_at_ns IS NULL
BEGIN
    SELECT RAISE(ABORT, '` + recoveryErrorCanary + `');
END`); err != nil {
		_ = database.Close()
		t.Fatalf("install recovery failure trigger: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close raw database: %v", err)
	}

	for _, mode := range []string{audit.ModeAvailable, audit.ModeStrict} {
		t.Run(mode, func(t *testing.T) {
			configuration := config.Default()
			configuration.Mode = mode
			configuration.DBPath = databasePath
			configuration.KeyPath = keyPath
			var logs bytes.Buffer

			runtime := assembleAudit(configuration, slog.New(slog.NewJSONHandler(&logs, nil)))
			if runtime.store != nil || runtime.cipher != nil {
				t.Fatalf("runtime retained usable storage after recovery failure: store=%v cipher=%v", runtime.store != nil, runtime.cipher != nil)
			}
			if runtime.manager == nil || runtime.sink == nil {
				t.Fatal("runtime did not install unavailable audit manager")
			}
			if runtime.manager.Healthy() || runtime.sink.Healthy() {
				t.Fatal("runtime reports healthy after recovery failure")
			}
			if runtime.sink.Mode() != mode {
				t.Fatalf("mode = %q, want %q", runtime.sink.Mode(), mode)
			}
			if strings.Contains(logs.String(), recoveryErrorCanary) {
				t.Fatal("logs contain underlying recovery error text")
			}
		})
	}
}
