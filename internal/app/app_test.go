package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/newapi"
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
	configuration.NewAPI.URL = upstream.URL
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

func TestUserAgentRuleBlocksGPTBeforeNewAPIAndUpdatesImmediately(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	configuration := config.Default()
	configuration.NewAPI.URL = upstream.URL
	configuration.DBPath = filepath.Join(t.TempDir(), "audit.db")
	configuration.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	configuration.AdminToken = "app-test-admin-token"
	configuration.Routes = []config.RouteConfig{{
		ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions",
	}}
	application, err := New(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new application: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })

	send := func(model, userAgent string) *httptest.ResponseRecorder {
		body := `{"model":"` + model + `","stream":true}`
		request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if userAgent != "" {
			request.Header.Set("User-Agent", userAgent)
		}
		response := httptest.NewRecorder()
		application.server.Handler.ServeHTTP(response, request)
		return response
	}

	response := send("gpt-test", "wrong-client")
	if response.Code != http.StatusUnauthorized || upstreamRequests.Load() != 0 || response.Body.String() != `{"error":{"code":"unauthorized","message":"unauthorized"}}` {
		t.Fatalf("blocked request: status=%d upstream=%d body=%q", response.Code, upstreamRequests.Load(), response.Body.String())
	}
	if strings.Contains(response.Body.String(), "user_agent_not_allowed") {
		t.Fatalf("blocked response leaked internal UA code: %q", response.Body.String())
	}
	response = send("gpt-test", "Codex Desktop/1.0")
	if response.Code != http.StatusNoContent || upstreamRequests.Load() != 1 {
		t.Fatalf("allowed GPT request: status=%d upstream=%d", response.Code, upstreamRequests.Load())
	}
	response = send("gpt-test", "codex-tui/1.0")
	if response.Code != http.StatusNoContent || upstreamRequests.Load() != 2 {
		t.Fatalf("allowed codex-tui request: status=%d upstream=%d", response.Code, upstreamRequests.Load())
	}
	response = send("deepseek-test", "wrong-client")
	if response.Code != http.StatusNoContent || upstreamRequests.Load() != 3 {
		t.Fatalf("non-GPT request: status=%d upstream=%d", response.Code, upstreamRequests.Load())
	}

	update := httptest.NewRequest(http.MethodPut, "http://admin/api/v1/user-agent-rules/1", strings.NewReader(`{"name":"updated","enabled":true,"model_pattern":"^gpt","user_agent_pattern":"Approved Client"}`))
	update.Header.Set("Authorization", "Bearer "+configuration.AdminToken)
	update.Header.Set("Content-Type", "application/json")
	updateResponse := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(updateResponse, update)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("rule update: status=%d body=%q", updateResponse.Code, updateResponse.Body.String())
	}

	response = send("gpt-test", "Codex Desktop/1.0")
	if response.Code != http.StatusUnauthorized || upstreamRequests.Load() != 3 {
		t.Fatalf("old UA after update: status=%d upstream=%d", response.Code, upstreamRequests.Load())
	}
	response = send("gpt-test", "Approved Client/2.0")
	if response.Code != http.StatusNoContent || upstreamRequests.Load() != 4 {
		t.Fatalf("new UA after update: status=%d upstream=%d", response.Code, upstreamRequests.Load())
	}
}

func TestNewUsesConfiguredHostAndTimeoutOptions(t *testing.T) {
	observedHosts := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observedHosts <- request.Host
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	configuration := config.Default()
	configuration.NewAPI.URL = upstream.URL
	configuration.NewAPI.ResponseHeaderTimeoutSeconds = 3900
	configuration.NewAPI.PreserveHost = true
	configuration.ShutdownTimeoutSeconds = 3900
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
	if application.shutdownTimeout != 65*time.Minute {
		t.Fatalf("shutdown timeout = %s, want 65m", application.shutdownTimeout)
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody),
		httptest.NewRequest(http.MethodGet, "http://audit-proxy/v1/models", http.NoBody),
	} {
		request.Host = "api.example.com"
		response := httptest.NewRecorder()
		application.server.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
		}
		if got := <-observedHosts; got != "api.example.com" {
			t.Fatalf("upstream Host = %q, want preserved public Host", got)
		}
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
	configuration.NewAPI.URL = "http://newapi.invalid"
	configuration.NewAPI.ProxyURL = upstreamProxy.URL
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
	configuration.NewAPI.URL = "http://newapi.invalid"
	configuration.NewAPI.ProxyURL = upstreamProxy.URL
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

func TestNewAPIManagementUsesConfiguredProxyAndResolvesCaller(t *testing.T) {
	const (
		managementAccessToken = "app-management-access-canary"
		requestID             = "req-app-caller"
	)
	var userRequests atomic.Int32
	var logRequests atomic.Int32

	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/user/":
			userRequests.Add(1)
			if request.URL.Scheme != "http" || request.URL.Host != "newapi.invalid" {
				t.Errorf("management proxy URL = %q, want NewAPI absolute URL", request.URL.String())
			}
			if request.URL.Query().Get("p") != "0" || request.URL.Query().Get("size") != "100" {
				t.Errorf("user query = %q, want p=0&size=100", request.URL.RawQuery)
			}
			if request.Header.Get("Authorization") != managementAccessToken {
				t.Error("management Authorization did not contain the configured access token")
			}
			if request.Header.Get("New-Api-User") != "73" {
				t.Errorf("catalog New-Api-User = %q, want 73", request.Header.Get("New-Api-User"))
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"total": 1,
					"items": []map[string]any{{
						"id": 7, "username": "alice", "display_name": "Alice",
						"status": 1, "group": "default",
					}},
				},
			})
		case "/api/log/":
			logRequests.Add(1)
			if request.URL.Query().Get("request_id") != requestID {
				t.Errorf("log request_id = %q", request.URL.Query().Get("request_id"))
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"total": 1,
					"items": []map[string]any{{
						"request_id": requestID, "user_id": 7, "username": "alice",
						"token_id": 42, "token_name": "codex", "model_name": "gpt-test",
					}},
				},
			})
		case "/v1/chat/completions":
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("X-Oneapi-Request-Id", requestID)
			_, _ = response.Write([]byte(`{"id":"chatcmpl-app","choices":[]}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer upstreamProxy.Close()

	configuration := config.Default()
	configuration.NewAPI.URL = "http://newapi.invalid"
	configuration.NewAPI.ProxyURL = upstreamProxy.URL
	configuration.NewAPI.AccessToken = managementAccessToken
	configuration.NewAPI.UserID = 73
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
	if application.newAPIClient == nil || application.callerWorker == nil {
		t.Fatal("New did not assemble the NewAPI management integration")
	}

	application.refreshUserCatalog(context.Background())
	if userRequests.Load() != 1 {
		t.Fatalf("user requests = %d, want 1", userRequests.Load())
	}
	snapshot := application.newAPIClient.Snapshot()
	if len(snapshot.Users) != 1 || snapshot.Users[0].ID != 7 || snapshot.Users[0].Username != "alice" {
		t.Fatalf("user snapshot = %#v", snapshot)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "http://admin/api/v1/newapi/callers", nil)
	adminRequest.Header.Set("Authorization", "Bearer "+configuration.AdminToken)
	adminResponse := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("caller catalog API status = %d, body = %q", adminResponse.Code, adminResponse.Body.String())
	}
	var callerResponse struct {
		Items []newapi.User `json:"items"`
	}
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &callerResponse); err != nil {
		t.Fatalf("decode caller catalog API: %v", err)
	}
	if len(callerResponse.Items) != 1 || callerResponse.Items[0].DisplayName != "Alice" {
		t.Fatalf("caller catalog API response = %#v", callerResponse)
	}
	if strings.Contains(adminResponse.Body.String(), managementAccessToken) || strings.Contains(adminResponse.Body.String(), "password") {
		t.Fatal("caller catalog API exposed a credential")
	}
	workerContext, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	if err := application.callerWorker.Start(workerContext); err != nil {
		t.Fatalf("start caller worker: %v", err)
	}

	proxyRequest := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	proxyRequest.Header.Set("Authorization", "Bearer client-key-never-inspected")
	proxyResponse := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(proxyResponse, proxyRequest)
	if proxyResponse.Code != http.StatusOK {
		t.Fatalf("proxied response = %d %q", proxyResponse.Code, proxyResponse.Body.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		page, listErr := application.auditStore.ListAudits(context.Background(), sqlite.AuditQueryFilter{}, sqlite.AuditQueryCursor{}, 10)
		if listErr != nil {
			t.Fatalf("list audits: %v", listErr)
		}
		if len(page.Rows) == 1 && page.Rows[0].NewAPITokenID != nil && *page.Rows[0].NewAPITokenID == 42 &&
			page.Rows[0].TokenName != nil && *page.Rows[0].TokenName == "codex" {
			snapshot, snapshotErr := application.auditStore.Snapshot(context.Background(), page.Rows[0].AuditID)
			if snapshotErr != nil {
				t.Fatalf("read resolved audit: %v", snapshotErr)
			}
			if snapshot.Audit.NewAPIRequestID == nil || *snapshot.Audit.NewAPIRequestID != requestID ||
				snapshot.Audit.CallerStatus != sqlite.CallerResolved {
				t.Fatalf("resolved audit state = %+v", snapshot.Audit)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("caller was not resolved: %+v", page.Rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if logRequests.Load() == 0 {
		t.Fatal("caller worker did not query the NewAPI system log")
	}
}

func TestUserCatalogRefreshLoopRetriesAfterInitialFailureAndStops(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		attempt := requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if attempt == 1 {
			_, _ = response.Write([]byte(`{"success":false,"message":"temporary"}`))
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"total": 1,
				"items": []map[string]any{{"id": 7, "username": "recovered", "status": 1}},
			},
		})
	}))
	defer server.Close()

	client, err := assembleNewAPIClient(config.NewAPIConfig{
		URL:         server.URL,
		AccessToken: "refresh-loop-access-canary",
		UserID:      9,
	}, nil)
	if err != nil {
		t.Fatalf("assemble user catalog: %v", err)
	}
	application := &App{
		newAPIClient:        client,
		userRefreshInterval: 10 * time.Millisecond,
		logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	stop := application.startUserCatalog(context.Background())
	if requests.Load() != 1 {
		stop()
		t.Fatalf("startup refresh requests = %d, want 1", requests.Load())
	}
	if len(client.Snapshot().Users) != 0 {
		stop()
		t.Fatal("failed startup refresh unexpectedly published a snapshot")
	}

	deadline := time.Now().Add(time.Second)
	for len(client.Snapshot().Users) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if users := client.Snapshot().Users; len(users) != 1 || users[0].ID != 7 {
		stop()
		t.Fatalf("periodic refresh did not recover: %#v", users)
	}

	stop()
	requestsAfterStop := requests.Load()
	time.Sleep(4 * application.userRefreshInterval)
	if requests.Load() != requestsAfterStop {
		t.Fatalf("refresh loop continued after stop: before=%d after=%d", requestsAfterStop, requests.Load())
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
