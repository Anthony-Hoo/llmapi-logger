package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	standardlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/observability"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestRewriteCopiesControlledForwardingHeaders(t *testing.T) {
	observed := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed <- request.Header.Clone()
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL)
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	request.Header.Add("X-Real-IP", "192.0.2.10")
	request.Header.Add("X-Forwarded-For", "192.0.2.10")
	request.Header.Add("X-Forwarded-For", "198.51.100.20")
	request.Header.Add("X-Forwarded-Proto", "https")
	request.Header.Add("X-Forwarded-Host", "api.example.com")
	request.Header.Add("X-Forwarded-Port", "443")

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}

	headers := <-observed
	assertHeaderValues(t, headers, "X-Real-IP", []string{"192.0.2.10"})
	assertHeaderValues(t, headers, "X-Forwarded-For", []string{"192.0.2.10", "198.51.100.20"})
	assertHeaderValues(t, headers, "X-Forwarded-Proto", []string{"https"})
	assertHeaderValues(t, headers, "X-Forwarded-Host", []string{"api.example.com"})
	assertHeaderValues(t, headers, "X-Forwarded-Port", []string{"443"})
}

func TestPreserveHostAppliesToAuditedAndPassthrough(t *testing.T) {
	observedHosts := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observedHosts <- request.Host
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	matcher, err := routing.Compile(defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(nil, defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	options := Options{PreserveHost: true}
	handlers := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
	}{
		{name: "audited", handler: NewWithOptions(target, matcher, engine, options, nil), method: http.MethodPost, path: "/v1/chat/completions"},
		{name: "passthrough", handler: NewPassthroughWithOptions(target, options, nil), method: http.MethodGet, path: "/v1/models"},
	}
	for _, test := range handlers {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://audit-proxy"+test.path, http.NoBody)
			request.Host = "api.example.com"
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
			}
			if got := <-observedHosts; got != "api.example.com" {
				t.Fatalf("upstream Host = %q, want preserved public Host", got)
			}
		})
	}
}

func TestTransportUsesOnlyExplicitUpstreamProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://environment-proxy.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://environment-proxy.invalid:8080")
	t.Setenv("NO_PROXY", "")

	target, err := url.Parse("http://newapi.example")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	proxyURL, err := url.Parse("http://proxy.example:7897")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	direct := newTestHandler(t, target.String()).(*handler)
	directTransport, ok := direct.reverseProxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("direct transport type = %T", direct.reverseProxy.Transport)
	}
	if directTransport.Proxy != nil {
		t.Fatal("direct transport unexpectedly uses a proxy function")
	}
	if directTransport.ResponseHeaderTimeout != 5*time.Minute {
		t.Fatalf("default response header timeout = %s, want 5m", directTransport.ResponseHeaderTimeout)
	}

	matcher, err := routing.Compile(defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(nil, defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	proxied := NewWithOptions(target, matcher, engine, Options{UpstreamProxy: proxyURL}, nil).(*handler)
	proxiedTransport, ok := proxied.reverseProxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("proxied transport type = %T", proxied.reverseProxy.Transport)
	}
	if proxiedTransport.Proxy == nil {
		t.Fatal("proxied transport has no proxy function")
	}

	proxyURL.Host = "mutated.example:9999"
	got, err := proxiedTransport.Proxy(httptest.NewRequest(http.MethodPost, target.String()+"/v1/chat/completions", http.NoBody))
	if err != nil {
		t.Fatalf("resolve explicit proxy: %v", err)
	}
	if got.String() != "http://proxy.example:7897" {
		t.Fatalf("proxy URL = %q, want explicit immutable URL", got)
	}
}

func TestConfiguredTransportOptionsAreSharedByAuditedAndPassthrough(t *testing.T) {
	target, err := url.Parse("http://newapi.example")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	matcher, err := routing.Compile(defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(nil, defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	options := Options{ResponseHeaderTimeout: 65 * time.Minute, PreserveHost: true}
	audited := NewWithOptions(target, matcher, engine, options, nil).(*handler)
	passthrough := NewPassthroughWithOptions(target, options, nil).(*passthroughHandler)

	for name, reverseProxy := range map[string]*httputil.ReverseProxy{
		"audited":     audited.reverseProxy,
		"passthrough": passthrough.reverseProxy,
	} {
		transport, ok := reverseProxy.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s transport type = %T", name, reverseProxy.Transport)
		}
		if transport.ResponseHeaderTimeout != 65*time.Minute {
			t.Errorf("%s response header timeout = %s, want 65m", name, transport.ResponseHeaderTimeout)
		}
	}
}

func TestConfiguredResponseHeaderTimeoutReturnsGatewayTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	matcher, err := routing.Compile(defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(nil, defaultTestRoutes())
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	handler := NewWithOptions(target, matcher, engine, Options{ResponseHeaderTimeout: 20 * time.Millisecond}, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))

	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d; body=%q", response.Code, http.StatusGatewayTimeout, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"newapi_timeout"`) {
		t.Fatalf("body = %q, want stable timeout JSON", response.Body.String())
	}
}

func TestCancelledRequestDoesNotReceiveJSONError(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody).WithContext(ctx)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Body.Len() != 0 {
		t.Fatalf("cancelled response body = %q, want empty", response.Body.String())
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func TestCompletionLogContainsOnlySafeAllowlistedRequestFields(t *testing.T) {
	const (
		authorizationCanary = "authorization-canary-1db22b"
		headerCanary        = "header-canary-cfb109"
		bodyCanary          = "body-canary-38ab85"
		queryCanary         = "query-canary-a8d961"
		responseCanary      = "response-canary-a321fd"
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Upstream-Secret", responseCanary)
		_, _ = response.Write([]byte(responseCanary))
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := newTestHandlerWithOptions(t, upstream.URL, nil, logger, nil, defaultTestRoutes())
	request := httptest.NewRequest(
		http.MethodPost,
		"http://audit-proxy/v1/chat/completions?api_key="+queryCanary,
		strings.NewReader(`{"prompt":"`+bodyCanary+`"}`),
	)
	request.Header.Set("Authorization", "Bearer "+authorizationCanary)
	request.Header.Set("X-Api-Key", headerCanary)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	for _, canary := range []string{authorizationCanary, headerCanary, bodyCanary, queryCanary, responseCanary} {
		if strings.Contains(logs.String(), canary) {
			t.Errorf("JSON logs contain sensitive canary %q", canary)
		}
	}

	records := completionLogRecords(t, logs.Bytes())
	if len(records) != 1 {
		t.Fatalf("completion logs = %d, want 1; logs=%s", len(records), logs.String())
	}
	record := records[0]
	assertLogField(t, record, "route_id", "chat")
	assertLogField(t, record, "protocol", "openai")
	assertLogField(t, record, "method", http.MethodPost)
	assertLogField(t, record, "path", "/v1/chat/completions")
	assertLogField(t, record, "status_code", float64(http.StatusOK))
	assertLogField(t, record, "forward_status", sqlite.ForwardCompleted)
	assertLogField(t, record, "capture_status", sqlite.CaptureFailed)
	assertLogField(t, record, "parse_status", sqlite.ParseSkipped)
	for key := range record {
		if !allowedCompletionLogKey(key) {
			t.Errorf("unexpected completion log field %q", key)
		}
	}
}

func TestNonWhitelistedRequestDoesNotEmitCompletionLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	handler := newTestHandlerWithOptions(
		t,
		upstream.URL,
		nil,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		nil,
		defaultTestRoutes(),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://audit-proxy/v1/models?token=do-not-log", http.NoBody))

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if records := completionLogRecords(t, logs.Bytes()); len(records) != 0 {
		t.Fatalf("completion logs = %d, want 0", len(records))
	}
}

func TestCompletionLogUsesFinalAuditSessionSummary(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("close audit store: %v", err)
		}
	}()
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	manager, err := audit.NewManager(store, cipher, nil, audit.ModeAvailable, logger)
	if err != nil {
		t.Fatalf("create audit manager: %v", err)
	}
	handler := newTestHandlerWithOptions(t, upstream.URL, manager, logger, nil, defaultTestRoutes())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	record := singleCompletionLogRecord(t, logs.Bytes())
	auditID, exists := record["audit_id"].(string)
	if !exists || !strings.HasPrefix(auditID, "apx_") {
		t.Errorf("audit_id = %#v, want generated apx_ id", record["audit_id"])
	}
	assertLogField(t, record, "forward_status", sqlite.ForwardCompleted)
	assertLogField(t, record, "capture_status", sqlite.CaptureComplete)
	assertLogField(t, record, "parse_status", sqlite.ParsePending)
}

func TestInterceptorRejectCompletionLogHasTerminalFields(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	routes := defaultTestRoutes()
	routes[0].Interceptors = []string{"credential"}
	definitions := map[string]config.InterceptorConfig{
		"credential": {Type: "require_credential"},
	}
	var logs bytes.Buffer
	handler := newTestHandlerWithOptions(
		t,
		upstream.URL,
		nil,
		slog.New(slog.NewJSONHandler(&logs, nil)),
		definitions,
		routes,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions?private=value", http.NoBody))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response.Body.String() != unauthorizedJSON {
		t.Fatalf("body = %q, want generic unauthorized response", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "credential_required") {
		t.Fatalf("response leaked internal block code: %q", response.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
	records := completionLogRecords(t, logs.Bytes())
	if len(records) != 1 {
		t.Fatalf("completion logs = %d, want 1; logs=%s", len(records), logs.String())
	}
	record := records[0]
	assertLogField(t, record, "status_code", float64(http.StatusUnauthorized))
	assertLogField(t, record, "forward_status", sqlite.ForwardRejected)
	assertLogField(t, record, "capture_status", sqlite.CaptureFailed)
	assertLogField(t, record, "parse_status", sqlite.ParseSkipped)
	assertLogField(t, record, "blocked_by", "credential")
	assertLogField(t, record, "block_code", "credential_required")
	if _, exists := record["error_code"]; exists {
		t.Errorf("error_code = %v, want omitted for an explicit policy reject", record["error_code"])
	}
}

func TestUpstreamErrorAndClientCancellationUseStableCompletionCodes(t *testing.T) {
	t.Run("upstream error", func(t *testing.T) {
		var logs bytes.Buffer
		handler := newTestHandlerWithOptions(
			t,
			"http://127.0.0.1",
			nil,
			slog.New(slog.NewJSONHandler(&logs, nil)),
			nil,
			defaultTestRoutes(),
		).(*handler)
		handler.reverseProxy.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport-secret-that-must-not-be-logged")
		})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))

		if strings.Contains(logs.String(), "transport-secret-that-must-not-be-logged") {
			t.Fatal("logs contain underlying transport error text")
		}
		record := singleCompletionLogRecord(t, logs.Bytes())
		assertLogField(t, record, "status_code", float64(http.StatusBadGateway))
		assertLogField(t, record, "forward_status", sqlite.ForwardNewAPIError)
		assertLogField(t, record, "error_code", "upstream_unavailable")
	})

	t.Run("upstream body read error", func(t *testing.T) {
		const errorCanary = "upstream-body-read-secret-that-must-not-be-logged"
		var logs bytes.Buffer
		var standardLogs bytes.Buffer
		previousOutput := standardlog.Writer()
		standardlog.SetOutput(&standardLogs)
		defer standardlog.SetOutput(previousOutput)

		handler := newTestHandlerWithOptions(
			t,
			"http://127.0.0.1",
			nil,
			slog.New(slog.NewJSONHandler(&logs, nil)),
			nil,
			defaultTestRoutes(),
		).(*handler)
		handler.reverseProxy.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &failingReadCloser{err: errors.New(errorCanary)},
				Request:    request,
			}, nil
		})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))

		if combined := logs.String() + standardLogs.String(); strings.Contains(combined, errorCanary) {
			t.Fatal("logs contain underlying upstream body error text")
		}
		record := singleCompletionLogRecord(t, logs.Bytes())
		assertLogField(t, record, "status_code", float64(http.StatusOK))
		assertLogField(t, record, "forward_status", sqlite.ForwardNewAPIError)
		assertLogField(t, record, "error_code", "upstream_body_read_error")
	})

	t.Run("client cancellation", func(t *testing.T) {
		var logs bytes.Buffer
		handler := newTestHandlerWithOptions(
			t,
			"http://127.0.0.1",
			nil,
			slog.New(slog.NewJSONHandler(&logs, nil)),
			nil,
			defaultTestRoutes(),
		)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody).WithContext(ctx)
		handler.ServeHTTP(httptest.NewRecorder(), request)

		record := singleCompletionLogRecord(t, logs.Bytes())
		assertLogField(t, record, "status_code", float64(clientClosedRequestStatus))
		assertLogField(t, record, "forward_status", sqlite.ForwardClientCancelled)
		assertLogField(t, record, "error_code", "client_cancelled")
		assertLogField(t, record, "ttft_ms", float64(-1))
	})
}

func TestAuditAdmissionModes(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	t.Run("available continues after Begin failure", func(t *testing.T) {
		upstreamCalls.Store(0)
		sink := &failingAuditSink{mode: audit.ModeAvailable}
		handler := newTestHandlerWithAudit(t, upstream.URL, sink)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
		}
		if got := sink.begins.Load(); got != 1 {
			t.Errorf("Begin calls = %d, want 1", got)
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Errorf("upstream calls = %d, want 1", got)
		}
	})

	t.Run("strict unhealthy still calls Begin and rejects on failure", func(t *testing.T) {
		upstreamCalls.Store(0)
		sink := &failingAuditSink{mode: audit.ModeStrict}
		handler := newTestHandlerWithAudit(t, upstream.URL, sink)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
		if got := sink.begins.Load(); got != 1 {
			t.Errorf("Begin calls = %d, want 1", got)
		}
		if got := upstreamCalls.Load(); got != 0 {
			t.Errorf("upstream calls = %d, want 0", got)
		}
	})

	t.Run("strict Begin failure rejects", func(t *testing.T) {
		upstreamCalls.Store(0)
		sink := &failingAuditSink{mode: audit.ModeStrict, healthy: true}
		handler := newTestHandlerWithAudit(t, upstream.URL, sink)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
		if got := sink.begins.Load(); got != 1 {
			t.Errorf("Begin calls = %d, want 1", got)
		}
		if got := upstreamCalls.Load(); got != 0 {
			t.Errorf("upstream calls = %d, want 0", got)
		}
	})
}

func newTestHandler(t *testing.T, upstreamURL string) http.Handler {
	return newTestHandlerWithAudit(t, upstreamURL, nil)
}

func newTestHandlerWithAudit(t *testing.T, upstreamURL string, sink audit.Sink) http.Handler {
	return newTestHandlerWithOptions(
		t,
		upstreamURL,
		sink,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		defaultTestRoutes(),
	)
}

func newTestHandlerWithOptions(
	t *testing.T,
	upstreamURL string,
	sink audit.Sink,
	logger *slog.Logger,
	definitions map[string]config.InterceptorConfig,
	routes []config.RouteConfig,
) http.Handler {
	t.Helper()
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(definitions, routes)
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	target, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return NewWithAudit(target, matcher, engine, sink, logger)
}

func defaultTestRoutes() []config.RouteConfig {
	return []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
}

type failingAuditSink struct {
	mode    string
	healthy bool
	begins  atomic.Int64
}

func (sink *failingAuditSink) Healthy() bool {
	return sink.healthy
}

func (sink *failingAuditSink) Mode() string {
	return sink.mode
}

func (sink *failingAuditSink) Begin(context.Context, *http.Request, routing.Match) (*audit.Session, error) {
	sink.begins.Add(1)
	return nil, errors.New("injected audit Begin failure")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReadCloser struct {
	err error
}

func (reader *failingReadCloser) Read([]byte) (int, error) {
	return 0, reader.err
}

func (reader *failingReadCloser) Close() error {
	return nil
}

func completionLogRecords(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []map[string]any
	for {
		var record map[string]any
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode JSON log: %v\nlogs=%s", err, data)
		}
		if record["msg"] == observability.RequestCompletedMessage {
			records = append(records, record)
		}
	}
	return records
}

func singleCompletionLogRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()
	records := completionLogRecords(t, data)
	if len(records) != 1 {
		t.Fatalf("completion logs = %d, want 1; logs=%s", len(records), data)
	}
	return records[0]
}

func assertLogField(t *testing.T, record map[string]any, name string, expected any) {
	t.Helper()
	if actual, exists := record[name]; !exists || actual != expected {
		t.Errorf("log field %s = %#v, want %#v", name, actual, expected)
	}
}

func allowedCompletionLogKey(key string) bool {
	switch key {
	case "time", "level", "msg", "audit_id", "route_id", "protocol", "method", "path",
		"status_code", "duration_ms", "ttft_ms", "forward_status", "capture_status",
		"parse_status", "blocked_by", "block_code", "error_code":
		return true
	default:
		return false
	}
}

func assertHeaderValues(t *testing.T, header http.Header, name string, expected []string) {
	t.Helper()
	actual := header.Values(name)
	if len(actual) != len(expected) {
		t.Fatalf("%s values = %#v, want %#v", name, actual, expected)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("%s values = %#v, want %#v", name, actual, expected)
		}
	}
}
