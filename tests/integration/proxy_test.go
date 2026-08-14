package integration_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
)

const integrationTimeout = 5 * time.Second

type observedRequest struct {
	method        string
	path          string
	rawPath       string
	rawQuery      string
	forceQuery    bool
	header        http.Header
	body          []byte
	contentLength int64
}

func TestProxyPreservesInboundRequest(t *testing.T) {
	requests := make(chan observedRequest, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requests <- observedRequest{
			method:        request.Method,
			path:          request.URL.Path,
			rawPath:       request.URL.RawPath,
			rawQuery:      request.URL.RawQuery,
			forceQuery:    request.URL.ForceQuery,
			header:        request.Header.Clone(),
			body:          append([]byte(nil), body...),
			contentLength: request.ContentLength,
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("upstream-response"))
	}))
	defer upstream.Close()

	handler := newProxyHandler(t, upstream.URL, "/v1/chat/%63ompletions", false)
	server := httptest.NewServer(handler)
	defer server.Close()

	body := []byte{'{', '"', 'x', '"', ':', 0, 0xff, '}'}
	request, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/v1/chat/%63ompletions?key=first&key=second&empty=",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer integration-secret")
	request.Header.Add("X-Api-Key", "api-key-first")
	request.Header.Add("X-Api-Key", "api-key-second")
	request.Header.Set("X-Goog-Api-Key", "google-key")

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	if string(responseBody) != "upstream-response" {
		t.Fatalf("response body = %q, want upstream response", responseBody)
	}

	observed := receiveRequest(t, requests)
	if observed.method != http.MethodPost {
		t.Errorf("method = %q, want POST", observed.method)
	}
	if observed.path != "/v1/chat/completions" {
		t.Errorf("path = %q, want decoded path", observed.path)
	}
	if observed.rawPath != "/v1/chat/%63ompletions" {
		t.Errorf("raw path = %q, want original escaping", observed.rawPath)
	}
	if observed.rawQuery != "key=first&key=second&empty=" {
		t.Errorf("raw query = %q, want original ordering and duplicates", observed.rawQuery)
	}
	if observed.forceQuery {
		t.Error("force query = true for a request with an explicit raw query")
	}
	if got := observed.header.Get("Authorization"); got != "Bearer integration-secret" {
		t.Errorf("Authorization = %q, want original value", got)
	}
	if got := observed.header.Values("X-Api-Key"); !equalStrings(got, []string{"api-key-first", "api-key-second"}) {
		t.Errorf("X-Api-Key = %#v, want both original values", got)
	}
	if got := observed.header.Get("X-Goog-Api-Key"); got != "google-key" {
		t.Errorf("X-Goog-Api-Key = %q, want original value", got)
	}
	if !bytes.Equal(observed.body, body) {
		t.Errorf("body = %v, want %v", observed.body, body)
	}
	if observed.contentLength != int64(len(body)) {
		t.Errorf("content length = %d, want %d", observed.contentLength, len(body))
	}

	forceQueryRequest, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/v1/chat/%63ompletions",
		http.NoBody,
	)
	if err != nil {
		t.Fatalf("new force-query request: %v", err)
	}
	forceQueryRequest.URL.ForceQuery = true
	forceQueryResponse, err := server.Client().Do(forceQueryRequest)
	if err != nil {
		t.Fatalf("send force-query request: %v", err)
	}
	_, _ = io.Copy(io.Discard, forceQueryResponse.Body)
	forceQueryResponse.Body.Close()
	if forceQueryResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("force-query status = %d, want %d", forceQueryResponse.StatusCode, http.StatusAccepted)
	}

	forceQueryObserved := receiveRequest(t, requests)
	if forceQueryObserved.rawQuery != "" {
		t.Errorf("force-query raw query = %q, want empty", forceQueryObserved.rawQuery)
	}
	if !forceQueryObserved.forceQuery {
		t.Error("force query was not preserved")
	}
	if forceQueryObserved.rawPath != "/v1/chat/%63ompletions" {
		t.Errorf("force-query raw path = %q, want original escaping", forceQueryObserved.rawPath)
	}
}

func TestProxyRejectsNonWhitelistedRouteWithoutCallingUpstream(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := newProxyHandler(t, upstream.URL, "/v1/chat/completions", false)
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/v1/models")
	if err != nil {
		t.Fatalf("send non-whitelisted request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func TestProxyReturnsFixedJSONWhenInterceptorRejects(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler := newProxyHandler(t, upstream.URL, "/v1/chat/completions", true)
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Post(
		server.URL+"/v1/chat/completions?tenant=private",
		"application/json",
		strings.NewReader(`{"prompt":"do not leak this"}`),
	)
	if err != nil {
		t.Fatalf("send rejected request: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read rejected response: %v", err)
	}

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Errorf("parse Content-Type %q: %v", contentType, err)
	} else if mediaType != "application/json" {
		t.Errorf("Content-Type media type = %q, want application/json", mediaType)
	}
	want := []byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`)
	if got := bytes.TrimSuffix(body, []byte("\n")); !bytes.Equal(got, want) {
		t.Errorf("response body = %q, want fixed JSON %q", body, want)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func TestProxyFlushesFirstSSEEventBeforeStreamEnds(t *testing.T) {
	release := make(chan struct{})
	upstreamDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer releaseUpstream()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}

		select {
		case <-release:
		case <-request.Context().Done():
			return
		}

		if _, err := io.WriteString(w, "data: second\n\n"); err != nil {
			return
		}
		_ = http.NewResponseController(w).Flush()
	}))
	defer upstream.Close()

	handler := newProxyHandler(t, upstream.URL, "/v1/chat/completions", false)
	server := httptest.NewServer(handler)
	defer server.Close()

	type responseResult struct {
		response *http.Response
		err      error
	}
	responseResults := make(chan responseResult, 1)
	go func() {
		response, err := server.Client().Post(
			server.URL+"/v1/chat/completions",
			"application/json",
			strings.NewReader(`{"stream":true}`),
		)
		responseResults <- responseResult{response: response, err: err}
	}()

	var response *http.Response
	select {
	case result := <-responseResults:
		if result.err != nil {
			t.Fatalf("open SSE response: %v", result.err)
		}
		response = result.response
	case <-time.After(integrationTimeout):
		t.Fatal("timed out waiting for flushed SSE response headers")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	type eventResult struct {
		event string
		err   error
	}
	firstEvents := make(chan eventResult, 1)
	reader := bufio.NewReader(response.Body)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			firstEvents <- eventResult{err: err}
			return
		}
		blank, err := reader.ReadString('\n')
		firstEvents <- eventResult{event: line + blank, err: err}
	}()

	select {
	case result := <-firstEvents:
		if result.err != nil {
			t.Fatalf("read first SSE event: %v", result.err)
		}
		if result.event != "data: first\n\n" {
			t.Fatalf("first SSE event = %q, want %q", result.event, "data: first\n\n")
		}
	case <-time.After(integrationTimeout):
		t.Fatal("first SSE event did not arrive while the upstream stream remained open")
	}

	select {
	case <-upstreamDone:
		t.Fatal("upstream stream ended before the client received the first event")
	default:
	}

	releaseUpstream()
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read remaining SSE stream: %v", err)
	}
	if string(rest) != "data: second\n\n" {
		t.Errorf("remaining SSE stream = %q, want second event", rest)
	}
}

func newProxyHandler(t *testing.T, upstreamURL, routePath string, requireCredential bool) http.Handler {
	t.Helper()

	cfg := loadConfig(t, upstreamURL, routePath, requireCredential)
	matcher, err := routing.Compile(cfg.Routes)
	if err != nil {
		t.Fatalf("compile routes: %v", err)
	}
	match, ok := matcher.Match(http.MethodPost, routePath)
	if !ok || match.RouteID != "chat" {
		t.Fatalf("compiled matcher did not match configured route %q: match=%+v ok=%v", routePath, match, ok)
	}

	engine, err := interceptor.NewEngine(cfg.Interceptors, cfg.Routes)
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	target, err := url.Parse(cfg.NewAPI.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return proxy.New(target, matcher, engine, logger)
}

func loadConfig(t *testing.T, upstreamURL, routePath string, requireCredential bool) config.Config {
	t.Helper()

	tempDir := t.TempDir()
	interceptorYAML := "interceptors: {}\n"
	routeInterceptorYAML := ""
	if requireCredential {
		interceptorYAML = "interceptors:\n  credential:\n    type: require_credential\n"
		routeInterceptorYAML = "\n    interceptors: [credential]"
	}

	contents := fmt.Sprintf(`listen: 127.0.0.1:18080
admin_listen: 127.0.0.1:18081
newapi:
  url: '%s'
mode: available
db_path: '%s'
key_path: '%s'
admin_token: integration-admin-token
retention_days: 0
%sroutes:
  - id: chat
    method: POST
    path: '%s'
    match: exact
    parser: openai.chat_completions%s
`, yamlQuote(upstreamURL), yamlQuote(filepath.ToSlash(filepath.Join(tempDir, "audit.db"))), yamlQuote(filepath.ToSlash(filepath.Join(tempDir, "audit.key"))), interceptorYAML, yamlQuote(routePath), routeInterceptorYAML)

	path := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v\nconfig:\n%s", err, contents)
	}
	return cfg
}

func receiveRequest(t *testing.T, requests <-chan observedRequest) observedRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(integrationTimeout):
		t.Fatal("timed out waiting for upstream request")
		return observedRequest{}
	}
}

func yamlQuote(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
