package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/routing"
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

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}

	headers := <-observed
	assertHeaderValues(t, headers, "X-Real-IP", []string{"192.0.2.10"})
	assertHeaderValues(t, headers, "X-Forwarded-For", []string{"192.0.2.10", "198.51.100.20"})
	assertHeaderValues(t, headers, "X-Forwarded-Proto", []string{"https"})
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

	t.Run("strict unhealthy rejects before Begin", func(t *testing.T) {
		upstreamCalls.Store(0)
		sink := &failingAuditSink{mode: audit.ModeStrict}
		handler := newTestHandlerWithAudit(t, upstream.URL, sink)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
		if got := sink.begins.Load(); got != 0 {
			t.Errorf("Begin calls = %d, want 0", got)
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
	t.Helper()
	routes := []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	engine, err := interceptor.NewEngine(nil, routes)
	if err != nil {
		t.Fatalf("compile interceptor engine: %v", err)
	}
	target, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return NewWithAudit(target, matcher, engine, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
