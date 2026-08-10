package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/query"
)

const testAdminToken = "admin-token-that-must-stay-secret"

func TestManagementEndpointsRequireBearerOnEveryRemoteAddress(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}})
	for _, remote := range []string{"127.0.0.1:1234", "203.0.113.10:5678"} {
		for _, path := range []string{"/healthz", "/readyz", "/metrics", "/api/v1/audits", "/api/v1/unknown"} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.RemoteAddr = remote
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("%s from %s status = %d, want 401", path, remote, response.Code)
			}
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), testAdminToken) || strings.Contains(response.Body.String(), "wrong-token") {
		t.Fatalf("unsafe unauthorized response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedRequest(http.MethodGet, "/healthz")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("authorized health response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestStaticUIIsAnonymousAndContainsNoManagementData(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}})
	request := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fallback UI status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, testAdminToken) || strings.Contains(body, "audit_id") || strings.Contains(body, "database") {
		t.Fatalf("fallback UI contains protected data: %q", body)
	}

	assets := EmbeddedAssets()
	if assets == nil {
		t.Fatal("EmbeddedAssets returned nil")
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		t.Fatalf("embedded index: %v", err)
	}
	embedded := newTestHandler(t, Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}, Assets: assets})
	response = httptest.NewRecorder()
	embedded.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<div id=\"root\"></div>") {
		t.Fatalf("embedded UI: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuditListUsesSafeIntegerStringsAndParsesFilters(t *testing.T) {
	t.Parallel()

	started := int64(9_007_199_254_740_995)
	ended := started + 1
	queries := &fakeQuery{healthy: true, page: query.Page{
		Items: []query.AuditSummary{{
			AuditID: "audit-list", StartedAtNS: started, EndedAtNS: &ended,
			RouteID: "openai", Protocol: "openai", ParserName: "openai.responses",
			Method: "POST", Path: "/v1/responses", Mode: "available",
			ForwardStatus: "completed", CaptureStatus: "complete", ParseStatus: "ok",
		}},
		NextCursor: &query.Cursor{BeforeStartedAtNS: started, BeforeID: "audit-list"},
	}}
	handler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: queries})
	request := authorizedRequest(http.MethodGet, "/api/v1/audits?limit=25&protocol=openai&from_ns=9007199254740993")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"started_at_ns":"9007199254740995"`) || !strings.Contains(body, `"before_started_at_ns":"9007199254740995"`) {
		t.Fatalf("nanosecond fields were not JSON strings: %s", body)
	}
	if queries.gotLimit != 25 || queries.gotFilter.Protocol != "openai" || queries.gotFilter.FromNS == nil || *queries.gotFilter.FromNS != 9_007_199_254_740_993 {
		t.Fatalf("parsed list query = filter %+v limit %d", queries.gotFilter, queries.gotLimit)
	}

	request = authorizedRequest(http.MethodGet, "/api/v1/audits?unknown=value")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "unknown") {
		t.Fatalf("invalid query response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuditDetailAndRawResponsesNeverExposeInternalErrors(t *testing.T) {
	t.Parallel()

	queries := &fakeQuery{
		healthy: true,
		detail: query.Detail{Audit: query.AuditSummary{
			AuditID: "audit-detail", StartedAtNS: 10, RouteID: "route", Protocol: "openai",
			ParserName: "openai.responses", Method: "POST", Path: "/v1/responses", Mode: "available",
			ForwardStatus: "completed", CaptureStatus: "complete", ParseStatus: "pending",
		}},
		rawMetadata: query.RawMetadata{
			ObservedLength: 12, StoredLength: 12, SHA256: strings.Repeat("a", 64), Complete: true, State: "complete",
		},
		rawData: []byte("raw evidence"),
	}
	handler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: queries})

	request := authorizedRequest(http.MethodGet, "/api/v1/audits/audit-detail")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "ciphertext") || strings.Contains(response.Body.String(), testAdminToken) {
		t.Fatalf("detail response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedRequest(http.MethodGet, "/api/v1/audits/audit-detail/raw/request")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "raw evidence" {
		t.Fatalf("raw response: status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Audit-Complete") != "true" || response.Header().Get("X-Audit-Stored-Length") != "12" || response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("raw headers = %v", response.Header())
	}

	queries.rawData = nil
	queries.rawErr = errors.New("database ciphertext included " + testAdminToken)
	request = authorizedRequest(http.MethodGet, "/api/v1/audits/audit-detail/raw/response")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "ciphertext") || strings.Contains(response.Body.String(), testAdminToken) {
		t.Fatalf("raw error leaked details: status=%d body=%q", response.Code, response.Body.String())
	}

	queries.rawErr = nil
	queries.rawMetaErr = query.ErrNotReady
	request = authorizedRequest(http.MethodGet, "/api/v1/audits/audit-detail/raw/request")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "raw_not_finalized") {
		t.Fatalf("streaming raw response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestReadinessAndHandlerValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewHandler(Options{Query: &fakeQuery{healthy: true}}); err == nil {
		t.Fatal("expected empty token rejection")
	}
	if _, err := NewHandler(Options{AdminToken: "token with spaces", Query: &fakeQuery{healthy: true}}); err == nil {
		t.Fatal("expected whitespace token rejection")
	}
	unavailable := newTestHandler(t, Options{AdminToken: testAdminToken})
	request := authorizedRequest(http.MethodGet, "/api/v1/audits")
	response := httptest.NewRecorder()
	unavailable.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil query list status = %d", response.Code)
	}
	request = authorizedRequest(http.MethodGet, "/readyz")
	response = httptest.NewRecorder()
	unavailable.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"degraded"`) {
		t.Fatalf("nil query readiness: status=%d body=%q", response.Code, response.Body.String())
	}

	handler := newTestHandler(t, Options{
		AdminToken: testAdminToken,
		Query:      &fakeQuery{healthy: true},
		Readiness: func(context.Context) ReadyStatus {
			return ReadyStatus{Status: "not_ready", Database: "unavailable", EncryptionKey: "ok", ParserQueue: 3}
		},
	})
	request = authorizedRequest(http.MethodGet, "/readyz")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d", response.Code)
	}
	var ready ReadyStatus
	if err := json.Unmarshal(response.Body.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if ready.Status != "not_ready" || ready.ParserQueue != 3 {
		t.Fatalf("ready body = %+v", ready)
	}
}

type fakeQuery struct {
	healthy     bool
	page        query.Page
	listErr     error
	detail      query.Detail
	detailErr   error
	rawMetadata query.RawMetadata
	rawMetaErr  error
	rawData     []byte
	rawErr      error

	gotFilter query.Filter
	gotCursor query.Cursor
	gotLimit  int
}

func (queries *fakeQuery) Healthy() bool { return queries.healthy }

func (queries *fakeQuery) List(_ context.Context, filter query.Filter, cursor query.Cursor, limit int) (query.Page, error) {
	queries.gotFilter = filter
	queries.gotCursor = cursor
	queries.gotLimit = limit
	return queries.page, queries.listErr
}

func (queries *fakeQuery) Get(context.Context, string) (query.Detail, error) {
	return queries.detail, queries.detailErr
}

func (queries *fakeQuery) RawMeta(_ context.Context, _ string, side query.Side) (query.RawMetadata, error) {
	if side != query.SideRequest && side != query.SideResponse {
		return query.RawMetadata{}, query.ErrInvalidQuery
	}
	return queries.rawMetadata, queries.rawMetaErr
}

func (queries *fakeQuery) StreamRaw(_ context.Context, _ string, _ query.Side, writer io.Writer) error {
	if len(queries.rawData) != 0 {
		if _, err := writer.Write(queries.rawData); err != nil {
			return err
		}
	}
	return queries.rawErr
}

func newTestHandler(t *testing.T, options Options) http.Handler {
	t.Helper()
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler, err := NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func authorizedRequest(method, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	return request
}
