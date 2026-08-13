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
	"time"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/uaguard"
)

const testAdminToken = "admin-token-that-must-stay-secret"

func TestManagementEndpointsRequireBearerOnEveryRemoteAddress(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}})
	for _, remote := range []string{"127.0.0.1:1234", "203.0.113.10:5678"} {
		for _, path := range []string{"/healthz", "/readyz", "/metrics", "/api/v1/audits", "/api/v1/newapi/callers", "/api/v1/user-agent-rules", "/api/v1/user-agent-rules/1", "/api/v1/audits/audit-id/raw/request", "/api/v1/unknown"} {
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

func TestNewAPIUserCatalogReturnsOnlySafeMetadata(t *testing.T) {
	t.Parallel()

	refreshedAt := time.Date(2026, time.August, 11, 3, 4, 5, 0, time.UTC)
	handler := newTestHandler(t, Options{
		AdminToken: testAdminToken,
		Query:      &fakeQuery{healthy: true},
		Users: fakeUserCatalog{snapshot: newapi.UserSnapshot{
			Users: []newapi.User{{
				ID: 42, Username: "alice", DisplayName: "Alice", Status: 1, Group: "default",
			}},
			RefreshedAt: refreshedAt,
		}},
	})

	request := authorizedRequest(http.MethodGet, "/api/v1/newapi/callers")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("user catalog status=%d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"id":42`) || !strings.Contains(body, `"username":"alice"`) ||
		!strings.Contains(body, `"display_name":"Alice"`) ||
		!strings.Contains(body, `"refreshed_at":"2026-08-11T03:04:05Z"`) {
		t.Fatalf("user catalog body=%s", body)
	}
	if strings.Contains(body, `"key":`) || strings.Contains(body, `"password":`) || strings.Contains(body, testAdminToken) {
		t.Fatalf("user catalog exposed a sensitive field: %s", body)
	}

	emptyHandler := newTestHandler(t, Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}})
	request = authorizedRequest(http.MethodGet, "/api/v1/newapi/callers")
	response = httptest.NewRecorder()
	emptyHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"items\":[],\"refreshed_at\":null}\n" {
		t.Fatalf("empty user catalog response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedRequest(http.MethodPost, "/api/v1/newapi/callers")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("user catalog POST status=%d", response.Code)
	}
}

func TestUserAgentRuleCRUDRequiresAuthAndRejectsInvalidRegex(t *testing.T) {
	t.Parallel()

	service, err := uaguard.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, Options{
		AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}, Rules: service,
	})

	request := authorizedRequest(http.MethodGet, "/api/v1/user-agent-rules")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"model_pattern":"^gpt"`) || !strings.Contains(response.Body.String(), `"user_agent_pattern":"Codex Desktop"`) {
		t.Fatalf("list response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedJSONRequest(http.MethodPost, "/api/v1/user-agent-rules", `{"name":"other","enabled":true,"model_pattern":"^other","user_agent_pattern":"Approved"}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"name":"other"`) {
		t.Fatalf("create response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedJSONRequest(http.MethodPut, "/api/v1/user-agent-rules/1", `{"name":"updated","enabled":false,"model_pattern":"(?i)^gpt","user_agent_pattern":"Desktop"}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatalf("update response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedJSONRequest(http.MethodPut, "/api/v1/user-agent-rules/1", `{"name":"bad","enabled":true,"model_pattern":"[","user_agent_pattern":"Desktop"}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), `"["`) {
		t.Fatalf("invalid regex response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedRequest(http.MethodDelete, "/api/v1/user-agent-rules/2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete response: status=%d body=%q", response.Code, response.Body.String())
	}
	request = authorizedRequest(http.MethodDelete, "/api/v1/user-agent-rules/2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("second delete response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/user-agent-rules", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "Codex Desktop") {
		t.Fatalf("unauthorized response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestSessionLoginAuthenticatesWithStrictSevenDayCookieAndLogoutClearsIt(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	handlerValue, err := NewHandler(Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*managementHandler)
	handler.authenticator.now = func() time.Time { return fixedNow }

	login := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK || loginResponse.Header().Get("Cache-Control") != "no-store" || strings.Contains(loginResponse.Body.String(), testAdminToken) {
		t.Fatalf("login response: status=%d headers=%v body=%q", loginResponse.Code, loginResponse.Header(), loginResponse.Body.String())
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %v", cookies)
	}
	sessionCookie := cookies[0]
	if sessionCookie.Name != sessionCookieName || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode ||
		sessionCookie.Path != "/" || sessionCookie.MaxAge != int(sessionLifetime/time.Second) || !sessionCookie.Expires.Equal(fixedNow.Add(sessionLifetime)) {
		t.Fatalf("session cookie = %+v", sessionCookie)
	}

	protected := httptest.NewRequest(http.MethodGet, "/api/v1/audits", nil)
	protected.AddCookie(sessionCookie)
	protectedResponse := httptest.NewRecorder()
	handler.ServeHTTP(protectedResponse, protected)
	if protectedResponse.Code != http.StatusOK {
		t.Fatalf("cookie-authenticated list status = %d body=%q", protectedResponse.Code, protectedResponse.Body.String())
	}
	wrongBearer := httptest.NewRequest(http.MethodGet, "/api/v1/audits", nil)
	wrongBearer.AddCookie(sessionCookie)
	wrongBearer.Header.Set("Authorization", "Bearer wrong-token")
	wrongBearerResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongBearerResponse, wrongBearer)
	if wrongBearerResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid explicit bearer fell back to cookie: status=%d", wrongBearerResponse.Code)
	}

	logout := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	logout.AddCookie(sessionCookie)
	logoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusNoContent || logoutResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("logout response: status=%d headers=%v", logoutResponse.Code, logoutResponse.Header())
	}
	cleared := logoutResponse.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != sessionCookieName || cleared[0].MaxAge != -1 || !cleared[0].HttpOnly || cleared[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cleared cookie = %v", cleared)
	}
}

func TestSessionRejectsInvalidLoginAndExpiredOrTamperedCookie(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	handlerValue, err := NewHandler(Options{AdminToken: testAdminToken, Query: &fakeQuery{healthy: true}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerValue.(*managementHandler)
	handler.authenticator.now = func() time.Time { return fixedNow }

	for _, body := range []string{
		`{"token":"wrong-token"}`,
		`{"token":"` + testAdminToken + `","extra":true}`,
		`{"token":"` + testAdminToken + `"}{}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(body))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
			t.Fatalf("invalid login status=%d body=%q", response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), testAdminToken) || len(response.Result().Cookies()) != 0 {
			t.Fatalf("unsafe invalid login response: headers=%v body=%q", response.Header(), response.Body.String())
		}
	}

	values := []string{
		handler.authenticator.sessionValue(fixedNow.Add(-time.Second).Unix()),
		handler.authenticator.sessionValue(fixedNow.Add(sessionLifetime).Unix()) + "tampered",
	}
	for _, value := range values {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid cookie response: status=%d headers=%v", response.Code, response.Header())
		}
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
	request := authorizedRequest(http.MethodGet, "/api/v1/audits?limit=25&protocol=openai&from_ns=9007199254740993&model=gpt-5&user_agent=Codex&newapi_user_id=7&newapi_token_id=42")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"started_at_ns":"9007199254740995"`) || !strings.Contains(body, `"before_started_at_ns":"9007199254740995"`) {
		t.Fatalf("nanosecond fields were not JSON strings: %s", body)
	}
	if queries.gotLimit != 25 || queries.gotFilter.Protocol != "openai" || queries.gotFilter.Model != "gpt-5" || queries.gotFilter.UserAgent != "Codex" ||
		queries.gotFilter.FromNS == nil || *queries.gotFilter.FromNS != 9_007_199_254_740_993 ||
		queries.gotFilter.NewAPIUserID == nil || *queries.gotFilter.NewAPIUserID != 7 ||
		queries.gotFilter.NewAPITokenID == nil || *queries.gotFilter.NewAPITokenID != 42 {
		t.Fatalf("parsed list query = filter %+v limit %d", queries.gotFilter, queries.gotLimit)
	}

	request = authorizedRequest(http.MethodGet, "/api/v1/audits?unknown=value")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "unknown") {
		t.Fatalf("invalid query response: status=%d body=%q", response.Code, response.Body.String())
	}

	request = authorizedRequest(http.MethodGet, "/api/v1/audits?newapi_token_id=not-an-integer")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "not-an-integer") {
		t.Fatalf("invalid token id response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAuditDetailAndRawResponsesNeverExposeInternalErrors(t *testing.T) {
	t.Parallel()

	queries := &fakeQuery{
		healthy: true,
		detail: query.Detail{
			Audit: query.AuditSummary{
				AuditID: "audit-detail", StartedAtNS: 10, RouteID: "route", Protocol: "openai",
				ParserName: "openai.responses", Method: "POST", Path: "/v1/responses", Mode: "available",
				ForwardStatus: "completed", CaptureStatus: "complete", ParseStatus: "pending",
			},
			RequestURI: "/v1/responses?private=query-value",
			Headers: []query.Header{{
				Stage: "request_sent_to_newapi", Kind: "header", Name: "Authorization",
				ValueIndex: 0, ValueLength: 19, Value: "Bearer header-value",
			}},
		},
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
	if !strings.Contains(response.Body.String(), `"request_uri":"/v1/responses?private=query-value"`) ||
		!strings.Contains(response.Body.String(), `"value":"Bearer header-value"`) {
		t.Fatalf("detail omitted decrypted evidence: %s", response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("detail cache policy = %q, want no-store", response.Header().Get("Cache-Control"))
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/audits/audit-detail", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "query-value") || strings.Contains(response.Body.String(), "header-value") {
		t.Fatalf("unauthorized detail leaked evidence: status=%d body=%q", response.Code, response.Body.String())
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
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("raw cache policy = %q, want no-store", response.Header().Get("Cache-Control"))
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

type fakeUserCatalog struct {
	snapshot newapi.UserSnapshot
}

func (catalog fakeUserCatalog) Snapshot() newapi.UserSnapshot { return catalog.snapshot }

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

func authorizedJSONRequest(method, target, body string) *http.Request {
	request := authorizedRequest(method, target)
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
