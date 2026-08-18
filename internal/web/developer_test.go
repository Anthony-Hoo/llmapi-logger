package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/uaguard"
)

const testDeveloperKey = "sk-test-developer-key"

func testFingerprinter(t *testing.T) *security.CredentialFingerprinter {
	t.Helper()
	fingerprints, err := security.NewCredentialFingerprinter(bytes.Repeat([]byte{0x31}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return fingerprints
}

func developerOptions(t *testing.T, identity newapi.TokenIdentity, validateErr error) DeveloperLogin {
	t.Helper()
	return DeveloperLogin{
		Enabled:      true,
		NewAPIURL:    "http://newapi.example.com",
		Fingerprints: testFingerprinter(t),
		ValidateKey: func(context.Context, string, *http.Client, string) (newapi.TokenIdentity, error) {
			return identity, validateErr
		},
	}
}

func newDeveloperHandler(t *testing.T, options Options) *managementHandler {
	t.Helper()
	if options.AdminToken == "" {
		options.AdminToken = testAdminToken
	}
	if options.Query == nil {
		options.Query = &fakeQuery{healthy: true}
	}
	options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handlerValue, err := NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return handlerValue.(*managementHandler)
}

// developerSignIn performs a login and returns the issued cookie.
func developerSignIn(t *testing.T, handler *managementHandler) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"api_key":"`+testDeveloperKey+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("developer login status = %d body = %q", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("developer login cookies = %v", cookies)
	}
	return cookies[0]
}

func TestDeveloperLoginIssuesScopedSessionWithoutLeakingTheKey(t *testing.T) {
	t.Parallel()
	identity := newapi.TokenIdentity{UserID: 7, Username: "developer", TokenID: 42, TokenName: "agent-token", HasIdentity: true}
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, identity, nil)})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"api_key":"`+testDeveloperKey+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, testDeveloperKey) {
		t.Fatal("login response echoed the submitted api key")
	}
	fingerprint := testFingerprinter(t).Fingerprint(testDeveloperKey)
	if strings.Contains(body, string(fingerprint)) || strings.Contains(body, "fpr") {
		t.Fatal("login response exposed the key fingerprint")
	}
	var decoded sessionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Role != roleDeveloper || decoded.Identity == nil ||
		decoded.Identity.Username != "developer" || decoded.Identity.TokenName != "agent-token" ||
		decoded.Identity.TokenID == nil || *decoded.Identity.TokenID != 42 {
		t.Fatalf("login response = %+v", decoded)
	}

	cookie := response.Result().Cookies()[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.MaxAge != int(sessionLifetime/time.Second) {
		t.Fatalf("developer cookie = %+v", cookie)
	}

	// The scope reaching the query layer must be the fingerprint of the key
	// that was actually submitted, plus the token NewAPI reported.
	caller, ok := handler.authenticator.validSession(cookie.Value)
	if !ok || caller.Role != roleDeveloper || caller.Scope == nil {
		t.Fatalf("session did not resolve to a scoped developer: %+v", caller)
	}
	if !bytes.Equal(caller.Scope.Fingerprint, fingerprint) {
		t.Fatal("session scope carries a different fingerprint than the submitted key")
	}
	if caller.Scope.TokenID == nil || *caller.Scope.TokenID != 42 {
		t.Fatalf("session scope token = %v", caller.Scope.TokenID)
	}
}

func TestDeveloperLoginWithoutUsageHistoryScopesByFingerprintOnly(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	cookie := developerSignIn(t, handler)

	caller, ok := handler.authenticator.validSession(cookie.Value)
	if !ok || caller.Scope == nil {
		t.Fatalf("session = %+v", caller)
	}
	// A key NewAPI cannot identify yet must not inherit token id 0, which
	// would match every record NewAPI ever linked to that id.
	if caller.Scope.TokenID != nil {
		t.Fatalf("scope token id = %v, want nil", caller.Scope.TokenID)
	}
}

func TestDeveloperLoginErrorsAreSeparatedByCause(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		options Options
		body    string
		want    int
	}{
		{
			name:    "disabled",
			options: Options{},
			body:    `{"api_key":"` + testDeveloperKey + `"}`,
			want:    http.StatusForbidden,
		},
		{
			name:    "rejected key",
			options: Options{Developer: developerOptions(t, newapi.TokenIdentity{}, newapi.ErrKeyRejected)},
			body:    `{"api_key":"` + testDeveloperKey + `"}`,
			want:    http.StatusUnauthorized,
		},
		{
			name:    "newapi unreachable",
			options: Options{Developer: developerOptions(t, newapi.TokenIdentity{}, newapi.ErrRequestFailed)},
			body:    `{"api_key":"` + testDeveloperKey + `"}`,
			want:    http.StatusBadGateway,
		},
		{
			name:    "both credentials",
			options: Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)},
			body:    `{"token":"` + testAdminToken + `","api_key":"` + testDeveloperKey + `"}`,
			want:    http.StatusBadRequest,
		},
		{
			name:    "neither credential",
			options: Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)},
			body:    `{}`,
			want:    http.StatusBadRequest,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newDeveloperHandler(t, testCase.options)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(testCase.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.want {
				t.Fatalf("status = %d, want %d (body %q)", response.Code, testCase.want, response.Body.String())
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("a failed sign-in issued a session cookie")
			}
		})
	}
}

func TestAdminLoginResponseStaysCompatible(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", response.Code, response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["status"] != "authenticated" || decoded["expires_at"] == "" || decoded["role"] != string(roleAdmin) {
		t.Fatalf("admin login response = %v", decoded)
	}
	if _, exists := decoded["identity"]; exists {
		t.Fatal("administrator response carried a developer identity")
	}
}

func TestDeveloperCookieCannotBeForgedFromTheAdminSessionKey(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	auth := handler.authenticator
	expires := auth.now().Add(sessionLifetime).UTC().Truncate(time.Second)

	payload := developerSessionPayload{Fingerprint: bytes.Repeat([]byte{0x09}, sqlite.APIKeyFingerprintSize)}
	value, err := auth.developerSessionValue(expires.Unix(), payload)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	signed := strings.Join(strings.Split(value, ".")[:3], ".")
	forged := signed + "." + encode(sessionMAC(auth.sessionKey[:], signed))
	if _, ok := auth.validSession(forged); ok {
		t.Fatal("a developer cookie signed with the administrator key was accepted")
	}

	// The reverse must fail too: an administrator cookie signed with the
	// developer key.
	adminPayload := adminSessionVersion + "." + strconv.FormatInt(expires.Unix(), 10)
	forgedAdmin := adminPayload + "." + encode(sessionMAC(auth.developerKey[:], adminPayload))
	if _, ok := auth.validSession(forgedAdmin); ok {
		t.Fatal("an administrator cookie signed with the developer key was accepted")
	}

	// A rewritten scope must not survive the signature either.
	tampered := strings.Split(value, ".")
	rewritten, err := json.Marshal(developerSessionPayload{
		Fingerprint: bytes.Repeat([]byte{0x0a}, sqlite.APIKeyFingerprintSize),
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered[2] = encode(rewritten)
	if _, ok := auth.validSession(strings.Join(tampered, ".")); ok {
		t.Fatal("a developer cookie with a rewritten scope was accepted")
	}
}

func TestDeveloperCookieIsRejectedWhenDeveloperLoginIsDisabled(t *testing.T) {
	t.Parallel()
	issuing := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	cookie := developerSignIn(t, issuing)

	// Turning the feature off must revoke sessions already handed out, not
	// merely hide the login form.
	disabled := newDeveloperHandler(t, Options{})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audits", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	disabled.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestDeveloperSessionIsDeniedAdministratorEndpoints(t *testing.T) {
	t.Parallel()
	rules, err := uaguard.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := newDeveloperHandler(t, Options{
		Developer: developerOptions(t, newapi.TokenIdentity{}, nil),
		Rules:     rules,
		Users:     fakeUserCatalog{},
	})
	cookie := developerSignIn(t, handler)

	adminOnly := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/readyz"},
		{http.MethodGet, "/metrics"},
		{http.MethodGet, "/api/v1/newapi/callers"},
		{http.MethodGet, "/api/v1/user-agent-rules"},
		{http.MethodPost, "/api/v1/user-agent-rules"},
		{http.MethodPut, "/api/v1/user-agent-rules/1"},
		{http.MethodDelete, "/api/v1/user-agent-rules/1"},
	}
	for _, endpoint := range adminOnly {
		request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s status = %d, want 403", endpoint.method, endpoint.path, response.Code)
		}
	}

	// The audit surface stays open to the developer.
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audits", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("audit list status = %d, want 200", response.Code)
	}
}

func TestDeveloperListIsScopedAndRefusesCallerFilters(t *testing.T) {
	t.Parallel()
	queries := &fakeQuery{healthy: true}
	handler := newDeveloperHandler(t, Options{
		Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7, TokenID: 42, HasIdentity: true}, nil),
		Query:     queries,
	})
	cookie := developerSignIn(t, handler)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/audits?model=model-example", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", response.Code, response.Body.String())
	}
	if queries.gotFilter.Scope == nil {
		t.Fatal("developer list reached the query layer without a scope")
	}
	if queries.gotFilter.Model != "model-example" {
		t.Fatalf("ordinary filters were dropped: %+v", queries.gotFilter)
	}

	// Caller filters are refused rather than silently overridden, so a
	// developer never believes they widened or narrowed their own scope.
	for _, key := range callerFilterKeys {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/audits?"+key+"=1", nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s filter status = %d, want 400", key, response.Code)
		}
	}

	// The administrator keeps every caller filter and gets no scope.
	for _, key := range callerFilterKeys {
		adminRequest := authorizedRequest(http.MethodGet, "/api/v1/audits?"+key+"=1")
		adminResponse := httptest.NewRecorder()
		handler.ServeHTTP(adminResponse, adminRequest)
		if adminResponse.Code != http.StatusOK {
			t.Fatalf("administrator %s filter status = %d", key, adminResponse.Code)
		}
	}
	if queries.gotFilter.Scope != nil {
		t.Fatal("administrator list carried a scope")
	}
}

func TestDeveloperAuditResourceFamilyIsAuthorizedOnce(t *testing.T) {
	t.Parallel()
	queries := &fakeQuery{
		healthy:      true,
		authorizeErr: map[string]error{"apx_foreign": query.ErrNotFound},
	}
	handler := newDeveloperHandler(t, Options{
		Developer: developerOptions(t, newapi.TokenIdentity{}, nil),
		Query:     queries,
	})
	cookie := developerSignIn(t, handler)

	paths := []string{
		"/api/v1/audits/apx_foreign",
		"/api/v1/audits/apx_foreign/raw/request",
		"/api/v1/audits/apx_foreign/reconstructed/request",
		"/api/v1/audits/apx_foreign/timeline/response",
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
		if strings.Contains(response.Body.String(), "forbidden") {
			t.Fatalf("%s revealed that the audit exists", path)
		}
	}
	if len(queries.gotAuthorize) != len(paths) {
		t.Fatalf("authorize calls = %v, want one per endpoint", queries.gotAuthorize)
	}

	// The administrator bypasses the gate entirely.
	queries.gotAuthorize = nil
	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, authorizedRequest(http.MethodGet, "/api/v1/audits/apx_foreign"))
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("administrator detail status = %d", adminResponse.Code)
	}
	if len(queries.gotAuthorize) != 0 {
		t.Fatal("administrator request was scope checked")
	}
}

func TestSessionInfoReportsTheCurrentCaller(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{
		Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7, Username: "developer", TokenID: 42, TokenName: "agent-token", HasIdentity: true}, nil),
	})

	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous session status = %d, want 401", anonymous.Code)
	}

	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, authorizedRequest(http.MethodGet, "/api/v1/session"))
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("administrator session status = %d", adminResponse.Code)
	}
	var adminDecoded sessionResponse
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &adminDecoded); err != nil {
		t.Fatal(err)
	}
	if adminDecoded.Role != roleAdmin || adminDecoded.Identity != nil {
		t.Fatalf("administrator session = %+v", adminDecoded)
	}

	cookie := developerSignIn(t, handler)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.AddCookie(cookie)
	developerResponse := httptest.NewRecorder()
	handler.ServeHTTP(developerResponse, request)
	if developerResponse.Code != http.StatusOK {
		t.Fatalf("developer session status = %d", developerResponse.Code)
	}
	var developerDecoded sessionResponse
	if err := json.Unmarshal(developerResponse.Body.Bytes(), &developerDecoded); err != nil {
		t.Fatal(err)
	}
	if developerDecoded.Role != roleDeveloper || developerDecoded.Identity == nil ||
		developerDecoded.Identity.Username != "developer" {
		t.Fatalf("developer session = %+v", developerDecoded)
	}
	if strings.Contains(developerResponse.Body.String(), "fpr") {
		t.Fatal("session info exposed the key fingerprint")
	}
}

func TestLoginRateLimiterThrottlesRepeatedFailures(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, newapi.ErrKeyRejected)})
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	handler.logins.now = func() time.Time { return now }

	attempt := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(body))
		request.RemoteAddr = "203.0.113.10:5678"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	for index := 0; index < loginFailureLimit; index++ {
		if got := attempt(`{"token":"wrong-token"}`).Code; got != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", index, got)
		}
	}
	limited := attempt(`{"token":"wrong-token"}`)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("status after %d failures = %d, want 429", loginFailureLimit, limited.Code)
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Fatal("throttled login did not advertise Retry-After")
	}
	// Even the correct credential is refused while the window is open.
	if got := attempt(`{"token":"` + testAdminToken + `"}`).Code; got != http.StatusTooManyRequests {
		t.Fatalf("throttled correct login status = %d, want 429", got)
	}

	// Another address is unaffected, and the window eventually reopens.
	other := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	other.RemoteAddr = "198.51.100.7:1234"
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, other)
	if otherResponse.Code != http.StatusOK {
		t.Fatalf("unrelated address status = %d, want 200", otherResponse.Code)
	}

	now = now.Add(loginFailureWindow + time.Second)
	if got := attempt(`{"token":"` + testAdminToken + `"}`).Code; got != http.StatusOK {
		t.Fatalf("status after the window expired = %d, want 200", got)
	}
}

func TestSuccessfulLoginClearsTheFailureCounter(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{})

	fail := func() {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"wrong-token"}`))
		request.RemoteAddr = "203.0.113.10:5678"
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	for index := 0; index < loginFailureLimit-1; index++ {
		fail()
	}
	success := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	success.RemoteAddr = "203.0.113.10:5678"
	successResponse := httptest.NewRecorder()
	handler.ServeHTTP(successResponse, success)
	if successResponse.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", successResponse.Code)
	}
	// A user who mistyped a few times before signing in must not stay one
	// failure away from a lockout.
	for index := 0; index < loginFailureLimit; index++ {
		fail()
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"wrong-token"}`))
	request.RemoteAddr = "203.0.113.10:5678"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 only after a fresh run of failures", response.Code)
	}
}

func TestDeveloperLoginRefusesUnusableKeyBeforeContactingNewAPI(t *testing.T) {
	t.Parallel()
	called := false
	options := developerOptions(t, newapi.TokenIdentity{}, nil)
	options.ValidateKey = func(context.Context, string, *http.Client, string) (newapi.TokenIdentity, error) {
		called = true
		return newapi.TokenIdentity{}, nil
	}
	handler := newDeveloperHandler(t, Options{Developer: options})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"api_key":"sk-"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	if called {
		t.Fatal("a key that cannot be fingerprinted was still sent to NewAPI")
	}
}
