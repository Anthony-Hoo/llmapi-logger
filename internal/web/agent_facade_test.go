package web

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

var agentTestIdentity = newapi.TokenIdentity{UserID: 7, Username: "developer", TokenID: 42, TokenName: "agent-token", HasIdentity: true}

// agentEnv is a management handler with agent access enabled, its service,
// the in-memory token store and a buffer that receives every log line.
type agentEnv struct {
	handler *managementHandler
	service *agentaccess.Service
	store   *agentaccesstest.Store
	logs    *bytes.Buffer
}

type agentEnvOptions struct {
	allowWrite bool
	// noDeveloper turns developer sign-in off.
	noDeveloper bool
	adminToken  string
	store       *agentaccesstest.Store
}

// newAgentEnv builds an enabled handler. Developer sign-in is on unless
// noDeveloper is set, and the service is told the same.
func newAgentEnv(t *testing.T, options agentEnvOptions) agentEnv {
	t.Helper()
	if options.adminToken == "" {
		options.adminToken = testAdminToken
	}
	if options.store == nil {
		options.store = agentaccesstest.NewStore()
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	service, err := agentaccess.New(agentaccess.Options{
		AdminToken: options.adminToken, Store: options.store, AllowWrite: options.allowWrite,
		DeveloperLogins: !options.noDeveloper, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	handlerOptions := Options{AdminToken: options.adminToken, Query: &fakeQuery{healthy: true}, AgentAccess: service, Logger: logger}
	if !options.noDeveloper {
		handlerOptions.Developer = developerOptions(t, agentTestIdentity, nil)
	}
	handlerValue, err := NewHandler(handlerOptions)
	if err != nil {
		t.Fatal(err)
	}
	return agentEnv{handler: handlerValue.(*managementHandler), service: service, store: options.store, logs: logs}
}

type agentCaller struct {
	cookie *http.Cookie
	bearer string
	// remote overrides the source address.
	remote string
}

func (env agentEnv) do(method, path, body string, caller agentCaller, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if caller.cookie != nil {
		request.AddCookie(caller.cookie)
	}
	if caller.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+caller.bearer)
	}
	if caller.remote != "" {
		request.RemoteAddr = caller.remote + ":40000"
	}
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	return response
}

func decodeAgent(t *testing.T, response *httptest.ResponseRecorder) agentapi.Response {
	t.Helper()
	var decoded agentapi.Response
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("not an envelope: %q", response.Body.String())
	}
	return decoded
}

func agentErrorCode(t *testing.T, response *httptest.ResponseRecorder) agentapi.Code {
	t.Helper()
	decoded := decodeAgent(t, response)
	if decoded.OK || decoded.Error == nil {
		return ""
	}
	if response.Code != agentapi.HTTPStatus(decoded.Error.Code) {
		t.Fatalf("%s answered with status %d", decoded.Error.Code, response.Code)
	}
	return decoded.Error.Code
}

func authorizationBody(tier agentapi.Tier, mode string, decision string) string {
	body := map[string]any{
		"challenge": agentaccesstest.Challenge(agentaccesstest.Verifier), "mode": mode,
		"device_name": "laptop", "cli_version": agentapi.LatestVersion, "tier": tier, "decision": decision,
	}
	if mode == agentaccess.ModeLoopback {
		body["port"] = 49152
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

// authorize posts an approval as caller and returns the decoded response.
func (env agentEnv) authorize(t *testing.T, caller agentCaller, tier agentapi.Tier, mode string) agentAuthorizationResponse {
	t.Helper()
	response := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(tier, mode, "approve"), caller)
	if response.Code != http.StatusOK {
		t.Fatalf("authorization = %d %s", response.Code, response.Body.String())
	}
	var decoded agentAuthorizationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || decoded.Code == "" {
		t.Fatalf("authorization body = %s", response.Body.String())
	}
	return decoded
}

func (env agentEnv) exchange(code, verifier string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	return env.do(http.MethodPost, "/api/agent/v1/token", string(body), agentCaller{remote: "198.51.100.9"})
}

// issueVia runs the whole browser and CLI flow for caller and returns the
// plaintext token.
func (env agentEnv) issueVia(t *testing.T, caller agentCaller, tier agentapi.Tier) string {
	t.Helper()
	authorization := env.authorize(t, caller, tier, agentaccess.ModeLoopback)
	response := env.exchange(authorization.Code, agentaccesstest.Verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("exchange = %d %s", response.Code, response.Body.String())
	}
	var token agentTokenResponse
	if err := json.Unmarshal(decodeAgent(t, response).Data, &token); err != nil || !agentapi.ValidTokenFormat(token.Token) {
		t.Fatalf("token response = %s", response.Body.String())
	}
	return token.Token
}

// Test helpers for later facade work: tokens of each kind.
func issueAgentAdmin(t *testing.T, env agentEnv, tier agentapi.Tier) string {
	t.Helper()
	return env.issueVia(t, agentCaller{bearer: testAdminToken}, tier)
}

func issueAgentDeveloper(t *testing.T, env agentEnv) (string, *http.Cookie) {
	t.Helper()
	cookie := developerSignIn(t, env.handler)
	return env.issueVia(t, agentCaller{cookie: cookie}, agentapi.TierRead), cookie
}

func TestAgentAccessDisabledIsUniform(t *testing.T) {
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, agentTestIdentity, nil)})
	env := agentEnv{handler: handler}
	cookie := developerSignIn(t, handler)
	callers := []agentCaller{
		{}, {bearer: testAdminToken}, {cookie: cookie},
		{bearer: agentapi.TokenPrefix + strings.Repeat("Q", agentapi.TokenEncodedChars)}, {bearer: "wrong"},
	}
	paths := []string{
		"/api/agent/v1/token", "/api/agent/v1/whoami", "/api/agent/v1/logout", "/api/agent/v1/requests",
		"/api/agent/v1/dl/sig/manifest.json", "/api/agent/", "/api/agent/x", "/api/agent/v2/whoami", "/api/agent/v1/",
	}
	var reference *httptest.ResponseRecorder
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			for _, caller := range callers {
				for _, version := range []string{"", "0.0.1"} {
					response := env.do(method, path, `{"code":"x"}`, caller, agentapi.HeaderCLIVersion, version)
					if response.Code != http.StatusNotFound || agentErrorCode(t, response) != agentapi.CodeFeatureDisabled {
						t.Fatalf("%s %s = %d %s", method, path, response.Code, response.Body.String())
					}
					if reference == nil {
						reference = response
						continue
					}
					if !bytes.Equal(response.Body.Bytes(), reference.Body.Bytes()) {
						t.Fatalf("%s %s body differs", method, path)
					}
					for _, name := range []string{"Content-Type", "Cache-Control", "Retry-After", "WWW-Authenticate", agentapi.HeaderLatest, agentapi.HeaderMin} {
						if response.Header().Get(name) != reference.Header().Get(name) {
							t.Fatalf("%s %s header %s = %q", method, path, name, response.Header().Get(name))
						}
					}
				}
			}
		}
	}
	// The web-side family answers exactly what the same caller gets for an
	// unknown sibling path under /api/v1: 404 for an administrator, 403 for a
	// developer, 401 without credentials.
	describe := func(response *httptest.ResponseRecorder) string {
		return strconv.Itoa(response.Code) + " " + response.Header().Get("Content-Type") + " " + response.Header().Get("Cache-Control") + " " +
			response.Header().Get("WWW-Authenticate") + " " + strings.TrimSpace(response.Body.String())
	}
	want := map[string]int{"admin": http.StatusNotFound, "developer": http.StatusForbidden, "none": http.StatusUnauthorized}
	for name, caller := range map[string]agentCaller{"admin": {bearer: testAdminToken}, "developer": {cookie: cookie}, "none": {}} {
		for _, call := range [][2]string{{http.MethodPost, agentAuthorizationsPath}, {http.MethodGet, agentTokensPath}, {http.MethodDelete, agentTokensPath + "/1"},
			{http.MethodGet, agentChangesPath}, {http.MethodPost, agentInstallLinksPath}, {http.MethodGet, "/api/v1/agent-access/other"}, {http.MethodGet, "/api/v1/agent-access"}} {
			body := authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "approve")
			response := env.do(call[0], call[1], body, caller)
			sibling := env.do(call[0], strings.Replace(call[1], "/agent-access", "/agent-accessx", 1), body, caller)
			if response.Code != want[name] || describe(response) != describe(sibling) {
				t.Fatalf("disabled %s %s as %s = %s; sibling = %s", call[0], call[1], name, describe(response), describe(sibling))
			}
		}
	}
	var session map[string]any
	_ = json.Unmarshal(env.do(http.MethodGet, "/api/v1/session", "", agentCaller{cookie: cookie}).Body.Bytes(), &session)
	if session["agent_access_enabled"] != false || session["agent_write_allowed"] != false {
		t.Fatalf("session = %v", session)
	}
	if frame := env.do(http.MethodGet, "/ui/", "", agentCaller{}).Header().Get("X-Frame-Options"); frame != "" {
		t.Fatalf("disabled UI gained X-Frame-Options %q", frame)
	}
}

func TestAgentSessionFlagsAndUIFraming(t *testing.T) {
	for _, allowWrite := range []bool{false, true} {
		env := newAgentEnv(t, agentEnvOptions{allowWrite: allowWrite})
		var session map[string]any
		_ = json.Unmarshal(env.do(http.MethodGet, "/api/v1/session", "", agentCaller{bearer: testAdminToken}).Body.Bytes(), &session)
		if session["agent_access_enabled"] != true || session["agent_write_allowed"] != allowWrite {
			t.Fatalf("allow_write=%v session = %v", allowWrite, session)
		}
		response := env.do(http.MethodGet, "/ui/", "", agentCaller{})
		if response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" {
			t.Fatalf("UI framing headers = %v", response.Header())
		}
	}
}

func TestAgentFlowForAnAdministrator(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
	authorization := env.authorize(t, agentCaller{bearer: testAdminToken}, agentapi.TierWrite, agentaccess.ModeLoopback)
	if authorization.RedirectURI != "http://127.0.0.1:49152/callback" || authorization.ExpiresIn != 60 || authorization.Denied {
		t.Fatalf("authorization = %+v", authorization)
	}
	response := env.exchange(authorization.Code, agentaccesstest.Verifier)
	decoded := decodeAgent(t, response)
	var token agentTokenResponse
	if response.Code != http.StatusOK || !decoded.OK || decoded.Meta != nil || json.Unmarshal(decoded.Data, &token) != nil ||
		token.Role != agentapi.RoleAdmin || token.Tier != agentapi.TierWrite || token.Identity != nil {
		t.Fatalf("exchange = %d %s", response.Code, response.Body.String())
	}
	expires, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil || expires.Sub(time.Now()) < 7*24*time.Hour-time.Minute || expires.Sub(time.Now()) > 7*24*time.Hour {
		t.Fatalf("expires_at = %q", token.ExpiresAt)
	}

	whoami := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token.Token}, agentapi.HeaderCLIVersion, agentapi.LatestVersion, agentapi.HeaderCommand, "whoami")
	if whoami.Code != http.StatusOK || whoami.Header().Get(agentapi.HeaderLatest) != agentapi.LatestVersion ||
		whoami.Header().Get(agentapi.HeaderMin) != agentapi.MinVersion || whoami.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("whoami = %d %v", whoami.Code, whoami.Header())
	}
	decoded = decodeAgent(t, whoami)
	var me agentWhoamiResponse
	if decoded.Meta == nil || !decoded.Meta.Complete || decoded.Meta.State == "" || json.Unmarshal(decoded.Data, &me) != nil ||
		me.Role != agentapi.RoleAdmin || me.Tier != agentapi.TierWrite || me.DeviceName != "laptop" || me.Identity != nil ||
		!me.Features.WriteAllowed || me.Features.Insights || me.ServerTime == "" || me.ExpiresAt != token.ExpiresAt {
		t.Fatalf("whoami body = %s", whoami.Body.String())
	}
	if !strings.Contains(whoami.Body.String(), `"incomplete_reason":""`) {
		t.Fatal("meta lacks incomplete_reason")
	}

	logout := env.do(http.MethodPost, "/api/agent/v1/logout", "", agentCaller{bearer: token.Token})
	if logout.Code != http.StatusOK || !strings.Contains(logout.Body.String(), `"revoked":true`) {
		t.Fatalf("logout = %d %s", logout.Code, logout.Body.String())
	}
	if code := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token.Token})); code != agentapi.CodeTokenRevoked {
		t.Fatalf("whoami after logout = %s", code)
	}
}

func TestAgentFlowForADeveloper(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
	cookie := developerSignIn(t, env.handler)
	// A developer can only ever authorize a read token.
	refused := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierWrite, agentaccess.ModeLoopback, "approve"), agentCaller{cookie: cookie})
	if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), `"field":"tier"`) {
		t.Fatalf("developer write authorization = %d %s", refused.Code, refused.Body.String())
	}
	token := env.issueVia(t, agentCaller{cookie: cookie}, agentapi.TierRead)
	whoami := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token})
	var me agentWhoamiResponse
	if whoami.Code != http.StatusOK || json.Unmarshal(decodeAgent(t, whoami).Data, &me) != nil || me.Role != agentapi.RoleDeveloper ||
		me.Tier != agentapi.TierRead || me.Identity == nil || me.Identity.UserID != 7 || me.Identity.Username != "developer" ||
		me.Identity.TokenID == nil || *me.Identity.TokenID != 42 || me.Identity.TokenName != "agent-token" {
		t.Fatalf("developer whoami = %s", whoami.Body.String())
	}
	// It expires with the web session that authorized it.
	if me.ExpiresAt != cookie.Expires.UTC().Format(time.RFC3339) {
		t.Fatalf("developer token expires %s, session %s", me.ExpiresAt, cookie.Expires.UTC().Format(time.RFC3339))
	}
	// The resolved principal is the same type and scope as the cookie's.
	tokens := env.store.Tokens()
	fingerprint := testFingerprinter(t).Fingerprint(testDeveloperKey)
	if len(tokens) != 1 || !bytes.Equal(tokens[0].ScopeFingerprint, fingerprint) || *tokens[0].ScopeTokenID != 42 {
		t.Fatalf("stored scope = %+v", tokens)
	}
}

// Plan section 12: cookies and the admin token do not open the facade, and an
// agent token does not open /api/v1.
func TestAgentCredentialsAreNotInterchangeable(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
	adminCookie := adminSignIn(t, env.handler)
	developerCookie := developerSignIn(t, env.handler)
	for name, caller := range map[string]agentCaller{
		"admin cookie": {cookie: adminCookie}, "developer cookie": {cookie: developerCookie},
		"admin bearer": {bearer: testAdminToken}, "nothing": {},
	} {
		for _, call := range [][2]string{{http.MethodGet, "/api/agent/v1/whoami"}, {http.MethodPost, "/api/agent/v1/logout"}} {
			if code := agentErrorCode(t, env.do(call[0], call[1], "", caller)); code != agentapi.CodeUnauthenticated {
				t.Fatalf("%s on %s = %s", name, call[1], code)
			}
		}
	}
	adminToken := issueAgentAdmin(t, env, agentapi.TierWrite)
	developerToken, _ := issueAgentDeveloper(t, env)
	// Each wrong bearer counts against the existing management limiter, so
	// every call comes from its own address to see the 401, not a 429.
	address := 0
	for _, token := range []string{adminToken, developerToken} {
		for _, call := range [][2]string{
			{http.MethodGet, "/api/v1/session"}, {http.MethodGet, "/api/v1/audits"}, {http.MethodGet, "/healthz"},
			{http.MethodGet, agentTokensPath}, {http.MethodPost, agentAuthorizationsPath}, {http.MethodGet, "/api/v1/user-agent-rules"},
		} {
			response := env.do(call[0], call[1], authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "approve"), agentCaller{bearer: token, remote: "203.0.113." + strconv.Itoa(100+address)})
			address++
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("agent token on %s %s = %d", call[0], call[1], response.Code)
			}
		}
	}
	// Both tokens still work on the facade.
	for _, token := range []string{adminToken, developerToken} {
		if response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token}); response.Code != http.StatusOK {
			t.Fatalf("token on the facade = %d", response.Code)
		}
	}
}

func adminSignIn(t *testing.T, handler *managementHandler) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatalf("admin login = %d", response.Code)
	}
	return response.Result().Cookies()[0]
}

// probeEndpoints adds one endpoint per access and tier combination, so the
// gates are exercised before any real admin-only or write endpoint exists.
func installProbes(env agentEnv) {
	probes := []agentapi.Endpoint{
		{ID: "probe.any.read", Method: http.MethodGet, Pattern: "/probe/any-read", Access: agentapi.AccessAny, Tier: agentapi.TierRead},
		{ID: "probe.admin.read", Method: http.MethodGet, Pattern: "/probe/admin-read", Access: agentapi.AccessAdmin, Tier: agentapi.TierRead},
		{ID: "probe.any.write", Method: http.MethodPost, Pattern: "/probe/any-write", Access: agentapi.AccessAny, Tier: agentapi.TierWrite},
		{ID: "probe.admin.write", Method: http.MethodPost, Pattern: "/probe/admin-write/{id}", Access: agentapi.AccessAdmin, Tier: agentapi.TierWrite},
	}
	env.handler.agentRegistry = agentapi.NewRegistry(append(append([]agentapi.Endpoint(nil), agentapi.Endpoints...), probes...))
	for _, probe := range probes {
		env.handler.agentHandlerTable[probe.ID] = func(writer http.ResponseWriter, request *http.Request, call agentCall) {
			caller, ok := principalFrom(request.Context())
			if !ok || caller.AgentTokenID != call.Identity.TokenID || caller.Tier != call.Identity.Tier {
				writeAgentError(writer, agentapi.CodeInternal, nil)
				return
			}
			writeAgentOK(writer, agentapi.Success(map[string]any{"id": call.Params["id"], "scoped": caller.Scope != nil}))
		}
	}
}

// Plan section 12: every endpoint that exists so far, plus one probe per
// access and tier, against every kind of token and the write switch.
func TestAgentRejectionMatrix(t *testing.T) {
	type cell struct {
		method, path string
	}
	cells := []cell{
		{http.MethodGet, "/api/agent/v1/whoami"},
		{http.MethodGet, "/api/agent/v1/probe/any-read"},
		{http.MethodGet, "/api/agent/v1/probe/admin-read"},
		{http.MethodPost, "/api/agent/v1/probe/any-write"},
		{http.MethodPost, "/api/agent/v1/probe/admin-write/12"},
		{http.MethodPost, "/api/agent/v1/logout"},
	}
	const ok = agentapi.Code("")
	for _, allowWrite := range []bool{false, true} {
		writeOK := ok
		if !allowWrite {
			writeOK = agentapi.CodeWriteDisabled
		}
		expected := map[string][]agentapi.Code{
			//               whoami  any-read admin-read                  any-write                     admin-write                   logout
			"admin read":  {ok, ok, ok, agentapi.CodeReadOnlyToken, agentapi.CodeReadOnlyToken, ok},
			"admin write": {ok, ok, ok, writeOK, writeOK, ok},
			"developer":   {ok, ok, agentapi.CodeForbiddenRole, agentapi.CodeReadOnlyToken, agentapi.CodeForbiddenRole, ok},
			"none":        {agentapi.CodeUnauthenticated, agentapi.CodeUnauthenticated, agentapi.CodeUnauthenticated, agentapi.CodeUnauthenticated, agentapi.CodeUnauthenticated, agentapi.CodeUnauthenticated},
			"revoked":     {agentapi.CodeTokenRevoked, agentapi.CodeTokenRevoked, agentapi.CodeTokenRevoked, agentapi.CodeTokenRevoked, agentapi.CodeTokenRevoked, agentapi.CodeTokenRevoked},
			"expired":     {agentapi.CodeTokenExpired, agentapi.CodeTokenExpired, agentapi.CodeTokenExpired, agentapi.CodeTokenExpired, agentapi.CodeTokenExpired, agentapi.CodeTokenExpired},
		}
		for kind, want := range expected {
			for index, target := range cells {
				// A fresh environment per cell: logout revokes the token.
				env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
				if !allowWrite {
					env = newAgentEnv(t, agentEnvOptions{allowWrite: false})
				}
				installProbes(env)
				var token string
				switch kind {
				case "admin read":
					token = issueAgentAdmin(t, env, agentapi.TierRead)
				case "admin write":
					if allowWrite {
						token = issueAgentAdmin(t, env, agentapi.TierWrite)
					} else {
						// The page cannot issue one now; a token issued while
						// writes were allowed is still refused at the gate.
						issued := agentaccesstest.IssueAdmin(t, mustService(t, env, true), agentapi.TierWrite)
						token = issued.Token
					}
				case "developer":
					token, _ = issueAgentDeveloper(t, env)
				case "revoked":
					token = issueAgentAdmin(t, env, agentapi.TierRead)
					env.do(http.MethodPost, "/api/agent/v1/logout", "", agentCaller{bearer: token})
				case "expired":
					token = issueAgentAdmin(t, env, agentapi.TierRead)
					past := time.Now().Add(-time.Minute).UnixNano()
					env.store.Mutate(env.store.Tokens()[0].ID, func(row *storage.AgentToken) { row.ExpiresAtNS = past })
				}
				response := env.do(target.method, target.path, "", agentCaller{bearer: token})
				got := agentErrorCode(t, response)
				if got != want[index] {
					t.Errorf("allow_write=%v %s %s %s = %s (%d), want %q", allowWrite, kind, target.method, target.path, got, response.Code, want[index])
				}
				if got == ok && response.Code != http.StatusOK {
					t.Errorf("%s %s status %d", kind, target.path, response.Code)
				}
			}
		}
	}
}

// mustService returns a service sharing env's store and admin token, with its
// own write switch; tokens it issues are valid for env.
func mustService(t *testing.T, env agentEnv, allowWrite bool) *agentaccess.Service {
	t.Helper()
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: env.store, AllowWrite: allowWrite, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestAgentDispatchOrder(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	token := issueAgentAdmin(t, env, agentapi.TierRead)
	// Unregistered paths and wrong methods are NOT_FOUND, before
	// authentication.
	for _, call := range [][2]string{
		{http.MethodGet, "/api/agent/v1/nothing"}, {http.MethodPost, "/api/agent/v1/requests"}, {http.MethodGet, "/api/agent/v1/"}, {http.MethodGet, "/api/agent/v2/whoami"},
		{http.MethodGet, "/api/agent/x"}, {http.MethodPost, "/api/agent/v1/whoami"}, {http.MethodGet, "/api/agent/v1/token"},
		{http.MethodGet, "/api/agent/v1/whoami/"}, {http.MethodGet, "/api/agent/v1/../v1/audits"},
	} {
		for _, caller := range []agentCaller{{}, {bearer: token}} {
			if code := agentErrorCode(t, env.do(call[0], call[1], "", caller)); code != agentapi.CodeNotFound {
				t.Fatalf("%s %s = %s", call[0], call[1], code)
			}
		}
	}
	// The client version is checked before routing and authentication.
	for _, version := range []string{"0.0.1", "not-a-version"} {
		response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token}, agentapi.HeaderCLIVersion, version)
		if code := agentErrorCode(t, response); code != agentapi.CodeClientTooOld || response.Code != http.StatusUpgradeRequired ||
			response.Header().Get(agentapi.HeaderMin) != agentapi.MinVersion {
			t.Fatalf("version %q = %s", version, code)
		}
		if code := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/nothing", "", agentCaller{}, agentapi.HeaderCLIVersion, version)); code != agentapi.CodeClientTooOld {
			t.Fatalf("version %q on an unknown path = %s", version, code)
		}
	}
	// The token exchange rejects a malformed body as an argument error.
	for _, body := range []string{"", "{", `{"code":"a","code_verifier":"b","extra":1}`, `{"code":"a"} {}`} {
		if code := agentErrorCode(t, env.do(http.MethodPost, "/api/agent/v1/token", body, agentCaller{})); code != agentapi.CodeInvalidArgument {
			t.Fatalf("token body %q = %s", body, code)
		}
	}
	if code := agentErrorCode(t, env.do(http.MethodPost, "/api/agent/v1/token", `{"code":"x","code_verifier":"y"}`, agentCaller{})); code != agentapi.CodeInvalidGrant {
		t.Fatalf("bad grant = %s", code)
	}
	if registered := len(agentapi.Endpoints); registered != len(env.handler.agentHandlers()) {
		t.Fatalf("registry %d, handlers %d", registered, len(env.handler.agentHandlers()))
	}
	if err := bindAgentHandlers(agentapi.NewRegistry(agentapi.Endpoints), map[string]agentHandler{"whoami": env.handler.serveAgentWhoami}); err == nil {
		t.Fatal("a registry without handlers was accepted")
	}
}

// Scope == nil means "reads everything": a developer token whose scope cannot
// be restored is refused, and so is any identity the conversion cannot map.
func TestIncompleteDeveloperScopeIsRejected(t *testing.T) {
	for name, mutate := range map[string]func(*storage.AgentToken){
		"no fingerprint":    func(row *storage.AgentToken) { row.ScopeFingerprint = nil },
		"short fingerprint": func(row *storage.AgentToken) { row.ScopeFingerprint = row.ScopeFingerprint[:31] },
		"negative token id": func(row *storage.AgentToken) { id := int64(-5); row.ScopeTokenID = &id },
		"write tier":        func(row *storage.AgentToken) { row.Tier = "write" },
		"claims admin":      func(row *storage.AgentToken) { row.Role = "admin" },
		"unknown role":      func(row *storage.AgentToken) { row.Role = "" },
	} {
		t.Run(name, func(t *testing.T) {
			env := newAgentEnv(t, agentEnvOptions{})
			installProbes(env)
			token, _ := issueAgentDeveloper(t, env)
			env.store.Mutate(env.store.Tokens()[0].ID, mutate)
			for _, path := range []string{"/api/agent/v1/whoami", "/api/agent/v1/probe/any-read", "/api/agent/v1/probe/admin-read"} {
				if code := agentErrorCode(t, env.do(http.MethodGet, path, "", agentCaller{bearer: token})); code != agentapi.CodeUnauthenticated {
					t.Fatalf("%s = %s", path, code)
				}
			}
		})
	}
	scope := agentaccesstest.DeveloperScope(1, 1)
	for name, identity := range map[string]agentaccess.Identity{
		"developer without scope": {TokenID: 1, Role: agentapi.RoleDeveloper, Tier: agentapi.TierRead},
		"developer short scope":   {TokenID: 1, Role: agentapi.RoleDeveloper, Tier: agentapi.TierRead, Scope: &agentaccess.Scope{Fingerprint: []byte{1}}},
		"developer write":         {TokenID: 1, Role: agentapi.RoleDeveloper, Tier: agentapi.TierWrite, Scope: scope},
		"admin with scope":        {TokenID: 1, Role: agentapi.RoleAdmin, Tier: agentapi.TierRead, Scope: scope},
		"no role":                 {TokenID: 1, Tier: agentapi.TierRead},
		"no token id":             {Role: agentapi.RoleAdmin, Tier: agentapi.TierRead},
		"no tier":                 {TokenID: 1, Role: agentapi.RoleAdmin},
	} {
		if caller, ok := agentPrincipal(identity); ok {
			t.Errorf("%s mapped to %+v", name, caller)
		}
	}
	caller, ok := agentPrincipal(agentaccess.Identity{TokenID: 3, Role: agentapi.RoleDeveloper, Tier: agentapi.TierRead, Scope: scope})
	if !ok || caller.Role != roleDeveloper || caller.Scope == nil || !bytes.Equal(caller.Scope.Fingerprint, scope.Fingerprint) ||
		caller.AgentTokenID != 3 || caller.Tier != agentapi.TierRead || caller.Identity.Username != "developer" {
		t.Fatalf("developer principal = %+v", caller)
	}
	admin, ok := agentPrincipal(agentaccess.Identity{TokenID: 4, Role: agentapi.RoleAdmin, Tier: agentapi.TierWrite})
	if !ok || admin.Role != roleAdmin || admin.Scope != nil || admin.Tier != agentapi.TierWrite {
		t.Fatalf("admin principal = %+v", admin)
	}
	var _ *query.Scope = caller.Scope
}

func TestRotatingTheAdminTokenInvalidatesAgentTokens(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	token := issueAgentAdmin(t, env, agentapi.TierRead)
	rotated := newAgentEnv(t, agentEnvOptions{store: env.store, adminToken: testAdminToken + "-rotated"})
	if code := agentErrorCode(t, rotated.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token})); code != agentapi.CodeUnauthenticated {
		t.Fatalf("after rotation = %s", code)
	}
	restarted := newAgentEnv(t, agentEnvOptions{store: env.store})
	if response := restarted.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token}); response.Code != http.StatusOK {
		t.Fatalf("after a restart with the same admin token = %d", response.Code)
	}
}

func TestDisablingDeveloperLoginInvalidatesDeveloperAgentTokens(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	developerToken, _ := issueAgentDeveloper(t, env)
	adminToken := issueAgentAdmin(t, env, agentapi.TierRead)
	off := newAgentEnv(t, agentEnvOptions{store: env.store, noDeveloper: true})
	response := off.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: developerToken})
	if code := agentErrorCode(t, response); code != agentapi.CodeRoleUnavailable || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("developer token with developer login off = %s", code)
	}
	if response := off.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: adminToken}); response.Code != http.StatusOK {
		t.Fatalf("admin token with developer login off = %d", response.Code)
	}
}

func TestAgentAuthorizationEndpoint(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: false})
	admin := agentCaller{bearer: testAdminToken}

	// Paste mode: no redirect_uri, five minutes.
	paste := env.authorize(t, admin, agentapi.TierRead, agentaccess.ModePaste)
	if paste.RedirectURI != "" || paste.ExpiresIn != 300 {
		t.Fatalf("paste = %+v", paste)
	}
	raw := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModePaste, "approve"), admin).Body.String()
	if strings.Contains(raw, "redirect_uri") || strings.Contains(raw, "denied") {
		t.Fatalf("paste body = %s", raw)
	}
	// Deny: loopback callback without a query, paste without one at all.
	denied := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "deny"), admin)
	if denied.Code != http.StatusOK || strings.TrimSpace(denied.Body.String()) != `{"denied":true,"redirect_uri":"http://127.0.0.1:49152/callback"}` {
		t.Fatalf("deny = %d %s", denied.Code, denied.Body.String())
	}
	deniedPaste := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModePaste, "deny"), admin)
	if strings.TrimSpace(deniedPaste.Body.String()) != `{"denied":true}` {
		t.Fatalf("paste deny = %s", deniedPaste.Body.String())
	}
	// Empty display values are accepted and replaced.
	empty := `{"challenge":"` + agentaccesstest.Challenge(agentaccesstest.Verifier) + `","mode":"paste","device_name":"","cli_version":"","tier":"read","decision":"approve"}`
	response := env.do(http.MethodPost, agentAuthorizationsPath, empty, admin)
	var approved agentAuthorizationResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &approved) != nil {
		t.Fatalf("empty display values = %d %s", response.Code, response.Body.String())
	}
	exchanged := env.exchange(approved.Code, agentaccesstest.Verifier)
	if exchanged.Code != http.StatusOK || env.store.Tokens()[0].DeviceName != agentaccess.PlaceholderDeviceName {
		t.Fatalf("placeholder exchange = %d %+v", exchanged.Code, env.store.Tokens())
	}

	bad := func(body, field string) {
		t.Helper()
		response := env.do(http.MethodPost, agentAuthorizationsPath, body, admin)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"field":"`+field+`"`) {
			t.Fatalf("%s = %d %s", body, response.Code, response.Body.String())
		}
	}
	base := map[string]any{
		"challenge": agentaccesstest.Challenge(agentaccesstest.Verifier), "mode": "loopback", "port": 49152,
		"device_name": "d", "cli_version": "0.1.0", "tier": "read", "decision": "approve",
	}
	with := func(key string, value any) string {
		copied := map[string]any{}
		for k, v := range base {
			copied[k] = v
		}
		if value == nil {
			delete(copied, key)
		} else {
			copied[key] = value
		}
		encoded, _ := json.Marshal(copied)
		return string(encoded)
	}
	bad(with("port", 80), "port")
	bad(with("port", 0), "port")
	bad(with("port", 65536), "port")
	bad(with("port", nil), "port")
	bad(with("port", "49152"), "body")
	bad(with("port", 49152.5), "body")
	bad(with("mode", "localhost"), "mode")
	bad(with("tier", "write"), "tier") // allow_write is off
	bad(with("tier", "owner"), "tier")
	bad(with("decision", "maybe"), "decision")
	bad(with("challenge", "plain"), "challenge")
	bad(with("extra", true), "body")
	bad(with("state", "s"), "body")
	// Wrong methods and unknown paths.
	for _, call := range [][2]string{{http.MethodGet, agentAuthorizationsPath}, {http.MethodPost, agentTokensPath}, {http.MethodGet, agentTokensPath + "/1"}} {
		if response := env.do(call[0], call[1], "", admin); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d", call[0], call[1], response.Code)
		}
	}
	if response := env.do(http.MethodGet, "/api/v1/agent-access/nothing", "", admin); response.Code != http.StatusNotFound {
		t.Fatalf("unknown agent-access path = %d", response.Code)
	}
}

// Behind one proxy address a developer session neither uses up the
// administrator's authorization allowance nor fills the code store
// (contract section 7: per approving identity).
func TestAgentAuthorizationLimitsFollowTheSession(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	developer := developerSignIn(t, env.handler)
	const proxy = "10.0.0.1"
	for index := 0; index < 20; index++ {
		env.do(http.MethodPost, agentAuthorizationsPath, `{"challenge":"x","mode":"x","device_name":"","cli_version":"","tier":"read","decision":"deny"}`,
			agentCaller{cookie: developer, remote: proxy})
	}
	limited := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModePaste, "approve"), agentCaller{cookie: developer, remote: proxy})
	if limited.Code != http.StatusTooManyRequests || strings.Contains(limited.Body.String(), "address") {
		t.Fatalf("developer after 20 requests = %d %s", limited.Code, limited.Body.String())
	}
	if response := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "approve"), agentCaller{bearer: testAdminToken, remote: proxy}); response.Code != http.StatusOK {
		t.Fatalf("administrator from the same address = %d %s", response.Code, response.Body.String())
	}

	env = newAgentEnv(t, agentEnvOptions{})
	developer = developerSignIn(t, env.handler)
	approved := 0
	for address := 0; address < 4; address++ {
		for index := 0; index < 5; index++ {
			response := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModePaste, "approve"),
				agentCaller{cookie: developer, remote: "2001:db8::" + strconv.Itoa(address)})
			if response.Code == http.StatusOK {
				approved++
			}
		}
	}
	if approved != 8 {
		t.Fatalf("open codes of one developer = %d, want 8", approved)
	}
	if response := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "approve"), agentCaller{bearer: testAdminToken, remote: "192.0.2.10"}); response.Code != http.StatusOK {
		t.Fatalf("administrator after a developer's codes = %d %s", response.Code, response.Body.String())
	}
}

// Contract section 3.1 through the HTTP surface: replay, expiry, verifier
// mismatch.
func TestAgentCodeExchangeThroughTheFacade(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	admin := agentCaller{bearer: testAdminToken}

	first := env.authorize(t, admin, agentapi.TierRead, agentaccess.ModeLoopback)
	response := env.exchange(first.Code, agentaccesstest.Verifier)
	var token agentTokenResponse
	_ = json.Unmarshal(decodeAgent(t, response).Data, &token)
	if code := agentErrorCode(t, env.exchange(first.Code, agentaccesstest.Verifier)); code != agentapi.CodeInvalidGrant {
		t.Fatalf("replay = %s", code)
	}
	if code := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token.Token})); code != agentapi.CodeTokenRevoked {
		t.Fatalf("token after replay = %s", code)
	}

	mismatch := env.authorize(t, admin, agentapi.TierRead, agentaccess.ModeLoopback)
	if code := agentErrorCode(t, env.exchange(mismatch.Code, agentaccesstest.Verifier+"x")); code != agentapi.CodeInvalidGrant {
		t.Fatalf("verifier mismatch = %s", code)
	}
	if code := agentErrorCode(t, env.exchange(mismatch.Code, agentaccesstest.Verifier)); code != agentapi.CodeInvalidGrant {
		t.Fatalf("code after a mismatch = %s", code)
	}
}

func TestAgentTokenListAndRevokeOverTheWeb(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
	admin := agentCaller{bearer: testAdminToken}
	adminToken := issueAgentAdmin(t, env, agentapi.TierWrite)
	developerToken, cookie := issueAgentDeveloper(t, env)
	// A token of another developer key: issued straight through the service.
	other := agentaccesstest.IssueDeveloper(t, env.service, agentaccesstest.DeveloperScope(0x77, 42), time.Now().Add(time.Hour))
	developer := agentCaller{cookie: cookie}

	list := func(caller agentCaller) []agentTokenItem {
		t.Helper()
		response := env.do(http.MethodGet, agentTokensPath, "", caller)
		var body struct {
			Items []agentTokenItem `json:"items"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatalf("list = %d %s", response.Code, response.Body.String())
		}
		return body.Items
	}
	all := list(admin)
	if len(all) != 3 || all[0].ID != other.Identity.TokenID {
		t.Fatalf("admin list = %+v", all)
	}
	mine := list(developer)
	if len(mine) != 1 || mine[0].Role != "developer" || mine[0].DeviceName != "laptop" || mine[0].Tier != "read" ||
		mine[0].LastUsedAt != nil || mine[0].RevokedAt != nil || mine[0].DisplayPrefix != developerToken[:8] {
		t.Fatalf("developer list = %+v", mine)
	}
	raw := env.do(http.MethodGet, agentTokensPath, "", developer).Body.String()
	if !strings.Contains(raw, `"last_used_at":null`) || !strings.Contains(raw, `"revoked_at":null`) {
		t.Fatalf("unset times are not null: %s", raw)
	}
	if _, err := time.Parse(time.RFC3339, mine[0].CreatedAt); err != nil {
		t.Fatalf("created_at = %q", mine[0].CreatedAt)
	}

	// A developer cannot revoke what it cannot see; the answer is still 204.
	for _, id := range []int64{all[2].ID, other.Identity.TokenID, 999} {
		if response := env.do(http.MethodDelete, agentTokensPath+"/"+strconv.FormatInt(id, 10), "", developer); response.Code != http.StatusNoContent {
			t.Fatalf("developer revoke %d = %d", id, response.Code)
		}
	}
	for _, token := range []string{adminToken, other.Token} {
		if response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token}); response.Code != http.StatusOK {
			t.Fatalf("a developer revoked an invisible token: %d", response.Code)
		}
	}
	for _, id := range []string{"abc", "0", "-1", "1x", "99999999999999999999"} {
		if response := env.do(http.MethodDelete, agentTokensPath+"/"+id, "", developer); response.Code != http.StatusBadRequest {
			t.Fatalf("revoke id %q = %d", id, response.Code)
		}
	}
	for range 2 {
		if response := env.do(http.MethodDelete, agentTokensPath+"/"+strconv.FormatInt(mine[0].ID, 10), "", developer); response.Code != http.StatusNoContent {
			t.Fatalf("own revoke = %d", response.Code)
		}
	}
	if code := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: developerToken})); code != agentapi.CodeTokenRevoked {
		t.Fatalf("own token after revoke = %s", code)
	}
	if revoked := list(developer); len(revoked) != 1 || revoked[0].RevokedAt == nil {
		t.Fatalf("revoked tokens stay listed with their state: %+v", revoked)
	}
	if response := env.do(http.MethodDelete, agentTokensPath+"/"+strconv.FormatInt(other.Identity.TokenID, 10), "", admin); response.Code != http.StatusNoContent {
		t.Fatalf("admin revoke = %d", response.Code)
	}
	if code := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: other.Token})); code != agentapi.CodeTokenRevoked {
		t.Fatalf("token after admin revoke = %s", code)
	}
}

// Contract section 7: the facade has its own failed-lookup counter. Only
// well-formed unknown tokens count, and once over the limit the address is
// refused for valid tokens too.
func TestAgentLookupLimiterOnTheFacade(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	token := issueAgentAdmin(t, env, agentapi.TierRead)
	unknown := agentapi.TokenPrefix + strings.Repeat("Z", agentapi.TokenEncodedChars)
	attacker := "203.0.113.5"
	for range 20 {
		env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: "malformed", remote: attacker})
	}
	if response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token, remote: attacker}); response.Code != http.StatusOK {
		t.Fatalf("malformed tokens counted: %d", response.Code)
	}
	for range 10 {
		env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: unknown, remote: attacker})
	}
	response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token, remote: attacker})
	if code := agentErrorCode(t, response); code != agentapi.CodeRateLimited || response.Header().Get("Retry-After") == "" {
		t.Fatalf("limited address = %s %v", code, response.Header())
	}
	if response := env.do(http.MethodGet, "/api/agent/v1/whoami", "", agentCaller{bearer: token, remote: "198.51.100.5"}); response.Code != http.StatusOK {
		t.Fatalf("other address = %d", response.Code)
	}
	// The web sign-in and bearer limiters are separate counters.
	if response := env.do(http.MethodGet, "/api/v1/session", "", agentCaller{bearer: testAdminToken, remote: attacker}); response.Code != http.StatusOK {
		t.Fatalf("admin bearer from the limited address = %d", response.Code)
	}
}

// Plan section 12: no response, log line or audit row carries a token, an
// authorization code or a key fingerprint, apart from the one response that
// hands each out.
func TestNoAgentSecretLeaks(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{allowWrite: true})
	installProbes(env)
	cookie := developerSignIn(t, env.handler)
	developer := agentCaller{cookie: cookie}
	var responses []string
	record := func(response *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		var headers strings.Builder
		_ = response.Header().Write(&headers)
		responses = append(responses, headers.String()+response.Body.String())
		return response
	}

	authorizationResponse := env.do(http.MethodPost, agentAuthorizationsPath, authorizationBody(agentapi.TierRead, agentaccess.ModeLoopback, "approve"), developer)
	var authorization agentAuthorizationResponse
	_ = json.Unmarshal(authorizationResponse.Body.Bytes(), &authorization)
	tokenResponse := env.exchange(authorization.Code, agentaccesstest.Verifier)
	var token agentTokenResponse
	_ = json.Unmarshal(decodeAgent(t, tokenResponse).Data, &token)
	if token.Token == "" {
		t.Fatalf("exchange = %s", tokenResponse.Body.String())
	}
	bearer := agentCaller{bearer: token.Token}
	record(env.exchange(authorization.Code, agentaccesstest.Verifier))
	second := env.authorize(t, agentCaller{bearer: testAdminToken}, agentapi.TierWrite, agentaccess.ModePaste)
	secondToken := env.exchange(second.Code, agentaccesstest.Verifier)
	var adminToken agentTokenResponse
	_ = json.Unmarshal(decodeAgent(t, secondToken).Data, &adminToken)
	for _, call := range [][2]string{
		{http.MethodGet, "/api/agent/v1/whoami"}, {http.MethodGet, "/api/agent/v1/probe/any-read"},
		{http.MethodGet, "/api/agent/v1/probe/admin-read"}, {http.MethodPost, "/api/agent/v1/probe/any-write"},
	} {
		record(env.do(call[0], call[1], "", bearer, agentapi.HeaderCommand, "probe"))
		record(env.do(call[0], call[1], "", agentCaller{bearer: adminToken.Token}))
	}
	record(env.do(http.MethodGet, agentTokensPath, "", developer))
	record(env.do(http.MethodGet, agentTokensPath, "", agentCaller{bearer: testAdminToken}))
	record(env.do(http.MethodGet, "/api/v1/session", "", developer))
	record(env.do(http.MethodPost, "/api/agent/v1/logout", "", bearer))
	record(env.do(http.MethodGet, "/api/agent/v1/whoami", "", bearer))

	fingerprint := testFingerprinter(t).Fingerprint(testDeveloperKey)
	secrets := map[string]string{
		"token": token.Token, "token body": token.Token[8:], "admin agent token": adminToken.Token,
		"code": authorization.Code, "second code": second.Code, "verifier": agentaccesstest.Verifier,
		"fingerprint raw": string(fingerprint), "fingerprint hex": hex.EncodeToString(fingerprint),
		"fingerprint b64": base64.StdEncoding.EncodeToString(fingerprint), "fingerprint b64url": base64.RawURLEncoding.EncodeToString(fingerprint),
		"admin token": testAdminToken,
	}
	audit := ""
	for _, entry := range env.store.Audit() {
		encoded, _ := json.Marshal(entry)
		audit += string(encoded)
	}
	for name, secret := range secrets {
		for index, response := range responses {
			if strings.Contains(response, secret) {
				t.Errorf("response %d contains the %s", index, name)
			}
		}
		if strings.Contains(env.logs.String(), secret) {
			t.Errorf("logs contain the %s", name)
		}
		if strings.Contains(audit, secret) {
			t.Errorf("audit contains the %s", name)
		}
	}
	// The two responses that hand a secret out carry only their own.
	if strings.Contains(authorizationResponse.Body.String(), token.Token) || strings.Contains(tokenResponse.Body.String(), authorization.Code) ||
		strings.Contains(tokenResponse.Body.String(), string(fingerprint)) || strings.Contains(tokenResponse.Body.String(), "fpr") {
		t.Fatal("an issuing response carries another secret")
	}
	if !strings.Contains(audit, "token_issued") || !strings.Contains(audit, "authorize_approved") {
		t.Fatalf("audit rows missing: %s", audit)
	}
}
