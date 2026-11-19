package agentaccess_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

const testAdminToken = "agent-access-test-admin-token"

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(step time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(step)
	c.mu.Unlock()
}

type harness struct {
	service *agentaccess.Service
	store   *agentaccesstest.Store
	clock   *clock
	logs    *bytes.Buffer
}

func newHarness(t *testing.T, allowWrite, developerLogins bool) harness {
	t.Helper()
	return newHarnessWith(t, agentaccesstest.NewStore(), testAdminToken, allowWrite, developerLogins, &clock{now: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)})
}

func newHarnessWith(t *testing.T, store *agentaccesstest.Store, adminToken string, allowWrite, developerLogins bool, c *clock) harness {
	t.Helper()
	logs := &bytes.Buffer{}
	service, err := agentaccess.New(agentaccess.Options{
		AdminToken: adminToken, Store: store, AllowWrite: allowWrite, DeveloperLogins: developerLogins,
		Logger: slog.New(slog.NewTextHandler(logs, nil)), Now: c.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness{service: service, store: store, clock: c, logs: logs}
}

func codeOf(err error) agentapi.Code {
	if err == nil {
		return ""
	}
	return agentaccess.CodeOf(err)
}

func bearer(token string) string { return "Bearer " + token }

func TestNewRequiresTokenAndStore(t *testing.T) {
	if _, err := agentaccess.New(agentaccess.Options{Store: agentaccesstest.NewStore()}); err == nil {
		t.Fatal("empty admin token accepted")
	}
	if _, err := agentaccess.New(agentaccess.Options{AdminToken: "x"}); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestIssuedTokensHaveTheContractShapeAndAreStoredAsMACs(t *testing.T) {
	h := newHarness(t, true, true)
	issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	if !agentapi.ValidTokenFormat(issued.Token) {
		t.Fatalf("token %q does not have the contract shape", issued.Token)
	}
	tokens := h.store.Tokens()
	if len(tokens) != 1 || len(tokens[0].TokenMAC) != 32 || bytes.Contains(tokens[0].TokenMAC, []byte(issued.Token)) ||
		tokens[0].DisplayPrefix != issued.Token[:8] || tokens[0].Role != "admin" || tokens[0].Tier != "read" ||
		tokens[0].DeviceName != "test-device" || tokens[0].ScopeFingerprint != nil {
		t.Fatalf("stored = %+v", tokens)
	}
	second := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	if second.Token == issued.Token {
		t.Fatal("two tokens are equal")
	}
}

func TestTokenLifetimes(t *testing.T) {
	h := newHarness(t, true, true)
	now := h.clock.Now()
	read := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	if !read.Identity.ExpiresAt.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("admin read expires %v", read.Identity.ExpiresAt)
	}
	write := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierWrite)
	if !write.Identity.ExpiresAt.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("admin write expires %v", write.Identity.ExpiresAt)
	}
	session := now.Add(26 * time.Hour)
	developer := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 42), session)
	if !developer.Identity.ExpiresAt.Equal(session) {
		t.Fatalf("developer expires %v, want the session end %v", developer.Identity.ExpiresAt, session)
	}
	// A developer token dies with its session.
	h.clock.Advance(26 * time.Hour)
	if _, err := h.service.Authenticate(context.Background(), bearer(developer.Token), "192.0.2.1"); codeOf(err) != agentapi.CodeTokenExpired {
		t.Fatalf("developer after session end = %v", err)
	}
	if _, err := h.service.Authenticate(context.Background(), bearer(read.Token), "192.0.2.1"); err != nil {
		t.Fatalf("admin read token still valid: %v", err)
	}
	// Never longer than a session, and never from a session without an end.
	long := h.clock.Now().Add(30 * 24 * time.Hour)
	capped := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 42), long)
	if !capped.Identity.ExpiresAt.Equal(h.clock.Now().Add(7 * 24 * time.Hour)) {
		t.Fatalf("developer cap = %v", capped.Identity.ExpiresAt)
	}
	for _, expires := range []time.Time{{}, h.clock.Now(), h.clock.Now().Add(-time.Hour)} {
		_, err := h.service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 42), SessionExpiresAt: expires}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.2")
		if err == nil {
			t.Fatalf("developer session ending %v authorized a token", expires)
		}
	}
}

// Plan section 5.3: each check answers with its own code.
func TestAuthenticateChecksInOrder(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	admin := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	well := agentapi.TokenPrefix + strings.Repeat("Q", agentapi.TokenEncodedChars)
	cases := []struct {
		name, header string
		want         agentapi.Code
	}{
		{"missing", "", agentapi.CodeUnauthenticated},
		{"not bearer", "Basic " + admin.Token, agentapi.CodeUnauthenticated},
		{"extra field", "Bearer " + admin.Token + " x", agentapi.CodeUnauthenticated},
		{"admin token shape", "Bearer " + testAdminToken, agentapi.CodeUnauthenticated},
		{"short", "Bearer lla_abc", agentapi.CodeUnauthenticated},
		{"unknown", "Bearer " + well, agentapi.CodeUnauthenticated},
		{"valid", bearer(admin.Token), ""},
		{"lower-case scheme", "bearer " + admin.Token, ""},
	}
	for _, test := range cases {
		identity, err := h.service.Authenticate(ctx, test.header, "192.0.2.10")
		if codeOf(err) != test.want {
			t.Errorf("%s = %v, want %s", test.name, err, test.want)
		}
		if test.want == "" && (identity.Role != agentapi.RoleAdmin || identity.Scope != nil || identity.TokenID <= 0 || identity.Tier != agentapi.TierRead) {
			t.Errorf("%s identity = %+v", test.name, identity)
		}
	}

	revoked := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	if err := h.service.Logout(ctx, revoked.Identity, agentaccess.RequestMeta{Command: "logout"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(revoked.Token), "192.0.2.10"); codeOf(err) != agentapi.CodeTokenRevoked {
		t.Fatalf("revoked = %v", err)
	}
	// Revoked is checked before expired.
	h.clock.Advance(31 * 24 * time.Hour)
	if _, err := h.service.Authenticate(ctx, bearer(revoked.Token), "192.0.2.10"); codeOf(err) != agentapi.CodeTokenRevoked {
		t.Fatalf("revoked and expired = %v", err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(admin.Token), "192.0.2.10"); codeOf(err) != agentapi.CodeTokenExpired {
		t.Fatalf("expired = %v", err)
	}

	broken := newHarness(t, true, true)
	token := agentaccesstest.IssueAdmin(t, broken.service, agentapi.TierRead)
	broken.store.FailFind = true
	if _, err := broken.service.Authenticate(ctx, bearer(token.Token), "192.0.2.10"); codeOf(err) != agentapi.CodeUpstreamUnavailable {
		t.Fatalf("store failure = %v", err)
	}
}

// Rotating admin_token makes every agent token unknown.
func TestRotatingTheAdminTokenInvalidatesTokens(t *testing.T) {
	h := newHarness(t, true, true)
	issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	rotated := newHarnessWith(t, h.store, testAdminToken+"-rotated", true, true, h.clock)
	if _, err := rotated.service.Authenticate(context.Background(), bearer(issued.Token), "192.0.2.3"); codeOf(err) != agentapi.CodeUnauthenticated {
		t.Fatalf("token after rotation = %v", err)
	}
	same := newHarnessWith(t, h.store, testAdminToken, true, true, h.clock)
	if _, err := same.service.Authenticate(context.Background(), bearer(issued.Token), "192.0.2.3"); err != nil {
		t.Fatalf("token after restart with the same admin token = %v", err)
	}
}

// Turning developer_login off invalidates developer tokens, not admin ones.
func TestDisablingDeveloperLoginInvalidatesDeveloperTokens(t *testing.T) {
	h := newHarness(t, true, true)
	developer := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 42), h.clock.Now().Add(time.Hour))
	admin := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	off := newHarnessWith(t, h.store, testAdminToken, true, false, h.clock)
	if _, err := off.service.Authenticate(context.Background(), bearer(developer.Token), "192.0.2.4"); codeOf(err) != agentapi.CodeRoleUnavailable {
		t.Fatalf("developer token with developer login off = %v", err)
	}
	if _, err := off.service.Authenticate(context.Background(), bearer(admin.Token), "192.0.2.4"); err != nil {
		t.Fatalf("admin token with developer login off = %v", err)
	}
	if _, err := off.service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 42), SessionExpiresAt: h.clock.Now().Add(time.Hour)}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.4"); codeOf(err) != agentapi.CodeRoleUnavailable {
		t.Fatalf("developer authorization with developer login off = %v", err)
	}
}

// Scope == nil means "reads everything", so a developer row whose scope cannot
// be restored completely, or an admin row that carries one, is refused.
func TestIncompleteScopeIsRejectedNeverUnscoped(t *testing.T) {
	cases := map[string]func(*storage.AgentToken){
		"developer without fingerprint": func(row *storage.AgentToken) { row.ScopeFingerprint = nil },
		"developer short fingerprint":   func(row *storage.AgentToken) { row.ScopeFingerprint = row.ScopeFingerprint[:16] },
		"developer long fingerprint":    func(row *storage.AgentToken) { row.ScopeFingerprint = append(row.ScopeFingerprint, 1) },
		"developer negative token id":   func(row *storage.AgentToken) { id := int64(-1); row.ScopeTokenID = &id },
		"developer write tier":          func(row *storage.AgentToken) { row.Tier = "write" },
		"developer unknown tier":        func(row *storage.AgentToken) { row.Tier = "owner" },
		"unknown role":                  func(row *storage.AgentToken) { row.Role = "owner" },
		"empty role":                    func(row *storage.AgentToken) { row.Role = "" },
		"developer row claiming admin":  func(row *storage.AgentToken) { row.Role = "admin" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, true, true)
			issued := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 42), h.clock.Now().Add(time.Hour))
			h.store.Mutate(issued.Identity.TokenID, mutate)
			identity, err := h.service.Authenticate(context.Background(), bearer(issued.Token), "192.0.2.5")
			if codeOf(err) != agentapi.CodeUnauthenticated || identity.Role != "" || identity.Scope != nil {
				t.Fatalf("damaged row = %+v, %v", identity, err)
			}
			if strings.Contains(h.logs.String(), issued.Token) {
				t.Fatal("log line contains the token")
			}
		})
	}
	for name, mutate := range map[string]func(*storage.AgentToken){
		"admin with fingerprint":   func(row *storage.AgentToken) { row.ScopeFingerprint = bytes.Repeat([]byte{1}, 32) },
		"admin with token id":      func(row *storage.AgentToken) { id := int64(1); row.ScopeTokenID = &id },
		"admin with user id":       func(row *storage.AgentToken) { row.ScopeUserID = 3 },
		"admin with username":      func(row *storage.AgentToken) { row.ScopeUsername = "x" },
		"admin with token name":    func(row *storage.AgentToken) { row.ScopeTokenName = "x" },
		"admin claiming developer": func(row *storage.AgentToken) { row.Role = "developer" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, true, true)
			issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
			h.store.Mutate(issued.Identity.TokenID, mutate)
			if _, err := h.service.Authenticate(context.Background(), bearer(issued.Token), "192.0.2.5"); codeOf(err) != agentapi.CodeUnauthenticated {
				t.Fatalf("mismatched admin row = %v", err)
			}
		})
	}
	// The intact developer token restores its complete scope.
	h := newHarness(t, true, true)
	scope := agentaccesstest.DeveloperScope(9, 42)
	issued := agentaccesstest.IssueDeveloper(t, h.service, scope, h.clock.Now().Add(time.Hour))
	identity, err := h.service.Authenticate(context.Background(), bearer(issued.Token), "192.0.2.5")
	if err != nil || identity.Role != agentapi.RoleDeveloper || identity.Scope == nil ||
		!bytes.Equal(identity.Scope.Fingerprint, scope.Fingerprint) || *identity.Scope.TokenID != 42 ||
		identity.Scope.UserID != 7 || identity.Scope.Username != "developer" || identity.Scope.TokenName != "agent-key" {
		t.Fatalf("developer identity = %+v, %v", identity, err)
	}
}

func TestPermit(t *testing.T) {
	endpoint := func(access agentapi.Access, tier agentapi.Tier) agentapi.Endpoint {
		return agentapi.Endpoint{ID: "probe", Method: "GET", Pattern: "/probe", Access: access, Tier: tier}
	}
	adminRead := agentaccess.Identity{Role: agentapi.RoleAdmin, Tier: agentapi.TierRead}
	adminWrite := agentaccess.Identity{Role: agentapi.RoleAdmin, Tier: agentapi.TierWrite}
	developer := agentaccess.Identity{Role: agentapi.RoleDeveloper, Tier: agentapi.TierRead, Scope: agentaccesstest.DeveloperScope(1, 1)}
	for _, allowWrite := range []bool{true, false} {
		h := newHarness(t, allowWrite, true)
		writeOutcome := agentapi.Code("")
		if !allowWrite {
			writeOutcome = agentapi.CodeWriteDisabled
		}
		cases := []struct {
			identity agentaccess.Identity
			endpoint agentapi.Endpoint
			want     agentapi.Code
		}{
			{adminRead, endpoint(agentapi.AccessAny, agentapi.TierRead), ""},
			{adminWrite, endpoint(agentapi.AccessAny, agentapi.TierRead), ""},
			{developer, endpoint(agentapi.AccessAny, agentapi.TierRead), ""},
			{adminRead, endpoint(agentapi.AccessAdmin, agentapi.TierRead), ""},
			{developer, endpoint(agentapi.AccessAdmin, agentapi.TierRead), agentapi.CodeForbiddenRole},
			{adminRead, endpoint(agentapi.AccessAdmin, agentapi.TierWrite), agentapi.CodeReadOnlyToken},
			{adminWrite, endpoint(agentapi.AccessAdmin, agentapi.TierWrite), writeOutcome},
			{developer, endpoint(agentapi.AccessAdmin, agentapi.TierWrite), agentapi.CodeForbiddenRole},
			{developer, endpoint(agentapi.AccessAny, agentapi.TierWrite), agentapi.CodeReadOnlyToken},
			{agentaccess.Identity{}, endpoint(agentapi.AccessAny, agentapi.TierRead), agentapi.CodeUnauthenticated},
			{adminWrite, endpoint("", agentapi.TierRead), agentapi.CodeForbiddenRole},
			{adminWrite, endpoint(agentapi.AccessAny, ""), agentapi.CodeReadOnlyToken},
		}
		for index, test := range cases {
			if got := codeOf(h.service.Permit(test.identity, test.endpoint)); got != test.want {
				t.Errorf("allow_write=%v case %d = %s, want %s", allowWrite, index, got, test.want)
			}
		}
	}
}

// Contract section 7: only well-formed unknown tokens count; over the limit
// the address is refused, a valid token included; other addresses are not.
func TestFailedLookupLimiter(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	valid := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	unknown := agentapi.TokenPrefix + strings.Repeat("Z", agentapi.TokenEncodedChars)
	for range 30 {
		if _, err := h.service.Authenticate(ctx, "Bearer garbage", "192.0.2.20"); codeOf(err) != agentapi.CodeUnauthenticated {
			t.Fatalf("malformed = %v", err)
		}
	}
	// Expired and revoked tokens do not count either.
	revoked := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	_ = h.service.Logout(ctx, revoked.Identity, agentaccess.RequestMeta{})
	for range 30 {
		if _, err := h.service.Authenticate(ctx, bearer(revoked.Token), "192.0.2.20"); codeOf(err) != agentapi.CodeTokenRevoked {
			t.Fatalf("revoked = %v", err)
		}
	}
	if _, err := h.service.Authenticate(ctx, bearer(valid.Token), "192.0.2.20"); err != nil {
		t.Fatalf("valid token after uncounted failures = %v", err)
	}
	for attempt := range 10 {
		if _, err := h.service.Authenticate(ctx, bearer(unknown), "192.0.2.20"); codeOf(err) != agentapi.CodeUnauthenticated {
			t.Fatalf("unknown %d = %v", attempt, err)
		}
	}
	_, err := h.service.Authenticate(ctx, bearer(valid.Token), "192.0.2.20")
	var coded *agentaccess.Error
	if codeOf(err) != agentapi.CodeRateLimited || !asError(err, &coded) || coded.RetryAfter <= 0 {
		t.Fatalf("valid token from a limited address = %v", err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(valid.Token), "198.51.100.20"); err != nil {
		t.Fatalf("another address = %v", err)
	}
	h.clock.Advance(5*time.Minute + time.Second)
	if _, err := h.service.Authenticate(ctx, bearer(valid.Token), "192.0.2.20"); err != nil {
		t.Fatalf("after the window = %v", err)
	}
}

func asError(err error, target **agentaccess.Error) bool {
	coded, ok := err.(*agentaccess.Error)
	if ok {
		*target = coded
	}
	return ok
}

func TestLastUsedIsWrittenAtMostOncePerMinute(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	for range 5 {
		if _, err := h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.30"); err != nil {
			t.Fatal(err)
		}
	}
	if h.store.Touches() != 1 {
		t.Fatalf("touches = %d", h.store.Touches())
	}
	h.clock.Advance(time.Minute)
	h.store.FailTouch = true
	if _, err := h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.30"); err != nil {
		t.Fatalf("a failed last-used write failed the request: %v", err)
	}
	if !strings.Contains(h.logs.String(), "agent_touch_failed") {
		t.Fatal("failed last-used write was not logged")
	}
}

func TestAuthorizationValidation(t *testing.T) {
	ctx := context.Background()
	admin := agentaccess.Grantor{Role: agentapi.RoleAdmin}
	developer := agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 1), SessionExpiresAt: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	type mutation func(*agentaccess.AuthorizationRequest)
	cases := []struct {
		name    string
		grantor agentaccess.Grantor
		write   bool
		mutate  mutation
		want    agentapi.Code
		field   string
	}{
		{"port too low", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Port = 1023 }, agentapi.CodeInvalidArgument, "port"},
		{"port too high", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Port = 65536 }, agentapi.CodeInvalidArgument, "port"},
		{"port missing", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Port = 0 }, agentapi.CodeInvalidArgument, "port"},
		{"paste with port", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Mode = agentaccess.ModePaste }, agentapi.CodeInvalidArgument, "port"},
		{"unknown mode", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Mode = "redirect" }, agentapi.CodeInvalidArgument, "mode"},
		{"plain challenge", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Challenge = agentaccesstest.Verifier }, agentapi.CodeInvalidArgument, "challenge"},
		{"padded challenge", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Challenge = r.Challenge[:42] + "=" }, agentapi.CodeInvalidArgument, "challenge"},
		{"unknown tier", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Tier = "admin" }, agentapi.CodeInvalidArgument, "tier"},
		{"developer write", developer, true, func(r *agentaccess.AuthorizationRequest) { r.Tier = agentapi.TierWrite }, agentapi.CodeInvalidArgument, "tier"},
		{"admin write while allow_write off", admin, false, func(r *agentaccess.AuthorizationRequest) { r.Tier = agentapi.TierWrite }, agentapi.CodeInvalidArgument, "tier"},
		{"developer without scope", agentaccess.Grantor{Role: agentapi.RoleDeveloper, SessionExpiresAt: developer.SessionExpiresAt}, true, func(*agentaccess.AuthorizationRequest) {}, agentapi.CodeForbiddenRole, ""},
		{"admin with scope", agentaccess.Grantor{Role: agentapi.RoleAdmin, Scope: agentaccesstest.DeveloperScope(1, 1)}, true, func(*agentaccess.AuthorizationRequest) {}, agentapi.CodeForbiddenRole, ""},
		{"no role", agentaccess.Grantor{}, true, func(*agentaccess.AuthorizationRequest) {}, agentapi.CodeForbiddenRole, ""},
		{"admin write allowed", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Tier = agentapi.TierWrite }, "", ""},
		{"paste mode", admin, true, func(r *agentaccess.AuthorizationRequest) { r.Mode, r.Port = agentaccess.ModePaste, 0 }, "", ""},
	}
	for _, test := range cases {
		h := newHarness(t, test.write, true)
		request := agentaccesstest.Request(agentapi.TierRead)
		test.mutate(&request)
		authorization, err := h.service.Approve(ctx, test.grantor, request, "192.0.2.40")
		if codeOf(err) != test.want {
			t.Errorf("%s = %v, want %s", test.name, err, test.want)
			continue
		}
		var coded *agentaccess.Error
		if test.field != "" && (!asError(err, &coded) || coded.Field != test.field) {
			t.Errorf("%s field = %v", test.name, err)
		}
		if test.want == "" {
			if request.Mode == agentaccess.ModePaste && (authorization.RedirectURI != "" || authorization.ExpiresIn != 300*time.Second) {
				t.Errorf("paste authorization = %+v", authorization)
			}
			if request.Mode == agentaccess.ModeLoopback && (authorization.RedirectURI != "http://127.0.0.1:49152/callback" || authorization.ExpiresIn != 60*time.Second) {
				t.Errorf("loopback authorization = %+v", authorization)
			}
		}
	}
}

// The page sends what it has; empty display values become placeholders and
// control characters never reach storage.
func TestAuthorizationPlaceholdersAndCleaning(t *testing.T) {
	h := newHarness(t, true, true)
	request := agentaccesstest.Request(agentapi.TierRead)
	request.DeviceName, request.CLIVersion = "", ""
	authorization, err := h.service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, request, "192.0.2.41")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.service.Exchange(context.Background(), authorization.Code, agentaccesstest.Verifier, "192.0.2.41", agentaccess.RequestMeta{})
	if err != nil || issued.Identity.DeviceName != agentaccess.PlaceholderDeviceName || issued.Identity.CLIVersion != agentaccess.PlaceholderCLIVersion {
		t.Fatalf("placeholders = %+v, %v", issued.Identity, err)
	}
	request.DeviceName = "  build\x00box\x1b[31m " + strings.Repeat("é", 80) + "\xff"
	request.CLIVersion = "1.0.0;rm -rf"
	authorization, _ = h.service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, request, "192.0.2.41")
	issued, err = h.service.Exchange(context.Background(), authorization.Code, agentaccesstest.Verifier, "192.0.2.41", agentaccess.RequestMeta{})
	if err != nil || strings.ContainsAny(issued.Identity.DeviceName, "\x00\x1b") || len([]rune(issued.Identity.DeviceName)) > 64 ||
		!strings.HasPrefix(issued.Identity.DeviceName, "buildbox") || issued.Identity.CLIVersion != agentaccess.PlaceholderCLIVersion {
		t.Fatalf("cleaned = %+v, %v", issued.Identity, err)
	}
}

func approve(t *testing.T, h harness, tier agentapi.Tier, mode string) agentaccess.Authorization {
	t.Helper()
	request := agentaccesstest.Request(tier)
	if mode == agentaccess.ModePaste {
		request.Mode, request.Port = agentaccess.ModePaste, 0
	}
	authorization, err := h.service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, request, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

// Contract section 3.1: replay, expiry, verifier mismatch; a code is consumed
// by its first redemption even when that redemption fails.
func TestAuthorizationCodes(t *testing.T) {
	ctx := context.Background()
	exchange := func(h harness, code, verifier string) (agentaccess.Issued, error) {
		return h.service.Exchange(ctx, code, verifier, "192.0.2.51", agentaccess.RequestMeta{Command: "login"})
	}

	t.Run("replay revokes the issued token", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
		issued, err := exchange(h, authorization.Code, agentaccesstest.Verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.51"); err != nil {
			t.Fatal(err)
		}
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("replay = %v", err)
		}
		if _, err := h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.51"); codeOf(err) != agentapi.CodeTokenRevoked {
			t.Fatalf("token after replay = %v", err)
		}
		// Still recognized after the code's own lifetime.
		h.clock.Advance(5 * time.Minute)
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("late replay = %v", err)
		}
		var revocations int
		for _, entry := range h.store.Audit() {
			if entry.Event == agentaccess.EventTokenRevoked {
				revocations++
			}
		}
		if revocations != 1 {
			t.Fatalf("revocation audit rows = %d", revocations)
		}
	})

	t.Run("loopback expiry", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
		h.clock.Advance(60 * time.Second)
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("expired loopback code = %v", err)
		}
		if len(h.store.Tokens()) != 0 {
			t.Fatal("an expired code issued a token")
		}
	})

	t.Run("paste lives five minutes", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization := approve(t, h, agentapi.TierRead, agentaccess.ModePaste)
		h.clock.Advance(299 * time.Second)
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); err != nil {
			t.Fatalf("paste code within five minutes = %v", err)
		}
		late := approve(t, h, agentapi.TierRead, agentaccess.ModePaste)
		h.clock.Advance(300 * time.Second)
		if _, err := exchange(h, late.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("paste code after five minutes = %v", err)
		}
	})

	t.Run("verifier mismatch consumes the code", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
		for _, verifier := range []string{"", "short", agentaccesstest.Verifier + "x", strings.Repeat("a", 129), agentaccesstest.Challenge(agentaccesstest.Verifier)} {
			if _, err := exchange(h, authorization.Code, verifier); codeOf(err) != agentapi.CodeInvalidGrant {
				t.Fatalf("verifier %q = %v", verifier, err)
			}
		}
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("correct verifier after a mismatch = %v", err)
		}
		if len(h.store.Tokens()) != 0 {
			t.Fatal("a consumed code issued a token")
		}
	})

	t.Run("unknown and malformed codes", func(t *testing.T) {
		h := newHarness(t, true, true)
		for _, code := range []string{"", "abc", strings.Repeat("A", 43), strings.Repeat("=", 43)} {
			if _, err := exchange(h, code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
				t.Fatalf("code %q = %v", code, err)
			}
		}
	})

	t.Run("a failed store write still consumes the code", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
		h.store.FailCreate = true
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeUpstreamUnavailable {
			t.Fatalf("store failure = %v", err)
		}
		h.store.FailCreate = false
		if _, err := exchange(h, authorization.Code, agentaccesstest.Verifier); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("retry after store failure = %v", err)
		}
	})

	t.Run("developer login turned off before exchange", func(t *testing.T) {
		h := newHarness(t, true, true)
		authorization, err := h.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 1), SessionExpiresAt: h.clock.Now().Add(time.Hour)}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.52")
		if err != nil {
			t.Fatal(err)
		}
		off := newHarnessWith(t, h.store, testAdminToken, true, false, h.clock)
		if _, err := off.service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.52", agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("code from another process = %v", err)
		}
	})
}

// replayingStore replays the code from inside CreateAgentToken, i.e. while the
// first redemption is still issuing its token.
type replayingStore struct {
	*agentaccesstest.Store
	replay func()
	once   sync.Once
}

func (store *replayingStore) CreateAgentToken(ctx context.Context, token storage.AgentToken) (storage.AgentToken, error) {
	store.once.Do(store.replay)
	return store.Store.CreateAgentToken(ctx, token)
}

func TestReplayDuringIssuanceRevokesTheToken(t *testing.T) {
	ctx := context.Background()
	inner := agentaccesstest.NewStore()
	c := &clock{now: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)}
	store := &replayingStore{Store: inner}
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.60")
	if err != nil {
		t.Fatal(err)
	}
	var replayErr error
	store.replay = func() {
		_, replayErr = service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.61", agentaccess.RequestMeta{})
	}
	issued, err := service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.60", agentaccess.RequestMeta{})
	if codeOf(err) != agentapi.CodeInvalidGrant || issued.Token != "" {
		t.Fatalf("first redemption = %+v, %v", issued, err)
	}
	if codeOf(replayErr) != agentapi.CodeInvalidGrant {
		t.Fatalf("replay = %v", replayErr)
	}
	tokens := inner.Tokens()
	if len(tokens) != 1 || tokens[0].RevokedAtNS == nil {
		t.Fatalf("token after a concurrent replay = %+v", tokens)
	}
}

func TestExchangeAndAuthorizationLimiters(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	good := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	for range 10 {
		if _, err := h.service.Exchange(ctx, strings.Repeat("B", 43), agentaccesstest.Verifier, "192.0.2.70", agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatal(err)
		}
	}
	if _, err := h.service.Exchange(ctx, good.Code, agentaccesstest.Verifier, "192.0.2.70", agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("exchange from a limited address = %v", err)
	}
	if _, err := h.service.Exchange(ctx, good.Code, agentaccesstest.Verifier, "198.51.100.70", agentaccess.RequestMeta{}); err != nil {
		t.Fatalf("the refused attempt must not have consumed the code: %v", err)
	}

	limited := newHarness(t, true, true)
	for attempt := range 20 {
		if _, err := limited.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71"); err != nil {
			t.Fatalf("authorization %d = %v", attempt, err)
		}
	}
	if _, err := limited.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71"); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("21st authorization = %v", err)
	}
	if _, err := limited.service.Deny(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71"); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("deny from a limited address = %v", err)
	}
}

func TestDeny(t *testing.T) {
	h := newHarness(t, true, true)
	redirect, err := h.service.Deny(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.80")
	if err != nil || redirect != "http://127.0.0.1:49152/callback" {
		t.Fatalf("deny = %q, %v", redirect, err)
	}
	paste := agentaccesstest.Request(agentapi.TierRead)
	paste.Mode, paste.Port = agentaccess.ModePaste, 0
	if redirect, err := h.service.Deny(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, paste, "192.0.2.80"); err != nil || redirect != "" {
		t.Fatalf("paste deny = %q, %v", redirect, err)
	}
	audit := h.store.Audit()
	if len(audit) != 2 || audit[0].Event != agentaccess.EventAuthorizeDenied || audit[0].Outcome != storage.AgentOutcomeDenied || audit[0].TokenID != nil {
		t.Fatalf("deny audit = %+v", audit)
	}
	if len(h.store.Tokens()) != 0 {
		t.Fatal("deny issued a token")
	}
}

func TestListAndRevokeFollowTheViewerScope(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	expires := h.clock.Now().Add(time.Hour)
	mine := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 42), expires)
	otherKey := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(2, 42), expires)
	otherToken := agentaccesstest.IssueDeveloper(t, h.service, agentaccesstest.DeveloperScope(1, 43), expires)
	admin := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	me := agentaccess.Viewer{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 42)}

	visible, err := h.service.ListTokens(ctx, me)
	if err != nil || len(visible) != 1 || visible[0].ID != mine.Identity.TokenID {
		t.Fatalf("developer list = %+v, %v", visible, err)
	}
	all, err := h.service.ListTokens(ctx, agentaccess.Viewer{Role: agentapi.RoleAdmin})
	if err != nil || len(all) != 4 {
		t.Fatalf("admin list = %+v, %v", all, err)
	}
	for _, viewer := range []agentaccess.Viewer{{Role: agentapi.RoleDeveloper}, {Role: agentapi.RoleDeveloper, Scope: &agentaccess.Scope{}}, {}} {
		if _, err := h.service.ListTokens(ctx, viewer); codeOf(err) != agentapi.CodeForbiddenRole {
			t.Fatalf("incomplete viewer %+v list = %v", viewer, err)
		}
		if err := h.service.RevokeToken(ctx, viewer, admin.Identity.TokenID); codeOf(err) != agentapi.CodeForbiddenRole {
			t.Fatalf("incomplete viewer %+v revoke = %v", viewer, err)
		}
	}
	// Invisible tokens: no error, nothing revoked.
	for _, other := range []agentaccess.Issued{otherKey, otherToken, admin} {
		if err := h.service.RevokeToken(ctx, me, other.Identity.TokenID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.service.Authenticate(ctx, bearer(other.Token), "192.0.2.90"); err != nil {
			t.Fatalf("a developer revoked an invisible token: %v", err)
		}
	}
	if err := h.service.RevokeToken(ctx, me, mine.Identity.TokenID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.RevokeToken(ctx, me, mine.Identity.TokenID); err != nil {
		t.Fatalf("second revoke = %v", err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(mine.Token), "192.0.2.90"); codeOf(err) != agentapi.CodeTokenRevoked {
		t.Fatalf("own token after revoke = %v", err)
	}
	if err := h.service.RevokeToken(ctx, agentaccess.Viewer{Role: agentapi.RoleAdmin}, otherKey.Identity.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(otherKey.Token), "192.0.2.90"); codeOf(err) != agentapi.CodeTokenRevoked {
		t.Fatalf("admin revoke = %v", err)
	}
	h.store.FailList = true
	if _, err := h.service.ListTokens(ctx, me); codeOf(err) != agentapi.CodeUpstreamUnavailable {
		t.Fatalf("list failure = %v", err)
	}
	h.store.FailRevoke = true
	if err := h.service.RevokeToken(ctx, me, 1); codeOf(err) != agentapi.CodeUpstreamUnavailable {
		t.Fatalf("revoke failure = %v", err)
	}
}

// No audit row and no log line carries a token, a code, a verifier or the
// key fingerprint; an audit write failure never fails the request.
func TestNoSecretInAuditOrLogs(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	scope := agentaccesstest.DeveloperScope(0xab, 42)
	authorization, err := h.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: scope, SessionExpiresAt: h.clock.Now().Add(time.Hour)}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.95")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.95", agentaccess.RequestMeta{Command: "login", CLIVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.95", agentaccess.RequestMeta{Command: "login"})
	_, _ = h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.95")
	h.store.FailAudit = true
	h.store.FailFind = true
	second := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	_, _ = h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.95")
	h.store.FailFind = false
	if _, err := h.service.Exchange(ctx, second.Code, agentaccesstest.Verifier, "192.0.2.95", agentaccess.RequestMeta{}); err != nil {
		t.Fatalf("audit failure failed the exchange: %v", err)
	}
	if !strings.Contains(h.logs.String(), "agent_audit_failed") {
		t.Fatal("audit failure was not logged")
	}
	secrets := []string{issued.Token, issued.Token[8:], authorization.Code, second.Code, agentaccesstest.Verifier,
		string(scope.Fingerprint), hex.EncodeToString(scope.Fingerprint),
		base64.StdEncoding.EncodeToString(scope.Fingerprint), base64.RawURLEncoding.EncodeToString(scope.Fingerprint)}
	dump := h.logs.String() + fmt.Sprintf("%+v", h.store.Audit())
	for _, secret := range secrets {
		if strings.Contains(dump, secret) {
			t.Fatalf("audit or log contains a secret (%d chars)", len(secret))
		}
	}
	events := map[string]int{}
	for _, entry := range h.store.Audit() {
		events[entry.Event]++
	}
	if events[agentaccess.EventAuthorizeApproved] != 1 || events[agentaccess.EventTokenIssued] != 1 ||
		events[agentaccess.EventTokenExchangeFailed] != 1 || events[agentaccess.EventTokenRevoked] != 1 {
		t.Fatalf("events = %v", events)
	}
}
