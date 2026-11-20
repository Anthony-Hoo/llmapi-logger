package agentaccess_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strconv"
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

// gatedStore holds every token lookup until release is closed, and counts the
// lookups that reached it. While passThrough is set lookups are not held.
type gatedStore struct {
	*agentaccesstest.Store
	mu          sync.Mutex
	lookups     int
	passThrough bool
	arrived     chan struct{}
	release     chan struct{}
}

func (store *gatedStore) FindAgentTokenByMAC(ctx context.Context, mac []byte) (storage.AgentToken, error) {
	store.mu.Lock()
	passThrough := store.passThrough
	if !passThrough {
		store.lookups++
	}
	store.mu.Unlock()
	if !passThrough {
		store.arrived <- struct{}{}
		<-store.release
	}
	return store.Store.FindAgentTokenByMAC(ctx, mac)
}

// Contract section 7 and section 0.1 item 100: legitimate concurrency is not
// limited by the failure limit. Twenty valid tokens from one address, all in
// flight at the same moment (the store holds every lookup until all twenty
// have arrived), all succeed; under the previous limiter, which held a place
// of the failure limit for every lookup, ten of them were refused.
func TestConcurrentValidLookupsFromOneAddressAllSucceed(t *testing.T) {
	inner := agentaccesstest.NewStore()
	store := &gatedStore{Store: inner, passThrough: true, arrived: make(chan struct{}, 64), release: make(chan struct{})}
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	valid := agentaccesstest.IssueAdmin(t, service, agentapi.TierRead)
	store.mu.Lock()
	store.passThrough = false
	store.mu.Unlock()
	const concurrent = 20
	results := make(chan error, concurrent)
	for range concurrent {
		go func() {
			_, err := service.Authenticate(context.Background(), bearer(valid.Token), "203.0.113.9")
			results <- err
		}()
	}
	for range concurrent {
		<-store.arrived
	}
	close(store.release)
	for range concurrent {
		if err := <-results; err != nil {
			t.Fatalf("valid token in flight with %d others = %v", concurrent-1, err)
		}
	}
}

// Contract section 7: concurrent wrong tokens from one address are bounded by
// the failure limit plus the in-flight cap. The first 32 lookups are in
// flight together; every attempt beyond them is refused by the cap with a
// one-second wait, without reaching the store. Once those 32 have failed the
// address is over the failure limit and is refused for the window.
func TestFailedLookupLimiterHoldsUnderConcurrency(t *testing.T) {
	inner := agentaccesstest.NewStore()
	store := &gatedStore{Store: inner, arrived: make(chan struct{}, 64), release: make(chan struct{})}
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	const guesses = 60
	results := make(chan agentapi.Code, guesses)
	var wait sync.WaitGroup
	for index := range guesses {
		wait.Add(1)
		go func() {
			defer wait.Done()
			token := agentapi.TokenPrefix + fmt.Sprintf("%043d", index)
			_, err := service.Authenticate(context.Background(), bearer(token), "203.0.113.7")
			results <- codeOf(err)
		}()
	}
	// The cap's worth of lookups are in flight; every other attempt must
	// already have been refused without reaching the store.
	const inFlightCap, failureLimit = 32, 10
	for range inFlightCap {
		<-store.arrived
	}
	limited := 0
	for range guesses - inFlightCap {
		if code := <-results; code != agentapi.CodeRateLimited {
			t.Fatalf("attempt beyond the in-flight cap = %s", code)
		}
		limited++
	}
	close(store.release)
	wait.Wait()
	close(results)
	for code := range results {
		if code != agentapi.CodeUnauthenticated {
			t.Fatalf("looked-up attempt = %s", code)
		}
	}
	if store.lookups != inFlightCap || store.lookups > failureLimit+inFlightCap || limited != guesses-inFlightCap {
		t.Fatalf("lookups = %d, limited = %d", store.lookups, limited)
	}
	// The failures are counted now: the address is refused for the window.
	_, err = service.Authenticate(context.Background(), bearer(agentapi.TokenPrefix+fmt.Sprintf("%043d", guesses)), "203.0.113.7")
	var coded *agentaccess.Error
	if codeOf(err) != agentapi.CodeRateLimited || !asError(err, &coded) || coded.RetryAfter <= time.Second {
		t.Fatalf("attempt after the failures = %v", err)
	}
	store.mu.Lock()
	lookups := store.lookups
	store.mu.Unlock()
	if lookups != inFlightCap {
		t.Fatalf("the refused attempt reached the store: %d lookups", lookups)
	}

	// A lookup that finds a token gives its place back: ten valid tokens in
	// a row from one address are never limited.
	h := newHarness(t, true, true)
	valid := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	for attempt := range 30 {
		if _, err := h.service.Authenticate(context.Background(), bearer(valid.Token), "203.0.113.8"); err != nil {
			t.Fatalf("valid token %d = %v", attempt, err)
		}
	}
}

// A token request cannot make its audit row look like a web-page action: the
// server's own command value and malformed values become "unknown"; an
// absent command stays empty.
func TestClientCommandCannotClaimAServerValue(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	for _, test := range []struct{ sent, recorded string }{
		{agentaccess.CommandWeb, agentaccess.CommandUnknown},
		{"Requests.List", agentaccess.CommandUnknown},
		{"web page", agentaccess.CommandUnknown},
		{strings.Repeat("a", 65), agentaccess.CommandUnknown},
		{"", ""},
		{"logout", "logout"},
		{"webhook", "webhook"},
	} {
		issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
		if err := h.service.Logout(ctx, issued.Identity, agentaccess.RequestMeta{Command: test.sent}); err != nil {
			t.Fatal(err)
		}
		rows := h.store.Audit()
		last := rows[len(rows)-1]
		if last.Event != agentaccess.EventTokenRevoked || last.Command != test.recorded {
			t.Errorf("command %q recorded as %q", test.sent, last.Command)
		}
	}
	// The web page's own rows keep the reserved value.
	issued := agentaccesstest.IssueAdmin(t, h.service, agentapi.TierRead)
	if err := h.service.RevokeToken(ctx, agentaccess.Viewer{Role: agentapi.RoleAdmin}, issued.Identity.TokenID); err != nil {
		t.Fatal(err)
	}
	rows := h.store.Audit()
	if last := rows[len(rows)-1]; last.Command != agentaccess.CommandWeb {
		t.Fatalf("web revocation command = %q", last.Command)
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

// NewAPI names are display-only; odd ones are cleaned before they reach
// storage, where they would otherwise fail the write after the code is spent.
func TestDeveloperIdentityNamesAreCleaned(t *testing.T) {
	h := newHarness(t, true, true)
	scope := agentaccesstest.DeveloperScope(3, 42)
	scope.Username = "dev\x00eloper\x1b"
	scope.TokenName = strings.Repeat("n", 400)
	issued := agentaccesstest.IssueDeveloper(t, h.service, scope, h.clock.Now().Add(time.Hour))
	if issued.Identity.Scope.Username != "developer" || len(issued.Identity.Scope.TokenName) != 256 ||
		!bytes.Equal(issued.Identity.Scope.Fingerprint, scope.Fingerprint) || *issued.Identity.Scope.TokenID != 42 {
		t.Fatalf("identity = %+v", issued.Identity.Scope)
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

	t.Run("codes do not survive a restart", func(t *testing.T) {
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
		authorization, err := limited.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71")
		if err != nil {
			t.Fatalf("authorization %d = %v", attempt, err)
		}
		// Redeemed, so that only the rate limit and not the cap on open
		// codes (TestAuthorizationLimitsFollowTheApprover) is in play.
		if _, err := limited.service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.71", agentaccess.RequestMeta{}); err != nil {
			t.Fatalf("exchange %d = %v", attempt, err)
		}
	}
	if _, err := limited.service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71"); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("21st authorization = %v", err)
	}
	if _, err := limited.service.Deny(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.71"); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("deny from a limited address = %v", err)
	}
}

// The authorization limiter and the cap on open codes follow the approving
// identity, not the address: behind one proxy address a developer session
// neither uses up the administrator's allowance nor fills the code store.
func TestAuthorizationLimitsFollowTheApprover(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	const proxy = "198.51.100.44"
	developer := agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(1, 42), SessionExpiresAt: h.clock.Now().Add(time.Hour)}
	other := agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: agentaccesstest.DeveloperScope(2, 43), SessionExpiresAt: h.clock.Now().Add(time.Hour)}
	admin := agentaccess.Grantor{Role: agentapi.RoleAdmin}
	bad := agentaccesstest.Request(agentapi.TierRead)
	bad.Mode = "x"
	for range 20 {
		if _, err := h.service.Deny(ctx, developer, bad, proxy); codeOf(err) != agentapi.CodeInvalidArgument {
			t.Fatalf("invalid deny = %v", err)
		}
	}
	if _, err := h.service.Approve(ctx, developer, agentaccesstest.Request(agentapi.TierRead), proxy); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("developer after 20 requests = %v", err)
	}
	if _, err := h.service.Approve(ctx, admin, agentaccesstest.Request(agentapi.TierRead), proxy); err != nil {
		t.Fatalf("administrator from the same address = %v", err)
	}

	// Open (unredeemed, unexpired) codes are capped per identity.
	h = newHarness(t, true, true)
	paste := agentaccesstest.Request(agentapi.TierRead)
	paste.Mode, paste.Port = agentaccess.ModePaste, 0
	var first agentaccess.Authorization
	for index := range 8 {
		authorization, err := h.service.Approve(ctx, developer, paste, "2001:db8::"+strconv.Itoa(index))
		if err != nil {
			t.Fatalf("open code %d = %v", index, err)
		}
		if index == 0 {
			first = authorization
		}
	}
	_, err := h.service.Approve(ctx, developer, paste, "2001:db8::99")
	var coded *agentaccess.Error
	if !asError(err, &coded) || coded.Code != agentapi.CodeRateLimited || coded.RetryAfter <= 0 || coded.RetryAfter > first.ExpiresIn {
		t.Fatalf("ninth open code = %v", err)
	}
	if _, err := h.service.Approve(ctx, other, paste, proxy); err != nil {
		t.Fatalf("another developer = %v", err)
	}
	if _, err := h.service.Approve(ctx, admin, agentaccesstest.Request(agentapi.TierRead), proxy); err != nil {
		t.Fatalf("administrator = %v", err)
	}
	// A redeemed code no longer counts.
	if _, err := h.service.Exchange(ctx, first.Code, agentaccesstest.Verifier, proxy, agentaccess.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Approve(ctx, developer, paste, proxy); err != nil {
		t.Fatalf("after a redemption = %v", err)
	}
	// Neither does an expired one.
	h.clock.Advance(5*time.Minute + time.Second)
	for index := range 8 {
		if _, err := h.service.Approve(ctx, developer, paste, proxy); err != nil {
			t.Fatalf("after expiry %d = %v", index, err)
		}
	}
}

// Contract section 3.1: a replayed code revokes the token it issued. A
// passing store error is retried with a short backoff; when every attempt
// fails the failure is logged and the next replay tries again.
func TestReplayRevocationIsRetried(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, true, true)
	authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	issued, err := h.service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.90", agentaccess.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h.store.FailRevokeTimes = 2
	cancelled, cancel := context.WithCancel(ctx)
	cancel() // the replaying client went away; the revocation still runs
	if _, err := h.service.Exchange(cancelled, authorization.Code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
		t.Fatalf("replay = %v", err)
	}
	if _, err := h.service.Authenticate(ctx, bearer(issued.Token), "192.0.2.92"); codeOf(err) != agentapi.CodeTokenRevoked {
		t.Fatalf("token after a replay with two failed revocations = %v", err)
	}
	if h.store.RevokeAttempts != 3 || strings.Contains(h.logs.String(), "revocation after code replay failed") {
		t.Fatalf("attempts = %d, logs = %s", h.store.RevokeAttempts, h.logs.String())
	}

	// The request's attempts are the first four; what happens when all of
	// them fail is TestReplayRevocationKeepsTryingInTheBackground.
}

// lockedBuffer is a log sink a background goroutine may write while the test
// reads it.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

// replayHarness issues a token through a code and returns the service, the
// store, the code and the token.
func replayHarness(t *testing.T, logs io.Writer) (*agentaccess.Service, *agentaccesstest.Store, string, string) {
	t.Helper()
	store := agentaccesstest.NewStore()
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	authorization, err := service.Approve(context.Background(), agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Exchange(context.Background(), authorization.Code, agentaccesstest.Verifier, "192.0.2.90", agentaccess.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, authorization.Code, issued.Token
}

// Contract section 0.1 item 82: when every attempt of the replaying request
// fails, the revocation goes on in the background with a growing wait until
// it succeeds. An outage longer than the request's attempts (the probe's 4
// failures within about 350 ms) no longer leaves the token live once the
// store recovers. One warning when it starts, one line when it ends, and a
// second replay meanwhile starts no second retry.
func TestReplayRevocationKeepsTryingInTheBackground(t *testing.T) {
	ctx := context.Background()
	logs := &lockedBuffer{}
	service, store, code, token := replayHarness(t, logs)
	agentaccess.SetReplayRetry(service, time.Millisecond, 4*time.Millisecond, time.Minute)
	store.SetFailRevokeTimes(1 << 30)
	for range 2 {
		if _, err := service.Exchange(ctx, code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("replay = %v", err)
		}
	}
	if _, err := service.Authenticate(ctx, bearer(token), "192.0.2.92"); err != nil {
		t.Fatalf("token while the store fails = %v", err)
	}
	// The background keeps attempting while the store fails.
	waitFor(t, func() bool { return store.RevokeAttemptCount() > 8+20 })
	store.SetFailRevokeTimes(0)
	waitFor(t, func() bool {
		_, err := service.Authenticate(ctx, bearer(token), "192.0.2.92")
		return codeOf(err) == agentapi.CodeTokenRevoked
	})
	waitFor(t, func() bool { return strings.Contains(logs.String(), "revoked after code replay on a background retry") })
	text := logs.String()
	if strings.Count(text, "retrying in the background") != 1 {
		t.Fatalf("a second replay started a second retry, or none was logged: %s", text)
	}
	if strings.Contains(text, "abandoned") {
		t.Fatalf("logs = %s", text)
	}
	revoked := 0
	for _, entry := range store.Audit() {
		if entry.Event == agentaccess.EventTokenRevoked {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("token_revoked rows = %d", revoked)
	}
}

// No goroutine outlives the service: Close stops a retry that is still
// failing, logs that it stopped, and no attempt is made afterwards. A replay
// after Close tries within the request only.
func TestCloseStopsTheReplayRevocationRetry(t *testing.T) {
	ctx := context.Background()
	logs := &lockedBuffer{}
	service, store, code, token := replayHarness(t, logs)
	agentaccess.SetReplayRetry(service, time.Millisecond, 2*time.Millisecond, time.Hour)
	store.SetFailRevokeTimes(1 << 30)
	_, _ = service.Exchange(ctx, code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{})
	waitFor(t, func() bool { return store.RevokeAttemptCount() > 10 })
	service.Close()
	stopped := store.RevokeAttemptCount()
	if !strings.Contains(logs.String(), "outcome=service_stopped") {
		t.Fatalf("logs = %s", logs.String())
	}
	time.Sleep(20 * time.Millisecond)
	if store.RevokeAttemptCount() != stopped {
		t.Fatal("a revocation was attempted after Close returned")
	}
	_, _ = service.Exchange(ctx, code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{})
	if store.RevokeAttemptCount() != stopped+4 {
		t.Fatalf("attempts after Close = %d, want the request's 4", store.RevokeAttemptCount()-stopped)
	}
	if _, err := service.Authenticate(ctx, bearer(token), "192.0.2.92"); err != nil {
		t.Fatalf("token = %v", err)
	}
	service.Close()
}

// A retry that never succeeds gives up after its time and says so.
func TestReplayRevocationRetryGivesUp(t *testing.T) {
	logs := &lockedBuffer{}
	service, store, code, _ := replayHarness(t, logs)
	agentaccess.SetReplayRetry(service, time.Millisecond, 2*time.Millisecond, 30*time.Millisecond)
	store.SetFailRevokeTimes(1 << 30)
	_, _ = service.Exchange(context.Background(), code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{})
	waitFor(t, func() bool { return strings.Contains(logs.String(), "outcome=gave_up") })
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 10 seconds")
		}
		time.Sleep(time.Millisecond)
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
