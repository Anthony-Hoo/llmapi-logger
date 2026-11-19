// Package agentaccesstest provides an in-memory agentaccess.Store and helpers
// that issue real agent tokens through the authorization-code flow, for the
// tests of agentaccess, the web facade and later facade endpoints.
package agentaccesstest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Store is an in-memory agentaccess.Store. Fail* make the next calls of that
// kind fail, to exercise the "log only" and upstream paths.
type Store struct {
	mu      sync.Mutex
	nextID  int64
	tokens  []storage.AgentToken
	audit   []storage.AgentAuditEntry
	touches int

	FailFind   bool
	FailCreate bool
	FailRevoke bool
	FailTouch  bool
	FailAudit  bool
	FailList   bool
	// FailRevokeTimes makes that many next revocations fail, then lets them
	// succeed again: a passing store error.
	FailRevokeTimes int
	// RevokeAttempts counts every revocation call, failed ones included.
	RevokeAttempts int
}

var _ agentaccess.Store = (*Store)(nil)

// NewStore returns an empty store.
func NewStore() *Store { return &Store{} }

func (store *Store) CreateAgentToken(_ context.Context, token storage.AgentToken) (storage.AgentToken, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.FailCreate {
		return storage.AgentToken{}, errors.New("create failed")
	}
	for _, existing := range store.tokens {
		if string(existing.TokenMAC) == string(token.TokenMAC) {
			return storage.AgentToken{}, errors.New("duplicate mac")
		}
	}
	store.nextID++
	token.ID = store.nextID
	token.TokenMAC = append([]byte(nil), token.TokenMAC...)
	token.ScopeFingerprint = append([]byte(nil), token.ScopeFingerprint...)
	if len(token.ScopeFingerprint) == 0 {
		token.ScopeFingerprint = nil
	}
	store.tokens = append(store.tokens, token)
	return token, nil
}

func (store *Store) FindAgentTokenByMAC(_ context.Context, mac []byte) (storage.AgentToken, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.FailFind {
		return storage.AgentToken{}, errors.New("find failed")
	}
	for _, token := range store.tokens {
		if string(token.TokenMAC) == string(mac) {
			return token, nil
		}
	}
	return storage.AgentToken{}, storage.ErrAgentTokenNotFound
}

func (store *Store) RevokeAgentToken(_ context.Context, id, atNS int64, scope *storage.AgentTokenScope) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.RevokeAttempts++
	if store.FailRevoke {
		return false, errors.New("revoke failed")
	}
	if store.FailRevokeTimes > 0 {
		store.FailRevokeTimes--
		return false, errors.New("revoke failed")
	}
	for index := range store.tokens {
		token := &store.tokens[index]
		if token.ID != id || token.RevokedAtNS != nil || !inScope(*token, scope) {
			continue
		}
		at := atNS
		token.RevokedAtNS = &at
		return true, nil
	}
	return false, nil
}

func (store *Store) TouchAgentToken(_ context.Context, id, atNS int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.FailTouch {
		return errors.New("touch failed")
	}
	store.touches++
	for index := range store.tokens {
		if store.tokens[index].ID == id {
			at := atNS
			store.tokens[index].LastUsedAtNS = &at
		}
	}
	return nil
}

func (store *Store) ListAgentTokens(_ context.Context, scope *storage.AgentTokenScope) ([]storage.AgentToken, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.FailList {
		return nil, errors.New("list failed")
	}
	tokens := make([]storage.AgentToken, 0)
	for index := len(store.tokens) - 1; index >= 0; index-- {
		if inScope(store.tokens[index], scope) {
			tokens = append(tokens, store.tokens[index])
		}
	}
	return tokens, nil
}

func (store *Store) InsertAgentAudit(_ context.Context, entry storage.AgentAuditEntry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.FailAudit {
		return errors.New("audit failed")
	}
	store.nextID++
	entry.ID = store.nextID
	store.audit = append(store.audit, entry)
	return nil
}

func (store *Store) ListAgentAudit(_ context.Context, limit int, events []string) ([]storage.AgentAuditEntry, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries := make([]storage.AgentAuditEntry, 0, len(store.audit))
	for _, entry := range store.audit {
		selected := len(events) == 0
		for _, event := range events {
			selected = selected || entry.Event == event
		}
		if selected {
			entries = append(entries, entry)
		}
	}
	// Newest first, ties by id, as the PostgreSQL query orders them.
	sort.SliceStable(entries, func(left, right int) bool {
		if entries[left].AtNS != entries[right].AtNS {
			return entries[left].AtNS > entries[right].AtNS
		}
		return entries[left].ID > entries[right].ID
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

// inScope mirrors the PostgreSQL scope filter: nil is the administrator view;
// otherwise developer rows with the same fingerprint and token id only.
func inScope(token storage.AgentToken, scope *storage.AgentTokenScope) bool {
	if scope == nil {
		return true
	}
	if len(scope.Fingerprint) != storage.APIKeyFingerprintSize || token.Role != storage.AgentRoleDeveloper ||
		string(token.ScopeFingerprint) != string(scope.Fingerprint) {
		return false
	}
	if (token.ScopeTokenID == nil) != (scope.TokenID == nil) {
		return false
	}
	return token.ScopeTokenID == nil || *token.ScopeTokenID == *scope.TokenID
}

// Tokens returns a copy of every stored token.
func (store *Store) Tokens() []storage.AgentToken {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]storage.AgentToken(nil), store.tokens...)
}

// Audit returns a copy of every audit row in insertion order.
func (store *Store) Audit() []storage.AgentAuditEntry {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]storage.AgentAuditEntry(nil), store.audit...)
}

// Touches counts last-used writes.
func (store *Store) Touches() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.touches
}

// Mutate edits a stored token in place, for tests that simulate a damaged or
// tampered row.
func (store *Store) Mutate(id int64, change func(*storage.AgentToken)) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for index := range store.tokens {
		if store.tokens[index].ID == id {
			change(&store.tokens[index])
		}
	}
}

// Verifier is a fixed RFC 7636 code verifier for tests; Challenge is its S256
// challenge.
const Verifier = "test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

// Challenge returns BASE64URL(SHA-256(verifier)).
func Challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// DeveloperScope is a complete developer scope for tests.
func DeveloperScope(fingerprintByte byte, tokenID int64) *agentaccess.Scope {
	id := tokenID
	return &agentaccess.Scope{
		Fingerprint: []byte(strings.Repeat(string([]byte{fingerprintByte}), storage.APIKeyFingerprintSize)),
		TokenID:     &id, UserID: 7, Username: "developer", TokenName: "agent-key",
	}
}

// Request is a valid loopback authorization request for tier.
func Request(tier agentapi.Tier) agentaccess.AuthorizationRequest {
	return agentaccess.AuthorizationRequest{
		Challenge: Challenge(Verifier), Mode: agentaccess.ModeLoopback, Port: 49152,
		DeviceName: "test-device", CLIVersion: agentapi.LatestVersion, Tier: tier,
	}
}

// Issue runs approve and exchange and returns the plaintext token.
func Issue(t testing.TB, service *agentaccess.Service, grantor agentaccess.Grantor, tier agentapi.Tier) agentaccess.Issued {
	t.Helper()
	authorization, err := service.Approve(context.Background(), grantor, Request(tier), "192.0.2.200")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	issued, err := service.Exchange(context.Background(), authorization.Code, Verifier, "192.0.2.200", agentaccess.RequestMeta{})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return issued
}

// IssueAdmin issues an administrator token of tier.
func IssueAdmin(t testing.TB, service *agentaccess.Service, tier agentapi.Tier) agentaccess.Issued {
	t.Helper()
	return Issue(t, service, agentaccess.Grantor{Role: agentapi.RoleAdmin}, tier)
}

// IssueDeveloper issues a read token for a developer session of scope that
// ends at sessionExpiresAt.
func IssueDeveloper(t testing.TB, service *agentaccess.Service, scope *agentaccess.Scope, sessionExpiresAt time.Time) agentaccess.Issued {
	t.Helper()
	return Issue(t, service, agentaccess.Grantor{Role: agentapi.RoleDeveloper, Scope: scope, SessionExpiresAt: sessionExpiresAt}, agentapi.TierRead)
}
