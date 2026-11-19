package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

func agentTestToken(mac byte, role, tier string) storage.AgentToken {
	token := storage.AgentToken{
		TokenMAC: bytes.Repeat([]byte{mac}, 32), DisplayPrefix: "lla_Ab12", Role: role, Tier: tier,
		DeviceName: "workstation", CLIVersion: "0.1.0", CreatedAtNS: 100, ExpiresAtNS: 200,
	}
	if role == storage.AgentRoleDeveloper {
		tokenID := int64(42)
		token.ScopeFingerprint = bytes.Repeat([]byte{0x5a}, 32)
		token.ScopeTokenID = &tokenID
		token.ScopeUserID = 7
		token.ScopeUsername = "developer"
		token.ScopeTokenName = "agent-key"
	}
	return token
}

func TestAgentTokenStorage(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()

	admin, err := store.CreateAgentToken(ctx, agentTestToken(1, storage.AgentRoleAdmin, storage.AgentTierWrite))
	if err != nil || admin.ID <= 0 {
		t.Fatalf("create admin token = %+v, %v", admin, err)
	}
	developer, err := store.CreateAgentToken(ctx, agentTestToken(2, storage.AgentRoleDeveloper, storage.AgentTierRead))
	if err != nil {
		t.Fatal(err)
	}
	// Same fingerprint, different NewAPI token: a different scope.
	other := agentTestToken(3, storage.AgentRoleDeveloper, storage.AgentTierRead)
	otherTokenID := int64(43)
	other.ScopeTokenID = &otherTokenID
	other, err = store.CreateAgentToken(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown identity: no token id, same fingerprint.
	unknown := agentTestToken(4, storage.AgentRoleDeveloper, storage.AgentTierRead)
	unknown.ScopeTokenID, unknown.ScopeUserID, unknown.ScopeUsername, unknown.ScopeTokenName = nil, 0, "", ""
	unknown, err = store.CreateAgentToken(ctx, unknown)
	if err != nil {
		t.Fatal(err)
	}

	found, err := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{2}, 32))
	if err != nil || found.ID != developer.ID || found.Role != storage.AgentRoleDeveloper ||
		!bytes.Equal(found.ScopeFingerprint, bytes.Repeat([]byte{0x5a}, 32)) || found.ScopeTokenID == nil || *found.ScopeTokenID != 42 ||
		found.ScopeUserID != 7 || found.ScopeUsername != "developer" || found.ScopeTokenName != "agent-key" ||
		found.RevokedAtNS != nil || found.LastUsedAtNS != nil || found.ExpiresAtNS != 200 {
		t.Fatalf("found = %+v, %v", found, err)
	}
	foundAdmin, err := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{1}, 32))
	if err != nil || foundAdmin.ScopeFingerprint != nil || foundAdmin.ScopeTokenID != nil || foundAdmin.Tier != storage.AgentTierWrite {
		t.Fatalf("admin = %+v, %v", foundAdmin, err)
	}
	if _, err := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{9}, 32)); !errors.Is(err, storage.ErrAgentTokenNotFound) {
		t.Fatalf("unknown mac: %v", err)
	}
	if _, err := store.FindAgentTokenByMAC(ctx, []byte{1}); !errors.Is(err, storage.ErrAgentTokenNotFound) {
		t.Fatalf("short mac: %v", err)
	}
	// The MAC is unique.
	if _, err := store.CreateAgentToken(ctx, agentTestToken(1, storage.AgentRoleAdmin, storage.AgentTierRead)); err == nil {
		t.Fatal("duplicate mac accepted")
	}
	if !store.Healthy() {
		t.Fatal("an isolated duplicate changed writer health")
	}

	all, err := store.ListAgentTokens(ctx, nil)
	if err != nil || len(all) != 4 || all[0].ID != unknown.ID || all[3].ID != admin.ID {
		t.Fatalf("all tokens = %+v, %v", all, err)
	}
	tokenID := int64(42)
	scope := &storage.AgentTokenScope{Fingerprint: bytes.Repeat([]byte{0x5a}, 32), TokenID: &tokenID}
	scoped, err := store.ListAgentTokens(ctx, scope)
	if err != nil || len(scoped) != 1 || scoped[0].ID != developer.ID {
		t.Fatalf("scoped tokens = %+v, %v", scoped, err)
	}
	nilScoped, err := store.ListAgentTokens(ctx, &storage.AgentTokenScope{Fingerprint: bytes.Repeat([]byte{0x5a}, 32)})
	if err != nil || len(nilScoped) != 1 || nilScoped[0].ID != unknown.ID {
		t.Fatalf("scope without token id = %+v, %v", nilScoped, err)
	}
	// An incomplete scope lists nothing rather than everything.
	if broken, err := store.ListAgentTokens(ctx, &storage.AgentTokenScope{}); err != nil || len(broken) != 0 {
		t.Fatalf("incomplete scope = %+v, %v", broken, err)
	}

	// Out-of-scope revocations revoke nothing: another developer, an admin token.
	for _, id := range []int64{other.ID, admin.ID, unknown.ID} {
		if revoked, err := store.RevokeAgentToken(ctx, id, 150, scope); err != nil || revoked {
			t.Fatalf("scoped revoke of %d = %v, %v", id, revoked, err)
		}
	}
	if revoked, err := store.RevokeAgentToken(ctx, admin.ID, 150, &storage.AgentTokenScope{}); err != nil || revoked {
		t.Fatalf("incomplete scope revoked = %v, %v", revoked, err)
	}
	if revoked, err := store.RevokeAgentToken(ctx, developer.ID, 150, scope); err != nil || !revoked {
		t.Fatalf("scoped revoke = %v, %v", revoked, err)
	}
	// Idempotent: again, unknown and administrator-wide.
	if revoked, err := store.RevokeAgentToken(ctx, developer.ID, 160, nil); err != nil || revoked {
		t.Fatalf("second revoke = %v, %v", revoked, err)
	}
	if revoked, err := store.RevokeAgentToken(ctx, 999999, 160, nil); err != nil || revoked {
		t.Fatalf("unknown revoke = %v, %v", revoked, err)
	}
	if revoked, err := store.RevokeAgentToken(ctx, admin.ID, 170, nil); err != nil || !revoked {
		t.Fatalf("admin revoke = %v, %v", revoked, err)
	}
	if again, _ := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{2}, 32)); again.RevokedAtNS == nil || *again.RevokedAtNS != 150 {
		t.Fatalf("revoked_at = %+v", again.RevokedAtNS)
	}
	if untouched, _ := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{3}, 32)); untouched.RevokedAtNS != nil {
		t.Fatal("another developer's token was revoked")
	}

	if err := store.TouchAgentToken(ctx, other.ID, 120); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchAgentToken(ctx, other.ID, 110); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchAgentToken(ctx, 999999, 110); err != nil {
		t.Fatal(err)
	}
	if touched, _ := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{3}, 32)); touched.LastUsedAtNS == nil || *touched.LastUsedAtNS != 120 {
		t.Fatalf("last used = %v", touched.LastUsedAtNS)
	}
}

func TestAgentTokenStorageRejectsInvalidRows(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	cases := map[string]func(*storage.AgentToken){
		"short mac":    func(token *storage.AgentToken) { token.TokenMAC = []byte{1} },
		"unknown role": func(token *storage.AgentToken) { token.Role = "owner" },
		"unknown tier": func(token *storage.AgentToken) { token.Tier = "admin" },
		"developer write": func(token *storage.AgentToken) {
			token.Role, token.Tier = storage.AgentRoleDeveloper, storage.AgentTierWrite
		},
		"developer without scope": func(token *storage.AgentToken) { token.Role = storage.AgentRoleDeveloper },
		"admin with scope":        func(token *storage.AgentToken) { token.ScopeFingerprint = bytes.Repeat([]byte{1}, 32) },
		"admin with identity":     func(token *storage.AgentToken) { token.ScopeUsername = "someone" },
		"empty device":            func(token *storage.AgentToken) { token.DeviceName = "" },
		"control device":          func(token *storage.AgentToken) { token.DeviceName = "dev\x00ice" },
		"long device":             func(token *storage.AgentToken) { token.DeviceName = strings.Repeat("d", 65) },
		"invalid utf8 version":    func(token *storage.AgentToken) { token.CLIVersion = "\xff" },
		"expires before creation": func(token *storage.AgentToken) { token.ExpiresAtNS = token.CreatedAtNS },
	}
	for name, mutate := range cases {
		token := agentTestToken(7, storage.AgentRoleAdmin, storage.AgentTierRead)
		mutate(&token)
		if _, err := store.CreateAgentToken(ctx, token); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !store.Healthy() {
		t.Fatal("rejected rows changed writer health")
	}
}

// Audit rows carry header-supplied text. Hostile values are sanitized, never
// rejected by PostgreSQL in a way that would fail the writer batch.
func TestAgentAuditStorageSanitizesHostileText(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	tokenID := int64(5)
	hostile := "req\x00uests.list\xff\x1b[31m" + strings.Repeat("x", 500)
	for index, entry := range []storage.AgentAuditEntry{
		{AtNS: 10, Event: "token_issued", TokenID: &tokenID, Role: "admin", Command: hostile, CLIVersion: hostile, Outcome: storage.AgentOutcomeOK},
		{AtNS: 20, Event: "token_exchange_failed", Outcome: storage.AgentOutcomeFailed, ErrorCode: "INVALID_GRANT", ObjectKind: "agent_token", ChangedKeys: `["enabled"]`},
	} {
		if err := store.InsertAgentAudit(ctx, entry); err != nil {
			t.Fatalf("insert %d: %v", index, err)
		}
	}
	if !store.Healthy() {
		t.Fatal("hostile audit text changed writer health")
	}
	for _, bad := range []storage.AgentAuditEntry{
		{AtNS: 0, Event: "token_issued", Outcome: storage.AgentOutcomeOK},
		{AtNS: 1, Event: "", Outcome: storage.AgentOutcomeOK},
		{AtNS: 1, Event: "token_issued", Outcome: "maybe"},
	} {
		if err := store.InsertAgentAudit(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	entries, err := store.ListAgentAudit(ctx, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	newest, oldest := entries[0], entries[1]
	if newest.Event != "token_exchange_failed" || newest.TokenID != nil || newest.Role != "" || newest.ErrorCode != "INVALID_GRANT" || newest.ChangedKeys != `["enabled"]` {
		t.Fatalf("newest = %+v", newest)
	}
	if oldest.TokenID == nil || *oldest.TokenID != 5 || strings.ContainsAny(oldest.Command, "\x00\x1b") ||
		len([]rune(oldest.Command)) > agentAuditTextMax || !strings.HasPrefix(oldest.Command, "requests.list") {
		t.Fatalf("oldest = %+v", oldest)
	}
	if limited, err := store.ListAgentAudit(ctx, 1); err != nil || len(limited) != 1 {
		t.Fatalf("limited = %+v, %v", limited, err)
	}
}

// Issuance and revocation wait for their definitive outcome even when the
// request is cancelled after the write was queued.
func TestAgentTokenWritesOutliveTheRequest(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"create", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			store, _ := openTestStore(t)
			existing, err := store.CreateAgentToken(ctx, agentTestToken(1, storage.AgentRoleAdmin, storage.AgentTierRead))
			if err != nil {
				t.Fatal(err)
			}
			writer := &Store{writerDB: store.writerDB, writerConn: store.writerConn, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
			requestCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "create" {
					_, err := writer.CreateAgentToken(requestCtx, agentTestToken(2, storage.AgentRoleAdmin, storage.AgentTierRead))
					done <- err
					return
				}
				_, err := writer.RevokeAgentToken(requestCtx, existing.ID, 150, nil)
				done <- err
			}()
			var request writeRequest
			select {
			case request = <-writer.queue:
			case <-time.After(time.Second):
				t.Fatal("write was not queued")
			}
			cancel()
			select {
			case err := <-done:
				t.Fatalf("queued write returned before its outcome: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			writer.queue <- request
			close(writer.queue)
			go writer.runWriter()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("agent token write hung")
			}
			<-writer.done
			if operation == "create" {
				if _, err := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{2}, 32)); err != nil {
					t.Fatalf("created token missing: %v", err)
				}
				return
			}
			if revoked, _ := store.FindAgentTokenByMAC(ctx, bytes.Repeat([]byte{1}, 32)); revoked.RevokedAtNS == nil {
				t.Fatal("revocation missing")
			}
		})
	}
}
