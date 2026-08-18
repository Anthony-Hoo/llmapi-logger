package query

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func developerFingerprint(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, sqlite.APIKeyFingerprintSize)
}

func int64Pointer(value int64) *int64 { return &value }

func stringPointer(value string) *string { return &value }

func newScopeService(t *testing.T, rows map[string]sqlite.AuditScopeRow) *Service {
	t.Helper()
	cipher, err := security.NewAESGCM(make([]byte, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(&fakeStore{healthy: true, scopeRows: rows}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// A developer must see the requests their key actually sent, including the ones
// the upstream refused, but never the ones this proxy blocked for policy
// reasons: blocked_by and block_code describe the protection rules themselves.
func TestAuthorizeHidesPolicyBlockedRecordsFromDeveloperSessions(t *testing.T) {
	t.Parallel()
	own := developerFingerprint(0x01)
	rows := map[string]sqlite.AuditScopeRow{
		"apx_forwarded": {
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardCompleted,
		},
		"apx_upstream_401": {
			// NewAPI itself refused the key: forwarded, so still the
			// developer's own call chain.
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardCompleted,
		},
		"apx_user_agent_blocked": {
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardRejected,
			BlockCode: stringPointer("user_agent_not_allowed"),
		},
		"apx_credential_required": {
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardRejected,
			BlockCode: stringPointer("credential_required"),
		},
		"apx_body_too_large": {
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardRejected,
			BlockCode: stringPointer("body_too_large"),
		},
		"apx_future_policy": {
			// A block code this build has never heard of must stay hidden;
			// the allow list fails closed on purpose.
			APIKeyFPR: own, ForwardStatus: sqlite.ForwardRejected,
			BlockCode: stringPointer("some_future_policy"),
		},
	}
	service := newScopeService(t, rows)
	scope := &Scope{Fingerprint: own}

	visible := []string{"apx_forwarded", "apx_upstream_401", "apx_body_too_large"}
	for _, auditID := range visible {
		if err := service.Authorize(context.Background(), auditID, scope); err != nil {
			t.Fatalf("Authorize(%s) = %v, want visible", auditID, err)
		}
	}
	hidden := []string{"apx_user_agent_blocked", "apx_credential_required", "apx_future_policy"}
	for _, auditID := range hidden {
		if err := service.Authorize(context.Background(), auditID, scope); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Authorize(%s) = %v, want ErrNotFound", auditID, err)
		}
	}

	// The same records stay fully readable for the administrator, whose
	// session carries no scope.
	for auditID := range rows {
		if err := service.Authorize(context.Background(), auditID, nil); err != nil {
			t.Fatalf("administrator Authorize(%s) = %v, want visible", auditID, err)
		}
	}
}

func TestAuthorizeMatchesFingerprintOrLinkedToken(t *testing.T) {
	t.Parallel()
	own := developerFingerprint(0x01)
	other := developerFingerprint(0x02)
	rows := map[string]sqlite.AuditScopeRow{
		"apx_by_fingerprint": {APIKeyFPR: own, ForwardStatus: sqlite.ForwardCompleted},
		"apx_by_token_link": {
			// Captured before this database stored fingerprints, attributed
			// later through the NewAPI request log.
			NewAPITokenID: int64Pointer(42), ForwardStatus: sqlite.ForwardCompleted,
		},
		"apx_other_key":   {APIKeyFPR: other, ForwardStatus: sqlite.ForwardCompleted},
		"apx_other_token": {NewAPITokenID: int64Pointer(43), ForwardStatus: sqlite.ForwardCompleted},
		"apx_anonymous":   {ForwardStatus: sqlite.ForwardCompleted},
	}
	service := newScopeService(t, rows)

	withToken := &Scope{Fingerprint: own, TokenID: int64Pointer(42)}
	for _, auditID := range []string{"apx_by_fingerprint", "apx_by_token_link"} {
		if err := service.Authorize(context.Background(), auditID, withToken); err != nil {
			t.Fatalf("Authorize(%s) = %v, want visible", auditID, err)
		}
	}
	for _, auditID := range []string{"apx_other_key", "apx_other_token", "apx_anonymous", "apx_missing"} {
		if err := service.Authorize(context.Background(), auditID, withToken); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Authorize(%s) = %v, want ErrNotFound", auditID, err)
		}
	}

	// A key NewAPI could not identify yet scopes by fingerprint alone and must
	// not fall back to matching every unlinked record.
	withoutToken := &Scope{Fingerprint: own}
	if err := service.Authorize(context.Background(), "apx_by_fingerprint", withoutToken); err != nil {
		t.Fatalf("Authorize by fingerprint = %v, want visible", err)
	}
	if err := service.Authorize(context.Background(), "apx_by_token_link", withoutToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Authorize by token link without a token id = %v, want ErrNotFound", err)
	}
}

func TestAuthorizeRejectsMalformedScope(t *testing.T) {
	t.Parallel()
	service := newScopeService(t, map[string]sqlite.AuditScopeRow{
		"apx_audit": {APIKeyFPR: developerFingerprint(0x01), ForwardStatus: sqlite.ForwardCompleted},
	})
	for _, scope := range []*Scope{
		{Fingerprint: nil},
		{Fingerprint: []byte{0x01, 0x02}},
		{Fingerprint: developerFingerprint(0x01), TokenID: int64Pointer(-1)},
	} {
		if err := service.Authorize(context.Background(), "apx_audit", scope); err == nil {
			t.Fatalf("Authorize accepted malformed scope %+v", scope)
		}
	}
}

func TestListPassesScopeToStorage(t *testing.T) {
	t.Parallel()
	cipher, err := security.NewAESGCM(make([]byte, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	var seen *sqlite.AuditScope
	store := &fakeStore{
		healthy: true,
		listFunc: func(filter sqlite.AuditQueryFilter, _ sqlite.AuditQueryCursor, _ int) (sqlite.AuditListPage, error) {
			seen = filter.Scope
			return sqlite.AuditListPage{}, nil
		},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}

	own := developerFingerprint(0x01)
	if _, err := service.List(context.Background(), Filter{
		Scope: &Scope{Fingerprint: own, TokenID: int64Pointer(42)},
	}, Cursor{}, 50); err != nil {
		t.Fatal(err)
	}
	if seen == nil || !bytes.Equal(seen.Fingerprint, own) || seen.TokenID == nil || *seen.TokenID != 42 {
		t.Fatalf("storage scope = %+v, want the session scope", seen)
	}

	// The user-agent path pages through storage in batches; every batch must
	// carry the scope or the substring filter would read other tenants' rows.
	seen = nil
	if _, err := service.List(context.Background(), Filter{
		UserAgent: "agent",
		Scope:     &Scope{Fingerprint: own},
	}, Cursor{}, 50); err != nil {
		t.Fatal(err)
	}
	if seen == nil || !bytes.Equal(seen.Fingerprint, own) {
		t.Fatalf("user agent scan scope = %+v, want the session scope", seen)
	}

	if _, err := service.List(context.Background(), Filter{
		Scope: &Scope{Fingerprint: []byte{0x01}},
	}, Cursor{}, 50); err == nil {
		t.Fatal("List accepted a malformed scope")
	}
}
