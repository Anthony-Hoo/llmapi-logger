package query

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/storage/sqlite"
)

// GetMetadata reads what Get reads without decrypting anything: a record whose
// encrypted content fails verification (Get answers ErrIntegrity) still gives
// its summary (contract section 0.1 item 183). Like Get it takes the caller's
// scope, which the store applies to the conversation turn count; ownership is
// Authorize's, which every caller runs first, and it refuses another key here.
func TestGetMetadataNeedsNoDecryption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := testCipher(t)
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	own, other := developerFingerprint(0x01), developerFingerprint(0x02)
	auditID := "audit-metadata-only"
	// The request URI is not a ciphertext of this key: every decryption Get
	// makes of this record fails.
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: auditID, StartedAtNS: 1, RouteID: "route-example", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
		RequestURIEnc: []byte{1, 2, 3}, Mode: "available", APIKeyFPR: own,
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: auditID, EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseSkipped,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, auditID, &Scope{Fingerprint: own}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Get of a record that does not decrypt = %v, want ErrIntegrity", err)
	}
	for name, scope := range map[string]*Scope{"owner": {Fingerprint: own}, "administrator": nil} {
		detail, err := service.GetMetadata(ctx, auditID, scope)
		if err != nil {
			t.Fatalf("%s GetMetadata = %v", name, err)
		}
		if detail.Audit.AuditID != auditID || detail.Audit.ForwardStatus != sqlite.ForwardCompleted || detail.Audit.CaptureStatus != sqlite.CaptureComplete ||
			detail.RequestURI != "" || detail.Headers != nil || detail.Conversation != nil || detail.Turn != nil || detail.ParsedResult != nil {
			t.Fatalf("%s GetMetadata = %+v", name, detail)
		}
	}
	if err := service.Authorize(ctx, auditID, &Scope{Fingerprint: other}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Authorize for another key = %v, want ErrNotFound", err)
	}
	if _, err := service.GetMetadata(ctx, "audit-missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMetadata of a missing record = %v, want ErrNotFound", err)
	}
	if _, err := service.GetMetadata(ctx, "bad id", nil); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("GetMetadata of a malformed id = %v, want ErrInvalidQuery", err)
	}
}
