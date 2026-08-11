package sqlite

import (
	"context"
	"testing"
)

func TestUpsertTokenLinkIsIdempotentAndUpdatesSnapshot(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-token-link")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}

	first := TokenLink{
		AuditID: record.AuditID, NewAPITokenID: 41,
		TokenName: "personal", MaskedKey: "sk-...1234", LinkedAtNS: 2,
	}
	if err := store.UpsertTokenLink(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTokenLink(ctx, first); err != nil {
		t.Fatal(err)
	}
	updated := TokenLink{
		AuditID: record.AuditID, NewAPITokenID: 42,
		TokenName: "renamed", MaskedKey: "sk-...5678", LinkedAtNS: 3,
	}
	if err := store.UpsertTokenLink(ctx, updated); err != nil {
		t.Fatal(err)
	}

	var count int
	var got TokenLink
	if err := store.readerDB.QueryRow(`
SELECT COUNT(*), audit_id, newapi_token_id, token_name, masked_key, linked_at_ns
FROM token_links
WHERE audit_id = ?`, record.AuditID).Scan(
		&count, &got.AuditID, &got.NewAPITokenID, &got.TokenName, &got.MaskedKey, &got.LinkedAtNS,
	); err != nil {
		t.Fatal(err)
	}
	if count != 1 || got != updated {
		t.Fatalf("token link count=%d got=%+v want=%+v", count, got, updated)
	}
}

func TestUpsertTokenLinkValidatesInputAndRequiresAuditParent(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.UpsertTokenLink(ctx, TokenLink{}); err == nil {
		t.Fatal("expected invalid token link error")
	}
	if err := store.UpsertTokenLink(ctx, TokenLink{
		AuditID: "missing", NewAPITokenID: 1, TokenName: "personal",
		MaskedKey: "sk-...1234", LinkedAtNS: 1,
	}); err == nil {
		t.Fatal("expected missing audit foreign-key error")
	}
	var count int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM token_links").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed token link write left %d rows", count)
	}
}
