package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// Integrity digests cover the stored parsed_json_enc ciphertext, so rows
// written before compression and compressed rows must both verify under
// semantic_compacted and reconstruction_failed events, and both must still
// detect a rewrite.
func TestParsedResultFormatsVerifyUnderIntegrityEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x4b}, security.KeySize)
	path := newTestDSN(t)
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"status":"partial","conversation":{"schema_version":1,"messages":[{"index":0,"role":"user","phase":"request","direction":"client_to_upstream","content":[{"index":0,"type":"text","text":"` + strings.Repeat("integrity example ", 1000) + `"}]}]}}`)

	type row struct {
		auditID    string
		compressed bool
		verified   bool
	}
	rows := []row{
		{auditID: "audit-parsed-legacy-failed"},
		{auditID: "audit-parsed-compressed-failed", compressed: true},
		{auditID: "audit-parsed-legacy-semantic", verified: true},
		{auditID: "audit-parsed-compressed-semantic", compressed: true, verified: true},
	}
	stored := make(map[string][]byte)
	for _, item := range rows {
		record := testAudit(item.auditID)
		if err := store.BeginAudit(ctx, record); err != nil {
			t.Fatal(err)
		}
		status := 200
		if err := store.FinishAudit(ctx, AuditFinish{
			AuditID: item.auditID, EndedAtNS: 2, StatusCode: &status,
			ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
		if claimed, err := store.ClaimPendingParse(ctx, item.auditID); err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", item.auditID, claimed, err)
		}
		var sealed []byte
		if item.compressed {
			sealed, err = auditmodel.SealParsedResult(cipher, item.auditID, record.ParserName, plaintext)
		} else {
			// Exactly what the base commit's writer stored.
			aad, aadErr := security.AAD(item.auditID, "parsed_json", record.ParserName)
			if aadErr != nil {
				t.Fatal(aadErr)
			}
			sealed, err = cipher.Encrypt(aad, plaintext)
		}
		if err != nil {
			t.Fatal(err)
		}
		stored[item.auditID] = sealed
		result := ParsedResult{
			AuditID: item.auditID, ParserName: record.ParserName, ParserVersion: "2",
			Status: ParsePartial, ParsedJSONEnc: sealed, ParsedAtNS: 4,
		}
		var turn *auditmodel.PreparedTurn
		if item.verified {
			message := map[string]any{"role": "user", "content": "integrity example"}
			prepared, err := auditmodel.Prepare(auditmodel.Turn{
				AuditID: item.auditID, Protocol: "openai", ParserName: record.ParserName,
				RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
				RequestEnvelope: map[string]any{"model": "model-example"},
				RequestItems:    []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: message}},
				RequestOriginal: map[string]any{"model": "model-example", "messages": []any{message}},
				CreatedAtNS:     3,
			}, cipher)
			if err != nil {
				t.Fatal(err)
			}
			turn = &prepared
		} else {
			code := "reconstruction_failed"
			result.ErrorCode = &code
		}
		if err := store.SaveParsedAudit(ctx, ParsedAudit{Result: result, Turn: turn}); err != nil {
			t.Fatal(err)
		}
	}

	var semantic, failed int
	if err := store.readerDB.QueryRow(`
SELECT COUNT(*) FILTER (WHERE event_type = 'semantic_compacted'),
       COUNT(*) FILTER (WHERE event_type = 'reconstruction_failed')
FROM integrity_events`).Scan(&semantic, &failed); err != nil {
		t.Fatal(err)
	}
	if semantic != 2 || failed != 2 {
		t.Fatalf("events: semantic_compacted=%d reconstruction_failed=%d, want 2 and 2", semantic, failed)
	}
	for _, item := range rows {
		detail, err := store.QueryAuditDetail(ctx, item.auditID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if detail.ParsedResult == nil || !bytes.Equal(detail.ParsedResult.ParsedJSONEnc, stored[item.auditID]) {
			t.Fatalf("%s: stored ciphertext changed on the way in", item.auditID)
		}
		opened, err := auditmodel.OpenParsedResult(cipher, item.auditID, detail.Audit.ParserName, detail.ParsedResult.ParsedJSONEnc)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("%s: read back = %v", item.auditID, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if err := reopened.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("verify payloads of legacy and compressed rows: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	// A compressed row is signed over its own ciphertext: replacing it with
	// another valid compressed seal of the same JSON must still be caught.
	resealed, err := auditmodel.SealParsedResult(cipher, "audit-parsed-compressed-failed", testAudit("x").ParserName, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("pgx", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE parsed_results SET parsed_json_enc = $1 WHERE audit_id = 'audit-parsed-compressed-failed'`, resealed); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	tampered, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tampered.Close() })
	if err := tampered.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("chain verification rejected an intact chain: %v", err)
	}
	if err := tampered.VerifyIntegrityPayloads(ctx); err == nil {
		t.Fatal("payload verification accepted a rewritten compressed parsed result")
	}
}
