package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

func TestIntegrityChainCoversCaptureAndSemanticGraph(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
	path := filepath.Join(t.TempDir(), "audit.db")
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
	if err := store.BeginAudit(ctx, testAudit("audit-integrity")); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: "audit-integrity", EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimPendingParse(ctx, "audit-integrity")
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	message := map[string]any{"role": "user", "content": "integrity example"}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: "audit-integrity", Protocol: "openai", ParserName: "openai.chat_completions",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
		RequestEnvelope: map[string]any{"model": "model-example"}, ResponseEnvelope: nil,
		RequestItems:     []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: message}},
		RequestOriginal:  map[string]any{"model": "model-example", "messages": []any{message}},
		ResponseOriginal: nil, CreatedAtNS: 3,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{
			AuditID: "audit-integrity", ParserName: "openai.chat_completions",
			ParserVersion: "2", Status: ParseOK, ParsedAtNS: 4,
		},
		Turn: &prepared,
	}); err != nil {
		t.Fatal(err)
	}
	var eventCount int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM integrity_events`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 2 {
		t.Fatalf("integrity event count = %d, want capture and semantic events", eventCount)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("verify intact chain: %v", err)
	}
}

func TestAPIKeyFingerprintStaysOutsideTheEvidenceChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x71}, security.KeySize)
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	record := testAudit("audit-fingerprint")
	record.APIKeyFPR = bytes.Repeat([]byte{0x01}, APIKeyFingerprintSize)
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: "audit-fingerprint", EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}

	// api_key_fpr is an access-control index, not evidence. Rewriting it must
	// leave the capture MAC valid, because the alternative -- folding the column
	// into capturePayloadDigest -- would change the recomputed digest of every
	// audit written before this migration and fail chain verification on every
	// existing database. The tradeoff is deliberate: scope attribution is not
	// tamper evident, captured bytes still are.
	if _, err := store.writerDB.ExecContext(ctx,
		`UPDATE audit_records SET api_key_fpr = ? WHERE audit_id = ?`,
		bytes.Repeat([]byte{0x02}, APIKeyFingerprintSize), "audit-fingerprint",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("api_key_fpr must not participate in the integrity chain: %v", err)
	}
}

func TestAuditRecordRejectsMalformedFingerprint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	record := testAudit("audit-bad-fingerprint")
	record.APIKeyFPR = []byte{0x01, 0x02}
	if err := store.BeginAudit(ctx, record); err == nil {
		t.Fatal("BeginAudit accepted a short api key fingerprint")
	}
}

func TestEnableIntegrityRejectsTamperedOrMissingEvents(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x3c}, security.KeySize)
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "tampered payload digest",
			mutate: func(t *testing.T, path string) {
				database, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				if _, err := database.Exec(`UPDATE integrity_events SET payload_digest = zeroblob(32) WHERE sequence = 1`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing capture event",
			mutate: func(t *testing.T, path string) {
				database, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				if _, err := database.Exec(`DELETE FROM integrity_events`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "audit.db")
			store, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnableIntegrity(ctx, key); err != nil {
				t.Fatal(err)
			}
			if err := store.BeginAudit(ctx, testAudit("audit-tamper")); err != nil {
				t.Fatal(err)
			}
			status := 500
			if err := store.FinishAudit(ctx, AuditFinish{
				AuditID: "audit-tamper", EndedAtNS: 2, StatusCode: &status,
				ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, path)
			reopened, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := reopened.EnableIntegrity(ctx, key); err == nil {
				t.Fatal("tampered integrity database was accepted")
			}
		})
	}
}
