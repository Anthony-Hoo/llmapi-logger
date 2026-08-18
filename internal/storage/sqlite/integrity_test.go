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

// saveIntegrityChainTurn records one audit through the real capture and parse
// path, so both a capture_finalized and a semantic_compacted event are appended
// with digests derived by the write path's single-use cache.
func saveIntegrityChainTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, previousResponseID, responseID string, createdAtNS int64, request, response []graphTestItem) {
	t.Helper()
	ctx := context.Background()
	record := testAudit(auditID)
	record.ParserName = "parser"
	record.StartedAtNS = createdAtNS
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatalf("begin %s: %v", auditID, err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: createdAtNS + 1, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatalf("finish %s: %v", auditID, err)
	}
	claimed, err := store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
	}
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": responseID, "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:    map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal:   map[string]any{"id": responseID, "items": responseValues},
		PreviousResponseID: previousResponseID, ResponseID: responseID, CreatedAtNS: createdAtNS + 2,
	}, cipher)
	if err != nil {
		t.Fatalf("prepare %s: %v", auditID, err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: createdAtNS + 3},
		Turn:   &prepared,
	}); err != nil {
		t.Fatalf("save %s: %v", auditID, err)
	}
}

// buildIntegrityChain writes three turns that each continue the previous one,
// so verifying the last has to walk back through both ancestors.
func buildIntegrityChain(t *testing.T, store *Store, cipher security.Cipher) {
	t.Helper()
	developer := graphItem("developer_message", map[string]any{"role": "developer", "content": "follow policy"})
	userOne := graphItem("user_message", map[string]any{"role": "user", "content": "question one"})
	assistantOne := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer one"})
	userTwo := graphItem("user_message", map[string]any{"role": "user", "content": "question two"})
	assistantTwo := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer two"})
	userThree := graphItem("user_message", map[string]any{"role": "user", "content": "question three"})
	assistantThree := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer three"})

	saveIntegrityChainTurn(t, store, cipher, "audit-chain-1", "", "response-chain-1", 100,
		[]graphTestItem{developer, userOne}, []graphTestItem{assistantOne})
	saveIntegrityChainTurn(t, store, cipher, "audit-chain-2", "response-chain-1", "response-chain-2", 200,
		[]graphTestItem{developer, userOne, assistantOne, userTwo}, []graphTestItem{assistantTwo})
	saveIntegrityChainTurn(t, store, cipher, "audit-chain-3", "response-chain-2", "response-chain-3", 300,
		[]graphTestItem{developer, userOne, assistantOne, userTwo, assistantTwo, userThree}, []graphTestItem{assistantThree})
}

func TestVerifyIntegrityPayloadsAcceptsOneCacheSharedAcrossATurnChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x2d}, security.KeySize)
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	buildIntegrityChain(t, store, graphTestCipher(t))

	// The cache is only shared within a conversation and only pays off along a
	// parent chain, so the fixture is worthless unless all three turns linked.
	var conversations, linked int
	if err := store.readerDB.QueryRow(`SELECT COUNT(DISTINCT conversation_id), COUNT(parent_turn_id) FROM turns`).Scan(&conversations, &linked); err != nil {
		t.Fatal(err)
	}
	if conversations != 1 || linked != 2 {
		t.Fatalf("fixture built %d conversations with %d linked turns, want 1 and 2", conversations, linked)
	}
	if state := store.IntegrityPayloadState(); state != "pending" {
		t.Fatalf("payload state before verification = %q", state)
	}
	// Every digest here was written with a single-use cache, while verification
	// reuses one cache across the whole chain. Matching digests are what proves
	// both paths encode the same bytes.
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("verify intact payloads: %v", err)
	}
	if state := store.IntegrityPayloadState(); state != "verified" {
		t.Fatalf("payload state after verification = %q", state)
	}
	if !store.Healthy() {
		t.Fatal("store reports unhealthy after successful payload verification")
	}
}

func TestVerifyIntegrityPayloadsDetectsRowsChangedUnderAnIntactChain(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x6e}, security.KeySize)
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{
			name:   "capture row rewritten",
			mutate: `UPDATE audit_records SET path = '/v1/rewritten' WHERE audit_id = 'audit-chain-2'`,
		},
		{
			name:   "content object ciphertext rewritten",
			mutate: `UPDATE content_objects SET data_enc = data_enc || X'00'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "audit.db")
			store, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnableIntegrity(ctx, key); err != nil {
				t.Fatal(err)
			}
			buildIntegrityChain(t, store, graphTestCipher(t))
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			database, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(test.mutate); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			// Nothing touched integrity_events, so the chain still signs itself
			// and startup stays fast; only the rows underneath it moved.
			if err := reopened.EnableIntegrity(ctx, key); err != nil {
				t.Fatalf("chain verification rejected an intact chain: %v", err)
			}
			if err := reopened.VerifyIntegrityPayloads(ctx); err == nil {
				t.Fatal("payload verification accepted rewritten audit rows")
			}
			if state := reopened.IntegrityPayloadState(); state != "failed" {
				t.Fatalf("payload state after mismatch = %q", state)
			}
			if reopened.Healthy() {
				t.Fatal("store stayed healthy after a payload mismatch")
			}
		})
	}
}
