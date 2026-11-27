package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// The SQLite twin of the PostgreSQL per-side retention test: the parser,
// query, web and proxy host suites run on this store, so it must apply the
// same rule.

var perSideRequest = []byte(`{"model":"model-example","messages":[{"role":"user","content":"per side example"}]}`)
var perSideResponse = []byte(`{"error":{"message":"upstream example failure"}}`)

func writePerSideAudit(t *testing.T, store *Store, cipher security.Cipher, auditID string, status int, forward, capture string, class *string, mismatch bool) {
	t.Helper()
	ctx := context.Background()
	if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent} {
		body := perSideRequest
		if stage == StageResponseReceived || stage == StageResponseSent {
			body = perSideResponse
		}
		if mismatch && stage == StageRequestSent {
			body = append(append([]byte(nil), perSideRequest[:len(perSideRequest)-1]...), ' ', '}')
		}
		httpStage := HTTPStage{AuditID: auditID, Stage: stage, Proto: "HTTP/1.1", Method: "POST", Host: "newapi.example.com", StartedAtNS: 2}
		if stage == StageResponseReceived || stage == StageResponseSent {
			httpStage.StatusCode = &status
		}
		if err := store.StartStage(ctx, httpStage); err != nil {
			t.Fatal(err)
		}
		if err := store.StartBody(ctx, BodyStream{AuditID: auditID, Stage: stage}); err != nil {
			t.Fatal(err)
		}
		aad, err := security.AAD(auditID, "body_chunk_v2", stage, strconv.FormatInt(0, 10), "none")
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := cipher.Encrypt(aad, body)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.AddChunk(ctx, BodyChunk{
			AuditID: auditID, Stage: stage, PlaintextLength: len(body), EncodedLength: len(body),
			Compression: "none", ObservedAtNS: 3, DataEnc: ciphertext,
		}); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		finish := StageFinish{
			AuditID: auditID, Stage: stage, State: StageStateComplete, StatusCode: httpStage.StatusCode, EndedAtNS: 4,
			Body: &BodyFinish{
				ObservedLength: int64(len(body)), StoredLength: int64(len(body)), SHA256: digest[:],
				HashComplete: true, EOFSeen: true, State: StageStateComplete, ChunkCount: 1,
			},
		}
		if mismatch && stage == StageRequestSent {
			code := "body_stage_mismatch"
			finish.State, finish.ErrorCode = StageStatePartial, &code
			finish.Body.State, finish.Body.ErrorCode = StageStatePartial, &code
		}
		if err := store.FinishStage(ctx, finish); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: 5, StatusCode: &status,
		ForwardStatus: forward, CaptureStatus: capture, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
	}
	var request map[string]any
	if err := json.Unmarshal(perSideRequest, &request); err != nil {
		t.Fatal(err)
	}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "openai.chat_completions",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
		RequestEnvelope: map[string]any{"model": "model-example"},
		RequestItems:    []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: request["messages"].([]any)[0]}},
		RequestOriginal: request, CreatedAtNS: 6,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{
			AuditID: auditID, ParserName: "openai.chat_completions", ParserVersion: "2",
			Status: ParseOK, UpstreamErrorClass: class, ParsedAtNS: 7,
		},
		Turn: &prepared,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRawRetentionIsDecidedPerSide(t *testing.T) {
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
	class := "content_policy"
	cases := []struct {
		id                string
		status            int
		forward, capture  string
		class             *string
		mismatch          bool
		request, response string
	}{
		{"per-side-200", 200, ForwardCompleted, CaptureComplete, nil, false, RetentionMetadata, RetentionMetadata},
		{"per-side-503", 503, ForwardCompleted, CaptureComplete, nil, false, RetentionMetadata, RetentionFull},
		{"per-side-429", 429, ForwardCompleted, CaptureComplete, nil, false, RetentionMetadata, RetentionFull},
		{"per-side-400-classified", 400, ForwardCompleted, CaptureComplete, &class, false, RetentionMetadata, RetentionFull},
		{"per-side-400", 400, ForwardCompleted, CaptureComplete, nil, false, RetentionFull, RetentionFull},
		{"per-side-404", 404, ForwardCompleted, CaptureComplete, nil, false, RetentionFull, RetentionFull},
		{"per-side-cancelled", 200, ForwardClientCancelled, CapturePartial, nil, false, RetentionMetadata, RetentionFull},
		{"per-side-mismatch-503", 503, ForwardCompleted, CapturePartial, nil, true, RetentionFull, RetentionFull},
	}
	for _, test := range cases {
		writePerSideAudit(t, store, cipher, test.id, test.status, test.forward, test.capture, test.class, test.mismatch)
	}
	for _, test := range cases {
		rows, err := store.readerDB.Query(`
SELECT b.stage, b.retention_state, b.stored_length, b.chunk_count,
       (SELECT COUNT(*) FROM body_chunks AS c WHERE c.audit_id = b.audit_id AND c.stage = b.stage)
FROM body_streams AS b WHERE b.audit_id = ?`, test.id)
		if err != nil {
			t.Fatal(err)
		}
		chunks := make(map[string]int)
		for rows.Next() {
			var stage, retention string
			var stored, chunkCount int64
			var count int
			if err := rows.Scan(&stage, &retention, &stored, &chunkCount, &count); err != nil {
				t.Fatal(err)
			}
			want := test.request
			if stage == StageResponseReceived || stage == StageResponseSent {
				want = test.response
			}
			if retention != want {
				t.Errorf("%s: %s retention = %s, want %s", test.id, stage, retention, want)
			}
			if retention == RetentionMetadata && (stored != 0 || chunkCount != 0 || count != 0) {
				t.Errorf("%s: released %s kept stored=%d chunk_count=%d chunks=%d", test.id, stage, stored, chunkCount, count)
			}
			chunks[stage] = count
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if test.response == RetentionFull && chunks[StageResponseReceived] != 1 {
			t.Errorf("%s: retained response chunks = %v", test.id, chunks)
		}
		if test.mismatch && (chunks[StageRequestReceived] != 1 || chunks[StageRequestSent] != 1) {
			t.Errorf("%s: a mismatched request must keep both copies, chunks = %v", test.id, chunks)
		}
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
		t.Fatalf("integrity chain: %v", err)
	}
	if err := reopened.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity payloads: %v", err)
	}
}
