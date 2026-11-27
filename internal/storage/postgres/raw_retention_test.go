package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// perSideAudit describes one audit written through the store the way the
// capture and the parser write it, with all four stages carrying a body.
type perSideAudit struct {
	id            string
	status        *int
	forward       string
	capture       string
	upstreamClass *string
	// mismatch makes request_sent differ from request_received, as the
	// capture records it: body_stage_mismatch on a partial request_sent.
	mismatch bool
}

func perSideStatus(code int) *int { return &code }

func perSideChunk(t *testing.T, cipher security.Cipher, auditID, stage string, plaintext []byte) BodyChunk {
	t.Helper()
	aad, err := security.AAD(auditID, "body_chunk_v2", stage, strconv.FormatInt(0, 10), "none")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return BodyChunk{
		AuditID: auditID, Stage: stage, Seq: 0, Offset: 0, PlaintextLength: len(plaintext),
		EncodedLength: len(plaintext), Compression: "none", ObservedAtNS: 3, DataEnc: ciphertext,
	}
}

var perSideRequest = []byte(`{"model":"model-example","messages":[{"role":"user","content":"per side example"}]}`)
var perSideResponse = []byte(`{"error":{"message":"upstream example failure"}}`)

func writePerSideAudit(t *testing.T, store *Store, cipher security.Cipher, audit perSideAudit) {
	t.Helper()
	ctx := context.Background()
	if err := store.BeginAudit(ctx, testAudit(audit.id)); err != nil {
		t.Fatal(err)
	}
	bodies := map[string][]byte{
		StageRequestReceived:  perSideRequest,
		StageRequestSent:      perSideRequest,
		StageResponseReceived: perSideResponse,
		StageResponseSent:     perSideResponse,
	}
	if audit.mismatch {
		bodies[StageRequestSent] = append(append([]byte(nil), perSideRequest[:len(perSideRequest)-1]...), ' ', '}')
	}
	for _, stage := range []string{StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent} {
		httpStage := HTTPStage{AuditID: audit.id, Stage: stage, Proto: "HTTP/1.1", Method: "POST", Host: "newapi.example.com", StartedAtNS: 2}
		if stage == StageResponseReceived || stage == StageResponseSent {
			httpStage.StatusCode = audit.status
		}
		if err := store.StartStage(ctx, httpStage); err != nil {
			t.Fatal(err)
		}
		if err := store.StartBody(ctx, BodyStream{AuditID: audit.id, Stage: stage}); err != nil {
			t.Fatal(err)
		}
		body := bodies[stage]
		if err := store.AddChunk(ctx, perSideChunk(t, cipher, audit.id, stage, body)); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		finish := StageFinish{
			AuditID: audit.id, Stage: stage, State: StageStateComplete, StatusCode: httpStage.StatusCode, EndedAtNS: 4,
			Body: &BodyFinish{
				ObservedLength: int64(len(body)), StoredLength: int64(len(body)), SHA256: digest[:],
				HashComplete: true, EOFSeen: true, State: StageStateComplete, ChunkCount: 1,
			},
		}
		if audit.mismatch && stage == StageRequestSent {
			code := "body_stage_mismatch"
			finish.State, finish.ErrorCode = StageStatePartial, &code
			finish.Body.State, finish.Body.ErrorCode = StageStatePartial, &code
		}
		if err := store.FinishStage(ctx, finish); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: audit.id, EndedAtNS: 5, StatusCode: audit.status,
		ForwardStatus: audit.forward, CaptureStatus: audit.capture, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimPendingParse(ctx, audit.id)
	if err != nil || !claimed {
		t.Fatalf("claim %s = %v, %v", audit.id, claimed, err)
	}
	var request map[string]any
	if err := json.Unmarshal(perSideRequest, &request); err != nil {
		t.Fatal(err)
	}
	messages := request["messages"].([]any)
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: audit.id, Protocol: "openai", ParserName: "openai.chat_completions",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
		RequestEnvelope: map[string]any{"model": "model-example"},
		RequestItems:    []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: messages[0]}},
		RequestOriginal: request, CreatedAtNS: 6,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{
			AuditID: audit.id, ParserName: "openai.chat_completions", ParserVersion: "2",
			Status: ParseOK, UpstreamErrorClass: audit.upstreamClass, ParsedAtNS: 7,
		},
		Turn: &prepared,
	}); err != nil {
		t.Fatal(err)
	}
}

type perSideStageState struct {
	retention   string
	sourceStage string
	stored      int64
	chunkCount  int64
	chunks      int
}

func readPerSideStages(t *testing.T, store *Store, auditID string) map[string]perSideStageState {
	t.Helper()
	rows, err := store.readerDB.Query(`
SELECT b.stage, b.retention_state, b.source_stage, b.stored_length, b.chunk_count,
       (SELECT COUNT(*) FROM body_chunks AS c WHERE c.audit_id = b.audit_id AND c.stage = b.stage)
FROM body_streams AS b WHERE b.audit_id = $1`, auditID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	states := make(map[string]perSideStageState)
	for rows.Next() {
		var stage string
		var state perSideStageState
		if err := rows.Scan(&stage, &state.retention, &state.sourceStage, &state.stored, &state.chunkCount, &state.chunks); err != nil {
			t.Fatal(err)
		}
		states[stage] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

// sideOf reports the retention a side's two stages ended with, and checks the
// stored counters and chunks match it.
func sideOf(t *testing.T, name string, states map[string]perSideStageState, first, second string) string {
	t.Helper()
	left, right := states[first], states[second]
	if left.retention != right.retention {
		t.Fatalf("%s: %s is %s but %s is %s", name, first, left.retention, second, right.retention)
	}
	for stage, state := range map[string]perSideStageState{first: left, second: right} {
		if state.retention == RetentionMetadata && (state.stored != 0 || state.chunkCount != 0 || state.chunks != 0) {
			t.Fatalf("%s: released %s kept stored=%d chunk_count=%d chunks=%d", name, stage, state.stored, state.chunkCount, state.chunks)
		}
	}
	if left.retention == RetentionFull && left.chunks+right.chunks == 0 {
		t.Fatalf("%s: retained side %s/%s has no chunks", name, first, second)
	}
	return left.retention
}

func openPerSideStore(t *testing.T) (*Store, string, []byte, security.Cipher) {
	t.Helper()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
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
	return store, path, key, cipher
}

// verifyReopened closes the store and proves on a fresh one that the chain
// and every event's payload digest still verify.
func verifyReopened(t *testing.T, store *Store, path string, key []byte) *Store {
	t.Helper()
	ctx := context.Background()
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
	return reopened
}

func TestRawRetentionIsDecidedPerSide(t *testing.T) {
	t.Parallel()

	store, path, key, cipher := openPerSideStore(t)
	class := upstreamClassPointer("content_policy")
	cases := []struct {
		audit             perSideAudit
		request, response string
		merged            bool
	}{
		{perSideAudit{id: "per-side-200", status: perSideStatus(200), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionMetadata, true},
		{perSideAudit{id: "per-side-500", status: perSideStatus(500), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-503", status: perSideStatus(503), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-429", status: perSideStatus(429), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-401", status: perSideStatus(401), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-403", status: perSideStatus(403), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-408", status: perSideStatus(408), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-409", status: perSideStatus(409), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-499", status: perSideStatus(499), forward: ForwardCompleted, capture: CaptureComplete}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-400-classified", status: perSideStatus(400), forward: ForwardCompleted, capture: CaptureComplete, upstreamClass: class}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-422-classified", status: perSideStatus(422), forward: ForwardCompleted, capture: CaptureComplete, upstreamClass: class}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-400", status: perSideStatus(400), forward: ForwardCompleted, capture: CaptureComplete}, RetentionFull, RetentionFull, true},
		{perSideAudit{id: "per-side-422", status: perSideStatus(422), forward: ForwardCompleted, capture: CaptureComplete}, RetentionFull, RetentionFull, true},
		{perSideAudit{id: "per-side-404", status: perSideStatus(404), forward: ForwardCompleted, capture: CaptureComplete}, RetentionFull, RetentionFull, true},
		{perSideAudit{id: "per-side-413", status: perSideStatus(413), forward: ForwardCompleted, capture: CaptureComplete}, RetentionFull, RetentionFull, true},
		{perSideAudit{id: "per-side-cancelled", status: perSideStatus(200), forward: ForwardClientCancelled, capture: CapturePartial}, RetentionMetadata, RetentionFull, true},
		{perSideAudit{id: "per-side-mismatch-503", status: perSideStatus(503), forward: ForwardCompleted, capture: CapturePartial, mismatch: true}, RetentionFull, RetentionFull, false},
	}
	for _, test := range cases {
		writePerSideAudit(t, store, cipher, test.audit)
	}
	for _, test := range cases {
		states := readPerSideStages(t, store, test.audit.id)
		if merged := states[StageRequestSent].sourceStage == StageRequestReceived; merged != test.merged {
			t.Fatalf("%s: request stages merged = %v, want %v", test.audit.id, merged, test.merged)
		}
		if got := sideOf(t, test.audit.id, states, StageRequestReceived, StageRequestSent); got != test.request {
			t.Errorf("%s: request side = %s, want %s", test.audit.id, got, test.request)
		}
		if got := sideOf(t, test.audit.id, states, StageResponseReceived, StageResponseSent); got != test.response {
			t.Errorf("%s: response side = %s, want %s", test.audit.id, got, test.response)
		}
		if test.audit.mismatch && (states[StageRequestReceived].chunks != 1 || states[StageRequestSent].chunks != 1) {
			t.Errorf("%s: a mismatched request must keep both copies, chunks = %d and %d", test.audit.id,
				states[StageRequestReceived].chunks, states[StageRequestSent].chunks)
		}
	}

	reopened := verifyReopened(t, store, path, key)
	service, err := query.New(reopened, cipher)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// A released request answers as a released body does; the retained
	// response of the same audit still downloads byte for byte, and the
	// request is rebuilt from the turn.
	var discard bytes.Buffer
	if err := service.StreamRaw(ctx, "per-side-503", query.SideRequest, &discard); !errors.Is(err, query.ErrNotRetained) {
		t.Fatalf("released request raw = %v, want ErrNotRetained", err)
	}
	var response bytes.Buffer
	if err := service.StreamRaw(ctx, "per-side-503", query.SideResponse, &response); err != nil || !bytes.Equal(response.Bytes(), perSideResponse) {
		t.Fatalf("retained response raw = %q, %v", response.Bytes(), err)
	}
	reconstructed, err := service.ReconstructTurn(ctx, "per-side-503")
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := json.Marshal(reconstructed.Request)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, rebuilt) != canonicalJSON(t, perSideRequest) {
		t.Fatalf("rebuilt request = %s", rebuilt)
	}
}

func canonicalJSON(t *testing.T, value []byte) string {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := auditmodel.CanonicalJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

// An abnormal audit written by an older binary kept all four stages full and
// was signed that way. The new rule must neither rewrite nor reject it.
func TestRawRetentionOldRuleRowsStillVerifyAndRead(t *testing.T) {
	store, path, key, cipher := openPerSideStore(t)
	previous := rawRetentionDecision
	rawRetentionDecision = func(outcome storage.RawRetentionOutcome) storage.RawRetention {
		// The rule before per-side retention: both sides or neither.
		if outcome.ForwardStatus == ForwardCompleted && outcome.CaptureStatus == CaptureComplete &&
			outcome.StatusCode != nil && *outcome.StatusCode >= 200 && *outcome.StatusCode < 400 {
			return storage.RawRetention{ReleaseRequest: true, ReleaseResponse: true}
		}
		return storage.RawRetention{}
	}
	writePerSideAudit(t, store, cipher, perSideAudit{id: "old-rule-503", status: perSideStatus(503), forward: ForwardCompleted, capture: CaptureComplete})
	rawRetentionDecision = previous
	// One audit under the new rule in the same chain.
	writePerSideAudit(t, store, cipher, perSideAudit{id: "new-rule-503", status: perSideStatus(503), forward: ForwardCompleted, capture: CaptureComplete})

	states := readPerSideStages(t, store, "old-rule-503")
	if states[StageRequestSent].sourceStage != StageRequestReceived {
		t.Fatalf("old-rule request stages were not merged: %+v", states)
	}
	if request := sideOf(t, "old-rule-503", states, StageRequestReceived, StageRequestSent); request != RetentionFull {
		t.Fatalf("old-rule request side = %s, want full", request)
	}
	if response := sideOf(t, "old-rule-503", states, StageResponseReceived, StageResponseSent); response != RetentionFull {
		t.Fatalf("old-rule response side = %s, want full", response)
	}
	var semantic int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM integrity_events WHERE audit_id = $1 AND event_type = $2`,
		"old-rule-503", integritySemanticCompacted).Scan(&semantic); err != nil || semantic != 1 {
		t.Fatalf("old-rule semantic events = %d, %v", semantic, err)
	}

	reopened := verifyReopened(t, store, path, key)
	service, err := query.New(reopened, cipher)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for side, want := range map[query.Side][]byte{query.SideRequest: perSideRequest, query.SideResponse: perSideResponse} {
		var body bytes.Buffer
		if err := service.StreamRaw(ctx, "old-rule-503", side, &body); err != nil || !bytes.Equal(body.Bytes(), want) {
			t.Fatalf("old-rule %s raw = %q, %v", side, body.Bytes(), err)
		}
	}
	if _, err := service.ReconstructTurn(ctx, "old-rule-503"); err != nil {
		t.Fatalf("old-rule turn: %v", err)
	}
	if after := readPerSideStages(t, reopened, "old-rule-503"); after[StageRequestReceived].retention != RetentionFull {
		t.Fatalf("old-rule row was rewritten: %+v", after)
	}
}
