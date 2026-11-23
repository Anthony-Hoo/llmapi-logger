package query

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"llmapi-logger/internal/auditmodel"
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

// GetMetadata does not read the turn graph at all (contract section 0.1 item
// 185): a record whose stored graph fails the store's own sequence check,
// so that Get fails, still gives the summary, stages and bodies Get gave
// while it was intact.
func TestGetMetadataSurvivesADamagedTurnGraph(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := testCipher(t)
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	own := developerFingerprint(0x01)
	auditID := "audit-metadata-damaged-graph"
	requestURI, err := cipher.Encrypt([]byte(auditID+"\x00request_uri"), []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: auditID, StartedAtNS: 1, RouteID: "route-example", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
		RequestURIEnc: requestURI, Mode: "available", APIKeyFPR: own,
	}); err != nil {
		t.Fatal(err)
	}
	stage := sqlite.HTTPStage{AuditID: auditID, Stage: sqlite.StageRequestSent, Proto: "HTTP/1.1", Method: "POST", Host: "upstream.example.com", StartedAtNS: 2}
	if err := store.StartStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, sqlite.BodyStream{AuditID: auditID, Stage: stage.Stage}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishStage(ctx, sqlite.StageFinish{AuditID: auditID, Stage: stage.Stage, State: sqlite.StageStateComplete, EndedAtNS: 3,
		Body: &sqlite.BodyFinish{State: sqlite.StageStateComplete, HashComplete: true, EOFSeen: true}}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: auditID, EndedAtNS: 4, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimPendingParse(ctx, auditID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	requestMessage := map[string]any{"role": "user", "content": "request text"}
	responseMessage := map[string]any{"role": "assistant", "content": "response text"}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "openai.chat_completions",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope: map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{
			"id":      "response-example",
			"choices": []any{map[string]any{"message": auditmodel.ItemMarker(0)}},
		},
		RequestItems:     []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: requestMessage}},
		ResponseItems:    []auditmodel.Item{{Slot: auditmodel.SlotChoice, Kind: "assistant_message", Value: responseMessage}},
		RequestOriginal:  map[string]any{"model": "model-example", "messages": []any{requestMessage}},
		ResponseOriginal: map[string]any{"id": "response-example", "choices": []any{map[string]any{"message": responseMessage}}},
		ResponseID:       "response-example", CreatedAtNS: 5,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, sqlite.ParsedAudit{
		Result: sqlite.ParsedResult{AuditID: auditID, ParserName: "openai.chat_completions", ParserVersion: "2", Status: sqlite.ParseOK, ParsedAtNS: 6},
		Turn:   &prepared,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	scope := &Scope{Fingerprint: own}
	intact, err := service.Get(ctx, auditID, scope)
	if err != nil || intact.Turn == nil || len(intact.Stages) != 1 || len(intact.Bodies) != 1 {
		t.Fatalf("Get of the intact record = %+v, %v", intact, err)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `UPDATE turns SET request_sequence_hash = zeroblob(32) WHERE audit_id = ?`, auditID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, auditID, scope); err == nil {
		t.Fatal("Get of a damaged turn graph succeeded; the test does not damage it")
	}
	for name, scope := range map[string]*Scope{"owner": scope, "administrator": nil} {
		metadata, err := service.GetMetadata(ctx, auditID, scope)
		if err != nil {
			t.Fatalf("%s GetMetadata of a damaged turn graph = %v", name, err)
		}
		if !reflect.DeepEqual(metadata.Audit, intact.Audit) || !reflect.DeepEqual(metadata.Stages, intact.Stages) || !reflect.DeepEqual(metadata.Bodies, intact.Bodies) {
			t.Fatalf("%s GetMetadata = %+v\nwant the intact summary, stages and bodies %+v", name, metadata, intact)
		}
		if metadata.RequestURI != "" || metadata.Headers != nil || metadata.Conversation != nil || metadata.Turn != nil || metadata.ParsedResult != nil || metadata.TokenLink != nil {
			t.Fatalf("%s GetMetadata filled a derived field: %+v", name, metadata)
		}
	}
}
