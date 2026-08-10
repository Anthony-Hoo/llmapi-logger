package sqlite

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

func TestParserLifecycleAndEvidenceReads(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	auditID := "audit-parser"
	if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
		t.Fatal(err)
	}
	stage := HTTPStage{
		AuditID: auditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 2,
	}
	if err := store.StartStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, BodyStream{AuditID: auditID, Stage: stage.Stage}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddHeaders(ctx, []HTTPHeader{
		{AuditID: auditID, Stage: stage.Stage, Kind: HeaderKindHeader, Name: "Content-Type", ValueIndex: 0, ValueLength: 16, ValueEnc: []byte("encrypted-type")},
		{AuditID: auditID, Stage: stage.Stage, Kind: HeaderKindHeader, Name: "Authorization", ValueIndex: 0, ValueLength: 6, ValueEnc: []byte("secret")},
	}); err != nil {
		t.Fatal(err)
	}
	for sequence, ciphertext := range [][]byte{{0x01, 0x02}, {0x03, 0x04}} {
		if err := store.AddChunk(ctx, BodyChunk{
			AuditID: auditID, Stage: stage.Stage, Seq: int64(sequence), Offset: int64(sequence * 2),
			PlaintextLength: 2, ObservedAtNS: int64(3 + sequence), DataEnc: ciphertext,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.FinishStage(ctx, StageFinish{
		AuditID: auditID, Stage: stage.Stage, State: StageStateComplete, EndedAtNS: 5,
		Body: &BodyFinish{ObservedLength: 4, StoredLength: 4, HashComplete: true, EOFSeen: true, State: StageStateComplete},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: 6, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}

	ids, err := store.ListPendingParseIDs(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids, []string{auditID}) {
		t.Fatalf("pending ids = %v", ids)
	}
	audit, err := store.LoadParserAudit(ctx, auditID)
	if err != nil {
		t.Fatal(err)
	}
	if audit.ParserName != "openai.chat_completions" || audit.ParseStatus != ParsePending {
		t.Fatalf("unexpected parser audit: %+v", audit)
	}
	loadedStage, err := store.LoadParserStage(ctx, auditID, StageRequestReceived)
	if err != nil {
		t.Fatal(err)
	}
	if loadedStage.Body == nil || loadedStage.Body.StoredLength != 4 {
		t.Fatalf("unexpected parser body: %+v", loadedStage.Body)
	}
	if len(loadedStage.Headers) != 1 || loadedStage.Headers[0].Name != "Content-Type" {
		t.Fatalf("parser headers leaked unrelated values: %+v", loadedStage.Headers)
	}
	firstPage, err := store.ReadParserChunks(ctx, auditID, StageRequestReceived, -1, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondPage, err := store.ReadParserChunks(ctx, auditID, StageRequestReceived, firstPage[0].Seq, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage) != 1 || len(secondPage) != 1 || secondPage[0].Seq != 1 {
		t.Fatalf("unexpected chunk pages: %+v %+v", firstPage, secondPage)
	}

	claimed, err := store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v", claimed, err)
	}
	claimed, err = store.ClaimPendingParse(ctx, auditID)
	if err != nil || claimed {
		t.Fatalf("second claim = %v, %v", claimed, err)
	}
	if err := store.ReleaseProcessingParse(ctx, auditID); err != nil {
		t.Fatal(err)
	}
	claimed, err = store.ClaimPendingParse(ctx, auditID)
	if err != nil || !claimed {
		t.Fatalf("claim after release = %v, %v", claimed, err)
	}
	requestModel := "gpt-test"
	stream := true
	messageCount, toolCount := 2, 1
	parsedCiphertext := []byte{0xaa, 0xbb, 0xcc}
	if err := store.SaveParsedResult(ctx, ParsedResult{
		AuditID: auditID, ParserName: audit.ParserName, ParserVersion: "1", Status: ParseOK,
		RequestModel: &requestModel, RequestedStream: &stream,
		MessageCount: &messageCount, ToolCallCount: &toolCount, HasToolCall: &stream,
		ParsedJSONEnc: parsedCiphertext, ParsedAtNS: 7,
	}); err != nil {
		t.Fatal(err)
	}
	var parseStatus, storedModel string
	var storedCiphertext []byte
	if err := store.readerDB.QueryRow(`
SELECT a.parse_status, p.request_model, p.parsed_json_enc
FROM audit_records a JOIN parsed_results p USING (audit_id)
WHERE a.audit_id = ?`, auditID).Scan(&parseStatus, &storedModel, &storedCiphertext); err != nil {
		t.Fatal(err)
	}
	if parseStatus != ParseOK || storedModel != requestModel || !bytes.Equal(storedCiphertext, parsedCiphertext) {
		t.Fatalf("stored parse = status %q model %q ciphertext %x", parseStatus, storedModel, storedCiphertext)
	}
}

func TestParserStartupResetAndRejectedExclusion(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, auditID := range []string{"pending-after-reset", "rejected-skip"} {
		if err := store.BeginAudit(ctx, testAudit(auditID)); err != nil {
			t.Fatal(err)
		}
		if auditID == "rejected-skip" {
			blockedBy, blockCode, status := "guard", "blocked", 403
			if err := store.FinishAudit(ctx, AuditFinish{
				AuditID: auditID, EndedAtNS: 2, StatusCode: &status,
				ForwardStatus: ForwardRejected, CaptureStatus: CapturePartial,
				BlockedBy: &blockedBy, BlockCode: &blockCode,
			}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := store.FinishAudit(ctx, AuditFinish{
			AuditID: auditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted,
			CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimPendingParse(ctx, auditID)
		if err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
		}
	}

	if err := store.ResetProcessingParses(ctx); err != nil {
		t.Fatal(err)
	}
	ids, err := store.ListPendingParseIDs(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids, []string{"pending-after-reset"}) {
		t.Fatalf("pending ids after reset = %v", ids)
	}
	var rejectedStatus string
	if err := store.readerDB.QueryRow("SELECT parse_status FROM audit_records WHERE audit_id = ?", "rejected-skip").Scan(&rejectedStatus); err != nil {
		t.Fatal(err)
	}
	if rejectedStatus != ParseSkipped {
		t.Fatalf("rejected parse status = %q", rejectedStatus)
	}
}
