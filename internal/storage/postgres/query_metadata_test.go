package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

// QueryAuditMetadata reads the summary row, the stages and the bodies and
// nothing derived (contract section 0.1 item 185): once the turn graph of a
// record fails verification QueryAuditDetail fails, and the metadata of the
// same record is still exactly what QueryAuditDetail returned while it was
// intact.
func TestQueryAuditMetadataSkipsADamagedTurnGraph(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	const auditID = "audit-metadata-damaged-graph"
	record := testAudit(auditID)
	record.APIKeyFPR = scopeFingerprint(0x01)
	record.ParserName = "parser" // the parser prepareGraphTestTurn records
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	stage := HTTPStage{AuditID: auditID, Stage: StageRequestSent, Proto: "HTTP/1.1", Method: "POST", Host: "upstream.example.com", StartedAtNS: 2}
	if err := store.StartStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, BodyStream{AuditID: auditID, Stage: stage.Stage}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddChunk(ctx, BodyChunk{AuditID: auditID, Stage: stage.Stage, Seq: 0, Offset: 0, PlaintextLength: 3, ObservedAtNS: 3, DataEnc: []byte("chunk-ciphertext")}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishStage(ctx, StageFinish{
		AuditID: auditID, Stage: stage.Stage, State: StageStateComplete, EndedAtNS: 4,
		Body: &BodyFinish{ObservedLength: 3, StoredLength: 3, SHA256: bytes.Repeat([]byte{0x5a}, 32), HashComplete: true, EOFSeen: true, State: StageStateComplete},
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: 5, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimPendingParse(ctx, auditID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	request, response := graphObjectFixture()
	prepared := prepareGraphTestTurn(t, cipher, auditID, "", "response-metadata", 6, request, response)
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: 7},
		Turn:   &prepared,
	}); err != nil {
		t.Fatal(err)
	}

	scopes := map[string]*AuditScope{"administrator": nil, "owner": {Fingerprint: record.APIKeyFPR}}
	intact := map[string]AuditQueryDetail{}
	for name, scope := range scopes {
		detail, err := store.QueryAuditDetail(ctx, auditID, scope)
		if err != nil {
			t.Fatalf("%s intact QueryAuditDetail = %v", name, err)
		}
		if detail.TurnGraph == nil || len(detail.Stages) != 1 || len(detail.Bodies) != 1 || detail.Audit.ConversationID == nil || detail.Audit.ConversationTurns == nil {
			t.Fatalf("%s intact detail = %+v", name, detail)
		}
		intact[name] = detail
	}
	if _, err := store.writerConn.ExecContext(ctx, `UPDATE turns SET request_sequence_hash = decode(repeat('00', 32), 'hex') WHERE audit_id = $1`, auditID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.QueryAuditDetail(ctx, auditID, nil); err == nil {
		t.Fatal("QueryAuditDetail of a damaged turn graph succeeded; the test does not damage it")
	}
	for name, scope := range scopes {
		want := intact[name]
		metadata, err := store.QueryAuditMetadata(ctx, auditID, scope)
		if err != nil {
			t.Fatalf("%s QueryAuditMetadata of a damaged turn graph = %v", name, err)
		}
		if !reflect.DeepEqual(metadata.Audit, want.Audit) || !reflect.DeepEqual(metadata.Stages, want.Stages) || !reflect.DeepEqual(metadata.Bodies, want.Bodies) {
			t.Fatalf("%s metadata = %+v\nwant the intact Audit, Stages and Bodies %+v", name, metadata, want)
		}
		if metadata.RequestURIEnc != nil || metadata.Headers != nil || metadata.ParsedResult != nil || metadata.TurnGraph != nil || metadata.TokenLink != nil {
			t.Fatalf("%s metadata read a derived record: %+v", name, metadata)
		}
	}
	if _, err := store.QueryAuditMetadata(ctx, "audit-missing", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("QueryAuditMetadata of a missing record = %v, want sql.ErrNoRows", err)
	}
}
