package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

func TestDeleteExpiredHonorsEligibilityAndCascades(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	insertRetentionAudit(t, store, "old", 100, int64Pointer(200), ParseOK, true)
	insertRetentionAudit(t, store, "boundary", 1000, int64Pointer(1100), ParsePending, false)
	insertRetentionAudit(t, store, "recent", 1001, int64Pointer(1100), ParsePending, false)
	insertRetentionAudit(t, store, "processing", 100, int64Pointer(200), ParseProcessing, false)
	insertRetentionAudit(t, store, "unfinished", 100, nil, ParsePending, false)

	if err := store.InsertAuditGaps(context.Background(), []AuditGap{
		{StartedAtNS: 100, EndedAtNS: 200, Reason: GapReasonWrite, RequestCount: 1, Detail: GapDetailWrite, CreatedAtNS: 200},
		{StartedAtNS: 1000, EndedAtNS: 1001, Reason: GapReasonQueueFull, RequestCount: 1, Detail: GapDetailQueueFull, CreatedAtNS: 1001},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.DeleteExpired(context.Background(), 1000, RetentionBatchLimit, RetentionBatchLimit)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 1 || result.DeletedGaps != 1 {
		t.Fatalf("delete result = %+v, want one audit and one gap", result)
	}

	for _, table := range []string{"audit_records", "http_stages", "http_headers", "body_streams", "body_chunks", "parsed_results", "token_links"} {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE audit_id = ?", table)
		if err := store.readerDB.QueryRow(query, "old").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d cascaded rows", table, count)
		}
	}

	for _, auditID := range []string{"boundary", "recent", "processing", "unfinished"} {
		var count int
		if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_records WHERE audit_id = ?", auditID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("eligible guard removed %q", auditID)
		}
	}
	var gapCount int
	if err := store.readerDB.QueryRow("SELECT COUNT(*) FROM audit_gaps").Scan(&gapCount); err != nil {
		t.Fatal(err)
	}
	if gapCount != 1 {
		t.Fatalf("remaining gaps = %d, want 1", gapCount)
	}
}

func TestDeleteExpiredLimitsEachClassToTwoHundred(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	transaction, err := store.writerDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 205; index++ {
		id := fmt.Sprintf("old-%03d", index)
		if _, err := transaction.Exec(`
INSERT INTO audit_records (
    audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
    method, path, request_uri_enc, mode, forward_status, capture_status, parse_status
) VALUES (?, ?, ?, 'route', 'openai', 'parser', 'POST', '/v1/test', X'01',
          'available', 'completed', 'complete', 'pending')`, id, int64(index+1), int64(index+2)); err != nil {
			_ = transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(`
INSERT INTO audit_gaps (started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns)
VALUES (?, ?, ?, 1, ?, ?)`, int64(index+1), int64(index+2), GapReasonWrite, GapDetailWrite, int64(index+2)); err != nil {
			_ = transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}

	result, err := store.DeleteExpired(context.Background(), 1000, RetentionBatchLimit, RetentionBatchLimit)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 200 || result.DeletedGaps != 200 {
		t.Fatalf("first delete result = %+v, want 200 each", result)
	}
	assertTableCount(t, store.readerDB, "audit_records", 5)
	assertTableCount(t, store.readerDB, "audit_gaps", 5)

	result, err = store.DeleteExpired(context.Background(), 1000, RetentionBatchLimit, RetentionBatchLimit)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 5 || result.DeletedGaps != 5 {
		t.Fatalf("second delete result = %+v, want 5 each", result)
	}

	if _, err := store.DeleteExpired(context.Background(), 1000, RetentionBatchLimit+1, 1); err == nil {
		t.Fatal("expected oversized audit batch to fail")
	}
	if _, err := store.DeleteExpired(context.Background(), 1000, 0, 0); err == nil {
		t.Fatal("expected empty maintenance batch to fail")
	}
}

func TestDeleteExpiredCheckpointsRetainedChildAndCollectsUnreachableObjects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x36}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	parentEnded := int64(200)
	childEnded := int64(2200)
	insertRetentionAudit(t, store, "parent-turn", 100, &parentEnded, ParseProcessing, false)
	insertRetentionAudit(t, store, "child-turn", 2000, &childEnded, ParseProcessing, false)

	userMessage := map[string]any{"role": "user", "content": "first question"}
	assistantMessage := map[string]any{"role": "assistant", "content": "first answer"}
	orphanBinary := map[string]any{
		"type": "output_image",
		"data": "data:image/png;base64," + base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x73}, 256)...)),
	}
	parentResponse := map[string]any{
		"id":     "response-parent",
		"output": []any{assistantMessage, orphanBinary},
	}
	parent, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: "parent-turn", Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope: map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{
			"id":     "response-parent",
			"output": []any{auditmodel.ItemMarker(0), auditmodel.ItemMarker(1)},
		},
		RequestItems: []auditmodel.Item{
			{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: userMessage},
		},
		ResponseItems: []auditmodel.Item{
			{Slot: auditmodel.SlotOutput, Kind: "assistant_message", Value: assistantMessage},
			{Slot: auditmodel.SlotOutput, Kind: "output_image", Value: orphanBinary},
		},
		RequestOriginal:  map[string]any{"model": "model-example", "messages": []any{userMessage}},
		ResponseOriginal: parentResponse, ResponseID: "response-parent", CreatedAtNS: 100,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{AuditID: "parent-turn", ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: 300},
		Turn:   &parent,
	}); err != nil {
		t.Fatal(err)
	}

	secondUserMessage := map[string]any{"role": "user", "content": "second question"}
	secondAssistantMessage := map[string]any{"role": "assistant", "content": "second answer"}
	childRequest := map[string]any{
		"model":    "model-example",
		"messages": []any{userMessage, assistantMessage, secondUserMessage},
	}
	childResponse := map[string]any{
		"id":      "response-child",
		"choices": []any{map[string]any{"message": secondAssistantMessage}},
	}
	child, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: "child-turn", Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{"id": "response-child", "choices": []any{map[string]any{"message": auditmodel.ItemMarker(0)}}},
		RequestItems: []auditmodel.Item{
			{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: userMessage},
			{Slot: auditmodel.SlotMessages, Kind: "assistant_message", Value: assistantMessage},
			{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: secondUserMessage},
		},
		ResponseItems: []auditmodel.Item{
			{Slot: auditmodel.SlotChoice, Kind: "assistant_message", Value: secondAssistantMessage},
		},
		RequestOriginal: childRequest, ResponseOriginal: childResponse,
		PreviousResponseID: "response-parent", ResponseID: "response-child", CreatedAtNS: 2000,
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveParsedAudit(ctx, ParsedAudit{
		Result: ParsedResult{AuditID: "child-turn", ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: 2300},
		Turn:   &child,
	}); err != nil {
		t.Fatal(err)
	}

	var parentTurnID string
	if err := store.readerDB.QueryRow(`SELECT parent_turn_id FROM turns WHERE turn_id = 'child-turn'`).Scan(&parentTurnID); err != nil {
		t.Fatal(err)
	}
	if parentTurnID != "parent-turn" {
		t.Fatalf("child parent = %q", parentTurnID)
	}
	if len(parent.Binaries) != 1 {
		t.Fatalf("parent binary objects = %d, want 1", len(parent.Binaries))
	}

	result, err := store.DeleteExpired(ctx, 1000, RetentionBatchLimit, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 1 {
		t.Fatalf("delete result = %+v", result)
	}
	detail, err := store.QueryAuditDetail(ctx, "child-turn")
	if err != nil {
		t.Fatal(err)
	}
	if detail.TurnGraph == nil || detail.TurnGraph.ParentTurnID != nil ||
		detail.TurnGraph.ParentBase != "root" || detail.TurnGraph.LinkReason != "retention_checkpoint" ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(detail.TurnGraph.RequestRefs), child.RequestSequenceHash) {
		t.Fatalf("checkpointed graph = %+v", detail.TurnGraph)
	}

	assertTableCount(t, store.readerDB, "audit_records", 1)
	assertTableCount(t, store.readerDB, "turns", 1)
	assertTableCount(t, store.readerDB, "conversations", 1)
	assertTableCount(t, store.readerDB, "binary_objects", 0)
	var orphanContent int
	if err := store.readerDB.QueryRow(`
SELECT COUNT(*)
FROM content_objects AS c
WHERE NOT EXISTS (SELECT 1 FROM turns AS t WHERE t.request_envelope_hash = c.object_hash)
  AND NOT EXISTS (SELECT 1 FROM turns AS t WHERE t.response_envelope_hash = c.object_hash)
  AND NOT EXISTS (SELECT 1 FROM turn_context_ops AS o WHERE o.object_hash = c.object_hash)
  AND NOT EXISTS (SELECT 1 FROM turn_response_items AS r WHERE r.object_hash = c.object_hash)`).Scan(&orphanContent); err != nil {
		t.Fatal(err)
	}
	if orphanContent != 0 {
		t.Fatalf("unreachable content objects = %d", orphanContent)
	}
}

func insertRetentionAudit(t *testing.T, store *Store, auditID string, startedAt int64, endedAt *int64, parseStatus string, withChildren bool) {
	t.Helper()
	forwardStatus := ForwardInProgress
	captureStatus := CapturePending
	if endedAt != nil {
		forwardStatus = ForwardCompleted
		captureStatus = CaptureComplete
	}
	transaction, err := store.writerDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec(`
INSERT INTO audit_records (
    audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
    method, path, request_uri_enc, mode, forward_status, capture_status, parse_status
) VALUES (?, ?, ?, 'route', 'openai', 'parser', 'POST', '/v1/test', X'01',
          'available', ?, ?, ?)`, auditID, startedAt, endedAt, forwardStatus, captureStatus, parseStatus); err != nil {
		t.Fatal(err)
	}
	if !withChildren {
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if endedAt == nil {
		t.Fatal("children fixture requires a terminal audit")
	}
	if _, err := transaction.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, started_at_ns, ended_at_ns
) VALUES (?, ?, 'complete', 'HTTP/1.1', 'POST', 'newapi.local', ?, ?)`,
		auditID, StageRequestReceived, startedAt, *endedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
INSERT INTO http_headers (
    audit_id, stage, kind, name, value_index, value_length, value_enc
) VALUES (?, ?, 'header', 'x-test', 0, 1, X'01')`, auditID, StageRequestReceived); err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x44}, 32)
	if _, err := transaction.Exec(`
INSERT INTO body_streams (
    audit_id, stage, source_stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state, retention_state
) VALUES (?, ?, ?, 1, 1, ?, 1, 1, 'complete', 'full')`, auditID, StageRequestReceived, StageRequestReceived, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
INSERT INTO body_chunks (
    audit_id, stage, seq, "offset", plaintext_length, encoded_length,
    observed_at_ns, compression, data_enc
) VALUES (?, ?, 0, 0, 1, 1, ?, 'none', X'01')`, auditID, StageRequestReceived, startedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status, parsed_at_ns
) VALUES (?, 'parser', 'v1', 'ok', ?)`, auditID, *endedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
	UPDATE audit_records
	SET newapi_request_id = ?, caller_status = 'resolved', caller_attempts = 1,
	    caller_updated_at_ns = ?
	WHERE audit_id = ?`, "retention-"+auditID, *endedAt, auditID); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
	INSERT INTO token_links (
	    audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns
	) VALUES (?, 1, 'owner', 1, 'personal', ?)`, auditID, *endedAt); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}

func assertTableCount(t *testing.T, database *sql.DB, table string, want int) {
	t.Helper()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s count = %d, want %d", table, count, want)
	}
}
