package postgres

import (
	"bytes"
	"context"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

func upstreamClassPointer(value string) *string { return &value }

func finishAuditForUpstreamClassTest(t *testing.T, store *Store, ctx context.Context, auditID string, startedAtNS int64, status int) {
	t.Helper()
	record := testAudit(auditID)
	record.StartedAtNS = startedAtNS
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: auditID, EndedAtNS: startedAtNS + 1, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestParsedResultPersistsUpstreamErrorClass(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	finishAuditForUpstreamClassTest(t, store, ctx, "audit-upstream-class", 1, 400)
	claimed, err := store.ClaimPendingParse(ctx, "audit-upstream-class")
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}

	errorType := "invalid_request_error"
	errorCode := "content_policy_violation"
	if err := store.SaveParsedResult(ctx, ParsedResult{
		AuditID: "audit-upstream-class", ParserName: "openai.chat_completions", ParserVersion: "2",
		Status: ParseError, ErrorType: &errorType, ErrorCode: &errorCode,
		UpstreamErrorClass: upstreamClassPointer("content_policy"), ParsedAtNS: 3,
	}); err != nil {
		t.Fatal(err)
	}

	var storedClass string
	var storedParseStatus string
	if err := store.readerDB.QueryRow(`
SELECT p.upstream_error_class, a.parse_status
FROM parsed_results p JOIN audit_records a USING (audit_id)
WHERE a.audit_id = $1`, "audit-upstream-class").Scan(&storedClass, &storedParseStatus); err != nil {
		t.Fatal(err)
	}
	if storedClass != "content_policy" || storedParseStatus != ParseError {
		t.Fatalf("stored class = %q parse_status = %q", storedClass, storedParseStatus)
	}

	// The column is nullable and optional: a result without a class must be
	// accepted and stored as NULL rather than as an empty string.
	finishAuditForUpstreamClassTest(t, store, ctx, "audit-no-upstream-class", 2, 200)
	claimed, err = store.ClaimPendingParse(ctx, "audit-no-upstream-class")
	if err != nil || !claimed {
		t.Fatalf("claim without class = %v, %v", claimed, err)
	}
	if err := store.SaveParsedResult(ctx, ParsedResult{
		AuditID: "audit-no-upstream-class", ParserName: "openai.chat_completions", ParserVersion: "2",
		Status: ParseOK, ParsedAtNS: 4,
	}); err != nil {
		t.Fatal(err)
	}
	var nullClass any
	if err := store.readerDB.QueryRow(
		`SELECT upstream_error_class FROM parsed_results WHERE audit_id = $1`, "audit-no-upstream-class",
	).Scan(&nullClass); err != nil {
		t.Fatal(err)
	}
	if nullClass != nil {
		t.Fatalf("missing class stored as %#v, want NULL", nullClass)
	}
}

func TestListAuditsExposesAndFiltersUpstreamErrorClass(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, item := range []struct {
		id      string
		started int64
	}{
		{id: "audit-class-cyber", started: 30},
		{id: "audit-class-content", started: 20},
		{id: "audit-class-none", started: 10},
	} {
		finishAuditForUpstreamClassTest(t, store, ctx, item.id, item.started, 400)
	}
	if _, err := store.writerConn.ExecContext(ctx, `
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status, request_model,
    error_type, error_code, upstream_error_class, parsed_at_ns
) VALUES
    ('audit-class-cyber', 'openai.chat_completions', '2', 'error', 'model-example',
     'invalid_request_error', 'cyber_policy', 'cyber_policy', 31),
    ('audit-class-content', 'openai.chat_completions', '2', 'error', 'model-example',
     'invalid_request_error', 'content_policy_violation', 'content_policy', 21)`); err != nil {
		t.Fatal(err)
	}

	all, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	rowsByID := make(map[string]AuditListRow, len(all.Rows))
	for _, row := range all.Rows {
		rowsByID[row.AuditID] = row
	}
	contentRow := rowsByID["audit-class-content"]
	if contentRow.ParsedErrorType == nil || *contentRow.ParsedErrorType != "invalid_request_error" ||
		contentRow.ParsedErrorCode == nil || *contentRow.ParsedErrorCode != "content_policy_violation" ||
		contentRow.UpstreamErrorClass == nil || *contentRow.UpstreamErrorClass != "content_policy" {
		t.Fatalf("list parsed error projection = %+v", contentRow)
	}
	noneRow := rowsByID["audit-class-none"]
	if noneRow.ParsedErrorType != nil || noneRow.ParsedErrorCode != nil || noneRow.UpstreamErrorClass != nil {
		t.Fatalf("audit without parsed row projected error fields = %+v", noneRow)
	}

	filtered, err := store.ListAudits(ctx, AuditQueryFilter{UpstreamErrorClass: "content_policy"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Rows) != 1 || filtered.Rows[0].AuditID != "audit-class-content" ||
		filtered.Rows[0].UpstreamErrorClass == nil || *filtered.Rows[0].UpstreamErrorClass != "content_policy" {
		t.Fatalf("upstream class filtered rows = %+v", filtered.Rows)
	}
	missing, err := store.ListAudits(ctx, AuditQueryFilter{UpstreamErrorClass: "safety_policy"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing.Rows) != 0 {
		t.Fatalf("unknown upstream class rows = %+v", missing.Rows)
	}

	detail, err := store.QueryAuditDetail(ctx, "audit-class-cyber", nil)
	if err != nil {
		t.Fatal(err)
	}
	if detail.ParsedResult == nil || detail.ParsedResult.UpstreamErrorClass == nil ||
		*detail.ParsedResult.UpstreamErrorClass != "cyber_policy" ||
		detail.ParsedResult.ErrorType == nil || *detail.ParsedResult.ErrorType != "invalid_request_error" ||
		detail.ParsedResult.ErrorCode == nil || *detail.ParsedResult.ErrorCode != "cyber_policy" {
		t.Fatalf("detail parsed summary = %+v", detail.ParsedResult)
	}
	detailRow := detail.Audit
	if detailRow.UpstreamErrorClass == nil || *detailRow.UpstreamErrorClass != "cyber_policy" {
		t.Fatalf("detail audit row upstream class = %+v", detailRow)
	}
}

// TestUpstreamErrorClassStaysOutsideTheEvidenceChain locks the invariant that
// upstream_error_class is derived, unsigned display data. Recomputing the
// signed capture digest must not depend on it: if it were folded into
// capturePayloadDigest or appendParsedResultDigest, rewriting the column would
// invalidate the chain and every existing database would fail verification
// after this column was added. The same lesson applies as for api_key_fpr
// (doc/features/04-sqlite-storage-and-migrations.md).
func TestUpstreamErrorClassStaysOutsideTheEvidenceChain(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := bytes.Repeat([]byte{0x6d}, security.KeySize)
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
	if err := store.BeginAudit(ctx, testAudit("audit-class-integrity")); err != nil {
		t.Fatal(err)
	}
	status := 400
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: "audit-class-integrity", EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimPendingParse(ctx, "audit-class-integrity")
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	message := map[string]any{"role": "user", "content": "integrity example"}
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: "audit-class-integrity", Protocol: "openai", ParserName: "openai.chat_completions",
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
			AuditID: "audit-class-integrity", ParserName: "openai.chat_completions",
			ParserVersion: "2", Status: ParseOK, UpstreamErrorClass: upstreamClassPointer("content_policy"),
			ParsedAtNS: 4,
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

	// Rewrite the derived column after the signed events exist. A digest that
	// covered it would now recompute differently and fail verification.
	if _, err := store.writerConn.ExecContext(ctx,
		`UPDATE parsed_results SET upstream_error_class = $1 WHERE audit_id = $2`,
		"cyber_policy", "audit-class-integrity",
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
		t.Fatalf("upstream_error_class must not participate in the integrity chain: %v", err)
	}
}
