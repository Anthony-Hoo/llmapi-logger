package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

func TestListAuditsUsesStableKeysetAndNarrowFilters(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, item := range []struct {
		id      string
		started int64
		status  int
	}{
		{id: "audit-a", started: 100, status: 200},
		{id: "audit-b", started: 100, status: 429},
		{id: "audit-c", started: 90, status: 200},
	} {
		record := testAudit(item.id)
		record.StartedAtNS = item.started
		if err := store.BeginAudit(ctx, record); err != nil {
			t.Fatal(err)
		}
		if err := store.FinishAudit(ctx, AuditFinish{
			AuditID: item.id, EndedAtNS: item.started + 1, StatusCode: &item.status,
			ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParseOK,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.writerDB.ExecContext(ctx, `
INSERT INTO parsed_results (
	 audit_id, parser_name, parser_version, status, request_model,
	 requested_stream, usage_input, parsed_json_enc, parsed_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, "audit-b", "openai.chat_completions", "test", ParseOK, "gpt-test", true, 123, []byte("encrypted-parsed-secret"), 101); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.ExecContext(ctx, `
	UPDATE audit_records
	SET newapi_request_id = 'req-b', caller_status = 'resolved', caller_attempts = 1,
	    caller_updated_at_ns = 102
	WHERE audit_id = 'audit-b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.ExecContext(ctx, `
	INSERT INTO token_links (
	    audit_id, newapi_token_id, token_name, masked_key, linked_at_ns,
	    newapi_user_id, username
	) VALUES (?, ?, ?, '', ?, ?, ?)`, "audit-b", 42, "personal", 102, 7, "alice"); err != nil {
		t.Fatal(err)
	}

	first, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	gotIDs := []string{first.Rows[0].AuditID, first.Rows[1].AuditID}
	if !reflect.DeepEqual(gotIDs, []string{"audit-b", "audit-a"}) || !first.HasMore {
		t.Fatalf("first page = ids %v has_more=%v", gotIDs, first.HasMore)
	}
	second, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{
		BeforeStartedAtNS: first.Rows[1].StartedAtNS,
		BeforeID:          first.Rows[1].AuditID,
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Rows) != 1 || second.Rows[0].AuditID != "audit-c" || second.HasMore {
		t.Fatalf("second page = %+v", second)
	}

	modelPage, err := store.ListAudits(ctx, AuditQueryFilter{Model: "gpt-test"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(modelPage.Rows) != 1 || modelPage.Rows[0].AuditID != "audit-b" ||
		modelPage.Rows[0].NewAPIUserID == nil || *modelPage.Rows[0].NewAPIUserID != 7 ||
		modelPage.Rows[0].Username == nil || *modelPage.Rows[0].Username != "alice" ||
		modelPage.Rows[0].NewAPITokenID == nil || *modelPage.Rows[0].NewAPITokenID != 42 ||
		modelPage.Rows[0].NewAPIRequestID == nil || *modelPage.Rows[0].NewAPIRequestID != "req-b" ||
		modelPage.Rows[0].CallerStatus != CallerResolved {
		t.Fatalf("model-filtered page = %+v", modelPage)
	}
	userIDPage, err := store.ListAudits(ctx, AuditQueryFilter{NewAPIUserID: int64Pointer(7)}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(userIDPage.Rows) != 1 || userIDPage.Rows[0].AuditID != "audit-b" {
		t.Fatalf("user-id-filtered page = %+v", userIDPage)
	}
	usernamePage, err := store.ListAudits(ctx, AuditQueryFilter{Username: "alice"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(usernamePage.Rows) != 1 || usernamePage.Rows[0].AuditID != "audit-b" {
		t.Fatalf("username-filtered page = %+v", usernamePage)
	}
	tokenIDPage, err := store.ListAudits(ctx, AuditQueryFilter{NewAPITokenID: int64Pointer(42)}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenIDPage.Rows) != 1 || tokenIDPage.Rows[0].AuditID != "audit-b" {
		t.Fatalf("token-id-filtered page = %+v", tokenIDPage)
	}
	tokenNamePage, err := store.ListAudits(ctx, AuditQueryFilter{TokenName: "personal"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenNamePage.Rows) != 1 || tokenNamePage.Rows[0].AuditID != "audit-b" {
		t.Fatalf("token-name-filtered page = %+v", tokenNamePage)
	}
	caseMismatch, err := store.ListAudits(ctx, AuditQueryFilter{Model: "GPT-TEST"}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(caseMismatch.Rows) != 0 {
		t.Fatalf("model filter must be exact and case-sensitive: %+v", caseMismatch)
	}
	statusPage, err := store.ListAudits(ctx, AuditQueryFilter{StatusCode: integerPointer(429)}, AuditQueryCursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(statusPage.Rows) != 1 || statusPage.Rows[0].AuditID != "audit-b" {
		t.Fatalf("status-filtered page = %+v", statusPage)
	}
	detail, err := store.QueryAuditDetail(ctx, "audit-b")
	if err != nil {
		t.Fatal(err)
	}
	if detail.ParsedResult == nil || detail.ParsedResult.RequestModel == nil || *detail.ParsedResult.RequestModel != "gpt-test" || detail.ParsedResult.RequestedStream == nil || !*detail.ParsedResult.RequestedStream || detail.ParsedResult.UsageInput == nil || *detail.ParsedResult.UsageInput != 123 || !bytes.Equal(detail.ParsedResult.ParsedJSONEnc, []byte("encrypted-parsed-secret")) {
		t.Fatalf("parsed summary = %+v", detail.ParsedResult)
	}
	if detail.TokenLink == nil || detail.TokenLink.NewAPIRequestID != "req-b" ||
		detail.TokenLink.NewAPIUserID != 7 || detail.TokenLink.Username != "alice" ||
		detail.TokenLink.NewAPITokenID != 42 || detail.TokenLink.TokenName != "personal" {
		t.Fatalf("token link = %+v", detail.TokenLink)
	}
}

func TestQueryAuditDetailLoadsEncryptedValuesForQueryService(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-detail")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	stage := HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestSent, Proto: "HTTP/1.1",
		Method: "POST", Host: "newapi.local", StartedAtNS: 2,
	}
	if err := store.StartStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.StartBody(ctx, BodyStream{AuditID: record.AuditID, Stage: stage.Stage}); err != nil {
		t.Fatal(err)
	}
	secretCiphertext := []byte("ciphertext-must-not-enter-detail")
	if err := store.AddHeaders(ctx, []HTTPHeader{{
		AuditID: record.AuditID, Stage: stage.Stage, Kind: HeaderKindHeader,
		Name: "authorization", ValueIndex: 0, ValueLength: 12, ValueEnc: secretCiphertext,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddChunk(ctx, BodyChunk{
		AuditID: record.AuditID, Stage: stage.Stage, Seq: 0, Offset: 0,
		PlaintextLength: 3, ObservedAtNS: 3, DataEnc: secretCiphertext,
	}); err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x5a}, 32)
	if err := store.FinishStage(ctx, StageFinish{
		AuditID: record.AuditID, Stage: stage.Stage, State: StageStateComplete, EndedAtNS: 4,
		Body: &BodyFinish{
			ObservedLength: 3, StoredLength: 3, SHA256: digest,
			HashComplete: true, EOFSeen: true, State: StageStateComplete,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 5,
		ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}

	detail, err := store.QueryAuditDetail(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(detail.RequestURIEnc, record.RequestURIEnc) {
		t.Fatalf("encrypted request URI = %x, want %x", detail.RequestURIEnc, record.RequestURIEnc)
	}
	if len(detail.Headers) != 1 || detail.Headers[0].Name != "authorization" || detail.Headers[0].ValueLength != 12 || !bytes.Equal(detail.Headers[0].ValueEnc, secretCiphertext) {
		t.Fatalf("header evidence = %+v", detail.Headers)
	}
	if len(detail.Bodies) != 1 || !bytes.Equal(detail.Bodies[0].SHA256, digest) {
		t.Fatalf("body metadata = %+v", detail.Bodies)
	}
	if detail.ParsedResult != nil || detail.TokenLink != nil {
		t.Fatalf("unexpected optional detail: %+v", detail)
	}

	metadata, err := store.RawBodyMeta(ctx, record.AuditID, stage.Stage)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.StoredLength != 3 || !metadata.HashComplete {
		t.Fatalf("raw metadata = %+v", metadata)
	}
	var chunks []BodyChunk
	if err := store.StreamBodyChunks(ctx, record.AuditID, stage.Stage, func(chunk BodyChunk) error {
		chunks = append(chunks, chunk)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || !bytes.Equal(chunks[0].DataEnc, secretCiphertext) {
		t.Fatalf("raw chunks = %+v", chunks)
	}
}

func TestQueryRequestHeaderEvidenceReadsOnlyFilterHeaders(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-filter-headers")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.StartStage(ctx, HTTPStage{
		AuditID: record.AuditID, Stage: StageRequestReceived, Proto: "HTTP/1.1",
		Method: "POST", Host: "logger.local", StartedAtNS: 2,
	}); err != nil {
		t.Fatal(err)
	}
	headers := []HTTPHeader{
		{AuditID: record.AuditID, Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "User-Agent", ValueIndex: 0, ValueLength: 3, ValueEnc: []byte("ua-cipher")},
		{AuditID: record.AuditID, Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "X-Api-Key", ValueIndex: 0, ValueLength: 3, ValueEnc: []byte("key-cipher")},
		{AuditID: record.AuditID, Stage: StageRequestReceived, Kind: HeaderKindHeader, Name: "Content-Type", ValueIndex: 0, ValueLength: 16, ValueEnc: []byte("type-cipher")},
		{AuditID: record.AuditID, Stage: StageRequestReceived, Kind: HeaderKindTrailer, Name: "Authorization", ValueIndex: 0, ValueLength: 3, ValueEnc: []byte("trailer-cipher")},
	}
	if err := store.AddHeaders(ctx, headers); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishStage(ctx, StageFinish{AuditID: record.AuditID, Stage: StageRequestReceived, State: StageStateComplete, EndedAtNS: 3}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 4, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
	}); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.QueryRequestHeaderEvidence(ctx, record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Name != "User-Agent" {
		t.Fatalf("filter header evidence = %+v", evidence)
	}
}

func TestQueryReadersNotFoundAndValidation(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.QueryAuditDetail(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("detail error = %v, want sql.ErrNoRows", err)
	}
	if _, err := store.RawBodyMeta(ctx, "missing", StageRequestSent); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("raw metadata error = %v, want sql.ErrNoRows", err)
	}
	if _, err := store.ListAudits(ctx, AuditQueryFilter{}, AuditQueryCursor{BeforeID: "only-id"}, 10); err == nil {
		t.Fatal("expected incomplete cursor error")
	}
	if err := store.StreamBodyChunks(ctx, "missing", StageRequestSent, nil); err == nil {
		t.Fatal("expected nil visitor error")
	}
}

func integerPointer(value int) *int {
	return &value
}
