package sqlite

import (
	"context"
	"testing"
)

func TestCallerLookupRetriesAndResolvesIdentity(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-caller-link")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	requestID := "req-caller-link"
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
		NewAPIRequestID: &requestID,
	}); err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDueCallerLookups(ctx, 2, 10)
	if err != nil || len(due) != 1 || due[0].RequestID != requestID || due[0].Attempts != 0 {
		t.Fatalf("initial due = %+v, err=%v", due, err)
	}

	next := int64(10)
	if err := store.RetryCallerLookup(ctx, CallerRetry{
		AuditID: record.AuditID, RequestID: requestID, Attempts: 1,
		NextAttemptAtNS: &next, UpdatedAtNS: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if due, err = store.ListDueCallerLookups(ctx, 9, 10); err != nil || len(due) != 0 {
		t.Fatalf("early due = %+v, err=%v", due, err)
	}
	if due, err = store.ListDueCallerLookups(ctx, 10, 10); err != nil || len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("retried due = %+v, err=%v", due, err)
	}

	link := TokenLink{
		AuditID: record.AuditID, NewAPIRequestID: requestID,
		NewAPIUserID: 7, Username: "alice", NewAPITokenID: 42,
		TokenName: "codex", LinkedAtNS: 11, Attempts: 2,
	}
	if err := store.UpsertTokenLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTokenLink(ctx, link); err == nil {
		t.Fatal("expected already-resolved link to be rejected")
	}

	var got TokenLink
	var callerStatus string
	if err := store.readerDB.QueryRow(`
SELECT t.audit_id, a.newapi_request_id, t.newapi_user_id, t.username,
       t.newapi_token_id, t.token_name, t.linked_at_ns,
       a.caller_attempts, a.caller_status
FROM token_links AS t
JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.audit_id = ?`, record.AuditID).Scan(
		&got.AuditID, &got.NewAPIRequestID, &got.NewAPIUserID, &got.Username,
		&got.NewAPITokenID, &got.TokenName, &got.LinkedAtNS,
		&got.Attempts, &callerStatus,
	); err != nil {
		t.Fatal(err)
	}
	if got != link || callerStatus != CallerResolved {
		t.Fatalf("resolved link = %+v status=%q", got, callerStatus)
	}
	if due, err = store.ListDueCallerLookups(ctx, 100, 10); err != nil || len(due) != 0 {
		t.Fatalf("resolved due = %+v, err=%v", due, err)
	}
}

func TestCallerLookupCanBecomeTerminallyUnresolved(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-caller-unresolved")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	requestID := "req-unresolved"
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending, NewAPIRequestID: &requestID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RetryCallerLookup(ctx, CallerRetry{
		AuditID: record.AuditID, RequestID: requestID, Attempts: 4, UpdatedAtNS: 3,
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	var next any
	if err := store.readerDB.QueryRow(`
SELECT caller_status, caller_next_at_ns FROM audit_records WHERE audit_id = ?`, record.AuditID).Scan(&status, &next); err != nil {
		t.Fatal(err)
	}
	if status != CallerUnresolved || next != nil {
		t.Fatalf("status=%q next=%v", status, next)
	}
}

func TestCallerLinkValidatesInputAndRequiresPendingParent(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.UpsertTokenLink(ctx, TokenLink{}); err == nil {
		t.Fatal("expected invalid caller link error")
	}
	if err := store.UpsertTokenLink(ctx, TokenLink{
		AuditID: "missing", NewAPIRequestID: "req-missing", NewAPIUserID: 1,
		Username: "user", NewAPITokenID: 1, TokenName: "token", LinkedAtNS: 1, Attempts: 1,
	}); err == nil {
		t.Fatal("expected missing audit error")
	}
}
