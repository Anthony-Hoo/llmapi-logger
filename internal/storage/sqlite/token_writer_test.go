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
	if err != nil || len(due) != 1 || due[0].RequestID != requestID || due[0].Attempts != 0 || due[0].StatusCode != nil {
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

	quota, quotaPerUnit, prompt, completion := int64(1500), 500000.0, int64(1200), int64(300)
	link := TokenLink{
		AuditID: record.AuditID, NewAPIRequestID: requestID,
		NewAPIUserID: 7, Username: "alice", NewAPITokenID: 42,
		TokenName: "codex", LinkedAtNS: 11, Attempts: 2,
		BillingState: BillingBilled, Quota: &quota, QuotaPerUnit: &quotaPerUnit,
		BilledPromptTokens: &prompt, BilledCompletionTokens: &completion,
	}
	if err := store.UpsertTokenLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTokenLink(ctx, link); err == nil {
		t.Fatal("expected already-resolved link to be rejected")
	}

	var got TokenLink
	var callerStatus string
	var gotQuota, gotPrompt, gotCompletion int64
	var gotQuotaPerUnit float64
	if err := store.readerDB.QueryRow(`
SELECT t.audit_id, a.newapi_request_id, t.newapi_user_id, t.username,
       t.newapi_token_id, t.token_name, t.linked_at_ns,
       a.caller_attempts, a.caller_status,
       t.billing_state, t.quota, t.quota_per_unit, t.billed_prompt_tokens, t.billed_completion_tokens
FROM token_links AS t
JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.audit_id = ?`, record.AuditID).Scan(
		&got.AuditID, &got.NewAPIRequestID, &got.NewAPIUserID, &got.Username,
		&got.NewAPITokenID, &got.TokenName, &got.LinkedAtNS,
		&got.Attempts, &callerStatus,
		&got.BillingState, &gotQuota, &gotQuotaPerUnit, &gotPrompt, &gotCompletion,
	); err != nil {
		t.Fatal(err)
	}
	if got.AuditID != link.AuditID || got.NewAPIRequestID != requestID || got.NewAPIUserID != 7 || got.Username != "alice" ||
		got.NewAPITokenID != 42 || got.TokenName != "codex" || got.LinkedAtNS != 11 || got.Attempts != 2 || callerStatus != CallerResolved {
		t.Fatalf("resolved link = %+v status=%q", got, callerStatus)
	}
	if got.BillingState != BillingBilled || gotQuota != quota || gotQuotaPerUnit != quotaPerUnit || gotPrompt != prompt || gotCompletion != completion {
		t.Fatalf("billing = %q %d %v %d %d", got.BillingState, gotQuota, gotQuotaPerUnit, gotPrompt, gotCompletion)
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
		Username: "user", NewAPITokenID: 1, TokenName: "token", LinkedAtNS: 1, Attempts: 1, BillingState: BillingUnbilled,
	}); err == nil {
		t.Fatal("expected missing audit error")
	}
	quota, quotaPerUnit, tokens := int64(1), 2.0, int64(0)
	negative := int64(-1)
	zero := 0.0
	base := TokenLink{
		AuditID: "audit", NewAPIRequestID: "req", NewAPIUserID: 1,
		Username: "user", NewAPITokenID: 1, TokenName: "token", LinkedAtNS: 1, Attempts: 1,
	}
	for name, mutate := range map[string]func(*TokenLink){
		"missing state":       func(link *TokenLink) {},
		"unchecked new link":  func(link *TokenLink) { link.BillingState = BillingUnchecked },
		"billed without data": func(link *TokenLink) { link.BillingState = BillingBilled },
		"unbilled with data": func(link *TokenLink) {
			link.BillingState, link.Quota = BillingUnbilled, &quota
		},
		"negative quota": func(link *TokenLink) {
			link.BillingState, link.Quota, link.QuotaPerUnit, link.BilledPromptTokens, link.BilledCompletionTokens = BillingBilled, &negative, &quotaPerUnit, &tokens, &tokens
		},
		"zero quota per unit": func(link *TokenLink) {
			link.BillingState, link.Quota, link.QuotaPerUnit, link.BilledPromptTokens, link.BilledCompletionTokens = BillingBilled, &quota, &zero, &tokens, &tokens
		},
	} {
		link := base
		mutate(&link)
		if err := validateTokenLink(link); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestDueCallerLookupCarriesResponseStatus(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	record := testAudit("audit-caller-status")
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	requestID, status := "req-status", 429
	if err := store.FinishAudit(ctx, AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 2, StatusCode: &status, ForwardStatus: ForwardCompleted,
		CaptureStatus: CaptureComplete, ParseStatus: ParsePending, NewAPIRequestID: &requestID,
	}); err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDueCallerLookups(ctx, 2, 10)
	if err != nil || len(due) != 1 || due[0].StatusCode == nil || *due[0].StatusCode != 429 {
		t.Fatalf("due = %+v, err=%v", due, err)
	}
}

func TestBillingBackfillOnlyChangesBillingColumns(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()
	for index, id := range []string{"audit-old", "audit-new"} {
		record := testAudit(id)
		record.StartedAtNS = int64(index + 1)
		if err := store.BeginAudit(ctx, record); err != nil {
			t.Fatal(err)
		}
		requestID := "req-" + id
		if err := store.FinishAudit(ctx, AuditFinish{
			AuditID: id, EndedAtNS: 5, ForwardStatus: ForwardCompleted,
			CaptureStatus: CaptureComplete, ParseStatus: ParsePending, NewAPIRequestID: &requestID,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.UpsertTokenLink(ctx, TokenLink{
			AuditID: id, NewAPIRequestID: requestID, NewAPIUserID: 3, Username: "bob",
			NewAPITokenID: 4, TokenName: "cli", LinkedAtNS: int64(10 + index), Attempts: 1, BillingState: BillingUnbilled,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate links written before migration 009.
	if _, err := store.writerDB.Exec("UPDATE token_links SET billing_state = 'unchecked'"); err != nil {
		t.Fatal(err)
	}

	item, ok, err := store.NextBillingBackfill(ctx)
	if err != nil || !ok || item.AuditID != "audit-new" || item.RequestID != "req-audit-new" || item.Attempts != 0 {
		t.Fatalf("first backfill = %+v %v %v", item, ok, err)
	}
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: item.AuditID, State: BillingUnchecked, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if item, _, _ = store.NextBillingBackfill(ctx); item.AuditID != "audit-new" || item.Attempts != 1 {
		t.Fatalf("retried backfill = %+v", item)
	}
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: item.AuditID, State: BillingUnchecked, Attempts: MaxBillingAttempts}); err == nil {
		t.Fatal("final attempt must not stay unchecked")
	}
	quota, quotaPerUnit, prompt, completion := int64(700), 500000.0, int64(10), int64(20)
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{
		AuditID: "audit-new", State: BillingBilled, Attempts: 2, Quota: &quota, QuotaPerUnit: &quotaPerUnit,
		BilledPromptTokens: &prompt, BilledCompletionTokens: &completion,
	}); err != nil {
		t.Fatal(err)
	}
	// A link that is no longer unchecked is never rewritten by the backfill.
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: "audit-new", State: BillingUnbilled, Attempts: 3}); err == nil {
		t.Fatal("expected checked link to be left alone")
	}
	if item, ok, _ = store.NextBillingBackfill(ctx); !ok || item.AuditID != "audit-old" {
		t.Fatalf("second backfill = %+v %v", item, ok)
	}
	if err := store.UpdateTokenLinkBilling(ctx, BillingUpdate{AuditID: "audit-old", State: BillingUnbilled, Attempts: MaxBillingAttempts}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err = store.NextBillingBackfill(ctx); ok || err != nil {
		t.Fatalf("backfill should be empty: %v %v", ok, err)
	}

	var callerStatus, state, username string
	var attempts int
	if err := store.readerDB.QueryRow(`
SELECT a.caller_status, a.caller_attempts, t.billing_state, t.username
FROM token_links AS t JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.audit_id = 'audit-new'`).Scan(&callerStatus, &attempts, &state, &username); err != nil {
		t.Fatal(err)
	}
	if callerStatus != CallerResolved || attempts != 1 || state != BillingBilled || username != "bob" {
		t.Fatalf("after backfill: %q %d %q %q", callerStatus, attempts, state, username)
	}
}
