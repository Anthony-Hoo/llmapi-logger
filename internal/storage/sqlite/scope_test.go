package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sort"
	"testing"
)

func scopeFingerprint(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, APIKeyFingerprintSize)
}

func scopeTokenID(value int64) *int64 { return &value }

type scopeFixture struct {
	auditID       string
	fingerprint   []byte
	tokenID       *int64
	forwardStatus string
	blockCode     string
	statusCode    int
}

func insertScopeFixture(t *testing.T, store *Store, index int, fixture scopeFixture) {
	t.Helper()
	ctx := context.Background()
	record := testAudit(fixture.auditID)
	record.StartedAtNS = int64(100 - index)
	record.APIKeyFPR = fixture.fingerprint
	if err := store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	finish := AuditFinish{
		AuditID: fixture.auditID, EndedAtNS: record.StartedAtNS + 1,
		StatusCode: &fixture.statusCode, ForwardStatus: fixture.forwardStatus,
		CaptureStatus: CaptureComplete, ParseStatus: ParseOK,
	}
	if fixture.forwardStatus == ForwardRejected {
		blockedBy := "policy"
		finish.BlockedBy = &blockedBy
		finish.BlockCode = &fixture.blockCode
		finish.ParseStatus = ParseSkipped
	}
	if err := store.FinishAudit(ctx, finish); err != nil {
		t.Fatal(err)
	}
	if fixture.tokenID != nil {
		if _, err := store.writerDB.ExecContext(ctx, `
UPDATE audit_records
SET newapi_request_id = ?, caller_status = 'resolved', caller_attempts = 1,
    caller_updated_at_ns = ?
WHERE audit_id = ?`, "req-"+fixture.auditID, record.StartedAtNS+2, fixture.auditID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.writerDB.ExecContext(ctx, `
INSERT INTO token_links (
    audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns
) VALUES (?, ?, ?, ?, ?, ?)`,
			fixture.auditID, 7, "developer", *fixture.tokenID, "agent-token", record.StartedAtNS+2,
		); err != nil {
			t.Fatal(err)
		}
	}
}

// The list SQL and AuditScope.Allows are two renderings of one rule. This test
// runs the whole matrix through both and fails if they ever disagree, because a
// divergence would either hide a developer's own records or leak somebody
// else's.
func TestScopeSQLAndPredicateAgreeAcrossVisibilityMatrix(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()

	own := scopeFingerprint(0x01)
	other := scopeFingerprint(0x02)
	fixtures := []scopeFixture{
		{auditID: "audit-own-forwarded", fingerprint: own, forwardStatus: ForwardCompleted, statusCode: 200},
		{auditID: "audit-own-upstream-401", fingerprint: own, forwardStatus: ForwardCompleted, statusCode: 401},
		{auditID: "audit-own-body-too-large", fingerprint: own, forwardStatus: ForwardRejected, blockCode: "body_too_large", statusCode: 413},
		{auditID: "audit-own-ua-blocked", fingerprint: own, forwardStatus: ForwardRejected, blockCode: "user_agent_not_allowed", statusCode: 401},
		{auditID: "audit-own-credential", fingerprint: own, forwardStatus: ForwardRejected, blockCode: "credential_required", statusCode: 401},
		{auditID: "audit-own-future-policy", fingerprint: own, forwardStatus: ForwardRejected, blockCode: "some_future_policy", statusCode: 403},
		{auditID: "audit-token-linked", tokenID: scopeTokenID(42), forwardStatus: ForwardCompleted, statusCode: 200},
		{auditID: "audit-other-key", fingerprint: other, forwardStatus: ForwardCompleted, statusCode: 200},
		{auditID: "audit-other-token", tokenID: scopeTokenID(43), forwardStatus: ForwardCompleted, statusCode: 200},
		{auditID: "audit-anonymous", forwardStatus: ForwardCompleted, statusCode: 200},
	}
	for index, fixture := range fixtures {
		insertScopeFixture(t, store, index, fixture)
	}

	scope := &AuditScope{Fingerprint: own, TokenID: scopeTokenID(42)}
	page, err := store.ListAudits(ctx, AuditQueryFilter{Scope: scope}, AuditQueryCursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	listed := make([]string, 0, len(page.Rows))
	for _, row := range page.Rows {
		listed = append(listed, row.AuditID)
	}
	sort.Strings(listed)

	want := []string{
		"audit-own-body-too-large",
		"audit-own-forwarded",
		"audit-own-upstream-401",
		"audit-token-linked",
	}
	sort.Strings(want)
	if len(listed) != len(want) {
		t.Fatalf("listed = %v, want %v", listed, want)
	}
	for index := range want {
		if listed[index] != want[index] {
			t.Fatalf("listed = %v, want %v", listed, want)
		}
	}

	allowed := make(map[string]bool, len(listed))
	for _, auditID := range listed {
		allowed[auditID] = true
	}
	for _, fixture := range fixtures {
		row, err := store.QueryAuditScope(ctx, fixture.auditID)
		if err != nil {
			t.Fatal(err)
		}
		if got := scope.Allows(row); got != allowed[fixture.auditID] {
			t.Fatalf("Allows(%s) = %v but the list query %s it", fixture.auditID, got,
				map[bool]string{true: "returned", false: "omitted"}[allowed[fixture.auditID]])
		}
	}

	if _, err := store.QueryAuditScope(ctx, "audit-missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("QueryAuditScope for a missing audit = %v, want sql.ErrNoRows", err)
	}
}

func TestListAuditsRejectsMalformedScope(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	for _, scope := range []*AuditScope{
		{},
		{Fingerprint: []byte{0x01, 0x02}},
		{Fingerprint: scopeFingerprint(0x01), TokenID: scopeTokenID(-1)},
	} {
		if _, err := store.ListAudits(context.Background(), AuditQueryFilter{Scope: scope}, AuditQueryCursor{}, 50); err == nil {
			t.Fatalf("ListAudits accepted malformed scope %+v", scope)
		}
	}
}
