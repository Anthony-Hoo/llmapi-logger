package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"
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
    audit_id, stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state
) VALUES (?, ?, 1, 1, ?, 1, 1, 'complete')`, auditID, StageRequestReceived, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
INSERT INTO body_chunks (
    audit_id, stage, seq, "offset", plaintext_length, observed_at_ns, data_enc
) VALUES (?, ?, 0, 0, 1, ?, X'01')`, auditID, StageRequestReceived, startedAt); err != nil {
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
