package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
)

func TestParseRetryMigrationPreservesExistingAuditAndIntegrity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	database, err := sql.Open("sqlite", sqliteDSN(path, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version <= 6 {
			if err := applyMigration(ctx, database, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := bytes.Repeat([]byte{0x52}, security.KeySize)
	signer, err := security.NewIntegritySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	record := testAudit("audit-before-retry-migration")
	record.defaults()
	if err := insertAudit(tx, record); err != nil {
		t.Fatal(err)
	}
	if err := finishAudit(tx, &AuditFinish{AuditID: record.AuditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete, ParseStatus: ParsePending}, signer); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	var failures int
	var next *int64
	if err := store.readerDB.QueryRow("SELECT parse_save_failures, parse_next_at_ns FROM audit_records WHERE audit_id = ?", record.AuditID).Scan(&failures, &next); err != nil || failures != 0 || next != nil {
		t.Fatalf("invalid retry defaults after upgrade: %d, %v, %v", failures, next, err)
	}
	if claimed, err := store.ClaimPendingParse(ctx, record.AuditID); err != nil || !claimed {
		t.Fatalf("cannot claim migrated audit: %v, %v", claimed, err)
	}
	if err := store.ReleaseProcessingParse(ctx, record.AuditID); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("retry scheduling changed historical evidence: %v", err)
	}
}

func TestBillingMigrationMarksExistingLinksUnchecked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	database, err := sql.Open("sqlite", sqliteDSN(path, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.version <= 8 {
			if err := applyMigration(ctx, database, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := bytes.Repeat([]byte{0x53}, security.KeySize)
	signer, err := security.NewIntegritySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	record := testAudit("audit-before-billing")
	record.defaults()
	if err := insertAudit(tx, record); err != nil {
		t.Fatal(err)
	}
	requestID := "req-before-billing"
	if err := finishAudit(tx, &AuditFinish{
		AuditID: record.AuditID, EndedAtNS: 2, ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete,
		ParseStatus: ParsePending, NewAPIRequestID: &requestID,
	}, signer); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`
INSERT INTO token_links (audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns)
VALUES (?, 5, 'carol', 6, 'agent', 3)`, record.AuditID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`
UPDATE audit_records SET caller_status = 'resolved', caller_attempts = 1, caller_next_at_ns = NULL, caller_updated_at_ns = 3
WHERE audit_id = ?`, record.AuditID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	var state, username, callerStatus string
	var quota, quotaPerUnit any
	var attempts int
	if err := store.readerDB.QueryRow(`
SELECT t.billing_state, t.quota, t.quota_per_unit, t.billing_attempts, t.username, a.caller_status
FROM token_links AS t JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.audit_id = ?`, record.AuditID).Scan(&state, &quota, &quotaPerUnit, &attempts, &username, &callerStatus); err != nil {
		t.Fatal(err)
	}
	if state != BillingUnchecked || quota != nil || quotaPerUnit != nil || attempts != 0 || username != "carol" || callerStatus != CallerResolved {
		t.Fatalf("migrated link = %q %v %v %d %q %q", state, quota, quotaPerUnit, attempts, username, callerStatus)
	}
	if item, ok, err := store.NextBillingBackfill(ctx); err != nil || !ok || item.AuditID != record.AuditID || item.RequestID != requestID {
		t.Fatalf("backfill item = %+v %v %v", item, ok, err)
	}
	// The billed-iff-values rule is enforced by the schema, not only in Go.
	if _, err := store.writerDB.Exec("UPDATE token_links SET billing_state = 'billed' WHERE audit_id = ?", record.AuditID); err == nil {
		t.Fatal("billed state without quota accepted")
	}
	if _, err := store.writerDB.Exec("UPDATE token_links SET quota = 1 WHERE audit_id = ?", record.AuditID); err == nil {
		t.Fatal("quota on an unchecked link accepted")
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("billing migration changed historical evidence: %v", err)
	}
}

func TestOpenAppliesBaselineMigrationAndPragmas(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)

	var journalMode string
	if err := store.writerDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if strings.ToLower(journalMode) != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	assertPragmaInt(t, store.writerDB, "synchronous", 2)
	assertPragmaInt(t, store.writerDB, "busy_timeout", 5000)
	assertPragmaInt(t, store.writerDB, "foreign_keys", 1)
	assertPragmaInt(t, store.readerDB, "query_only", 1)
	assertPragmaInt(t, store.readerDB, "busy_timeout", 5000)
	assertPragmaInt(t, store.readerDB, "foreign_keys", 1)

	rows, err := store.readerDB.Query(`
SELECT name
FROM sqlite_schema
WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	wantTables := []string{
		"agent_spawn_hints",
		"audit_analysis",
		"audit_gaps",
		"audit_records",
		"binary_objects",
		"body_chunks",
		"body_streams",
		"content_binary_refs",
		"content_external_refs",
		"content_objects",
		"conversations",
		"http_headers",
		"http_stages",
		"integrity_events",
		"parsed_results",
		"schema_migrations",
		"stream_timelines",
		"token_links",
		"turn_context_ops",
		"turn_response_items",
		"turns",
		"user_agent_rules",
	}
	sort.Strings(wantTables)
	if !reflect.DeepEqual(tables, wantTables) {
		t.Fatalf("tables = %v, want %v", tables, wantTables)
	}

	tokenLinkColumns := readTableColumns(t, store.readerDB, "token_links")
	wantTokenLinkColumns := []string{
		"audit_id",
		"newapi_user_id",
		"username",
		"newapi_token_id",
		"token_name",
		"linked_at_ns",
		"billing_state",
		"quota",
		"quota_per_unit",
		"billed_prompt_tokens",
		"billed_completion_tokens",
		"billing_attempts",
	}
	if !reflect.DeepEqual(tokenLinkColumns, wantTokenLinkColumns) {
		t.Fatalf("token_links columns = %v, want %v", tokenLinkColumns, wantTokenLinkColumns)
	}

	var versionCount, version int
	if err := store.readerDB.QueryRow("SELECT COUNT(*), MAX(version) FROM schema_migrations").Scan(&versionCount, &version); err != nil {
		t.Fatal(err)
	}
	if versionCount != 7 || version != 9 {
		t.Fatalf("migration rows = %d max=%d, want versions 1, 4, 5, 6, 7, 8 and 9", versionCount, version)
	}
	var quickCheck string
	if err := store.readerDB.QueryRow("PRAGMA quick_check").Scan(&quickCheck); err != nil {
		t.Fatalf("PRAGMA quick_check: %v", err)
	}
	if quickCheck != "ok" {
		t.Fatalf("PRAGMA quick_check = %q, want ok", quickCheck)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.readerDB.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&versionCount); err != nil {
		t.Fatal(err)
	}
	if versionCount != 7 {
		t.Fatalf("migration reran: row count = %d", versionCount)
	}
}

func TestOpenRejectsDatabaseNewerThanProgram(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	if _, err := store.writerDB.Exec(
		"INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)",
		10,
		int64(2),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open error = %v, want newer-version rejection", err)
	}
}

func TestOpenRejectsAppliedMigrationNotEmbeddedByProgram(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	if _, err := store.writerDB.Exec(
		"INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)",
		2,
		int64(2),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not supported by this program") {
		t.Fatalf("Open error = %v, want unsupported-version rejection", err)
	}
}

func TestOpenSkipsFullForeignKeyScanWhenSchemaIsCurrent(t *testing.T) {
	store, path := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, started_at_ns
) VALUES ('missing-audit', ?, 'streaming', 'HTTP/1.1', 'POST', 'example', 1)`, StageRequestReceived); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open current schema: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
}

func TestOpenChecksForeignKeysAfterApplyingMigration(t *testing.T) {
	store, path := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, started_at_ns
) VALUES ('missing-audit', ?, 'streaming', 'HTTP/1.1', 'POST', 'example', 1)`, StageRequestReceived); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM schema_migrations WHERE version = 4"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec("DROP TABLE user_agent_rules"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "foreign key check reported violations") {
		t.Fatalf("Open error = %v, want foreign-key check failure", err)
	}
}

func TestSchemaRejectsInvalidRejectedRowsAndForeignKeys(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	record := testAudit("audit-schema")
	if err := store.BeginAudit(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	if _, err := store.writerDB.Exec(`
UPDATE audit_records
SET ended_at_ns = 2, status_code = 401, forward_status = 'rejected', parse_status = 'skipped'
WHERE audit_id = ?`, record.AuditID); err == nil {
		t.Fatal("expected rejected block-field CHECK failure")
	}

	if _, err := store.writerDB.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, started_at_ns
) VALUES ('missing-audit', ?, 'streaming', 'HTTP/1.1', 'POST', 'example', 1)`, StageRequestReceived); err == nil {
		t.Fatal("expected foreign-key failure")
	}

	blockedBy, blockCode, status := "credential", "credential_required", 401
	if err := store.FinishAudit(context.Background(), AuditFinish{
		AuditID:       record.AuditID,
		EndedAtNS:     2,
		StatusCode:    &status,
		ForwardStatus: ForwardRejected,
		CaptureStatus: CapturePartial,
		BlockedBy:     &blockedBy,
		BlockCode:     &blockCode,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background(), record.AuditID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.ParseStatus != ParseSkipped || snapshot.Audit.BlockedBy == nil || *snapshot.Audit.BlockedBy != blockedBy {
		t.Fatalf("unexpected rejected audit: %+v", snapshot.Audit)
	}
}

func TestSnapshotNotFoundAndClosedReader(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	if _, err := store.Snapshot(context.Background(), "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Snapshot error = %v, want sql.ErrNoRows", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.HasAudits(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("HasAudits error = %v, want ErrClosed", err)
	}
	if _, err := store.Snapshot(context.Background(), "missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Snapshot error = %v, want ErrClosed", err)
	}
}

func assertPragmaInt(t *testing.T, database *sql.DB, name string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s = %d, want %d", name, got, want)
	}
}

func readTableColumns(t *testing.T, database *sql.DB, table string) []string {
	t.Helper()
	rows, err := database.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}
