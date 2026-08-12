package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestOpenAppliesFinalMigrationAndPragmas(t *testing.T) {
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
		"audit_gaps",
		"audit_records",
		"body_chunks",
		"body_streams",
		"http_headers",
		"http_stages",
		"parsed_results",
		"schema_migrations",
		"token_links",
	}
	sort.Strings(wantTables)
	if !reflect.DeepEqual(tables, wantTables) {
		t.Fatalf("tables = %v, want %v", tables, wantTables)
	}

	var versionCount, version int
	if err := store.readerDB.QueryRow("SELECT COUNT(*), MAX(version) FROM schema_migrations").Scan(&versionCount, &version); err != nil {
		t.Fatal(err)
	}
	if versionCount != 4 || version != 4 {
		t.Fatalf("migration rows = %d max=%d, want versions 1 through 4", versionCount, version)
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
	if versionCount != 4 {
		t.Fatalf("migration reran: row count = %d", versionCount)
	}
}

func TestOpenRejectsDatabaseNewerThanProgram(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	if _, err := store.writerDB.Exec(
		"INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)",
		5,
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

func TestTokenLinkMaskedKeyMigrationPreservesLegacyRows(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", sqliteDSN(path, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeWriter(context.Background(), database); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	for _, item := range migrations {
		if item.version > 2 {
			continue
		}
		if err := applyMigration(context.Background(), database, item); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`
INSERT INTO audit_records (
    audit_id, started_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status
) VALUES ('legacy-audit', 1, 'route', 'openai', 'parser', 'POST', '/v1/test',
          X'01', 'available', 'in_progress', 'pending', 'pending')`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO token_links (audit_id, newapi_token_id, token_name, linked_at_ns)
VALUES ('legacy-audit', 42, 'legacy', 2)`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var tokenName, maskedKey string
	if err := store.readerDB.QueryRow(`
SELECT token_name, masked_key
FROM token_links
WHERE audit_id = 'legacy-audit'`).Scan(&tokenName, &maskedKey); err != nil {
		t.Fatal(err)
	}
	if tokenName != "legacy" || maskedKey != "" {
		t.Fatalf("migrated token link = name %q masked %q", tokenName, maskedKey)
	}
}

func TestConversationMigrationRequeuesVersionOneParserResults(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	record := testAudit("audit-conversation-backfill")
	if err := store.BeginAudit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec(`
UPDATE audit_records
SET ended_at_ns = 2, forward_status = 'completed', capture_status = 'complete', parse_status = 'ok'
WHERE audit_id = ?`, record.AuditID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec(`
INSERT INTO parsed_results (
    audit_id, parser_name, parser_version, status, parsed_json_enc, parsed_at_ns
) VALUES (?, ?, '1', 'ok', X'01', 3)`, record.AuditID, record.ParserName); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec("DELETE FROM schema_migrations WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var parseStatus string
	if err := reopened.readerDB.QueryRow("SELECT parse_status FROM audit_records WHERE audit_id = ?", record.AuditID).Scan(&parseStatus); err != nil {
		t.Fatal(err)
	}
	if parseStatus != ParsePending {
		t.Fatalf("parse_status = %q, want %q", parseStatus, ParsePending)
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
