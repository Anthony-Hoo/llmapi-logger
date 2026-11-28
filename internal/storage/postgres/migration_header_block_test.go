package postgres

import (
	"context"
	"database/sql"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// rollbackToSchemaSixSQL is the rollback documented in
// doc/deployment/postgresql-migration.md for returning to a binary that only
// understands schema version 6. The tests run it verbatim. Its first statement
// refuses to run once a version 2 audit exists.
const rollbackToSchemaSixSQL = `
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM audit_records WHERE capture_version <> 1)
       OR EXISTS (SELECT 1 FROM http_header_blocks) THEN
        RAISE EXCEPTION 'capture version 2 audits exist; schema version 7 cannot be rolled back with SQL';
    END IF;
END
$$;
DELETE FROM runtime_settings WHERE section = 'audit_capture';
ALTER TABLE runtime_settings DROP CONSTRAINT runtime_settings_section_check;
ALTER TABLE runtime_settings ADD CONSTRAINT runtime_settings_section_check
    CHECK (section IN ('session_analysis', 'org_reports'));
DROP TABLE http_header_blocks;
ALTER TABLE http_stages DROP COLUMN content_type, DROP COLUMN content_encoding;
ALTER TABLE audit_records DROP COLUMN user_agent_enc, DROP COLUMN capture_version;
DELETE FROM schema_migrations WHERE version = 7;
COMMIT;
`

// migration007Rows is the number of audits the no-rewrite test seeds. The
// default keeps the shared test database light; the timing reported in
// doc/deployment/postgresql-migration.md was measured with
// TEST_MIGRATION_007_ROWS=300000.
func migration007Rows(t *testing.T) int {
	t.Helper()
	if value := os.Getenv("TEST_MIGRATION_007_ROWS"); value != "" {
		rows, err := strconv.Atoi(value)
		if err != nil || rows < 1 {
			t.Fatalf("TEST_MIGRATION_007_ROWS = %q", value)
		}
		return rows
	}
	return 20_000
}

func columnExists(t *testing.T, db rowQueryer, table, column string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRowContext(context.Background(), `
SELECT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, column).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func requireVersionSevenShape(t *testing.T, db rowQueryer, present bool) {
	t.Helper()
	for _, column := range [][2]string{
		{"audit_records", "capture_version"}, {"audit_records", "user_agent_enc"},
		{"http_stages", "content_type"}, {"http_stages", "content_encoding"},
	} {
		if got := columnExists(t, db, column[0], column[1]); got != present {
			t.Fatalf("column %s.%s exists = %v, want %v", column[0], column[1], got, present)
		}
	}
	var table bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('http_header_blocks') IS NOT NULL`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if table != present {
		t.Fatalf("http_header_blocks exists = %v, want %v", table, present)
	}
}

// constraintDefinitions maps the CHECK constraints of a table to their
// definition, which ends in NOT VALID for one that was not validated.
func constraintDefinitions(t *testing.T, db rowQueryer, table string) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = to_regclass($1) AND contype = 'c'`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		result[name] = definition
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFreshStoreEndsAtVersionSevenWithHeaderBlock(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	requireVersions(t, appliedSchemaVersions(t, store.readerDB), 1, 2, 3, 4, 5, 6, 7, 8)
	requireVersionSevenShape(t, store.readerDB, true)
	audits := constraintDefinitions(t, store.readerDB, "audit_records")
	if got := audits["audit_records_capture_version_check"]; got != "CHECK ((capture_version = ANY (ARRAY[(1)::bigint, (2)::bigint]))) NOT VALID" {
		t.Fatalf("capture_version constraint = %q", got)
	}
	stages := constraintDefinitions(t, store.readerDB, "http_stages")
	if stages["http_stages_content_type_check"] != "CHECK ((content_type <> ''::text)) NOT VALID" ||
		stages["http_stages_content_encoding_check"] != "CHECK ((content_encoding <> ''::text)) NOT VALID" {
		t.Fatalf("http_stages constraints = %v", stages)
	}
	settings := constraintDefinitions(t, store.readerDB, "runtime_settings")
	if want := "CHECK ((section = ANY (ARRAY['session_analysis'::text, 'org_reports'::text, 'audit_capture'::text])))"; settings["runtime_settings_section_check"] != want || len(settings) != 1 {
		t.Fatalf("runtime_settings constraints = %v", settings)
	}

	// The settings page (H.3) stores the audit_capture section; nothing else
	// is accepted.
	if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO runtime_settings(section, settings, updated_at_ns) VALUES ('audit_capture', '{"commit_retries":3}', 1)`); err != nil {
		t.Fatalf("audit_capture section rejected: %v", err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO runtime_settings(section, settings, updated_at_ns) VALUES ('other', '{}', 1)`); err == nil {
		t.Fatal("unknown settings section accepted")
	}
	// NOT VALID constraints still hold for new and updated rows.
	if err := store.BeginAudit(ctx, testAudit("version-check")); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE audit_records SET capture_version = 3 WHERE audit_id = 'version-check'`,
		`UPDATE audit_records SET capture_version = 0 WHERE audit_id = 'version-check'`,
		`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns, content_type)
		 VALUES ('version-check', 'request_for_newapi_received_from_nginx', 'streaming', 'HTTP/1.1', 'POST', 'example.com', 1, '')`,
		`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, started_at_ns, content_encoding)
		 VALUES ('version-check', 'request_for_newapi_received_from_nginx', 'streaming', 'HTTP/1.1', 'POST', 'example.com', 1, '')`,
		`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('version-check', 'zstd', 1, '\x01')`,
		`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('version-check', 'none', -1, '\x01')`,
		`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('missing', 'none', 1, '\x01')`,
	} {
		if _, err := store.writerConn.ExecContext(ctx, statement); err == nil {
			t.Fatalf("accepted: %s", statement)
		}
	}
	var version int
	var userAgent []byte
	if err := store.readerDB.QueryRow(`SELECT capture_version, user_agent_enc FROM audit_records WHERE audit_id = 'version-check'`).Scan(&version, &userAgent); err != nil || version != 1 || userAgent != nil {
		t.Fatalf("legacy BeginAudit row: version %d, user agent %v, %v", version, userAgent, err)
	}
	// A block goes with its audit.
	if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('version-check', 'none', 1, '\x01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerConn.ExecContext(ctx, `DELETE FROM audit_records WHERE audit_id = 'version-check'`); err != nil {
		t.Fatal(err)
	}
	var blocks int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM http_header_blocks`).Scan(&blocks); err != nil || blocks != 0 {
		t.Fatalf("blocks after deleting the audit = %d, %v", blocks, err)
	}
}

type relationFile struct {
	Name     string
	FileNode int64
}

func relationFiles(t *testing.T, db rowQueryer, tables ...string) []relationFile {
	t.Helper()
	var files []relationFile
	for _, table := range tables {
		var node int64
		if err := db.QueryRowContext(context.Background(), `SELECT relfilenode FROM pg_class WHERE oid = to_regclass($1)`, table).Scan(&node); err != nil {
			t.Fatal(err)
		}
		files = append(files, relationFile{table, node})
	}
	return files
}

// Migration 007 on a version 6 database with rows: no relation file is
// rewritten, no existing table is scanned, every existing row reads back as
// version 1 with the new columns NULL, and the documented rollback returns to
// version 6. The test also prints what the migration takes: its time and the
// relation locks it holds until commit.
func TestMigrationSevenUpgradesVersionSixDatabaseWithoutRewrite(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatalf("documented rollback SQL: %v", err)
		}
	}
	versions := appliedSchemaVersions(t, admin)
	requireVersions(t, versions, 1, 2, 3, 4, 5, 6)
	requireVersionSevenShape(t, admin, false)
	if err := requireSupportedSchema(versions[len(versions)-1], 6); err != nil {
		t.Fatalf("a version 6 binary rejects the rolled-back database: %v", err)
	}

	rows := migration007Rows(t)
	seedStarted := time.Now()
	for _, statement := range []string{
		`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
		    request_uri_enc, mode, status_code, forward_status, capture_status, parse_status)
		 SELECT 'seed-' || g, g, g + 1, 'route', 'openai', 'openai.chat_completions', 'POST', '/v1/chat/completions',
		    decode(md5(g::text), 'hex'), 'available', 200, 'completed', 'complete', 'ok'
		 FROM generate_series(1, $1::bigint) AS g`,
		`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, status_code, started_at_ns, ended_at_ns)
		 SELECT 'seed-' || g, 'request_for_newapi_received_from_nginx', 'complete', 'HTTP/1.1', 'POST', 'proxy.example.com', NULL, g, g + 1
		 FROM generate_series(1, $1::bigint) AS g`,
		`INSERT INTO http_headers (audit_id, stage, kind, name, value_index, value_length, value_enc)
		 SELECT 'seed-' || g, 'request_for_newapi_received_from_nginx', 'header', 'User-Agent', 0, 16, decode(md5('ua' || g), 'hex')
		 FROM generate_series(1, $1::bigint) AS g`,
	} {
		if _, err := admin.ExecContext(ctx, statement, rows); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if _, err := admin.ExecContext(ctx, `ANALYZE audit_records; ANALYZE http_stages`); err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d audits, stages and header rows in %v", rows, time.Since(seedStarted).Round(time.Millisecond))
	var auditBytes, stageBytes int64
	if err := admin.QueryRow(`SELECT pg_table_size('audit_records'), pg_table_size('http_stages')`).Scan(&auditBytes, &stageBytes); err != nil {
		t.Fatal(err)
	}
	tables := []string{"audit_records", "http_stages", "runtime_settings"}
	before := relationFiles(t, admin, tables...)

	// The migration body in a transaction of its own, rolled back: which rows
	// it reads and which relation locks it holds until commit.
	body, err := migrationFiles.ReadFile("migrations/007_header_block.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	scanned := func(table string) int64 {
		var tuples int64
		if err := transaction.QueryRowContext(ctx, `SELECT pg_stat_get_xact_tuples_returned(to_regclass($1))`, table).Scan(&tuples); err != nil {
			t.Fatal(err)
		}
		return tuples
	}
	scannedBefore := map[string]int64{"audit_records": scanned("audit_records"), "http_stages": scanned("http_stages")}
	migrationStarted := time.Now()
	if _, err := transaction.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("migration 007: %v", err)
	}
	statementTime := time.Since(migrationStarted)
	for table, previous := range scannedBefore {
		if read := scanned(table) - previous; read != 0 {
			t.Fatalf("migration 007 read %d rows of %s", read, table)
		}
	}
	lockRows, err := transaction.QueryContext(ctx, `
SELECT c.relname, l.mode
FROM pg_locks AS l JOIN pg_class AS c ON c.oid = l.relation
WHERE l.pid = pg_backend_pid() AND l.locktype = 'relation' AND c.relnamespace = to_regnamespace(current_schema())
ORDER BY c.relname, l.mode`)
	if err != nil {
		t.Fatal(err)
	}
	locks := map[string][]string{}
	for lockRows.Next() {
		var relation, mode string
		if err := lockRows.Scan(&relation, &mode); err != nil {
			t.Fatal(err)
		}
		locks[relation] = append(locks[relation], mode)
	}
	if err := closeRows(lockRows); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"audit_records", "http_stages", "runtime_settings"} {
		if !slices.Contains(locks[table], "AccessExclusiveLock") {
			t.Fatalf("locks = %v", locks)
		}
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	lockText := make([]string, 0, len(locks))
	for relation, modes := range locks {
		lockText = append(lockText, relation+"="+strings.Join(modes, "+"))
	}
	slices.Sort(lockText)
	t.Logf("migration 007 statements: %v on %d audits (audit_records %d MiB, http_stages %d MiB); locks held until commit: %s",
		statementTime.Round(time.Microsecond), rows, auditBytes>>20, stageBytes>>20, strings.Join(lockText, ", "))

	openStarted := time.Now()
	upgraded, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 6 database: %v", err)
	}
	t.Logf("Open with migration 007: %v", time.Since(openStarted).Round(time.Millisecond))
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	requireVersionSevenShape(t, admin, true)
	if after := relationFiles(t, admin, tables...); !slices.Equal(before, after) {
		t.Fatalf("relation files before %v, after %v", before, after)
	}
	var versionOne, userAgents, contents int
	if err := admin.QueryRow(`
SELECT (SELECT COUNT(*) FROM audit_records WHERE capture_version = 1),
       (SELECT COUNT(*) FROM audit_records WHERE user_agent_enc IS NOT NULL),
       (SELECT COUNT(*) FROM http_stages WHERE content_type IS NOT NULL OR content_encoding IS NOT NULL)`).Scan(&versionOne, &userAgents, &contents); err != nil {
		t.Fatal(err)
	}
	if versionOne != rows || userAgents != 0 || contents != 0 {
		t.Fatalf("after migration: %d version 1 audits of %d, %d user agents, %d content columns", versionOne, rows, userAgents, contents)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}

	// The documented rollback undoes 007 on a database with version 1 rows,
	// and refuses once a version 2 audit exists. Migration 008 is rolled back
	// first each time.
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatalf("documented rollback SQL with rows: %v", err)
		}
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6)
	requireVersionSevenShape(t, admin, false)
	reopened, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE audit_records SET capture_version = 2 WHERE audit_id = 'seed-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, rollbackToSchemaSevenSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, rollbackToSchemaSixSQL); err == nil || !strings.Contains(err.Error(), "capture version 2 audits exist") {
		t.Fatalf("rollback with a version 2 audit: %v", err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7)
	requireVersionSevenShape(t, admin, true)
}
