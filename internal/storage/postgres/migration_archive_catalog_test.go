package postgres

import (
	"context"
	"database/sql"
	"slices"
	"testing"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// rollbackToSchemaSevenSQL is the rollback documented in
// doc/deployment/postgresql-migration.md for returning to a binary that only
// understands schema version 7 (design I.3). The tests run it verbatim.
const rollbackToSchemaSevenSQL = `
BEGIN;
DROP TABLE archive_gap_members;
DROP TABLE archive_deferred;
DROP TABLE archive_members;
DROP TABLE archive_segments;
DROP TABLE archive_runs;
DELETE FROM schema_migrations WHERE version = 8;
COMMIT;
`

var archiveCatalogTables = []string{"archive_runs", "archive_deferred", "archive_segments", "archive_members", "archive_gap_members"}

func requireArchiveCatalog(t *testing.T, db rowQueryer, present bool) {
	t.Helper()
	for _, table := range archiveCatalogTables {
		var exists bool
		if err := db.QueryRowContext(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != present {
			t.Fatalf("%s exists = %v, want %v", table, exists, present)
		}
	}
}

func TestFreshStoreEndsAtVersionEightWithArchiveCatalog(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	requireVersions(t, appliedSchemaVersions(t, store.readerDB), 1, 2, 3, 4, 5, 6, 7, 8)
	requireArchiveCatalog(t, store.readerDB, true)

	// No catalog table references an archived table: an archived audit is
	// later removed while its member row stays.
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT c.conrelid::regclass::text, c.confrelid::regclass::text
FROM pg_constraint AS c
WHERE c.contype = 'f' AND c.connamespace = to_regnamespace(current_schema())
  AND c.conrelid::regclass::text LIKE 'archive\_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var references []string
	for rows.Next() {
		var table, referenced string
		if err := rows.Scan(&table, &referenced); err != nil {
			t.Fatal(err)
		}
		references = append(references, table+"->"+referenced)
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}
	slices.Sort(references)
	want := []string{"archive_gap_members->archive_segments", "archive_members->archive_segments", "archive_segments->archive_runs"}
	if !slices.Equal(references, want) {
		t.Fatalf("catalog foreign keys = %v, want %v", references, want)
	}

	exec := func(statement string) error {
		_, err := store.writerConn.ExecContext(ctx, statement)
		return err
	}
	for _, statement := range []string{
		`INSERT INTO archive_runs (run_id, mode, cutoff_ns, started_at_ns, status, format_version)
		 VALUES ('00000000000000000000000000000001', 'export_only', 1, 1, 'running', 0)`,
		`INSERT INTO archive_segments (segment_id, run_id, bundle_kind, format_version, manifest_name, key_fingerprint,
		     encrypted, member_count, disk_bytes, state, created_at_ns)
		 VALUES ('0000000000000000000000000000000a', '00000000000000000000000000000001', 'bucket', 0, 'sessions/a.manifest.json',
		     decode(repeat('11', 32), 'hex'), 1, 2, 0, 'publishing', 1)`,
		`INSERT INTO archive_members (audit_id, revision, segment_id, record_digest, change_stamp, state, started_at_ns, state_changed_at_ns)
		 VALUES ('a-1', 1, '0000000000000000000000000000000a', decode(repeat('22', 32), 'hex'), decode(repeat('33', 32), 'hex'), 'sealed', 1, 1)`,
		`INSERT INTO archive_members (audit_id, revision, segment_id, record_digest, change_stamp, state, started_at_ns, state_changed_at_ns)
		 VALUES ('a-1', 2, '0000000000000000000000000000000a', decode(repeat('22', 32), 'hex'), NULL, 'stale', 1, 1)`,
		`INSERT INTO archive_deferred (audit_id, reason, first_seen_at_ns, last_checked_at_ns) VALUES
		 ('d-1', 'open', 1, 1), ('d-2', 'parse_pending', 1, 1), ('d-3', 'caller_pending', 1, 1),
		 ('d-4', 'integrity_failed', 1, 1), ('d-5', 'export_failed', 1, 2)`,
	} {
		if err := exec(statement); err != nil {
			t.Fatalf("rejected: %s: %v", statement, err)
		}
	}
	for _, statement := range []string{
		// A second current member of the same audit.
		`INSERT INTO archive_members (audit_id, revision, segment_id, record_digest, change_stamp, state, started_at_ns, state_changed_at_ns)
		 VALUES ('a-1', 3, '0000000000000000000000000000000a', decode(repeat('22', 32), 'hex'), decode(repeat('33', 32), 'hex'), 'sealed', 1, 1)`,
		// A current member without a change stamp.
		`INSERT INTO archive_members (audit_id, revision, segment_id, record_digest, change_stamp, state, started_at_ns, state_changed_at_ns)
		 VALUES ('a-2', 1, '0000000000000000000000000000000a', decode(repeat('22', 32), 'hex'), NULL, 'sealed', 1, 1)`,
		// A sealed segment without its manifest digest.
		`UPDATE archive_segments SET state = 'sealed' WHERE segment_id = '0000000000000000000000000000000a'`,
		// An absolute manifest name.
		`INSERT INTO archive_segments (segment_id, run_id, bundle_kind, format_version, manifest_name, key_fingerprint,
		     encrypted, member_count, disk_bytes, state, created_at_ns)
		 VALUES ('0000000000000000000000000000000b', '00000000000000000000000000000001', 'bucket', 0, '/abs.manifest.json',
		     decode(repeat('11', 32), 'hex'), 1, 0, 0, 'publishing', 1)`,
		`INSERT INTO archive_deferred (audit_id, reason, first_seen_at_ns, last_checked_at_ns) VALUES ('a-3', 'other', 1, 1)`,
		`INSERT INTO archive_runs (run_id, mode, cutoff_ns, started_at_ns, status, format_version, watermark_started_at_ns)
		 VALUES ('00000000000000000000000000000002', 'export_only', 1, 1, 'running', 0, 5)`,
		// A run with segments cannot be deleted.
		`DELETE FROM archive_runs WHERE run_id = '00000000000000000000000000000001'`,
	} {
		if err := exec(statement); err == nil {
			t.Fatalf("accepted: %s", statement)
		}
	}
	// Dropping an intent removes its members.
	if err := exec(`DELETE FROM archive_segments WHERE segment_id = '0000000000000000000000000000000a'`); err != nil {
		t.Fatal(err)
	}
	var members int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM archive_members`).Scan(&members); err != nil || members != 0 {
		t.Fatalf("members after dropping the segment = %d, %v", members, err)
	}
}

// Migration 008 on a version 7 database with signed audits of both capture
// versions: it only creates tables, so no relation file is rewritten and no
// row of an existing table changes (its xmin stays), the integrity chain and
// every payload verify before and after, and the documented rollback returns
// to version 7. Reopening an upgraded database applies nothing again.
func TestMigrationEightUpgradesVersionSevenDatabase(t *testing.T) {
	ctx := context.Background()
	store, dsn := openSignedStore(t)
	cipher := v2TestCipher(t)
	writeV2Audit(t, store, cipher, v2Audit{id: "upgrade-v2"})
	writeV1Audit(t, store, cipher, "upgrade-v1")
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, rollbackToSchemaSevenSQL); err != nil {
		t.Fatalf("documented rollback SQL: %v", err)
	}
	versions := appliedSchemaVersions(t, admin)
	requireVersions(t, versions, 1, 2, 3, 4, 5, 6, 7)
	requireArchiveCatalog(t, admin, false)
	if err := requireSupportedSchema(versions[len(versions)-1], 7); err != nil {
		t.Fatalf("a version 7 binary rejects the rolled-back database: %v", err)
	}

	tables := []string{"audit_records", "http_stages", "http_header_blocks", "http_headers", "body_streams", "integrity_events"}
	rowVersions := func() []string {
		var result []string
		for _, table := range tables {
			rows, err := admin.QueryContext(ctx, `SELECT ctid::text || ':' || xmin::text FROM `+table+` ORDER BY ctid`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var value string
				if err := rows.Scan(&value); err != nil {
					t.Fatal(err)
				}
				result = append(result, table+"/"+value)
			}
			if err := closeRows(rows); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	beforeFiles := relationFiles(t, admin, tables...)
	beforeRows := rowVersions()
	if len(beforeRows) == 0 {
		t.Fatal("fixture has no rows")
	}

	upgraded, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 7 database: %v", err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	requireArchiveCatalog(t, admin, true)
	if after := relationFiles(t, admin, tables...); !slices.Equal(beforeFiles, after) {
		t.Fatalf("relation files before %v, after %v", beforeFiles, after)
	}
	if after := rowVersions(); !slices.Equal(beforeRows, after) {
		t.Fatalf("migration 008 rewrote rows")
	}
	if err := upgraded.EnableIntegrity(ctx, v2TestKey); err != nil {
		t.Fatalf("chain after upgrade: %v", err)
	}
	if err := upgraded.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payloads after upgrade: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}

	// Idempotent: reopening applies nothing and changes nothing.
	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := Open(ctx, dsn)
		if err != nil {
			t.Fatalf("reopen %d: %v", attempt, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	if after := rowVersions(); !slices.Equal(beforeRows, after) {
		t.Fatalf("reopening rewrote rows")
	}

	// The rollback, then the upgrade again.
	if _, err := admin.ExecContext(ctx, rollbackToSchemaSevenSQL); err != nil {
		t.Fatalf("rollback after upgrade: %v", err)
	}
	requireArchiveCatalog(t, admin, false)
	again, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	if err := again.EnableIntegrity(ctx, v2TestKey); err != nil {
		t.Fatal(err)
	}
	if err := again.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatal(err)
	}
}

// HasAudits is true for audit rows, for integrity events alone, and for a
// catalogued archive segment alone (design L.3).
func TestHasAuditsSeesArchiveCatalog(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	has, err := store.HasAudits(ctx)
	if err != nil || has {
		t.Fatalf("empty store HasAudits = %v, %v", has, err)
	}
	run := testArchiveRun("10000000000000000000000000000001", 100)
	if _, err := store.BeginArchiveRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	// A run alone is not archived history.
	if has, err := store.HasAudits(ctx); err != nil || has {
		t.Fatalf("HasAudits with only a run = %v, %v", has, err)
	}
	segment := testArchiveSegment("20000000000000000000000000000001", run.RunID, "sessions/x.manifest.json", 0)
	if _, err := store.RegisterArchiveIntent(ctx, ArchiveIntent{Segment: segment}); err != nil {
		t.Fatal(err)
	}
	if has, err := store.HasAudits(ctx); err != nil || !has {
		t.Fatalf("HasAudits with a catalogued segment = %v, %v", has, err)
	}
	var audits, events int
	if err := store.readerDB.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_records), (SELECT COUNT(*) FROM integrity_events)`).Scan(&audits, &events); err != nil || audits != 0 || events != 0 {
		t.Fatalf("fixture has %d audits and %d events, %v", audits, events, err)
	}
}
