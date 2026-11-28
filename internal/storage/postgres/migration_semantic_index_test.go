package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// rollbackToSchemaFourSQL is the rollback documented in
// doc/deployment/postgresql-migration.md for returning to a binary that only
// understands schema version 4. The upgrade test runs it verbatim, after the
// rollbacks to versions 7, 6 and 5 that a version 8 database needs first.
const rollbackToSchemaFourSQL = `
BEGIN;
CREATE INDEX IF NOT EXISTS content_objects_semantic_idx
    ON content_objects(semantic_hash, kind);
DELETE FROM schema_migrations WHERE version = 5;
COMMIT;
`

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func semanticIndexExists(t *testing.T, db rowQueryer) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('content_objects_semantic_idx') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func appliedSchemaVersions(t *testing.T, db rowQueryer) []int {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return versions
}

func requireVersions(t *testing.T, got []int, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("schema versions = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("schema versions = %v, want %v", got, want)
		}
	}
}

func TestFreshStoreHasNoSemanticIndex(t *testing.T) {
	store, _ := openTestStore(t)
	requireVersions(t, appliedSchemaVersions(t, store.readerDB), 1, 2, 3, 4, 5, 6, 7, 8)
	if semanticIndexExists(t, store.readerDB) {
		t.Fatal("content_objects_semantic_idx survived migration 5")
	}
	// The table and its primary key, which every object lookup uses, stay.
	var primaryKey bool
	if err := store.readerDB.QueryRow(`SELECT to_regclass('content_objects_pkey') IS NOT NULL`).Scan(&primaryKey); err != nil || !primaryKey {
		t.Fatalf("content_objects primary key missing: %v %v", primaryKey, err)
	}
}

func TestMigrationFiveUpgradesVersionFourDatabase(t *testing.T) {
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

	// The documented rollbacks, 008, 007, 006 and then 005, leave exactly the
	// version 4 state.
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL, rollbackToSchemaFiveSQL, rollbackToSchemaFourSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatalf("documented rollback SQL: %v", err)
		}
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4)
	if !semanticIndexExists(t, admin) {
		t.Fatal("rollback SQL did not recreate the index")
	}

	upgraded, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 4 database: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
	if semanticIndexExists(t, admin) {
		t.Fatal("upgrade from version 4 kept content_objects_semantic_idx")
	}

	// A version 4 database whose index an operator already dropped by hand.
	for _, rollback := range []string{rollbackToSchemaSevenSQL, rollbackToSchemaSixSQL, rollbackToSchemaFiveSQL} {
		if _, err := admin.ExecContext(ctx, rollback); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 5`); err != nil {
		t.Fatal(err)
	}
	upgraded, err = Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open version 4 database without the index: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	requireVersions(t, appliedSchemaVersions(t, admin), 1, 2, 3, 4, 5, 6, 7, 8)
}

func TestMigrationFiveIsIdempotent(t *testing.T) {
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
	body, err := migrationFiles.ReadFile("migrations/005_drop_content_objects_semantic_idx.sql")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := admin.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("re-running migration 5 (attempt %d): %v", attempt, err)
		}
	}
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
	if semanticIndexExists(t, admin) {
		t.Fatal("index reappeared")
	}
}

func TestOlderSchemaCheckRejectsNewerDatabase(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	var version int
	if err := store.readerDB.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 8 {
		t.Fatalf("fresh store version = %d", version)
	}
	// Binaries from before migrations 8, 7, 6 and 5 understand versions 7, 6,
	// 5 and 4 only.
	for _, older := range []int{7, 6, 5, 4} {
		if err := requireSupportedSchema(version, older); !errors.Is(err, errSchemaTooNew) {
			t.Fatalf("version %d binary accepted a version %d database: %v", older, version, err)
		}
	}
	if err := requireSupportedSchema(version, latestSchemaVersion); err != nil {
		t.Fatalf("current binary rejected its own schema: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The same check, end to end, against a database one version ahead.
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at_ns) VALUES ($1, 1)`, latestSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if newer, err := Open(ctx, dsn); !errors.Is(err, errSchemaTooNew) {
		if newer != nil {
			newer.Close()
		}
		t.Fatalf("open newer schema = %v", err)
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := InitializeImportSchema(ctx, tx); !errors.Is(err, errSchemaTooNew) {
		t.Fatalf("import schema on newer database = %v", err)
	}
}

func TestImportBaselineKeepsVersionOneIndexesUntilStoreOpens(t *testing.T) {
	ctx := context.Background()
	dsn := newTestDSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcquireWriterLock(ctx, conn); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeImportSchema(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// The offline importer's target holds the version 1 baseline alone.
	requireVersions(t, appliedSchemaVersions(t, conn), 1)
	if !semanticIndexExists(t, conn) {
		t.Fatal("import baseline lacks the 001 index")
	}
	requireTurnsCreatedIndex(t, conn, false)
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock_all()`); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open imported baseline: %v", err)
	}
	defer store.Close()
	requireVersions(t, appliedSchemaVersions(t, store.readerDB), 1, 2, 3, 4, 5, 6, 7, 8)
	if semanticIndexExists(t, store.readerDB) {
		t.Fatal("first open of an import target kept the index")
	}
	requireTurnsCreatedIndex(t, store.readerDB, true)
}
