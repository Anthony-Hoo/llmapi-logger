package migrate

import (
	"context"
	"testing"

	"llmapi-logger/internal/storage/postgres"
)

// The import target holds the 001 baseline alone, without capture_version, and
// its verification reads every capture event as version 1 (design D.3, E.3).
// The first start of the proxy then applies migrations 002 to 007; every
// imported row is capture version 1 and the whole chain and every payload
// still verify.
func TestImportThenFirstOpenVerifies(t *testing.T) {
	path, key := sourceFixture(t)
	dsn, db := pgTarget(t)
	if _, err := Run(context.Background(), Options{SourcePath: path, DatabaseURL: dsn, Key: key, ServiceStopped: true}); err != nil {
		t.Fatal(err)
	}
	var columns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND column_name = 'capture_version'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("import target has capture_version: %d, %v", columns, err)
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("chain after the first open: %v", err)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("payloads after the first open: %v", err)
	}
	if state := store.IntegrityPayloadState(); state != "verified" {
		t.Fatalf("payload state = %q", state)
	}
	var version, audits, versionOne int
	if err := db.QueryRow(`SELECT MAX(version), (SELECT COUNT(*) FROM audit_records), (SELECT COUNT(*) FROM audit_records WHERE capture_version = 1 AND user_agent_enc IS NULL)
		FROM schema_migrations`).Scan(&version, &audits, &versionOne); err != nil {
		t.Fatal(err)
	}
	if version != 7 || audits == 0 || versionOne != audits {
		t.Fatalf("after the first open: schema %d, %d audits, %d of them version 1", version, audits, versionOne)
	}
}
