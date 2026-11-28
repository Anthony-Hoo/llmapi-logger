package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/storage/sqlite"
)

// keyCreationBackend seeds one store with a finished audit signed by a key
// that is never written to disk, optionally lets retention delete it, and
// returns the opener start-up should use for that store.
type keyCreationBackend struct {
	name string
	seed func(t *testing.T, retain bool) storeOpener
}

// Retention deletes audits but never integrity events. If the key file is then
// missing, start-up must refuse to create a new key, exactly as it does while
// audits remain: a new key would fail the chain verification anyway.
func TestStartupDoesNotReplaceMissingKeyWhileIntegrityEventsRemain(t *testing.T) {
	backends := []keyCreationBackend{{name: "sqlite", seed: seedSQLiteKeyCreation}}
	if os.Getenv("TEST_DATABASE_URL") != "" {
		backends = append(backends, keyCreationBackend{name: "postgres", seed: seedPostgresKeyCreation})
	}
	for _, backend := range backends {
		for _, scenario := range []struct {
			name      string
			retention bool
		}{
			{name: "audits remain", retention: false},
			{name: "only integrity events remain", retention: true},
		} {
			t.Run(backend.name+"/"+scenario.name, func(t *testing.T) {
				open := backend.seed(t, scenario.retention)
				configuration := testConfig(t)
				configuration.KeyPath = filepath.Join(t.TempDir(), "key", "audit.key")
				var logs bytes.Buffer

				runtime := assembleAuditWithStore(context.Background(), configuration, slog.New(slog.NewJSONHandler(&logs, nil)), open)
				if runtime.store != nil || runtime.cipher != nil {
					t.Fatal("start-up kept usable storage without the original key")
				}
				if runtime.manager == nil || runtime.manager.Healthy() {
					t.Fatal("start-up did not install an unavailable audit manager")
				}
				if !strings.Contains(logs.String(), `"error_category":"key_unavailable"`) {
					t.Fatalf("start-up logs = %s, want key_unavailable", logs.String())
				}
				if _, err := os.Stat(configuration.KeyPath); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("key file stat = %v, want no new key", err)
				}
			})
		}
	}
}

func seedSQLiteKeyCreation(t *testing.T, retain bool) storeOpener {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x3c}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: "audit-key-seed", StartedAtNS: 1, RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
		RequestURIEnc: []byte{1, 2, 3}, Mode: "available",
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: "audit-key-seed", EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseSkipped,
	}); err != nil {
		t.Fatal(err)
	}
	if retain {
		result, err := store.DeleteExpired(ctx, 10, sqlite.RetentionBatchLimit, sqlite.RetentionBatchLimit)
		if err != nil || result.DeletedAudits != 1 {
			t.Fatalf("retention = %+v, %v", result, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, _ string, logger *slog.Logger) (runtimeStore, error) {
		return sqlite.OpenWithLogger(ctx, path, logger)
	}
}

func seedPostgresKeyCreation(t *testing.T, retain bool) storeOpener {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := fmt.Sprintf("app_key_test_%d", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	schemaDSN := parsed.String()

	store, err := postgres.Open(ctx, schemaDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x3c}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, postgres.AuditRecord{
		AuditID: "audit-key-seed", StartedAtNS: 1, RouteID: "chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
		RequestURIEnc: []byte{1, 2, 3}, Mode: "available",
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, postgres.AuditFinish{
		AuditID: "audit-key-seed", EndedAtNS: 2, StatusCode: &status,
		ForwardStatus: postgres.ForwardCompleted, CaptureStatus: postgres.CaptureComplete, ParseStatus: postgres.ParseSkipped,
	}); err != nil {
		t.Fatal(err)
	}
	if retain {
		result, err := store.DeleteExpired(ctx, 10, postgres.RetentionBatchLimit, postgres.RetentionBatchLimit)
		if err != nil || result.DeletedAudits != 1 {
			t.Fatalf("retention = %+v, %v", result, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, _ string, logger *slog.Logger) (runtimeStore, error) {
		return postgres.OpenWithLogger(ctx, schemaDSN, logger)
	}
}
