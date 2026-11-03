package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

var schemaSequence atomic.Uint64

func newTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("LOGGER_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for real PostgreSQL integration tests")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL test connection configuration")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("logger_test_%d_%d", time.Now().UnixNano(), schemaSequence.Add(1))
	if _, err := db.ExecContext(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("clean test schema: %v", err)
		}
		db.Close()
	})
	config.RuntimeParams["search_path"] = schema
	// ConnString retains runtime parameters only when explicitly rebuilt: use
	// libpq key/value suffix, with the generated identifier containing no quotes.
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " search_path=" + schema
}

func TestWriterOwnershipAndLostSessionFencing(t *testing.T) {
	store, dsn := openTestStore(t)
	ctx := context.Background()
	if second, err := Open(ctx, dsn); !errors.Is(err, ErrWriterOwned) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second writer = %v", err)
	}
	var pid int
	if err := store.writerConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, testAudit("lost-session")); err == nil {
		t.Fatal("writer continued after losing its locked session")
	}
	if store.Healthy() {
		t.Fatal("lost writer reports healthy")
	}
	successor, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	if err := successor.BeginAudit(ctx, testAudit("successor")); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginAudit(ctx, testAudit("stale-owner")); err == nil {
		t.Fatal("stale writer reconnected")
	}
	var count int
	if err := admin.QueryRow(`SELECT count(*) FROM audit_records WHERE audit_id IN ('lost-session','stale-owner')`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale writes = %d, err=%v", count, err)
	}
}

func TestReaderPoolIsReadOnly(t *testing.T) {
	store, _ := openTestStore(t)
	_, err := store.readerDB.Exec(`INSERT INTO schema_migrations(version,applied_at_ns) VALUES(99,1)`)
	if ErrorClass(err) != "postgres_read_only" {
		t.Fatalf("reader accepted mutation or wrong error: %v", err)
	}
}

func TestSchemaInitializationRollsBack(t *testing.T) {
	dsn := newTestDSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := AcquireWriterLock(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeImportSchema(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := conn.QueryRowContext(context.Background(), `SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("rollback retained %d tables: %v", tables, err)
	}
}
