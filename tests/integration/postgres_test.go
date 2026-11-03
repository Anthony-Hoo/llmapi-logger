package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

var integrationSchemaSequence atomic.Uint64

// Each fixture gets its own schema, including when two applications run in one
// test. Cleanup runs after application shutdown and never touches other schemas.
func newIntegrationDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is required in CI for PostgreSQL integration tests")
		}
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
	}
	if _, err := pgx.ParseConfig(dsn); err != nil {
		t.Fatal("invalid PostgreSQL test connection configuration")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open PostgreSQL test connection")
	}
	schema := fmt.Sprintf("logger_integration_%d_%d", time.Now().UnixNano(), integrationSchemaSequence.Add(1))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		db.Close()
		t.Fatalf("create PostgreSQL integration schema: %v", err)
	}
	t.Cleanup(func() {
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("clean PostgreSQL integration schema: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid PostgreSQL test URL")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " search_path=" + schema
}
