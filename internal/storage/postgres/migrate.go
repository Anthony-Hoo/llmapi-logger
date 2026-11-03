package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func migrate(ctx context.Context, conn *sql.Conn) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin migration: %w", err)
	}
	defer tx.Rollback()
	var fresh bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NULL`).Scan(&fresh); err != nil {
		return err
	}
	if err := InitializeImportSchema(ctx, tx); err != nil {
		return err
	}
	if fresh {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_agent_rules(id,name,enabled,model_pattern,user_agent_pattern,created_at_ns,updated_at_ns) VALUES(1,'GPT models require Codex clients',1,'^gpt','^(codex-tui|Codex Desktop)',$1,$1)`, time.Now().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InitializeImportSchema applies the schema inside the caller's transaction.
// The caller must first hold AcquireWriterLock on the same pinned connection.
func InitializeImportSchema(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':' || current_schema() || ':llmapi-migrations', 0))`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at_ns BIGINT NOT NULL)`); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version > 1 {
		return errors.New("postgres: schema is newer than supported")
	}
	if version == 0 {
		body, err := migrationFiles.ReadFile("migrations/001_init.sql")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("postgres: initialize schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at_ns) VALUES (1, $1)`, time.Now().UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

// AcquireWriterLock holds exclusive store ownership for the lifetime of conn.
// Importers must keep this exact connection until rollback/commit and close.
func AcquireWriterLock(ctx context.Context, conn *sql.Conn) error {
	var acquired bool
	err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended(current_database() || ':' || current_schema() || ':llmapi-writer', 0))`).Scan(&acquired)
	if err != nil {
		return errors.New("postgres: acquire writer lock failed")
	}
	if !acquired {
		return ErrWriterOwned
	}
	return nil
}
