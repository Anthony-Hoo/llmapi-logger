package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

func migrate(ctx context.Context, database *sql.DB) error {
	if _, err := database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL
)`); err != nil {
		return fmt.Errorf("sqlite: create migration table: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return errors.New("sqlite: no embedded migrations")
	}

	applied := make(map[int]struct{})
	rows, err := database.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("sqlite: read migration versions: %w", err)
	}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite: scan migration version: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlite: close migration rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate migration versions: %w", err)
	}

	latestSupported := migrations[len(migrations)-1].version
	supported := make(map[int]struct{}, len(migrations))
	for _, item := range migrations {
		supported[item.version] = struct{}{}
	}
	for version := range applied {
		if version > latestSupported {
			return fmt.Errorf("sqlite: database version %d is newer than supported version %d", version, latestSupported)
		}
		if _, exists := supported[version]; !exists {
			return fmt.Errorf("sqlite: database migration version %d is not supported by this program", version)
		}
	}

	for _, item := range migrations {
		if _, exists := applied[item.version]; exists {
			continue
		}
		if err := applyMigration(ctx, database, item); err != nil {
			return err
		}
	}
	return foreignKeyCheck(ctx, database)
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list migrations: %w", err)
	}

	loaded := make([]migration, 0, len(entries))
	seen := make(map[int]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("sqlite: invalid migration name %q", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("sqlite: invalid migration version in %q", entry.Name())
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("sqlite: duplicate migration version %d in %q and %q", version, previous, entry.Name())
		}
		contents, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("sqlite: read migration %q: %w", entry.Name(), err)
		}
		seen[version] = entry.Name()
		loaded = append(loaded, migration{version: version, name: entry.Name(), sql: string(contents)})
	}
	sort.Slice(loaded, func(left, right int) bool { return loaded[left].version < loaded[right].version })
	return loaded, nil
}

func applyMigration(ctx context.Context, database *sql.DB, item migration) error {
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin migration %d: %w", item.version, err)
	}
	if _, err := transaction.ExecContext(ctx, item.sql); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("sqlite: execute migration %d: %w", item.version, err)
	}
	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)",
		item.version,
		time.Now().UnixNano(),
	); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("sqlite: record migration %d: %w", item.version, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit migration %d: %w", item.version, err)
	}
	return nil
}

func foreignKeyCheck(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("sqlite: foreign key check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sqlite: foreign key check reported violations")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: foreign key check rows: %w", err)
	}
	return nil
}
