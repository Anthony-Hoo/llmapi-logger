package app

import (
	"context"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage/sqlite"
	"log/slog"
)

// Legacy behavioral fixtures remain local SQLite tests. Production constructors
// always open PostgreSQL; the opener is injected only by this test package.
func newSQLiteTest(cfg config.Config, logger *slog.Logger) (*App, error) {
	return newSQLiteTestContext(context.Background(), cfg, logger)
}
func newSQLiteTestContext(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	cfg.DatabaseURL = "postgresql://localhost/test?sslmode=disable"
	return newContextWithStore(ctx, cfg, logger, func(ctx context.Context, _ string, logger *slog.Logger) (runtimeStore, error) {
		return sqlite.OpenWithLogger(ctx, cfg.DBPath, logger)
	})
}
func assembleSQLiteTest(ctx context.Context, cfg config.Config, logger *slog.Logger) auditRuntime {
	return assembleAuditWithStore(ctx, cfg, logger, func(ctx context.Context, _ string, logger *slog.Logger) (runtimeStore, error) {
		return sqlite.OpenWithLogger(ctx, cfg.DBPath, logger)
	})
}
