package app

import (
	"context"
	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/retention"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/uaguard"
	"log/slog"
)

// runtimeStore preserves narrow consumer contracts without coupling the
// application lifecycle to a particular SQL driver's concrete type.
type runtimeStore interface {
	audit.Store
	parser.Store
	newapi.CallerStore
	query.Store
	query.InsightsStore
	insights.RunnerStore
	retention.Store
	sessionanalysis.Store
	sessionanalysis.QueryStore
	sessionanalysis.SettingsStore
	contentpolicy.Repository
	uaguard.Repository
	Close() error
	HasAudits(context.Context) (bool, error)
	EnableIntegrity(context.Context, []byte) error
	IntegrityEnabled() bool
	VerifyIntegrityPayloads(context.Context) error
	IntegrityPayloadState() string
	RecoverInterruptedAudits(context.Context, int64) (int, error)
}
type storeOpener func(context.Context, string, *slog.Logger) (runtimeStore, error)

func openPostgres(ctx context.Context, dsn string, logger *slog.Logger) (runtimeStore, error) {
	return postgres.OpenWithLogger(ctx, dsn, logger)
}
