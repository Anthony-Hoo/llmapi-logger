package app

import (
	"context"
	"fmt"
	"log/slog"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
)

// assembleCaptureSettings builds the audit capture setting of the "系统配置"
// page (the CommitAudit retry count, design H.3) and applies the saved value
// to the manager. It is assembled even when the audit manager is the
// unavailable one: the page then shows the values, and a value saved while
// no session uses it applies from the next start. Without a store (the audit
// storage could not be opened, or was closed when the manager became
// unavailable) reads answer with the configuration file and writes are
// refused.
func assembleCaptureSettings(ctx context.Context, configuration config.Config, runtime auditRuntime, logger *slog.Logger) (*audit.CaptureSettings, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var store audit.SettingsStore
	if runtime.store != nil {
		store = runtime.store
	}
	loadContext, cancel := context.WithTimeout(ctx, savedSettingsTimeout)
	defer cancel()
	service, err := audit.NewCaptureSettings(loadContext, audit.CaptureSettingsOptions{
		FileRetries: configuration.Audit.CommitRetries,
		WritePath:   configuration.Audit.WritePath,
		Store:       store,
		Manager:     runtime.manager,
		Logger:      logger,
	})
	if err != nil {
		return nil, fmt.Errorf("assemble audit capture settings: %w", err)
	}
	return service, nil
}
