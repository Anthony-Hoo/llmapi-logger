package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/security"
)

// orgStore is the persistence the organisation reports need; the PostgreSQL
// store implements it.
type orgStore interface {
	insights.ProjectStore
	orgreport.Repository
	orgreport.DataStore
	orgreport.SnapshotStore
}

// orgAssembly is what the organisation reports need from the rest of the
// application. config.Validate already guarantees NewAPI identity and
// insights; the store must additionally implement orgStore.
type orgAssembly struct {
	ctx           context.Context
	configuration config.Config
	logger        *slog.Logger
	store         runtimeStore
	cipher        security.Cipher
	vocabulary    *insights.Vocabulary
	fingerprints  *security.AnalysisFingerprinter
	worker        *parser.Worker
}

// assembleOrgReports builds the organisation report service of an enabled
// deployment and installs its parser hooks: the project identity extractor
// on the live path and its backfill.
func assembleOrgReports(assembly orgAssembly) (*orgreport.Service, error) {
	settings, err := orgreport.SettingsFromConfig(assembly.configuration.OrgReports, assembly.configuration.NewAPI.UserID)
	if err != nil {
		return nil, err
	}
	store, ok := assembly.store.(orgStore)
	if !ok || assembly.cipher == nil || assembly.fingerprints == nil || assembly.vocabulary == nil {
		return nil, errors.New("org reports need the PostgreSQL store, the audit key and insights")
	}
	runner, err := insights.NewProjectRunner(store, assembly.cipher, assembly.vocabulary, assembly.fingerprints)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(assembly.ctx, 10*time.Second)
	defer cancel()
	service, err := orgreport.NewService(ctx, orgreport.Options{
		Settings: settings, Repository: store, Data: store, Snapshots: store,
		Cipher: assembly.cipher, Logger: assembly.logger, IdentityVersion: insights.ProjectIdentityVersion,
	})
	if err != nil {
		return nil, err
	}
	if assembly.worker != nil {
		allowlist := append(assembly.vocabulary.HeaderAllowlist(), assembly.vocabulary.ProjectHeaderAllowlist()...)
		assembly.worker.SetHeaderAllowlist(allowlist)
		assembly.worker.SetProjectAnalyzer(runner)
		// Weekly snapshots ride the parser idle cadence; the tick only
		// starts a guarded goroutine and never blocks parsing.
		assembly.worker.AddIdleTask(service.SnapshotTick)
	}
	return service, nil
}
