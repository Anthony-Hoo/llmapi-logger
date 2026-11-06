package app

import (
	"errors"
	"log/slog"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/security"
)

// orgAssembly is what the organisation reports need from the rest of the
// application. config.Validate already guarantees NewAPI identity and
// insights; the store must additionally implement the org persistence.
type orgAssembly struct {
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
	projectStore, ok := assembly.store.(insights.ProjectStore)
	if !ok || assembly.cipher == nil || assembly.fingerprints == nil || assembly.vocabulary == nil {
		return nil, errors.New("org reports need the PostgreSQL store, the audit key and insights")
	}
	runner, err := insights.NewProjectRunner(projectStore, assembly.cipher, assembly.vocabulary, assembly.fingerprints)
	if err != nil {
		return nil, err
	}
	service, err := orgreport.NewService(orgreport.Options{Settings: settings, Logger: assembly.logger})
	if err != nil {
		return nil, err
	}
	if assembly.worker != nil {
		allowlist := append(assembly.vocabulary.HeaderAllowlist(), assembly.vocabulary.ProjectHeaderAllowlist()...)
		assembly.worker.SetHeaderAllowlist(allowlist)
		assembly.worker.SetProjectAnalyzer(runner)
	}
	return service, nil
}
