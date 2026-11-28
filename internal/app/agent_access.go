package app

import (
	"errors"
	"log/slog"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentdist"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/uaguard"
	"llmapi-logger/internal/web"
)

// The runtime type assertion in assembleAgentAccess is only exercised by an
// enabled PostgreSQL deployment; pin the contract at compile time. Like the
// organisation reports the store is reached through an optional interface
// rather than runtimeStore, so the test stores need no stub methods.
var _ agentaccess.Store = (*postgres.Store)(nil)

// The write facade reaches the services' agent entry points through optional
// interfaces asserted at use (web.Agent…). A service passed under another
// type would make every write of its kind UPSTREAM_UNAVAILABLE with all unit
// tests green, so the concrete types assembled here are pinned too.
var (
	_ web.AgentUARuleWriter           = (*uaguard.Service)(nil)
	_ web.AgentContentRuleWriter      = (*contentpolicy.Service)(nil)
	_ web.AgentOrgWriter              = (*orgreport.Service)(nil)
	_ web.AgentAnalysisSettingsWriter = (*sessionanalysis.SettingsService)(nil)
	_ web.AgentAnalysisRunner         = (*sessionanalysis.QueryService)(nil)
	// A dismissal plan checks the suggestion through the store the query
	// service holds; without the read every such plan would be refused.
	_ sessionanalysis.SuggestionStore   = (*postgres.Store)(nil)
	_ sessionanalysis.SuggestionChecker = (*postgres.Store)(nil)
)

// assembleAgentAccess builds the agent token service of an enabled
// deployment (doc/features/25-agent-access.md). It returns nil, and the
// facade then answers FEATURE_DISABLED, when the section is off or when the
// audit store did not open at startup: the latter matches the other optional
// features, which also stay unassembled in an available-mode start without a
// database. A store that opened but cannot hold agent tokens is an error.
func assembleAgentAccess(configuration config.Config, store runtimeStore, developer web.DeveloperLogin, logger *slog.Logger) (*agentaccess.Service, error) {
	if !configuration.AgentAccess.Enabled {
		return nil, nil
	}
	if store == nil {
		logger.Warn("agent access unavailable without the audit store", "error_category", "agent_access_unavailable")
		return nil, nil
	}
	agentStore, ok := store.(agentaccess.Store)
	if !ok {
		return nil, errors.New("agent access needs the PostgreSQL store")
	}
	return agentaccess.New(agentaccess.Options{
		AdminToken: configuration.AdminToken,
		Store:      agentStore,
		AllowWrite: configuration.AgentAccess.AllowWrite,
		// The same condition that makes developer sign-in usable; when it is
		// not, developer agent tokens are refused like developer cookies.
		DeveloperLogins: developer.Enabled && developer.NewAPIURL != "" && developer.Fingerprints != nil && developer.ValidateKey != nil,
		Logger:          logger,
	})
}

// Option adjusts the assembly. The only one is a test seam; production
// starts pass none.
type Option func(*assemblyOptions)

type assemblyOptions struct {
	agentPackageDir string
	archive         archiveSeams
}

// WithAgentPackageDir reads the agent packages from dir instead of the
// agent-packages directory next to the executable. Tests use it: a test
// binary has no packages beside it.
func WithAgentPackageDir(dir string) Option {
	return func(options *assemblyOptions) { options.agentPackageDir = dir }
}

// assembleAgentDist builds the distribution service of an assembled agent
// access module (contract section 5). Packages are optional at run time: a
// missing or broken package directory logs one warning and the two
// endpoints answer that no packages ship with this deployment, so a build
// without packages still starts. The download-link key is derived inside
// agentdist from the admin token; neither is stored here or logged.
func assembleAgentDist(configuration config.Config, agent *agentaccess.Service, packageDir string, logger *slog.Logger) *agentdist.Service {
	if agent == nil {
		return nil
	}
	if packageDir == "" {
		dir, err := agentdist.DefaultPackageDir()
		if err != nil {
			logger.Warn("agent packages unavailable", "error_category", "agent_packages_unavailable", "reason", "cannot locate the executable")
			return nil
		}
		packageDir = dir
	}
	service, err := agentdist.New(agentdist.Options{PackageDir: packageDir, AdminToken: configuration.AdminToken})
	if err != nil {
		logger.Warn("agent packages unavailable", "error_category", "agent_packages_unavailable", "reason", "the download signer could not be built")
		return nil
	}
	if loadErr := service.LoadError(); loadErr != nil {
		// LoadError names the problem (missing directory, version mismatch,
		// a file that does not match the manifest) and holds no secret.
		logger.Warn("agent packages unavailable", "error_category", "agent_packages_unavailable", "reason", loadErr.Error())
	}
	return service
}
