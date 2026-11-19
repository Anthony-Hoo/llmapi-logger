package app

import (
	"errors"
	"log/slog"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage/postgres"
	"llmapi-logger/internal/web"
)

// The runtime type assertion in assembleAgentAccess is only exercised by an
// enabled PostgreSQL deployment; pin the contract at compile time. Like the
// organisation reports the store is reached through an optional interface
// rather than runtimeStore, so the test stores need no stub methods.
var _ agentaccess.Store = (*postgres.Store)(nil)

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
