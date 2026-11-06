package app

import (
	"log/slog"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/orgreport"
)

// assembleOrgReports builds the organisation report service of an enabled
// deployment. config.Validate already guarantees NewAPI identity and insights.
func assembleOrgReports(configuration config.Config, logger *slog.Logger) (*orgreport.Service, error) {
	settings, err := orgreport.SettingsFromConfig(configuration.OrgReports, configuration.NewAPI.UserID)
	if err != nil {
		return nil, err
	}
	return orgreport.NewService(orgreport.Options{Settings: settings, Logger: logger})
}
