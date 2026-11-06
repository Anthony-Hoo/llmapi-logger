package orgreport

import (
	"errors"
	"log/slog"
)

// Options assembles a Service.
type Options struct {
	Settings Settings
	Logger   *slog.Logger
}

// Service is the organisation report surface used by the web layer and the
// parser worker's idle cadence.
type Service struct {
	settings Settings
	logger   *slog.Logger
}

// NewService validates the collaborators of an enabled deployment.
func NewService(options Options) (*Service, error) {
	if options.Settings.Location == nil || options.Settings.IdleGap <= 0 {
		return nil, errors.New("orgreport: settings are incomplete")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &Service{settings: options.Settings, logger: options.Logger}, nil
}

// Settings returns the UI view of the report settings.
func (service *Service) Settings() PublicSettings {
	return service.settings.Public()
}
