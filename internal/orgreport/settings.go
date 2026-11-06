// Package orgreport implements the optional organisation project reports
// (doc/features/23-org-project-reports.md): project groups, project rules,
// per-root active time, weekly ranking snapshots.
//
// The time engine in this package is made of pure functions over already
// loaded request rows. Storage, decryption and HTTP live in their own layers;
// raw repository paths, remote URLs and working directories only exist in
// memory while rules are resolved and are never logged.
package orgreport

import (
	"errors"
	"sort"
	"time"

	"llmapi-logger/internal/config"
)

// Settings is the validated runtime form of config.OrgReportsConfig.
type Settings struct {
	Location              *time.Location
	WeekStart             time.Weekday
	IdleGap               time.Duration
	RankedClients         map[string]bool
	MaxConcurrentRoots    int
	MaxSingleRequestRoots int
	// AdminUserID is the configured NewAPI administrator. It is proposed as a
	// service principal until an administrator classifies it.
	AdminUserID int64
}

// SettingsFromConfig converts an enabled, validated section.
func SettingsFromConfig(section config.OrgReportsConfig, adminUserID int64) (Settings, error) {
	if !section.Enabled {
		return Settings{}, errors.New("orgreport: org_reports is disabled")
	}
	location, err := config.OrgLocation(section.Timezone)
	if err != nil {
		return Settings{}, err
	}
	weekStart, err := config.OrgWeekStart(section.WeekStart)
	if err != nil {
		return Settings{}, err
	}
	if section.IdleGapSeconds <= 0 {
		return Settings{}, errors.New("orgreport: idle gap must be positive")
	}
	ranked := make(map[string]bool, len(section.RankedClients))
	for _, client := range section.RankedClients {
		ranked[client] = true
	}
	return Settings{
		Location:              location,
		WeekStart:             weekStart,
		IdleGap:               time.Duration(section.IdleGapSeconds) * time.Second,
		RankedClients:         ranked,
		MaxConcurrentRoots:    section.Anomaly.MaxConcurrentRoots,
		MaxSingleRequestRoots: section.Anomaly.MaxSingleRequestRoots,
		AdminUserID:           adminUserID,
	}, nil
}

// PublicSettings is the subset the UI may read.
type PublicSettings struct {
	Timezone              string   `json:"timezone"`
	WeekStart             string   `json:"week_start"`
	IdleGapSeconds        int64    `json:"idle_gap_seconds"`
	RankedClients         []string `json:"ranked_clients"`
	MaxConcurrentRoots    int      `json:"max_concurrent_roots"`
	MaxSingleRequestRoots int      `json:"max_single_request_roots"`
}

// Public returns the UI view of the settings.
func (settings Settings) Public() PublicSettings {
	clients := make([]string, 0, len(settings.RankedClients))
	for client := range settings.RankedClients {
		clients = append(clients, client)
	}
	sort.Strings(clients)
	weekStart := "monday"
	if settings.WeekStart == time.Sunday {
		weekStart = "sunday"
	}
	zone := "UTC"
	if settings.Location != nil {
		zone = settings.Location.String()
	}
	return PublicSettings{
		Timezone:              zone,
		WeekStart:             weekStart,
		IdleGapSeconds:        int64(settings.IdleGap / time.Second),
		RankedClients:         clients,
		MaxConcurrentRoots:    settings.MaxConcurrentRoots,
		MaxSingleRequestRoots: settings.MaxSingleRequestRoots,
	}
}
