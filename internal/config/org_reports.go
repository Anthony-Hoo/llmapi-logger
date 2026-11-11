package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	// Report week boundaries are computed in a named zone; container images
	// often ship without a zoneinfo database.
	_ "time/tzdata"
)

const (
	maxOrgIdleGapSeconds = 3600
	maxOrgRankedClients  = 64
	maxOrgClientNameLen  = 64
	maxOrgAnomalyLimit   = 1_000_000
)

// validateOrgReports checks the org_reports section. A disabled section is
// not inspected at all, so a personal deployment never fails on it.
func validateOrgReports(cfg Config) error {
	org := cfg.OrgReports
	if !org.Enabled {
		return nil
	}
	if cfg.NewAPI.AccessToken == "" || cfg.NewAPI.UserID <= 0 {
		return errors.New("org_reports.enabled requires newapi.access_token and newapi.user_id (NewAPI caller identity)")
	}
	if !cfg.Insights.Enabled {
		return errors.New("org_reports.enabled requires insights.enabled (sessions and agent trees)")
	}
	if _, err := OrgLocation(org.Timezone); err != nil {
		return err
	}
	if _, err := OrgWeekStart(org.WeekStart); err != nil {
		return err
	}
	if org.IdleGapSeconds < 1 || org.IdleGapSeconds > maxOrgIdleGapSeconds {
		return fmt.Errorf("org_reports.idle_gap_seconds must be between 1 and %d, got %d", maxOrgIdleGapSeconds, org.IdleGapSeconds)
	}
	if len(org.RankedClients) == 0 || len(org.RankedClients) > maxOrgRankedClients {
		return fmt.Errorf("org_reports.ranked_clients must list between 1 and %d clients", maxOrgRankedClients)
	}
	seen := make(map[string]struct{}, len(org.RankedClients))
	for _, client := range org.RankedClients {
		if !validOrgClientName(client) {
			return fmt.Errorf("org_reports.ranked_clients entry %q must be a lower-case vocabulary client key", client)
		}
		if _, duplicate := seen[client]; duplicate {
			return fmt.Errorf("org_reports.ranked_clients lists %q twice", client)
		}
		seen[client] = struct{}{}
	}
	if org.Anomaly.MaxConcurrentRoots < 1 || org.Anomaly.MaxConcurrentRoots > maxOrgAnomalyLimit {
		return fmt.Errorf("org_reports.anomaly.max_concurrent_roots must be between 1 and %d", maxOrgAnomalyLimit)
	}
	if org.Anomaly.MaxSingleRequestRoots < 1 || org.Anomaly.MaxSingleRequestRoots > maxOrgAnomalyLimit {
		return fmt.Errorf("org_reports.anomaly.max_single_request_roots must be between 1 and %d", maxOrgAnomalyLimit)
	}
	if org.LLMClassification.Enabled {
		return errors.New("org_reports.llm_classification was replaced by session_analysis and must stay disabled")
	}
	return nil
}

// OrgLocation loads the report time zone.
func OrgLocation(name string) (*time.Location, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return nil, errors.New("org_reports.timezone must be a non-empty IANA zone name")
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("org_reports.timezone %q is not a known IANA zone", name)
	}
	return location, nil
}

// OrgWeekStart parses week_start.
func OrgWeekStart(value string) (time.Weekday, error) {
	switch value {
	case "monday":
		return time.Monday, nil
	case "sunday":
		return time.Sunday, nil
	default:
		return 0, fmt.Errorf("org_reports.week_start must be monday or sunday, got %q", value)
	}
}

func validOrgClientName(name string) bool {
	if name == "" || len(name) > maxOrgClientNameLen {
		return false
	}
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '_', char == '-':
		default:
			return false
		}
	}
	return true
}
