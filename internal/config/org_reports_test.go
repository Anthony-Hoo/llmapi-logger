package config

import (
	"reflect"
	"strings"
	"testing"
)

func orgEnabledConfig() Config {
	cfg := testConfig()
	cfg.NewAPI.AccessToken = "placeholder-token"
	cfg.NewAPI.UserID = 1
	cfg.OrgReports.Enabled = true
	return cfg
}

func TestOrgReportsDefaultToDisabled(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(cfg.OrgReports, DefaultOrgReports()) || cfg.OrgReports.Enabled {
		t.Fatalf("OrgReports = %+v, want disabled defaults", cfg.OrgReports)
	}
	if cfg.OrgReports.IdleGapSeconds != 180 || cfg.OrgReports.Timezone != "Asia/Shanghai" || cfg.OrgReports.WeekStart != "monday" {
		t.Fatalf("defaults drifted: %+v", cfg.OrgReports)
	}
}

func TestDisabledOrgReportsIsNeverInspected(t *testing.T) {
	cfg := testConfig()
	cfg.OrgReports = OrgReportsConfig{Timezone: "Not/AZone", WeekStart: "friday", IdleGapSeconds: -1}
	cfg.Insights.Enabled = false
	if err := Validate(cfg); err != nil {
		t.Fatalf("disabled org_reports must not be validated: %v", err)
	}
}

func TestLoadOrgReportsBlockReplacesLists(t *testing.T) {
	cfg, err := Load(writeConfig(t, `admin_token: test-token
newapi:
  access_token: placeholder-token
  user_id: 1
org_reports:
  enabled: true
  timezone: UTC
  week_start: sunday
  idle_gap_seconds: 120
  ranked_clients: [codex, my_agent]
  anomaly:
    max_concurrent_roots: 4
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	org := cfg.OrgReports
	if !org.Enabled || org.Timezone != "UTC" || org.WeekStart != "sunday" || org.IdleGapSeconds != 120 {
		t.Fatalf("OrgReports = %+v", org)
	}
	if !reflect.DeepEqual(org.RankedClients, []string{"codex", "my_agent"}) {
		t.Fatalf("ranked_clients = %v, want the YAML list to replace the default", org.RankedClients)
	}
	if org.Anomaly.MaxConcurrentRoots != 4 || org.Anomaly.MaxSingleRequestRoots != DefaultOrgMaxSingleRequestRoots {
		t.Fatalf("anomaly = %+v", org.Anomaly)
	}
	if _, err := Load(writeConfig(t, "admin_token: test-token\norg_reports:\n  unknown: 1\n")); err == nil {
		t.Fatal("Load() accepted an unknown org_reports field")
	}
}

func TestValidateOrgReports(t *testing.T) {
	if err := Validate(orgEnabledConfig()); err != nil {
		t.Fatalf("enabled defaults rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no newapi token", func(cfg *Config) { cfg.NewAPI.AccessToken, cfg.NewAPI.UserID = "", 0 }, "requires newapi.access_token"},
		{"insights disabled", func(cfg *Config) { cfg.Insights.Enabled = false }, "requires insights.enabled"},
		{"bad timezone", func(cfg *Config) { cfg.OrgReports.Timezone = "Mars/Base" }, "org_reports.timezone"},
		{"empty timezone", func(cfg *Config) { cfg.OrgReports.Timezone = "" }, "org_reports.timezone"},
		{"bad week start", func(cfg *Config) { cfg.OrgReports.WeekStart = "friday" }, "org_reports.week_start"},
		{"zero gap", func(cfg *Config) { cfg.OrgReports.IdleGapSeconds = 0 }, "idle_gap_seconds"},
		{"huge gap", func(cfg *Config) { cfg.OrgReports.IdleGapSeconds = 7200 }, "idle_gap_seconds"},
		{"no ranked clients", func(cfg *Config) { cfg.OrgReports.RankedClients = nil }, "ranked_clients"},
		{"upper-case client", func(cfg *Config) { cfg.OrgReports.RankedClients = []string{"Codex"} }, "ranked_clients"},
		{"duplicate client", func(cfg *Config) { cfg.OrgReports.RankedClients = []string{"codex", "codex"} }, "twice"},
		{"zero concurrency", func(cfg *Config) { cfg.OrgReports.Anomaly.MaxConcurrentRoots = 0 }, "max_concurrent_roots"},
		{"zero single", func(cfg *Config) { cfg.OrgReports.Anomaly.MaxSingleRequestRoots = 0 }, "max_single_request_roots"},
		{"llm classification", func(cfg *Config) { cfg.OrgReports.LLMClassification.Enabled = true }, "llm_classification"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := orgEnabledConfig()
			test.mutate(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestOrgRankedClientsMayNameClientsOutsideTheVocabulary(t *testing.T) {
	cfg := orgEnabledConfig()
	cfg.OrgReports.RankedClients = []string{"pi", "zcode", "an-override-client"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("clients added by a later vocabulary must be accepted: %v", err)
	}
}
