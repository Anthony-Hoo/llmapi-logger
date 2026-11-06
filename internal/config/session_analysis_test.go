package config

import (
	"net"
	"strings"
	"testing"
)

func TestSessionAnalysisDefaultsAreOffAndValid(t *testing.T) {
	cfg := testConfig()
	if cfg.SessionAnalysis.Enabled || cfg.SessionAnalysis.LLM.Enabled || !cfg.SessionAnalysis.LLM.DisableThinking {
		t.Fatalf("defaults = %+v", cfg.SessionAnalysis)
	}
	cfg.SessionAnalysis.Enabled = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("enabled defaults rejected: %v", err)
	}
	cfg.SessionAnalysis.LLM.Enabled = true
	cfg.SessionAnalysis.LLM.Model = "local-small"
	if err := Validate(cfg); err != nil {
		t.Fatalf("local llm defaults rejected: %v", err)
	}
}

func TestSessionAnalysisValidation(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*Config)
		want      string
	}{
		{"needs insights", func(cfg *Config) { cfg.Insights.Enabled = false }, "insights.enabled"},
		{"run_at", func(cfg *Config) { cfg.SessionAnalysis.RunAt = "2:00" }, "run_at"},
		{"run_at range", func(cfg *Config) { cfg.SessionAnalysis.RunAt = "24:00" }, "run_at"},
		{"idle", func(cfg *Config) { cfg.SessionAnalysis.SessionIdleMinutes = 1 }, "session_idle_minutes"},
		{"settle", func(cfg *Config) { cfg.SessionAnalysis.L1SettleHours = -1 }, "l1_settle_hours"},
		{"turns", func(cfg *Config) { cfg.SessionAnalysis.MinUserTurns = 0 }, "min_user_turns"},
		{"pack", func(cfg *Config) { cfg.SessionAnalysis.Pack.MaxTokens = 10 }, "pack.max_tokens"},
		{"compliance", func(cfg *Config) { cfg.SessionAnalysis.Compliance.Enabled = true }, "compliance"},
		{"vocabulary", func(cfg *Config) { cfg.SessionAnalysis.VocabularyFile = "missing-vocabulary.yaml" }, "vocabulary_file"},
		{"model required", func(cfg *Config) { cfg.SessionAnalysis.LLM.Enabled = true }, "llm.model"},
		{"structured output", func(cfg *Config) {
			cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
			cfg.SessionAnalysis.LLM.StructuredOutput = "xml"
		}, "structured_output"},
		{"context budget", func(cfg *Config) {
			cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
			cfg.SessionAnalysis.LLM.ContextTokens = 8192
		}, "exceeds llm.context_tokens"},
		{"remote endpoint", func(cfg *Config) {
			cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
			cfg.SessionAnalysis.LLM.BaseURL = "https://api.example.com/v1"
		}, "allow_non_local"},
		{"host name", func(cfg *Config) {
			cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
			cfg.SessionAnalysis.LLM.BaseURL = "http://model-box:8000/v1"
		}, "allow_non_local"},
		{"credentials in url", func(cfg *Config) {
			cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
			cfg.SessionAnalysis.LLM.BaseURL = "http://user:pass@127.0.0.1:8000/v1"
		}, "without credentials"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.SessionAnalysis.Enabled = true
			testCase.configure(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("err = %v, want %q", err, testCase.want)
			}
		})
	}
	cfg := testConfig()
	cfg.SessionAnalysis.Enabled = true
	cfg.SessionAnalysis.LLM.Enabled, cfg.SessionAnalysis.LLM.Model = true, "m"
	cfg.SessionAnalysis.LLM.BaseURL = "https://api.example.com/v1"
	cfg.SessionAnalysis.LLM.AllowNonLocal = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("explicit non-local endpoint rejected: %v", err)
	}
	// A disabled section is never validated.
	disabled := testConfig()
	disabled.SessionAnalysis.RunAt = "garbage"
	if err := Validate(disabled); err != nil {
		t.Fatalf("disabled section validated: %v", err)
	}
}

func TestLocalModelHosts(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.20", "100.64.3.4", "fd00::1", "[::1]"} {
		if !LocalModelHost(host) {
			t.Errorf("%s rejected", host)
		}
	}
	for _, host := range []string{"example.com", "8.8.8.8", "0.0.0.0", "169.254.1.1", "100.128.0.1", "2001:db8::1", ""} {
		if LocalModelHost(host) {
			t.Errorf("%s accepted", host)
		}
	}
	if LocalModelIP(net.ParseIP("203.0.113.5")) || !LocalModelIP(net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatal("LocalModelIP")
	}
}

func TestParseRunAt(t *testing.T) {
	hour, minute, err := ParseRunAt("02:30")
	if err != nil || hour != 2 || minute != 30 {
		t.Fatalf("%d:%d %v", hour, minute, err)
	}
	for _, bad := range []string{"", "2:30", "02-30", "12:60", "aa:bb"} {
		if _, _, err := ParseRunAt(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
