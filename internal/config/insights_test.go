package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInsightsDefaultsToEnabledWithoutOverrides(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Insights.Enabled || cfg.Insights.PricingFile != "" || cfg.Insights.VocabularyFile != "" {
		t.Fatalf("Insights = %+v, want enabled without override files", cfg.Insights)
	}
}

func TestLoadInsightsBlock(t *testing.T) {
	directory := t.TempDir()
	pricing := filepath.Join(directory, "prices.json")
	vocabulary := filepath.Join(directory, "vocabulary.yaml")
	for _, path := range []string{pricing, vocabulary} {
		// Contents are not parsed by config validation.
		if err := os.WriteFile(path, []byte("not parsed here"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A partial block keeps the enabled default.
	cfg, err := Load(writeConfig(t, "admin_token: test-token\ninsights:\n  pricing_file: "+quoteYAML(pricing)+"\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Insights.Enabled || cfg.Insights.PricingFile != pricing || cfg.Insights.VocabularyFile != "" {
		t.Fatalf("Insights = %+v", cfg.Insights)
	}

	cfg, err = Load(writeConfig(t, "admin_token: test-token\ninsights:\n  enabled: false\n  pricing_file: "+
		quoteYAML(pricing)+"\n  vocabulary_file: "+quoteYAML(vocabulary)+"\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Insights.Enabled || cfg.Insights.PricingFile != pricing || cfg.Insights.VocabularyFile != vocabulary {
		t.Fatalf("Insights = %+v", cfg.Insights)
	}

	if _, err := Load(writeConfig(t, "admin_token: test-token\ninsights:\n  unknown: true\n")); err == nil {
		t.Fatal("Load() accepted an unknown insights field")
	}
}

func TestValidateInsightsFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "prices.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "missing.json")
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"missing pricing file", func(cfg *Config) { cfg.Insights.PricingFile = missing }, "insights.pricing_file does not exist"},
		{"directory pricing file", func(cfg *Config) { cfg.Insights.PricingFile = directory }, "insights.pricing_file must name a regular file"},
		{"padded pricing file", func(cfg *Config) { cfg.Insights.PricingFile = " " + regular }, "insights.pricing_file"},
		{"missing vocabulary file", func(cfg *Config) { cfg.Insights.VocabularyFile = missing }, "insights.vocabulary_file does not exist"},
		{"directory vocabulary file", func(cfg *Config) { cfg.Insights.VocabularyFile = directory }, "insights.vocabulary_file must name a regular file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			test.mutate(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}

	cfg := testConfig()
	cfg.Insights = InsightsConfig{Enabled: false, PricingFile: regular, VocabularyFile: regular}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// quoteYAML single-quotes a path so Windows separators survive YAML decoding.
func quoteYAML(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
