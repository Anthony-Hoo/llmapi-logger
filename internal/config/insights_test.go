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
	regular := filepath.Join(directory, "vocabulary.yaml")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "missing.yaml")
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
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

	// Disabled insights never read the file, so missing or invalid paths are ignored.
	for _, path := range []string{missing, directory, " " + regular} {
		cfg := testConfig()
		cfg.Insights = InsightsConfig{Enabled: false, VocabularyFile: path}
		if err := Validate(cfg); err != nil {
			t.Errorf("Validate() with insights disabled and file %q: %v", path, err)
		}
	}
}

func TestDeprecatedPricingFileIsNeverChecked(t *testing.T) {
	directory := t.TempDir()
	// The deprecated setting is a no-op: even a missing file or a directory
	// must not block startup of an old configuration.
	for _, path := range []string{filepath.Join(directory, "missing.json"), directory, " padded.json"} {
		cfg := testConfig()
		cfg.Insights = InsightsConfig{Enabled: true, PricingFile: path}
		if err := Validate(cfg); err != nil {
			t.Errorf("Validate() with pricing_file %q: %v", path, err)
		}
	}
}

func TestLoadAndValidateContextWindows(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\ninsights:\n  context_windows:\n    my-gateway-alias: 200000\n    openai/gpt-4.1: 1047576\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Insights.Enabled || len(cfg.Insights.ContextWindows) != 2 || cfg.Insights.ContextWindows["my-gateway-alias"] != 200000 {
		t.Fatalf("Insights = %+v", cfg.Insights)
	}
	for name, windows := range map[string]map[string]int64{
		"zero":           {"model": 0},
		"negative":       {"model": -5},
		"empty key":      {"": 1000},
		"space in key":   {"my model": 1000},
		"padded key":     {" model": 1000},
		"nul in key":     {"a\x00b": 1000},
		"case duplicate": {"Model-A": 1000, "model-a": 2000},
	} {
		cfg := testConfig()
		cfg.Insights.ContextWindows = windows
		if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "insights.context_windows") {
			t.Errorf("%s: Validate() error = %v", name, err)
		}
	}
	if _, err := Load(writeConfig(t, "admin_token: test-token\ninsights:\n  context_windows:\n    model: many\n")); err == nil {
		t.Fatal("Load() accepted a non-integer context window")
	}
}

// quoteYAML single-quotes a path so Windows separators survive YAML decoding.
func quoteYAML(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
