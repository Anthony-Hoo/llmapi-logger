package app

import (
	"path/filepath"
	"testing"

	"llmapi-logger/internal/config"
)

// testConfig is how the tests of this package start from the defaults: with
// audit.staging.dir on a temporary directory, which the configuration
// requires, so that no test depends on a start without staging. A test of a
// missing or unusable directory changes it afterwards.
func testConfig(t testing.TB) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Audit.Staging.Dir = filepath.Join(t.TempDir(), "staging")
	return cfg
}
