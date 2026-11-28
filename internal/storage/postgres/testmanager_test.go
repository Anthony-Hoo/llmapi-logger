package postgres

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
)

// newTestManager is how the tests of this package build an audit manager:
// with a stager on a temporary directory under the manager's cipher, so that
// no test depends on what a manager without staging does.
func newTestManager(t *testing.T, store audit.Store, cipher security.Cipher, logger *slog.Logger) *audit.Manager {
	t.Helper()
	stager, err := staging.Open(filepath.Join(t.TempDir(), "staging"), cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	manager, err := audit.NewManagerWithOptions(store, cipher, nil, audit.ModeAvailable, logger, audit.Options{Stager: stager})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
