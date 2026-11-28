package audit

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
)

// newTestManager is how the tests of this package build a manager that runs
// sessions: with options.Stager unset it gets a stager on a temporary
// directory under the manager's cipher, so that no test depends on what a
// manager without staging does.
func newTestManager(t testing.TB, store Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, mode string, logger *slog.Logger, options Options) *Manager {
	t.Helper()
	if options.Stager == nil {
		stager, err := staging.Open(filepath.Join(t.TempDir(), "staging"), cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stager.Close() })
		options.Stager = stager
	}
	manager, err := NewManagerWithOptions(store, cipher, fingerprints, mode, logger, options)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
