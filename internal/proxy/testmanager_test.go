package proxy

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// newTestManager is how the tests of this package build an audit manager:
// with options.Stager unset it gets a stager on a temporary directory under
// the manager's cipher, so that no test depends on what a manager without
// staging does.
func newTestManager(t *testing.T, store audit.Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, logger *slog.Logger, options audit.Options) *audit.Manager {
	t.Helper()
	if options.Stager == nil {
		stager, err := staging.Open(filepath.Join(t.TempDir(), "staging"), cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stager.Close() })
		options.Stager = stager
	}
	manager, err := audit.NewManagerWithOptions(store, cipher, fingerprints, audit.ModeAvailable, logger, options)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// refusingStager takes no chunk, as a manager without staging: content beyond
// the memory budget is not retained (design F.6).
type refusingStager struct{}

func (refusingStager) Stage(storage.BodyChunk) (*staging.Ref, error) {
	return nil, audit.ErrStagingUnavailable
}
func (refusingStager) Discard(string) {}
func (refusingStager) Keep(string)    {}
