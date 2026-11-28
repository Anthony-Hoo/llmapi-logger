package parser_test

import (
	"io"
	"log/slog"
	"path/filepath"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
)

// newTestManager is how the tests of this package build an audit manager:
// with options.Stager unset it gets a stager in a directory below dir under
// the manager's cipher, so that no test depends on what a manager without
// staging does. close releases the stager.
func newTestManager(dir string, store audit.Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, logger *slog.Logger, options audit.Options) (manager *audit.Manager, close func(), err error) {
	close = func() {}
	if options.Stager == nil {
		stager, err := staging.Open(filepath.Join(dir, "staging"), cipher, staging.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			return nil, close, err
		}
		close = func() { _ = stager.Close() }
		options.Stager = stager
	}
	manager, err = audit.NewManagerWithOptions(store, cipher, fingerprints, audit.ModeAvailable, logger, options)
	if err != nil {
		close()
		return nil, func() {}, err
	}
	return manager, close, nil
}
