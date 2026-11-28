package archivecli

import (
	"errors"
	"os"

	"llmapi-logger/internal/security"
)

// Keys are the keys the reader derives from the master key file: the archive
// keys (K_enc, K_sign, K_fpr, design F.3), the integrity signer that checks
// the copied integrity events (J.2 item 7), and the credential fingerprinter
// of audit_records.api_key_fpr (D.4, the third fpr candidate). The master key
// itself is not kept.
type Keys struct {
	Archive    *security.ArchiveKeys
	Events     *security.IntegritySigner
	Credential *security.CredentialFingerprinter
}

// errKeyFile is a key file that cannot be used. Its message names no path
// and no key material.
var errKeyFile = errors.New("the key file cannot be read or is not a 32-byte key")

// LoadKeys reads the master key file the way the application does
// (security.LoadOrCreateKey without creating it: a raw 32-byte file) and
// derives the keys. A missing file is never created.
func LoadKeys(path string) (*Keys, error) {
	master, err := security.LoadOrCreateKey(path, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &cliError{code: codeKeyFile, message: "the key file does not exist"}
		}
		return nil, &cliError{code: codeKeyFile, message: errKeyFile.Error()}
	}
	defer clear(master)
	return NewKeys(master)
}

// NewKeys derives the keys from a master key. The caller keeps and clears
// master.
func NewKeys(master []byte) (*Keys, error) {
	archiveKeys, err := security.DeriveArchiveKeys(master)
	if err != nil {
		return nil, &cliError{code: codeKeyFile, message: errKeyFile.Error()}
	}
	events, err := security.NewIntegritySigner(master)
	if err != nil {
		return nil, &cliError{code: codeKeyFile, message: errKeyFile.Error()}
	}
	credential, err := security.NewCredentialFingerprinter(master)
	if err != nil {
		return nil, &cliError{code: codeKeyFile, message: errKeyFile.Error()}
	}
	return &Keys{Archive: archiveKeys, Events: events, Credential: credential}, nil
}
