//go:build !windows

package agentcli

import "os"

// createPrivateFile creates path (which must not exist) with mode 0600.
func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

// createPrivateDir creates path with mode 0700.
func createPrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}
