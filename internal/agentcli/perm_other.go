//go:build !windows

package agentcli

import (
	"errors"
	"io/fs"
	"os"
)

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

// tightenPrivate makes an existing path accessible to its owner only: mode
// (0700 for the state directory, 0600 for credentials.json) when group or
// others have any access. A missing path is fine. It reports the path it
// could not tighten.
func tightenPrivate(path string, mode os.FileMode) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if info, err = os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		return errors.New("still accessible to others")
	}
	return nil
}
