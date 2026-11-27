//go:build unix

package staging

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkDirectoryAccess requires the directory to belong to the process's
// user and to grant nothing to group or others (F.1), as the key file is
// created 0600 in a 0700 directory.
func checkDirectoryAccess(info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("staging: directory is owned by uid %d, not by the process (uid %d)", stat.Uid, os.Geteuid())
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("staging: directory permissions %#o grant access to group or others; want 0700", permissions)
	}
	return nil
}

// syncDirectory makes created, renamed and removed entries durable.
func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	return errors.Join(syncErr, handle.Close())
}

func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
