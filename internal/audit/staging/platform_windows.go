//go:build windows

package staging

import (
	"errors"
	"os"
	"syscall"
)

// checkDirectoryAccess accepts any directory: on Windows access is the
// directory's ACL, which is not checked, as for the key file (F.1).
func checkDirectoryAccess(os.FileInfo) error { return nil }

// syncDirectory is a no-op: Windows has no directory fsync, and NTFS journals
// its directory entries.
func syncDirectory(string) error { return nil }

const (
	errorHandleDiskFull syscall.Errno = 39
	errorDiskFull       syscall.Errno = 112
)

func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
}
