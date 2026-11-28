//go:build windows

package bundle

import (
	"errors"
	"syscall"
)

// syncDirectory is a no-op: Windows has no directory fsync, and NTFS journals
// its directory entries (H.2 step 5, as for the staging directory).
func syncDirectory(string) error { return nil }

const (
	errorHandleDiskFull syscall.Errno = 39
	errorDiskFull       syscall.Errno = 112
)

func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
}
