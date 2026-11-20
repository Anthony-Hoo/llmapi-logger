//go:build !windows

package agentcli

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
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

// inspectPrivate checks one entry of the credential store (the state
// directory when dir is true, credentials.json otherwise) without following
// a symbolic link, and reports whether it exists and what is wrong with it.
// An entry that is a link, of the wrong type, owned by another user, or (a
// directory) sticky, as shared directories such as /tmp are, is never
// changed. One the current user owns that group or others can access is
// made private (mode) when fix is true, through a descriptor opened without
// following links, and reported with problemMode otherwise or when that
// fails.
func inspectPrivate(path string, dir bool, mode os.FileMode, fix bool) (bool, string) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, ""
	}
	if err != nil {
		return true, problemUnreadable
	}
	if problem := entryKindProblem(info, dir); problem != "" {
		return true, problem
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return true, problemNotOwned
	}
	if dir && info.Mode()&os.ModeSticky != 0 {
		return true, problemShared
	}
	if info.Mode().Perm()&0o077 == 0 {
		return true, ""
	}
	if !fix {
		return true, problemMode
	}
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return true, problemMode
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return true, problemMode
	}
	if err := handle.Chmod(mode); err != nil {
		return true, problemMode
	}
	if opened, err = handle.Stat(); err != nil || opened.Mode().Perm()&0o077 != 0 {
		return true, problemMode
	}
	return true, ""
}
