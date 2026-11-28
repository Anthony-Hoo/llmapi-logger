//go:build linux || darwin

package termio

import (
	"syscall"
	"unsafe"
)

// Linux and macOS: the termios ioctls succeed only on a terminal; clearing
// ECHO (keeping ICANON and ISIG) hides what is typed while Enter still ends
// the line and Ctrl+C still interrupts.

func getTermios(fd uintptr) (*syscall.Termios, error) {
	var termios syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&termios))); errno != 0 {
		return nil, errno
	}
	return &termios, nil
}

func setTermios(fd uintptr, termios *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(termios))); errno != 0 {
		return errno
	}
	return nil
}

func isTerminal(fd uintptr) bool {
	_, err := getTermios(fd)
	return err == nil
}

func disableEcho(fd uintptr) (func(), error) {
	original, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	hidden := *original
	hidden.Lflag &^= syscall.ECHO
	hidden.Lflag |= syscall.ICANON | syscall.ISIG
	if err := setTermios(fd, &hidden); err != nil {
		return nil, err
	}
	return func() { _ = setTermios(fd, original) }, nil
}
