//go:build windows

package agentcli

import "syscall"

// Windows console input: GetConsoleMode succeeds only on a console handle,
// and clearing ENABLE_ECHO_INPUT (kept in line mode) hides what is typed.

const (
	enableProcessedInput = 0x0001
	enableLineInput      = 0x0002
	enableEchoInput      = 0x0004
)

var procSetConsoleMode = modKernel32.NewProc("SetConsoleMode")

func setConsoleMode(handle syscall.Handle, mode uint32) error {
	result, _, err := procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if result == 0 {
		return err
	}
	return nil
}

func isTerminal(fd uintptr) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(fd), &mode) == nil
}

func disableEcho(fd uintptr) (func(), error) {
	handle := syscall.Handle(fd)
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		return nil, err
	}
	hidden := (mode &^ enableEchoInput) | enableLineInput | enableProcessedInput
	if err := setConsoleMode(handle, hidden); err != nil {
		return nil, err
	}
	return func() { _ = setConsoleMode(handle, mode) }, nil
}
