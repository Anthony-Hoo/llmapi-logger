//go:build !windows && !linux && !darwin

package termio

import "errors"

// Other systems: no terminal support, so keys cannot be entered (NO_TTY).

func isTerminal(uintptr) bool { return false }

func disableEcho(uintptr) (func(), error) {
	return nil, errors.New("terminal control is not supported on this system")
}
