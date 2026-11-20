//go:build linux

package agentcli

import "syscall"

const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)
