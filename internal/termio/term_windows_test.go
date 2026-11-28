//go:build windows

package termio

import (
	"os"
	"syscall"
	"testing"
)

// TestConsoleEchoToggle turns echo off and back on on the real console input
// buffer. It is skipped when the test process has no console.
func TestConsoleEchoToggle(t *testing.T) {
	console, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no console attached")
	}
	defer console.Close()
	if !isTerminal(console.Fd()) {
		t.Skip("CONIN$ is not a console")
	}
	handle := syscall.Handle(console.Fd())
	var before, during, after uint32
	if err := syscall.GetConsoleMode(handle, &before); err != nil {
		t.Fatal(err)
	}
	restore, err := disableEcho(console.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.GetConsoleMode(handle, &during); err != nil {
		t.Fatal(err)
	}
	restore()
	if err := syscall.GetConsoleMode(handle, &after); err != nil {
		t.Fatal(err)
	}
	if during&enableEchoInput != 0 || during&enableLineInput == 0 {
		t.Fatalf("mode while hidden %#x", during)
	}
	if after != before {
		t.Fatalf("mode not restored: %#x, was %#x", after, before)
	}
}
