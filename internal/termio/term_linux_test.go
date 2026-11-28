//go:build linux

package termio

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openPTY opens a pseudo-terminal pair through /dev/ptmx with the standard
// library only. It skips when the system has no usable ptmx.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	unlock := int32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Skipf("unlockpt: %v", errno)
	}
	var number uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		t.Skipf("ptsname: %v", errno)
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(number)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pts: %v", err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// TestPTYEchoOffAndRestored: on a real pseudo-terminal, disableEcho clears
// ECHO and keeps line mode and signals, restore puts the original modes
// back, and ReadLineNoEcho returns the typed line without echoing it.
func TestPTYEchoOffAndRestored(t *testing.T) {
	master, slave := openPTY(t)
	if !isTerminal(slave.Fd()) {
		t.Fatal("the pty slave is not a terminal")
	}
	before, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag&syscall.ECHO == 0 {
		t.Fatal("a new pty does not echo; the test would assert nothing")
	}
	restore, err := disableEcho(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	during, _ := getTermios(slave.Fd())
	if during.Lflag&syscall.ECHO != 0 || during.Lflag&syscall.ICANON == 0 || during.Lflag&syscall.ISIG == 0 {
		t.Fatalf("modes while hidden: %#x", during.Lflag)
	}
	restore()
	after, _ := getTermios(slave.Fd())
	if *after != *before {
		t.Fatalf("modes not restored: %#x, was %#x", after.Lflag, before.Lflag)
	}

	// Control: with echo on, a typed line does come back on the master.
	fd := int(master.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(fd, []byte("visible\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := readLine(slave); err != nil || string(line) != "visible" {
		t.Fatalf("control line %q, %v", line, err)
	}
	time.Sleep(100 * time.Millisecond)
	echoed := make([]byte, 64)
	if count, _ := syscall.Read(fd, echoed); count <= 0 || !strings.Contains(string(echoed[:count]), "visible") {
		t.Fatalf("echo on but nothing echoed (%d bytes): the no-echo check below would assert nothing", count)
	}

	// The whole read: the key is typed only once echo is off, as a user
	// types at the prompt.
	type result struct {
		line []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := NewTerminal(slave).ReadLineNoEcho()
		done <- result{line, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		current, err := getTermios(slave.Fd())
		if err == nil && current.Lflag&syscall.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ReadLineNoEcho never turned echo off")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := syscall.Write(fd, []byte("sk-typed-secret\n")); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || string(got.line) != "sk-typed-secret" {
		t.Fatalf("read %q, %v", got.line, got.err)
	}
	// Nothing came back to the master side: the key was not echoed. The
	// master is read without blocking; EAGAIN means there is nothing.
	time.Sleep(100 * time.Millisecond)
	buffer := make([]byte, 64)
	count, err := syscall.Read(fd, buffer)
	if count > 0 {
		t.Fatalf("echoed %q", buffer[:count])
	}
	if err != syscall.EAGAIN {
		t.Fatalf("reading the master: %d bytes, %v", count, err)
	}
	if final, _ := getTermios(slave.Fd()); *final != *before {
		t.Fatal("echo not restored after the read")
	}
}
