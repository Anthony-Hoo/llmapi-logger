//go:build windows

package agentcli

import (
	"syscall"
	"testing"
	"unsafe"
)

var (
	procGetNamedSecurityInfoW = modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procSDToStringSDW         = modAdvapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
)

const (
	seFileObject            = 1
	daclSecurityInformation = 0x4
)

// daclOf returns the DACL of path in SDDL.
func daclOf(t *testing.T, path string) string {
	t.Helper()
	name, _ := syscall.UTF16PtrFromString(path)
	var descriptor uintptr
	if result, _, _ := procGetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(name)), seFileObject, daclSecurityInformation,
		0, 0, 0, 0, uintptr(unsafe.Pointer(&descriptor))); result != 0 {
		t.Fatalf("GetNamedSecurityInfo: %d", result)
	}
	defer procLocalFree.Call(descriptor)
	var text *uint16
	if result, _, err := procSDToStringSDW.Call(descriptor, sddlRevision1, daclSecurityInformation, uintptr(unsafe.Pointer(&text)), 0); result == 0 {
		t.Fatalf("ConvertSecurityDescriptorToStringSecurityDescriptor: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	var chars []uint16
	for pointer := unsafe.Pointer(text); *(*uint16)(pointer) != 0; pointer = unsafe.Add(pointer, 2) {
		chars = append(chars, *(*uint16)(pointer))
	}
	return syscall.UTF16ToString(chars)
}

// assertPrivate: a protected DACL with one entry, full access for the
// current user. Checked after a replace, the path that matters.
func assertPrivate(t *testing.T, path string) {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := daclOf(t, path), "D:P(A;;FA;;;"+sid+")"; got != want {
		t.Fatalf("DACL of the credentials file = %s, want %s", got, want)
	}
}

func assertPrivateDir(t *testing.T, path string) {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := daclOf(t, path), "D:P(A;OICI;FA;;;"+sid+")"; got != want {
		t.Fatalf("DACL of the state directory = %s, want %s", got, want)
	}
}
