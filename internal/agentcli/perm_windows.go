//go:build windows

package agentcli

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

// On Windows a private file or directory gets a protected DACL with a single
// entry that grants the current user full control: nothing is inherited from
// the parent and no other account (not even Administrators or SYSTEM) is
// listed. The security descriptor is built from SDDL with advapi32 through
// the syscall package; no other dependency is needed.

var (
	modAdvapi32              = syscall.NewLazyDLL("advapi32.dll")
	modKernel32              = syscall.NewLazyDLL("kernel32.dll")
	procConvertStringSDToSDW = modAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree            = modKernel32.NewProc("LocalFree")
)

const (
	sddlRevision1      = 1
	errorFileExists    = 80
	errorAlreadyExists = 183
)

// currentUserSID is the string SID of the process token's user.
func currentUserSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

// ownerOnlySDDL is the descriptor of a private object; containers pass their
// entry on to new children (object and container inherit).
func ownerOnlySDDL(container bool) (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	flags := ""
	if container {
		flags = "OICI"
	}
	return "D:P(A;" + flags + ";FA;;;" + sid + ")", nil
}

func ownerOnlyAttributes(container bool) (*syscall.SecurityAttributes, func(), error) {
	sddl, err := ownerOnlySDDL(container)
	if err != nil {
		return nil, nil, err
	}
	text, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, nil, err
	}
	var descriptor uintptr
	result, _, callErr := procConvertStringSDToSDW.Call(uintptr(unsafe.Pointer(text)), sddlRevision1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if result == 0 {
		return nil, nil, callErr
	}
	attributes := &syscall.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	return attributes, func() { _, _, _ = procLocalFree.Call(descriptor) }, nil
}

func isExists(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (uint32(errno) == errorFileExists || uint32(errno) == errorAlreadyExists)
}

// createPrivateFile creates path (which must not exist) for writing, with
// the owner-only descriptor applied at creation.
func createPrivateFile(path string) (*os.File, error) {
	attributes, free, err := ownerOnlyAttributes(false)
	if err != nil {
		return nil, err
	}
	defer free()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, attributes,
		syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if isExists(err) {
			return nil, fs.ErrExist
		}
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func createPrivateDir(path string) error {
	attributes, free, err := ownerOnlyAttributes(true)
	if err != nil {
		return err
	}
	defer free()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := syscall.CreateDirectory(name, attributes); err != nil && !isExists(err) {
		return err
	}
	return nil
}
