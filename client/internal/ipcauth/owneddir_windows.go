//go:build windows

package ipcauth

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procAccessCheck = modadvapi32.NewProc("AccessCheck")

const (
	fileAddFile         = 0x0002
	fileAddSubdirectory = 0x0004

	fileGenericRead    = 0x00120089
	fileGenericWrite   = 0x00120116
	fileGenericExecute = 0x001200A0
	fileAllAccess      = 0x001F01FF
	fileListDirectory  = 0x0001
	fileTraverse       = 0x0020
)

type genericMapping struct {
	GenericRead    uint32
	GenericWrite   uint32
	GenericExecute uint32
	GenericAll     uint32
}

// openDir opens a directory without following the final path component
// through a symlink or reparse point.
func openDir(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("convert path %s: %w", path, err)
	}

	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open directory %s: %w", path, err)
	}

	return os.NewFile(uintptr(handle), path), nil
}

// openWritableDir opens a directory that the authenticated IPC caller may
// write to. Windows authorization is evaluated against the caller's retained
// token and the directory DACL.
func openWritableDir(id Identity, tok *callerToken, path string) (*os.File, error) {
	dir, err := openDir(path)
	if err != nil {
		return nil, err
	}

	if IsPrivilegedCaller(id) {
		return dir, nil
	}

	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not a directory", path)
	}

	sd, err := windows.GetSecurityInfo(
		windows.Handle(dir.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("read directory security descriptor: %w", err)
	}

	var allowed bool
	err = tok.use(func(h uintptr) error {
		var checkErr error
		allowed, checkErr = accessCheck(sd, windows.Token(h), fileAddFile|fileAddSubdirectory)
		return checkErr
	})
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	if !allowed {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not writable by the caller (%s)", path, id)
	}

	return dir, nil
}

// openReadableDir opens a directory that the authenticated IPC caller may
// list and traverse. Windows authorization is evaluated against the caller's
// retained token and the directory DACL.
func openReadableDir(id Identity, tok *callerToken, path string) (*os.File, error) {
	dir, err := openDir(path)
	if err != nil {
		return nil, err
	}

	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not a directory", path)
	}

	if IsPrivilegedCaller(id) {
		return dir, nil
	}

	sd, err := windows.GetSecurityInfo(
		windows.Handle(dir.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("read directory security descriptor: %w", err)
	}

	var allowed bool
	err = tok.use(func(h uintptr) error {
		var checkErr error
		allowed, checkErr = accessCheck(sd, windows.Token(h), fileListDirectory|fileTraverse)
		return checkErr
	})
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	if !allowed {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	return dir, nil
}

// accessCheck evaluates a Windows security descriptor against the authenticated
// caller's retained token for the requested access rights.
func accessCheck(sd *windows.SECURITY_DESCRIPTOR, token windows.Token, desiredAccess uint32) (bool, error) {
	mapping := genericMapping{
		GenericRead:    fileGenericRead,
		GenericWrite:   fileGenericWrite,
		GenericExecute: fileGenericExecute,
		GenericAll:     fileAllAccess,
	}

	var (
		privilegeSetLength uint32
		grantedAccess      uint32
		accessStatus       int32
	)

	// First call determines the required PRIVILEGE_SET buffer size.
	r1, _, callErr := procAccessCheck.Call(
		uintptr(unsafe.Pointer(sd)),
		uintptr(token),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&mapping)),
		0,
		uintptr(unsafe.Pointer(&privilegeSetLength)),
		uintptr(unsafe.Pointer(&grantedAccess)),
		uintptr(unsafe.Pointer(&accessStatus)),
	)
	if r1 == 0 && callErr != windows.ERROR_INSUFFICIENT_BUFFER {
		return false, fmt.Errorf("AccessCheck size query: %w", callErr)
	}

	if privilegeSetLength == 0 {
		return false, fmt.Errorf("AccessCheck returned an empty privilege-set size")
	}

	privileges := make([]byte, privilegeSetLength)

	r1, _, callErr = procAccessCheck.Call(
		uintptr(unsafe.Pointer(sd)),
		uintptr(token),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&privileges[0])),
		uintptr(unsafe.Pointer(&privilegeSetLength)),
		uintptr(unsafe.Pointer(&grantedAccess)),
		uintptr(unsafe.Pointer(&accessStatus)),
	)
	if r1 == 0 {
		return false, fmt.Errorf("AccessCheck: %w", callErr)
	}

	return accessStatus != 0, nil
}
