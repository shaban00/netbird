//go:build windows

package ipcauth

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openReadableFile opens a regular file that the authenticated IPC caller may
// read. Windows authorization is evaluated against the caller's retained token
// and the file DACL.
func openReadableFile(id Identity, tok *callerToken, path string) (*os.File, error) {
	f, err := openForRead(path)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	if IsPrivilegedCaller(id) {
		return f, nil
	}

	sd, err := windows.GetSecurityInfo(
		windows.Handle(f.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("read file security descriptor: %w", err)
	}

	var allowed bool
	err = tok.use(func(h uintptr) error {
		var checkErr error
		allowed, checkErr = accessCheck(sd, windows.Token(h), fileGenericRead)
		return checkErr
	})
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !allowed {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	return f, nil
}
