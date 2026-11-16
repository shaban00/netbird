//go:build windows

package birddrop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF).
const fileAllAccess windows.ACCESS_MASK = 0x001F01FF

// chownRootedTree hands a freshly extracted tree to the Windows account own.sid.
func chownRootedTree(root *os.Root, own owner) error {
	if own.sid == "" {
		return nil
	}
	sid, err := windows.StringToSid(own.sid)
	if err != nil {
		return fmt.Errorf("parse receiving account SID: %w", err)
	}

	var paths []string
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}

	for i := len(paths) - 1; i >= 0; i-- {
		f, err := root.Open(paths[i])
		if err != nil {
			return fmt.Errorf("open received path %q for hand-over: %w", paths[i], err)
		}
		err = handOverHandle(windows.Handle(f.Fd()), sid)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("hand over %q: %w", paths[i], err)
		}
	}
	return nil
}

// handOverFile gives a single file the daemon just created to own.sid.
func handOverFile(f *os.File, own owner) error {
	if own.sid == "" {
		return nil
	}
	sid, err := windows.StringToSid(own.sid)
	if err != nil {
		return fmt.Errorf("parse receiving account SID: %w", err)
	}
	return handOverHandle(windows.Handle(f.Fd()), sid)
}

// handOverHandle grants sid full control of the object behind h and makes it the owner
func handOverHandle(h windows.Handle, sid *windows.SID) error {
	rh, err := reopenHandle(h, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return fmt.Errorf("re-open for permission change: %w", err)
	}
	defer windows.CloseHandle(rh)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(rh, &info); err != nil {
		return fmt.Errorf("read file information: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("refusing to change permissions of a reparse point")
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if !isDir && info.NumberOfLinks != 1 {
		return fmt.Errorf("refusing to change permissions of a file with %d links", info.NumberOfLinks)
	}

	sd, err := windows.GetSecurityInfo(rh, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read permissions: %w", err)
	}
	current, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("read permissions: %w", err)
	}

	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	updated, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileAllAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, current)
	if err != nil {
		return fmt.Errorf("build permissions: %w", err)
	}
	if err := windows.SetSecurityInfo(rh, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil); err != nil {
		return fmt.Errorf("grant access: %w", err)
	}

	if err := withThreadPrivilege("SeRestorePrivilege", func() error {
		return windows.SetSecurityInfo(rh, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)
	}); err != nil {
		log.Warnf("birddrop: received file stays owned by the service (the user has full control): %v", err)
	}
	return nil
}

// reopenHandle opens the object behind h again with different access
func reopenHandle(h windows.Handle, access uint32) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: h,
		ObjectName:    name,
	}
	var iosb windows.IO_STATUS_BLOCK
	var out windows.Handle
	err = windows.NtCreateFile(
		&out,
		access,
		&oa,
		&iosb,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	return out, nil
}

// withThreadPrivilege runs fn with a privilege enabled on a private
// impersonation token for the current OS thread only, so the daemon's own
// token never gains it.
func withThreadPrivilege(name string, fn func() error) (err error) {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("impersonate self: %w", err)
	}
	defer func() {
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			if err == nil {
				err = fmt.Errorf("revert impersonation: %w", revertErr)
			}
			return
		}
		runtime.UnlockOSThread()
	}()

	var tok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &tok); err != nil {
		return fmt.Errorf("open thread token: %w", err)
	}
	defer tok.Close()

	privName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, privName, &luid); err != nil {
		return fmt.Errorf("look up %s: %w", name, err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("enable %s: %w", name, err)
	}

	return fn()
}
