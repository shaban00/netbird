//go:build windows

package server

import (
	"errors"

	"golang.org/x/sys/windows"
)

// checkLocalVolume refuses drive letters that map to a network share, so the
// daemon never opens a remote file system on a caller's behalf.
func checkLocalVolume(p string) error {
	root, err := windows.UTF16PtrFromString(p[:3])
	if err != nil {
		return err
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_REMOTE, windows.DRIVE_NO_ROOT_DIR, windows.DRIVE_UNKNOWN:
		return errors.New("path must be on a local drive")
	}
	return nil
}
