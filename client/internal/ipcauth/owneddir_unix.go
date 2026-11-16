//go:build !windows

package ipcauth

import (
	"fmt"
	"os"
	"syscall"
)

// openDir opens a directory without following the final path component through a symlink.
func openDir(path string) (*os.File, error) {
	f, err := os.OpenFile(
		path,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open directory %s: %w", path, err)
	}

	return f, nil
}

// dirOwnedBy reports whether the opened directory is owned by the
// authenticated IPC caller and is writable/traversable by that owner.
func dirOwnedBy(id Identity, dir *os.File) (bool, error) {
	info, err := dir.Stat()
	if err != nil {
		return false, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no owner information in %T", info.Sys())
	}

	if stat.Uid != id.UID {
		return false, nil
	}

	const ownerWriteExecute = 0o300
	if info.Mode().Perm()&ownerWriteExecute != ownerWriteExecute {
		return false, nil
	}

	return true, nil
}

// openWritableDir opens a directory that the authenticated IPC caller may
// write to. Unix authorization is ownership plus owner write/execute bits.
func openWritableDir(id Identity, _ *callerToken, path string) (*os.File, error) {
	return openOwnedDir(id, path)
}

// openOwnedDir opens a directory the caller owns and may create entries in.
func openOwnedDir(id Identity, path string) (*os.File, error) {
	dir, err := openDir(path)
	if err != nil {
		return nil, err
	}

	if err := checkDirOwnership(id, dir); err != nil {
		if cerr := dir.Close(); cerr != nil {
			return nil, fmt.Errorf("%w (close: %v)", err, cerr)
		}
		return nil, err
	}

	return dir, nil
}

// checkDirOwnership verifies that dir belongs to the IPC caller.
func checkDirOwnership(id Identity, dir *os.File) error {
	info, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir.Name(), err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir.Name())
	}

	if IsPrivilegedCaller(id) {
		return nil
	}

	allowed, err := dirOwnedBy(id, dir)
	if err != nil {
		return fmt.Errorf("check access to %s: %w", dir.Name(), err)
	}
	if !allowed {
		return fmt.Errorf("%s is not writable by the caller (%s)", dir.Name(), id)
	}

	return nil
}

// openReadableDir opens a directory that the authenticated IPC caller may
// read and traverse. Unix authorization is ownership plus owner read/execute bits.
func openReadableDir(id Identity, _ *callerToken, path string) (*os.File, error) {
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

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = dir.Close()
		return nil, fmt.Errorf("no owner information in %T", info.Sys())
	}

	if stat.Uid != id.UID {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	const ownerReadExecute = 0o500
	if info.Mode().Perm()&ownerReadExecute != ownerReadExecute {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	return dir, nil
}
