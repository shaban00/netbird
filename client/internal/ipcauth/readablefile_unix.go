//go:build !windows && !wasm

package ipcauth

import (
	"fmt"
	"os"
	"syscall"
)

// openReadableFile opens a regular file that the authenticated IPC caller may
// read. Unix authorization is ownership plus the owner read bit.
func openReadableFile(id Identity, _ *callerToken, path string) (*os.File, error) {
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

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = f.Close()
		return nil, fmt.Errorf("no owner information in %T", info.Sys())
	}

	if stat.Uid != id.UID {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	// Because the caller owns the file, the owner permission bits determine
	// whether it may read the file.
	if info.Mode().Perm()&0o400 == 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not readable by the caller (%s)", path, id)
	}

	return f, nil
}
