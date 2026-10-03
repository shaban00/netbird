//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// openCredentialFileNoFollow opens path for truncating write with O_NOFOLLOW,
// so a symlink planted by another local user can't redirect the write.
func openCredentialFileNoFollow(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
}
