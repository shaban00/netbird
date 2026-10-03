//go:build windows

package cmd

import "os"

// openCredentialFileNoFollow does a plain create/truncate on Windows, where
// creating symlinks requires a privilege unprivileged users lack by default.
func openCredentialFileNoFollow(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
}
