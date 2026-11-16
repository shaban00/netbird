package ipcauth

import (
	"context"
	"os"
)

// OpenWritableDir opens path after verifying that the authenticated local IPC
// caller is allowed to create files and directories in it.
func OpenWritableDir(ctx context.Context, path string) (*os.File, error) {
	auth, err := directCallerAuth(ctx)
	if err != nil {
		return nil, err
	}

	return openWritableDir(auth.Identity, auth.token, path)
}

// OpenReadableDir opens a directory after verifying that the authenticated local
// IPC caller is allowed to read and traverse it.
func OpenReadableDir(ctx context.Context, path string) (*os.File, error) {
	auth, err := directCallerAuth(ctx)
	if err != nil {
		return nil, err
	}

	return openReadableDir(auth.Identity, auth.token, path)
}
