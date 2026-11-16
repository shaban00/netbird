package ipcauth

import (
	"context"
	"os"
)

// OpenReadableFile opens a regular file after verifying that the authenticated
// local IPC caller is allowed to read it. Directory transfers use this helper
// to authorize each file as it is encountered.
func OpenReadableFile(ctx context.Context, path string) (*os.File, error) {
	auth, err := directCallerAuth(ctx)
	if err != nil {
		return nil, err
	}

	return openReadableFile(auth.Identity, auth.token, path)
}
