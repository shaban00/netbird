package ipcauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestFileHelpersRefuseForwardedRequests(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	forwarded := transportCtx(root, metadata.Pairs(mdFwd, "1"))

	_, err := OpenReadableFile(forwarded, file)
	require.ErrorContains(t, err, "JSON gateway")
	_, err = OpenReadableDir(forwarded, dir)
	require.ErrorContains(t, err, "JSON gateway")
	_, err = OpenWritableDir(forwarded, dir)
	require.ErrorContains(t, err, "JSON gateway")

	direct := transportCtx(Identity{known: true, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, nil)
	f, err := OpenReadableFile(direct, file)
	if err == nil {
		_ = f.Close()
	} else {
		require.NotContains(t, err.Error(), "JSON gateway")
	}
}
