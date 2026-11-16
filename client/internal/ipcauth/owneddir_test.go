//go:build !windows

package ipcauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenOwnedDirOpensDirectoryOwnedByCaller(t *testing.T) {
	dir := t.TempDir()

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	f, err := openOwnedDir(id, dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	info, err := f.Stat()
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestOpenOwnedDirRefusesDirectoryOwnedByAnother(t *testing.T) {
	dir := t.TempDir()

	_, err := openOwnedDir(otherIdentity(t), dir)
	require.ErrorContains(t, err, "not writable by the caller")
}

func TestOpenOwnedDirRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = openOwnedDir(id, path)
	require.ErrorContains(t, err, "not a directory")
}

func TestOpenOwnedDirRefusesMissingDirectory(t *testing.T) {
	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	_, err = openOwnedDir(id, filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestDirOwnedByRejectsOwnedNonWritableDirectory(t *testing.T) {

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))

	id, err := CurrentProcessIdentity()
	require.NoError(t, err)

	f, err := openDir(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	allowed, err := dirOwnedBy(id, f)
	require.NoError(t, err)
	require.False(t, allowed)
}
