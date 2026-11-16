//go:build windows

package birddrop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	return user.User.Sid.String()
}

func requireHandedOver(t *testing.T, path, sid string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)

	ownerSID, _, err := sd.Owner()
	require.NoError(t, err)
	require.Equal(t, sid, ownerSID.String(), "the receiving user must own %s", path)

	sddl := sd.String()
	require.True(t, strings.Contains(sddl, ";FA;;;"+sid+")"),
		"expected a full-control grant for %s in %s", sid, sddl)
}

func TestHandOverFileGrantsAndOwns(t *testing.T) {
	sid := currentUserSID(t)
	path := filepath.Join(t.TempDir(), "received.txt")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	require.NoError(t, err)
	require.NoError(t, handOverFile(f, owner{uid: -1, gid: -1, sid: sid}))
	require.NoError(t, f.Close())

	requireHandedOver(t, path, sid)
}

func TestChownRootedTreeWindowsHandsOverEveryEntry(t *testing.T) {
	sid := currentUserSID(t)
	dest := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "a", "b", "f.txt"), []byte("x"), 0o644))

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	require.NoError(t, chownRootedTree(root, owner{uid: -1, gid: -1, sid: sid}))
	for _, p := range []string{"a", filepath.Join("a", "b"), filepath.Join("a", "b", "f.txt")} {
		requireHandedOver(t, filepath.Join(dest, p), sid)
	}
}

func TestHandOverRefusesHardLink(t *testing.T) {
	sid := currentUserSID(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("x"), 0o644))

	dest := t.TempDir()
	require.NoError(t, os.Link(outside, filepath.Join(dest, "innocent.txt")))

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	err = chownRootedTree(root, owner{uid: -1, gid: -1, sid: sid})
	require.ErrorContains(t, err, "links")
}

func TestNoSIDLeavesFilesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.txt")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, handOverFile(f, owner{uid: -1, gid: -1}))
}
