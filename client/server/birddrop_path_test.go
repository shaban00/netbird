package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func TestValidateTransferPathWindows(t *testing.T) {
	ok := []string{`C:\Users\a\f.txt`, `d:/data/dir`, `C:\`}
	for _, p := range ok {
		require.NoError(t, validateTransferPathFor("windows", p), p)
	}

	bad := []string{
		``,
		`\\attacker@80\share\x`,   // WebDAV coercion
		`\\host\share\file`,       // SMB coercion
		`//host/share/file`,       // forward-slash UNC
		`\\?\UNC\host\share\file`, // extended-length UNC
		`\\.\pipe\x`,              // device namespace
		`\\?\C:\Windows\x`,        // extended-length local
		`C:relative\path`,         // drive-relative
		`relative\path`,
		`C:\file.txt:stream`, // alternate data stream
		`1:\x`,
	}
	for _, p := range bad {
		require.Error(t, validateTransferPathFor("windows", p), p)
	}
}

func TestValidateTransferPathUnix(t *testing.T) {
	require.NoError(t, validateTransferPathFor("linux", "/home/a/f.txt"))
	require.Error(t, validateTransferPathFor("linux", ""))
	require.Error(t, validateTransferPathFor("linux", "relative/f.txt"))
	require.Error(t, validateTransferPathFor("darwin", "."))
}

func TestReceiveOwnerPerPlatform(t *testing.T) {
	uid, gid := receiveOwner("windows", ipcauth.Identity{SID: "S-1-5-21-1-2-3-1001"})
	require.Equal(t, -1, uid)
	require.Equal(t, -1, gid)

	uid, gid = receiveOwner("linux", ipcauth.Identity{UID: 1000, GID: 1000})
	require.Equal(t, 1000, uid)
	require.Equal(t, 1000, gid)
}
