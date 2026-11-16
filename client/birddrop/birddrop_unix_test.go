//go:build !windows

package birddrop

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func requireRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root to verify ownership changes")
	}
}

func TestChownRootedTreeChangesOwnership(t *testing.T) {
	requireRoot(t)

	dest := t.TempDir()
	file := filepath.Join(dest, "nested", "file.txt")

	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte("received"), 0o644))

	info, err := os.Stat(file)
	require.NoError(t, err)

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	newUID := int(stat.Uid) + 1
	newGID := int(stat.Gid)

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	require.NoError(t, chownRootedTree(root, owner{uid: newUID, gid: newGID}))

	info, err = os.Stat(file)
	require.NoError(t, err)

	stat, ok = info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.Equal(t, uint32(newUID), stat.Uid)
	require.Equal(t, uint32(newGID), stat.Gid)
}

func TestChownRootedTreeDoesNotFollowSymlinkOutsideRoot(t *testing.T) {
	requireRoot(t)

	dest := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target.txt")

	require.NoError(t, os.WriteFile(target, []byte("outside"), 0o644))

	before, err := os.Stat(target)
	require.NoError(t, err)

	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	require.NoError(t, os.Symlink(target, filepath.Join(dest, "link")))

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	require.NoError(t, chownRootedTree(root, owner{uid: int(beforeStat.Uid) + 1, gid: int(beforeStat.Gid)}))

	after, err := os.Stat(target)
	require.NoError(t, err)

	afterStat, ok := after.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	require.Equal(t, beforeStat.Uid, afterStat.Uid)
	require.Equal(t, beforeStat.Gid, afterStat.Gid)
}

func TestChownRootedTreeChildrenBeforeParents(t *testing.T) {
	dest := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "a", "b", "f.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "a", "g.txt"), []byte("y"), 0o644))

	var order []string
	orig := chownFile
	chownFile = func(f *os.File, uid, gid int) error {
		order = append(order, f.Name())
		return nil
	}
	t.Cleanup(func() { chownFile = orig })

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	require.NoError(t, chownRootedTree(root, owner{uid: os.Getuid(), gid: os.Getgid()}))

	pos := map[string]int{}
	for i, p := range order {
		pos[filepath.Clean(p)] = i
	}
	require.Len(t, pos, 5)
	require.Less(t, pos[filepath.Join(dest, "a", "b", "f.txt")], pos[filepath.Join(dest, "a", "b")])
	require.Less(t, pos[filepath.Join(dest, "a", "b")], pos[filepath.Join(dest, "a")])
	require.Less(t, pos[filepath.Join(dest, "a", "g.txt")], pos[filepath.Join(dest, "a")])
	require.Equal(t, len(order)-1, pos[filepath.Clean(dest)], "the top directory must be handed over last")
}

func TestChownRootedTreeRefusesHardLinks(t *testing.T) {
	dest := t.TempDir()
	outside := filepath.Join(t.TempDir(), "sudoers")
	require.NoError(t, os.WriteFile(outside, []byte("root ALL=(ALL) ALL"), 0o600))
	require.NoError(t, os.Link(outside, filepath.Join(dest, "innocent.txt")))

	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()

	err = chownRootedTree(root, owner{uid: os.Getuid(), gid: os.Getgid()})
	require.ErrorContains(t, err, "links")
}

func TestTarDirWritesNoHeaderForUnreadableEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file, so the unreadable case cannot be built")
	}
	src := t.TempDir()
	secret := filepath.Join(src, "secret-name.txt")
	require.NoError(t, os.WriteFile(secret, []byte("hidden"), 0o200))

	var buf bytes.Buffer
	err := tarDir(authenticatedContext(t), src, &buf)
	require.Error(t, err)
	require.NotContains(t, buf.String(), "secret-name.txt")
}

func TestTarDirStopsWhenCanceled(t *testing.T) {
	src := t.TempDir()
	for i := 0; i < 5; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(src, fmt.Sprintf("f%d", i)), []byte("x"), 0o600))
	}
	ctx, cancel := context.WithCancel(authenticatedContext(t))
	cancel()

	var buf bytes.Buffer
	err := tarDir(ctx, src, &buf)
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, buf.String(), "f0")
}

func TestTarDirStripsOwnerMetadata(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o600))

	var buf bytes.Buffer
	require.NoError(t, tarDir(authenticatedContext(t), src, &buf))

	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "a.txt", hdr.Name)
	require.Zero(t, hdr.Uid)
	require.Zero(t, hdr.Gid)
	require.Empty(t, hdr.Uname)
	require.Empty(t, hdr.Gname)
}

func TestReceiveHandsSingleFileToUser(t *testing.T) {
	var handed []string
	orig := chownFile
	chownFile = func(f *os.File, uid, gid int) error {
		handed = append(handed, filepath.Base(f.Name()))
		require.Equal(t, os.Getuid(), uid)
		require.Equal(t, os.Getgid(), gid)
		return nil
	}
	t.Cleanup(func() { chownFile = orig })

	s, r, rPort := pair(t)
	src := filepath.Join(t.TempDir(), "note.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))
	evc, err := sendTestFile(s, context.Background(), "127.0.0.1", rPort, "receiver.netbird.cloud", src, 10*time.Second)
	require.NoError(t, err)
	go collectSendEvents(evc)

	dest := t.TempDir()
	_, err = r.Receive(context.Background(), nil, dest, testRoot(t, dest), os.Getuid(), os.Getgid(), nil,
		WithOwnerSID("S-1-5-21-1-2-3-1001"))
	require.NoError(t, err)
	require.Len(t, handed, 1)
	require.True(t, strings.HasSuffix(handed[0], ".part"), handed[0])
	got, err := os.ReadFile(filepath.Join(dest, "note.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}
