//go:build !windows

package birddrop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// chownFile is the ownership change itself; tests replace it to observe order.
var chownFile = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// chownRootedTree hands a freshly extracted tree to uid/gid through an
// already-open directory root.
//
// Ownership is changed children-first: a directory is handed to the user only
// after everything inside it has been processed. Until then the directory is
// still daemon-owned, so the user cannot rename, replace or link entries inside
// it while the daemon is working there. Regular files with more than one link
// are refused, so a hard link to a file outside the tree is never handed over.
func chownRootedTree(root *os.Root, own owner) error {
	if own.uid < 0 || own.gid < 0 {
		return nil
	}

	var paths []string
	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Never follow a symlink that may have been raced into the extracted tree.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}

	// WalkDir is pre-order (every directory before its contents), so walking
	// the list backwards processes every entry before the directory holding it.
	for i := len(paths) - 1; i >= 0; i-- {
		if err := chownOne(root, paths[i], own.uid, own.gid); err != nil {
			return err
		}
	}
	return nil
}

func chownOne(root *os.Root, path string, uid, gid int) error {
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open received path %q for ownership change: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing ownership change of %q: not a regular file", path)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("unexpected file information type")
		}
		if uint64(st.Nlink) != 1 {
			return fmt.Errorf("refusing ownership change of %q: file has %d links", path, st.Nlink)
		}
	}

	if err := chownFile(f, uid, gid); err != nil {
		return fmt.Errorf("chown %q: %w", path, err)
	}
	return nil
}

// handOverFile gives a single file the daemon just created to the local user.
func handOverFile(f *os.File, own owner) error {
	if own.uid < 0 || own.gid < 0 {
		return nil
	}
	return chownFile(f, own.uid, own.gid)
}
