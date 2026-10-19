package storage

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStore_CreateAndOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	w, path, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	if _, err := w.Write([]byte("recording bytes")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("expected absolute path, got %q", path)
	}

	r, err := s.OpenReader(id)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "recording bytes" {
		t.Fatalf("got %q, want %q", got, "recording bytes")
	}
}

func TestStore_FilePermissionsAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	w, path, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	w.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600, got %o", perm)
	}
}

func TestStore_RejectsPathTraversalSessionIDs(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	malicious := []string{
		"../../../etc/passwd",
		"..%2F..%2Fetc%2Fpasswd",
		"../../etc/shadow",
		"a/../../../etc/passwd",
		"",
		"not-a-uuid",
		"00000000-0000-0000-0000-00000000000g", // invalid hex char
		"/etc/passwd",
		"....//....//etc/passwd",
	}

	for _, id := range malicious {
		if _, _, err := s.CreateWriter(id); err == nil {
			t.Errorf("CreateWriter(%q): expected rejection, got nil error", id)
		}
		if _, err := s.OpenReader(id); err == nil {
			t.Errorf("OpenReader(%q): expected rejection, got nil error", id)
		}
	}
}

func TestStore_CollidingSessionIDFails(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	w1, _, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("first CreateWriter: %v", err)
	}
	w1.Close()

	if _, _, err := s.CreateWriter(id); err == nil {
		t.Fatal("expected error creating a recording with a duplicate session id, got nil")
	}
}

func TestStore_DeleteRemovesFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	w, path, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	w.Close()

	if err := s.Delete(path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file to be gone, stat error: %v", err)
	}
}

func TestStore_DeleteIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	w, path, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	w.Close()

	if err := s.Delete(path); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := s.Delete(path); err != nil {
		t.Fatalf("second Delete on already-gone file should succeed, got: %v", err)
	}
}

func TestStore_DeleteRejectsPathOutsideRecordingsDir(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	outside := filepath.Join(dir, "escaped.cast.enc")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	malicious := []string{
		outside,
		filepath.Join(dir, "recordings", "..", "escaped.cast.enc"),
		"/etc/passwd",
	}
	for _, path := range malicious {
		if err := s.Delete(path); err == nil {
			t.Errorf("Delete(%q): expected rejection, got nil error", path)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("file outside recordings dir should be untouched: %v", err)
	}
}

func TestStore_ShardsBySessionIDPrefix(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id := NewSessionID()
	_, path, err := s.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}

	expectedShardDir := filepath.Join(dir, "recordings", id[:2])
	if filepath.Dir(path) != expectedShardDir {
		t.Fatalf("expected shard dir %q, got %q", expectedShardDir, filepath.Dir(path))
	}
}
