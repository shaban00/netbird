package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const recordingExt = ".cast.enc"

type Store struct {
	recordingsDir string
}

func New(dataDir string) (*Store, error) {
	recordingsDir := filepath.Join(dataDir, "recordings")
	if err := os.MkdirAll(recordingsDir, 0o750); err != nil {
		return nil, fmt.Errorf("create recordings directory: %w", err)
	}
	return &Store{recordingsDir: recordingsDir}, nil
}

func NewSessionID() string {
	return uuid.NewString()
}

func ValidSessionID(id string) bool {
	return sessionIDPattern.MatchString(id)
}

// pathFor validates sessionID and returns its on-disk path
func (s *Store) pathFor(sessionID string) (string, error) {
	if !sessionIDPattern.MatchString(sessionID) {
		return "", fmt.Errorf("invalid session id %q", sessionID)
	}

	shard := sessionID[:2]
	dir := filepath.Join(s.recordingsDir, shard)
	path := filepath.Join(dir, sessionID+recordingExt)

	cleanBase := filepath.Clean(s.recordingsDir) + string(filepath.Separator)
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, cleanBase) {
		return "", fmt.Errorf("resolved path escapes recordings directory")
	}

	return path, nil
}

// CreateWriter creates a new recording file for sessionID
func (s *Store) CreateWriter(sessionID string) (io.WriteCloser, string, error) {
	path, err := s.pathFor(sessionID)
	if err != nil {
		return nil, "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, "", fmt.Errorf("create session shard directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create recording file: %w", err)
	}
	return f, path, nil
}

// OpenReader opens an existing recording for reading (playback).
func (s *Store) OpenReader(sessionID string) (io.ReadCloser, error) {
	path, err := s.pathFor(sessionID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("open recording file: %w", err)
	}
	return f, nil
}

// Delete removes a recording file by its stored cast path
func (s *Store) Delete(castPath string) error {
	cleanBase := filepath.Clean(s.recordingsDir) + string(filepath.Separator)
	cleanPath := filepath.Clean(castPath)
	if !strings.HasPrefix(cleanPath, cleanBase) {
		return fmt.Errorf("path %q escapes recordings directory", castPath)
	}

	if err := os.Remove(cleanPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove recording file: %w", err)
	}
	return nil
}
