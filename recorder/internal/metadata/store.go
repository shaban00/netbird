package metadata

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("session not found")

const (
	EngineSQLite      Engine = "sqlite"
	EnginePostgres    Engine = "postgres"
	StatusRecording          = "recording"
	StatusCompleted          = "completed"
	StatusInterrupted        = "interrupted"
	StatusFailed             = "failed"
)

type Engine string

type Session struct {
	ID             string
	PeerID         string
	PeerName       string
	PeerIP         string
	SourcePeerID   string
	SourcePeerName string
	SourcePeerIP   string
	UserIDHash     string
	OSUsername     string
	StartedAt      time.Time
	EndedAt        *time.Time
	ExitCode       *int32
	CastPath       string
	Cols           int
	Rows           int
	Status         string
}

type ListFilter struct {
	Query    string
	Statuses []string
	After    time.Time
	Before   time.Time
	Limit    int
	Offset   int
}

type Store interface {
	// CreateSession inserts a new session row with StatusRecording.
	CreateSession(ctx context.Context, s *Session) error
	// FinalizeSession sets EndedAt/ExitCode/Status for a completed or interrupted session.
	FinalizeSession(ctx context.Context, id string, endedAt time.Time, exitCode *int32, status string) error
	// GetSession returns ErrNotFound if id doesn't exist.
	GetSession(ctx context.Context, id string) (*Session, error)
	// ListSessions returns a page of sessions (newest first) and the total matching count (ignoring Limit/Offset) for pagination.
	ListSessions(ctx context.Context, filter ListFilter) ([]*Session, int, error)
	MarkAllRecordingAsInterrupted(ctx context.Context) (int, error)
	DeleteSessionsBefore(ctx context.Context, cutoff time.Time) (castPaths []string, err error)
	// Ready reports whether the store can currently serve requests
	Ready(ctx context.Context) error
	Close() error
}
