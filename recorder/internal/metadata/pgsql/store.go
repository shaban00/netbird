package pgsql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/util/crypt"
)

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
	id               TEXT PRIMARY KEY,
	peer_id          TEXT NOT NULL,
	peer_name        TEXT NOT NULL DEFAULT '',
	peer_ip          TEXT NOT NULL DEFAULT '',
	source_peer_id   TEXT NOT NULL DEFAULT '',
	source_peer_name TEXT NOT NULL DEFAULT '',
	source_peer_ip   TEXT NOT NULL DEFAULT '',
	user_id_hash     TEXT NOT NULL,
	os_username      TEXT NOT NULL,
	started_at       TIMESTAMPTZ NOT NULL,
	ended_at         TIMESTAMPTZ,
	exit_code        INTEGER,
	cast_path        TEXT NOT NULL,
	cols             INTEGER NOT NULL,
	rows             INTEGER NOT NULL,
	status           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_peer_id ON sessions(peer_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
`

const (
	maxConns      = 10
	minConns      = 1
	maxConnLife   = 60 * time.Minute
	selectColumns = "id, peer_id, peer_name, peer_ip, source_peer_id, source_peer_name, source_peer_ip, user_id_hash, os_username, started_at, ended_at, exit_code, cast_path, cols, rows, status"
)

type Store struct {
	pool *pgxpool.Pool
	enc  *crypt.FieldEncrypt
}

type rowScanner interface {
	Scan(dest ...any) error
}

func New(ctx context.Context, dsn string, enc *crypt.FieldEncrypt) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = minConns
	cfg.MaxConnLifetime = maxConnLife

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate postgres schema: %w", err)
	}

	return &Store{pool: pool, enc: enc}, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *metadata.Session) error {
	osUsername, err := s.enc.Encrypt(sess.OSUsername)
	if err != nil {
		return fmt.Errorf("encrypt os_username: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO sessions (id, peer_id, peer_name, peer_ip, source_peer_id, source_peer_name, source_peer_ip, user_id_hash, os_username, started_at, cast_path, cols, rows, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		sess.ID, sess.PeerID, sess.PeerName, sess.PeerIP, sess.SourcePeerID, sess.SourcePeerName, sess.SourcePeerIP,
		sess.UserIDHash, osUsername, sess.StartedAt, sess.CastPath, sess.Cols, sess.Rows, sess.Status)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (s *Store) FinalizeSession(ctx context.Context, id string, endedAt time.Time, exitCode *int32, status string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET ended_at = $1, exit_code = $2, status = $3 WHERE id = $4`,
		endedAt, exitCode, status, id)
	if err != nil {
		return fmt.Errorf("finalize session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return metadata.ErrNotFound
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*metadata.Session, error) {
	row := s.pool.QueryRow(ctx, "SELECT "+selectColumns+" FROM sessions WHERE id = $1", id)
	return s.scanSession(row)
}

func (s *Store) ListSessions(ctx context.Context, filter metadata.ListFilter) ([]*metadata.Session, int, error) {
	if filter.Query != "" {
		return s.listSessionsFilteredByQuery(ctx, filter)
	}

	where, args := buildWhere(filter)

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf("SELECT "+selectColumns+" FROM sessions%s ORDER BY started_at DESC LIMIT $%d OFFSET $%d", where, len(args)+1, len(args)+2)
	rows, err := s.pool.Query(ctx, query, append(args, limit, filter.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []*metadata.Session
	for rows.Next() {
		sess, err := s.scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list sessions rows: %w", err)
	}
	return out, total, nil
}

func (s *Store) listSessionsFilteredByQuery(ctx context.Context, filter metadata.ListFilter) ([]*metadata.Session, int, error) {
	where, args := buildWhere(metadata.ListFilter{Statuses: filter.Statuses, After: filter.After, Before: filter.Before})

	query := "SELECT " + selectColumns + " FROM sessions" + where + " ORDER BY started_at DESC"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	needle := strings.ToLower(filter.Query)
	var matched []*metadata.Session
	for rows.Next() {
		sess, err := s.scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		if matchesQuery(sess, needle) {
			matched = append(matched, sess)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list sessions rows: %w", err)
	}

	return paginate(matched, filter.Limit, filter.Offset), len(matched), nil
}

func matchesQuery(sess *metadata.Session, needle string) bool {
	fields := []string{
		sess.PeerID, sess.PeerName, sess.PeerIP,
		sess.SourcePeerID, sess.SourcePeerName, sess.SourcePeerIP,
		sess.UserIDHash, sess.OSUsername,
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

func paginate(sessions []*metadata.Session, limit, offset int) []*metadata.Session {
	if limit <= 0 {
		limit = 50
	}
	total := len(sessions)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	return sessions[start:end]
}

func buildWhere(filter metadata.ListFilter) (string, []any) {
	var clauses []string
	var args []any
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			args = append(args, s)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		clauses = append(clauses, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if !filter.After.IsZero() {
		args = append(args, filter.After)
		clauses = append(clauses, fmt.Sprintf("started_at >= $%d", len(args)))
	}
	if !filter.Before.IsZero() {
		args = append(args, filter.Before)
		clauses = append(clauses, fmt.Sprintf("started_at <= $%d", len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *Store) scanSession(row rowScanner) (*metadata.Session, error) {
	var sess metadata.Session
	var osUsername string
	var endedAt *time.Time
	var exitCode *int32

	err := row.Scan(&sess.ID, &sess.PeerID, &sess.PeerName, &sess.PeerIP,
		&sess.SourcePeerID, &sess.SourcePeerName, &sess.SourcePeerIP,
		&sess.UserIDHash, &osUsername, &sess.StartedAt,
		&endedAt, &exitCode, &sess.CastPath, &sess.Cols, &sess.Rows, &sess.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, metadata.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}

	sess.OSUsername, err = s.enc.Decrypt(osUsername)
	if err != nil {
		return nil, fmt.Errorf("decrypt os_username: %w", err)
	}
	sess.EndedAt = endedAt
	sess.ExitCode = exitCode
	return &sess, nil
}

func (s *Store) MarkAllRecordingAsInterrupted(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET status = $1, ended_at = $2 WHERE status = $3`,
		metadata.StatusInterrupted, time.Now().UTC(), metadata.StatusRecording)
	if err != nil {
		return 0, fmt.Errorf("mark interrupted sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) DeleteSessionsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `DELETE FROM sessions WHERE started_at < $1 AND status != $2 RETURNING cast_path`, cutoff, metadata.StatusRecording)
	if err != nil {
		return nil, fmt.Errorf("delete sessions: %w", err)
	}
	defer rows.Close()

	var castPaths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, fmt.Errorf("scan cast_path: %w", err)
		}
		castPaths = append(castPaths, path)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("delete sessions rows: %w", err)
	}
	return castPaths, nil
}

func (s *Store) Ready(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) Close() error {
	s.pool.Close()
	return nil
}
