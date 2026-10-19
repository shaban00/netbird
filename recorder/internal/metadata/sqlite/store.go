package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

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
	started_at       INTEGER NOT NULL,
	ended_at         INTEGER,
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
	selectColumns = "id, peer_id, peer_name, peer_ip, source_peer_id, source_peer_name, source_peer_ip, user_id_hash, os_username, started_at, ended_at, exit_code, cast_path, cols, rows, status"
)

type Store struct {
	db  *sql.DB
	enc *crypt.FieldEncrypt
}

type rowScanner interface {
	Scan(dest ...any) error
}

func New(dataDir, dbFile string, enc *crypt.FieldEncrypt) (*Store, error) {
	path := dbFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(dataDir, dbFile)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite schema: %w", err)
	}

	return &Store{db: db, enc: enc}, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *metadata.Session) error {
	osUsername, err := s.enc.Encrypt(sess.OSUsername)
	if err != nil {
		return fmt.Errorf("encrypt os_username: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, peer_id, peer_name, peer_ip, source_peer_id, source_peer_name, source_peer_ip, user_id_hash, os_username, started_at, cast_path, cols, rows, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.PeerID, sess.PeerName, sess.PeerIP, sess.SourcePeerID, sess.SourcePeerName, sess.SourcePeerIP,
		sess.UserIDHash, osUsername, sess.StartedAt.UnixNano(), sess.CastPath, sess.Cols, sess.Rows, sess.Status)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (s *Store) FinalizeSession(ctx context.Context, id string, endedAt time.Time, exitCode *int32, status string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET ended_at = ?, exit_code = ?, status = ? WHERE id = ?`,
		endedAt.UnixNano(), exitCode, status, id)
	if err != nil {
		return fmt.Errorf("finalize session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("finalize session: rows affected: %w", err)
	}
	if n == 0 {
		return metadata.ErrNotFound
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, id string) (*metadata.Session, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM sessions WHERE id = ?", id)
	return s.scanSession(row)
}

func (s *Store) ListSessions(ctx context.Context, filter metadata.ListFilter) ([]*metadata.Session, int, error) {
	if filter.Query != "" {
		return s.listSessionsFilteredByQuery(ctx, filter)
	}

	where, args := buildWhere(filter)

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := "SELECT " + selectColumns + " FROM sessions" + where + " ORDER BY started_at DESC LIMIT ? OFFSET ?" //nolint:gosec // selectColumns is a hardcoded constant and where's clauses (buildWhere) use ? placeholders, never raw interpolation
	rows, err := s.db.QueryContext(ctx, query, append(args, limit, filter.Offset)...)
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

	query := "SELECT " + selectColumns + " FROM sessions" + where + " ORDER BY started_at DESC" //nolint:gosec // selectColumns is a hardcoded constant and where's clauses (buildWhere) use ? placeholders, never raw interpolation
	rows, err := s.db.QueryContext(ctx, query, args...)
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
			placeholders[i] = "?"
			args = append(args, s)
		}
		clauses = append(clauses, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if !filter.After.IsZero() {
		args = append(args, filter.After.UnixNano())
		clauses = append(clauses, "started_at >= ?")
	}
	if !filter.Before.IsZero() {
		args = append(args, filter.Before.UnixNano())
		clauses = append(clauses, "started_at <= ?")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *Store) scanSession(row rowScanner) (*metadata.Session, error) {
	var sess metadata.Session
	var osUsername string
	var startedAtRaw, endedAtRaw any
	var exitCode *int32

	err := row.Scan(&sess.ID, &sess.PeerID, &sess.PeerName, &sess.PeerIP,
		&sess.SourcePeerID, &sess.SourcePeerName, &sess.SourcePeerIP,
		&sess.UserIDHash, &osUsername, &startedAtRaw,
		&endedAtRaw, &exitCode, &sess.CastPath, &sess.Cols, &sess.Rows, &sess.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, metadata.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}

	sess.OSUsername, err = s.enc.Decrypt(osUsername)
	if err != nil {
		return nil, fmt.Errorf("decrypt os_username: %w", err)
	}

	startedAt, err := parseTimestampColumn(startedAtRaw)
	if err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	sess.StartedAt = startedAt

	if endedAtRaw != nil {
		endedAt, err := parseTimestampColumn(endedAtRaw)
		if err != nil {
			return nil, fmt.Errorf("parse ended_at: %w", err)
		}
		sess.EndedAt = &endedAt
	}
	sess.ExitCode = exitCode
	return &sess, nil
}

func parseTimestampColumn(v any) (time.Time, error) {
	ns, ok := v.(int64)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected timestamp column type %T", v)
	}
	return time.Unix(0, ns).UTC(), nil
}

func (s *Store) MarkAllRecordingAsInterrupted(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET status = ?, ended_at = ? WHERE status = ?`,
		metadata.StatusInterrupted, time.Now().UTC().UnixNano(), metadata.StatusRecording)
	if err != nil {
		return 0, fmt.Errorf("mark interrupted sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mark interrupted sessions: rows affected: %w", err)
	}
	return int(n), nil
}

func (s *Store) DeleteSessionsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT cast_path FROM sessions WHERE started_at < ? AND status != ?`, cutoff.UnixNano(), metadata.StatusRecording)
	if err != nil {
		return nil, fmt.Errorf("select sessions to delete: %w", err)
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
		return nil, fmt.Errorf("select sessions to delete rows: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE started_at < ? AND status != ?`, cutoff.UnixNano(), metadata.StatusRecording); err != nil {
		return nil, fmt.Errorf("delete sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return castPaths, nil
}

func (s *Store) Ready(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Close() error {
	return s.db.Close()
}
