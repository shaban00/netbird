package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	reccrypt "github.com/netbirdio/netbird/recorder/internal/crypt"
	"github.com/netbirdio/netbird/recorder/internal/live"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	metasqlite "github.com/netbirdio/netbird/recorder/internal/metadata/sqlite"
	"github.com/netbirdio/netbird/recorder/internal/storage"
	"github.com/netbirdio/netbird/util/crypt"
)

func newTestAPI(t *testing.T) (*API, *storage.Store, metadata.Store) {
	t.Helper()

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	fieldKey, _ := crypt.GenerateKey()
	fieldEnc, err := crypt.NewFieldEncrypt(fieldKey)
	if err != nil {
		t.Fatalf("NewFieldEncrypt: %v", err)
	}
	meta, err := metasqlite.New(t.TempDir(), "test.db", fieldEnc)
	if err != nil {
		t.Fatalf("metasqlite.New: %v", err)
	}
	t.Cleanup(func() { meta.Close() })

	recKey, _ := reccrypt.GenerateKey()
	gcm, err := reccrypt.NewCipher(recKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	return New(meta, store, gcm, live.NewHub(), logger), store, meta
}

func writeFixtureSession(t *testing.T, a *API, store *storage.Store, meta metadata.Store, id, peerID, content string) {
	t.Helper()
	w, path, err := store.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	sw := reccrypt.NewStreamWriter(w, a.gcm)
	if _, err := sw.Write([]byte(content)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close stream writer: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	if err := meta.CreateSession(context.Background(), &metadata.Session{
		ID:         id,
		PeerID:     peerID,
		UserIDHash: "hash",
		OSUsername: "ubuntu",
		StartedAt:  time.Now().UTC(),
		CastPath:   path,
		Cols:       80,
		Rows:       24,
		Status:     metadata.StatusCompleted,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
}

func TestListSessions(t *testing.T) {
	a, store, meta := newTestAPI(t)
	id := storage.NewSessionID()
	writeFixtureSession(t, a, store, meta, id, "peer-1", "hello")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Sessions []sessionDTO `json:"sessions"`
		Total    int          `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 1 || len(body.Sessions) != 1 {
		t.Fatalf("expected 1 session, got total=%d len=%d", body.Total, len(body.Sessions))
	}
	if body.Sessions[0].ID != id {
		t.Fatalf("expected session id %q, got %q", id, body.Sessions[0].ID)
	}
}

func TestGetSession_IncludesPeerNameAndIP(t *testing.T) {
	a, store, meta := newTestAPI(t)
	id := storage.NewSessionID()

	w, path, err := store.CreateWriter(id)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	if err := meta.CreateSession(context.Background(), &metadata.Session{
		ID:             id,
		PeerID:         "pubkey-abc",
		PeerName:       "web-01.netbird.cloud",
		PeerIP:         "100.64.0.5",
		SourcePeerID:   "pubkey-xyz",
		SourcePeerName: "laptop-01.netbird.cloud",
		SourcePeerIP:   "100.64.0.9",
		UserIDHash:     "hash",
		OSUsername:     "ubuntu",
		StartedAt:      time.Now().UTC(),
		CastPath:       path,
		Cols:           80,
		Rows:           24,
		Status:         metadata.StatusCompleted,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+id, nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got sessionDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PeerName != "web-01.netbird.cloud" {
		t.Fatalf("expected peer_name %q, got %q", "web-01.netbird.cloud", got.PeerName)
	}
	if got.PeerIP != "100.64.0.5" {
		t.Fatalf("expected peer_ip %q, got %q", "100.64.0.5", got.PeerIP)
	}
	if got.SourcePeerName != "laptop-01.netbird.cloud" {
		t.Fatalf("expected source_peer_name %q, got %q", "laptop-01.netbird.cloud", got.SourcePeerName)
	}
	if got.SourcePeerIP != "100.64.0.9" {
		t.Fatalf("expected source_peer_ip %q, got %q", "100.64.0.9", got.SourcePeerIP)
	}
	if got.UserIDHash != "hash" {
		t.Fatalf("expected user_id_hash %q, got %q", "hash", got.UserIDHash)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	a, _, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+storage.NewSessionID(), nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetSession_InvalidID(t *testing.T) {
	a, _, _ := newTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a malformed session id, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/sessions/../../etc/passwd", nil)
	rec2 := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Fatalf("expected traversal attempt to never return 200, got 200: %s", rec2.Body.String())
	}
}

func TestStreamRecording_DecryptsAndReturnsContent(t *testing.T) {
	a, store, meta := newTestAPI(t)
	id := storage.NewSessionID()
	writeFixtureSession(t, a, store, meta, id, "peer-1", `{"version":3}`+"\n")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+id+"/recording", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"version":3}`+"\n" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestStreamRecording_UnknownSessionIsNotFound(t *testing.T) {
	a, _, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+storage.NewSessionID()+"/recording", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	a, _, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestListSessions_FilterByQuery(t *testing.T) {
	a, store, meta := newTestAPI(t)
	writeFixtureSession(t, a, store, meta, storage.NewSessionID(), "peer-a", "x")
	writeFixtureSession(t, a, store, meta, storage.NewSessionID(), "peer-b", "y")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?q=peer-a", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 1 {
		t.Fatalf("expected 1 session for peer-a, got %d", body.Total)
	}
}

func TestListSessions_FilterByMultipleStatuses(t *testing.T) {
	a, store, meta := newTestAPI(t)
	writeFixtureSession(t, a, store, meta, storage.NewSessionID(), "peer-completed", "x")

	failedID := storage.NewSessionID()
	w, path, err := store.CreateWriter(failedID)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	if err := meta.CreateSession(context.Background(), &metadata.Session{
		ID:         failedID,
		PeerID:     "peer-failed",
		UserIDHash: "hash",
		OSUsername: "ubuntu",
		StartedAt:  time.Now().UTC(),
		CastPath:   path,
		Cols:       80,
		Rows:       24,
		Status:     metadata.StatusRecording,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := meta.FinalizeSession(context.Background(), failedID, time.Now().UTC(), nil, metadata.StatusFailed); err != nil {
		t.Fatalf("FinalizeSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?status=completed&status=failed", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 2 {
		t.Fatalf("expected 2 sessions matching status=completed OR status=failed, got %d", body.Total)
	}

	reqSingle := httptest.NewRequest(http.MethodGet, "/api/sessions?status=completed", nil)
	recSingle := httptest.NewRecorder()
	a.Handler().ServeHTTP(recSingle, reqSingle)
	var bodySingle struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(recSingle.Body.Bytes(), &bodySingle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if bodySingle.Total != 1 {
		t.Fatalf("expected 1 session for status=completed alone, got %d", bodySingle.Total)
	}
}

func TestSanitizeStatuses(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, []string{}},
		{"empty", []string{}, []string{}},
		{"all valid", []string{"recording", "completed", "interrupted", "failed"}, []string{"recording", "completed", "interrupted", "failed"}},
		{"garbage value dropped", []string{"completed", "not-a-real-status"}, []string{"completed"}},
		{"duplicates collapse", []string{"completed", "completed", "completed"}, []string{"completed"}},
		{"large repeated garbage never grows the result", repeat("not-a-real-status", 10000), []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeStatuses(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("sanitizeStatuses(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i, w := range tt.want {
				if got[i] != w {
					t.Fatalf("sanitizeStatuses(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestListSessions_IgnoresUnknownStatusValues(t *testing.T) {
	a, store, meta := newTestAPI(t)
	writeFixtureSession(t, a, store, meta, storage.NewSessionID(), "peer-a", "x")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions?status=not-a-real-status", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 1 {
		t.Fatalf("expected the unknown status value to be ignored (no filter applied, not zero results), got total=%d", body.Total)
	}
}

func TestListSessions_QueryMatchesAnyIdentityField(t *testing.T) {
	a, store, meta := newTestAPI(t)

	create := func(id string, sess *metadata.Session) {
		w, path, err := store.CreateWriter(id)
		if err != nil {
			t.Fatalf("CreateWriter: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		sess.ID = id
		sess.CastPath = path
		sess.Cols, sess.Rows = 80, 24
		sess.Status = metadata.StatusCompleted
		sess.StartedAt = time.Now().UTC()
		sess.UserIDHash = "hash"
		if sess.OSUsername == "" {
			sess.OSUsername = "ubuntu"
		}
		if sess.PeerID == "" {
			sess.PeerID = "peer-x"
		}
		if err := meta.CreateSession(context.Background(), sess); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	create(storage.NewSessionID(), &metadata.Session{PeerID: "pubkey-abc", PeerName: "web-01.netbird.cloud"})
	create(storage.NewSessionID(), &metadata.Session{SourcePeerID: "src-pubkey", SourcePeerName: "deploy-bastion"})
	create(storage.NewSessionID(), &metadata.Session{OSUsername: "postgres"})
	create(storage.NewSessionID(), &metadata.Session{PeerName: "app-01.netbird.cloud", OSUsername: "ubuntu"})

	for _, query := range []string{"web-01", "bastion", "postgres"} {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?q="+query, nil)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)

		var body struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body.Total != 1 {
			t.Fatalf("query %q: expected 1 matching session, got %d", query, body.Total)
		}
	}
}

func TestListSessions_FilterByDateRange(t *testing.T) {
	a, store, meta := newTestAPI(t)

	create := func(id string, startedAt time.Time) {
		w, path, err := store.CreateWriter(id)
		if err != nil {
			t.Fatalf("CreateWriter: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close file: %v", err)
		}
		if err := meta.CreateSession(context.Background(), &metadata.Session{
			ID:         id,
			PeerID:     "peer-1",
			UserIDHash: "hash",
			OSUsername: "ubuntu",
			StartedAt:  startedAt,
			CastPath:   path,
			Cols:       80,
			Rows:       24,
			Status:     metadata.StatusCompleted,
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	create(storage.NewSessionID(), base)
	create(storage.NewSessionID(), base.Add(10*24*time.Hour))
	create(storage.NewSessionID(), base.Add(20*24*time.Hour))

	after := base.Add(5 * 24 * time.Hour).Format(timeFormat)
	before := base.Add(15 * 24 * time.Hour).Format(timeFormat)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?after="+after+"&before="+before, nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 1 {
		t.Fatalf("expected 1 session in range, got %d", body.Total)
	}
}
