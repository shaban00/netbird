package api

import (
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	reccrypt "github.com/netbirdio/netbird/recorder/internal/crypt"
	"github.com/netbirdio/netbird/recorder/internal/live"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/storage"
)

const (
	defaultListLimit = 50
	timeFormat       = "2006-01-02T15:04:05Z07:00"
)

var knownStatuses = map[string]bool{
	metadata.StatusRecording:   true,
	metadata.StatusCompleted:   true,
	metadata.StatusInterrupted: true,
	metadata.StatusFailed:      true,
}

type API struct {
	meta    metadata.Store
	storage *storage.Store
	gcm     cipher.AEAD
	live    *live.Hub
	logger  *log.Logger

	livePingInterval time.Duration
	livePingTimeout  time.Duration
}

type sessionDTO struct {
	ID             string `json:"id"`
	PeerID         string `json:"peer_id"`
	PeerName       string `json:"peer_name"`
	PeerIP         string `json:"peer_ip"`
	SourcePeerID   string `json:"source_peer_id"`
	SourcePeerName string `json:"source_peer_name"`
	SourcePeerIP   string `json:"source_peer_ip"`
	// UserIDHash is the hashed JWT user ID (see shared/sshauth), empty when the session wasn't authenticated via SSH JWT auth.
	UserIDHash string  `json:"user_id_hash"`
	OSUsername string  `json:"os_username"`
	StartedAt  string  `json:"started_at"`
	EndedAt    *string `json:"ended_at,omitempty"`
	ExitCode   *int32  `json:"exit_code,omitempty"`
	Cols       int     `json:"cols"`
	Rows       int     `json:"rows"`
	Status     string  `json:"status"`
}

func New(meta metadata.Store, store *storage.Store, gcm cipher.AEAD, liveHub *live.Hub, logger *log.Logger) *API {
	return &API{
		meta:             meta,
		storage:          store,
		gcm:              gcm,
		live:             liveHub,
		logger:           logger,
		livePingInterval: defaultLivePingInterval,
		livePingTimeout:  defaultLivePingTimeout,
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions", a.listSessions)
	mux.HandleFunc("GET /api/sessions/{id}", a.getSession)
	mux.HandleFunc("GET /api/sessions/{id}/recording", a.streamRecording)
	mux.HandleFunc("GET /api/sessions/{id}/live", a.liveSession)
	mux.HandleFunc("GET /api/healthz", a.healthz)
	return mux
}

func toDTO(s *metadata.Session) sessionDTO {
	dto := sessionDTO{
		ID:             s.ID,
		PeerID:         s.PeerID,
		PeerName:       s.PeerName,
		PeerIP:         s.PeerIP,
		SourcePeerID:   s.SourcePeerID,
		SourcePeerName: s.SourcePeerName,
		SourcePeerIP:   s.SourcePeerIP,
		UserIDHash:     s.UserIDHash,
		OSUsername:     s.OSUsername,
		StartedAt:      s.StartedAt.Format(timeFormat),
		ExitCode:       s.ExitCode,
		Cols:           s.Cols,
		Rows:           s.Rows,
		Status:         s.Status,
	}
	if s.EndedAt != nil {
		ended := s.EndedAt.Format(timeFormat)
		dto.EndedAt = &ended
	}
	return dto
}

func sanitizeStatuses(raw []string) []string {
	seen := make(map[string]bool, len(knownStatuses))
	out := make([]string, 0, len(knownStatuses))
	for _, s := range raw {
		if !knownStatuses[s] || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := metadata.ListFilter{
		Query:    q.Get("q"),
		Statuses: sanitizeStatuses(q["status"]),
		Limit:    defaultListLimit,
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			filter.Offset = n
		}
	}
	if v := q.Get("after"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			filter.After = t
		}
	}
	if v := q.Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			filter.Before = t
		}
	}

	sessions, total, err := a.meta.ListSessions(r.Context(), filter)
	if err != nil {
		a.logger.Errorf("list sessions: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	dtos := make([]sessionDTO, 0, len(sessions))
	for _, s := range sessions {
		dtos = append(dtos, toDTO(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": dtos,
		"total":    total,
		"limit":    filter.Limit,
		"offset":   filter.Offset,
	})
}

func (a *API) getSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !storage.ValidSessionID(id) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}

	sess, err := a.meta.GetSession(r.Context(), id)
	if errors.Is(err, metadata.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Errorf("get session %s: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toDTO(sess))
}

func (a *API) streamRecording(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !storage.ValidSessionID(id) {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}

	if _, err := a.meta.GetSession(r.Context(), id); err != nil {
		if errors.Is(err, metadata.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		a.logger.Errorf("get session %s: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	f, err := a.storage.OpenReader(id)
	if err != nil {
		a.logger.Errorf("open recording %s: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")

	reader := reccrypt.NewStreamReader(f, a.gcm)
	if _, err := io.Copy(w, reader); err != nil {
		a.logger.Debugf("stream recording %s: %v", id, err)
	}
}

func (a *API) healthz(w http.ResponseWriter, r *http.Request) {
	if err := a.meta.Ready(r.Context()); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Debugf("write json response: %v", err)
	}
}
