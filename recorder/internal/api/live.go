package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"

	recauth "github.com/netbirdio/netbird/recorder/internal/auth"

	"github.com/netbirdio/netbird/recorder/internal/asciicast"
	"github.com/netbirdio/netbird/recorder/internal/live"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/storage"
)

const (
	defaultLivePingInterval = 30 * time.Second
	defaultLivePingTimeout  = 10 * time.Second
	liveSubprotocol         = "v3.asciicast"
)

func (a *API) liveSession(w http.ResponseWriter, r *http.Request) {
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
	if sess.Status != metadata.StatusRecording {
		http.Error(w, "session is not currently recording", http.StatusConflict)
		return
	}

	header, err := asciicast.Header(uint32(sess.Cols), uint32(sess.Rows)) //nolint:gosec
	if err != nil {
		a.logger.Errorf("build live header for session %s: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{liveSubprotocol},
	})
	if err != nil {
		a.logger.Debugf("accept live websocket for session %s: %v", id, err)
		return
	}
	defer conn.CloseNow() //nolint:errcheck

	sub := a.live.Subscribe(id, header)
	defer a.live.Unsubscribe(id, sub)

	var sessionExpiresAt time.Time
	if identity := recauth.IdentityFromContext(r.Context()); identity != nil {
		sessionExpiresAt = identity.ExpiresAt
	}

	ctx := conn.CloseRead(r.Context())
	pumpLiveEvents(ctx, conn, sub, a.livePingInterval, a.livePingTimeout, sessionExpiresAt)
}

// pumpLiveEvents forwards sub's events to conn until ctx or sub is done.
func pumpLiveEvents(ctx context.Context, conn *websocket.Conn, sub *live.Subscriber, pingInterval, pingTimeout time.Duration, sessionExpiresAt time.Time) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.Done():
			drainLiveEvents(ctx, conn, sub)
			_ = conn.Close(websocket.StatusNormalClosure, "session ended")
			return
		case <-ticker.C:
			if !sessionExpiresAt.IsZero() && !time.Now().Before(sessionExpiresAt) {
				_ = conn.Close(websocket.StatusPolicyViolation, "session expired")
				return
			}
			if err := pingViewer(ctx, conn, pingTimeout); err != nil {
				return
			}
		case line, ok := <-sub.Events():
			if !ok {
				return
			}
			if err := conn.Write(ctx, websocket.MessageText, line); err != nil {
				return
			}
		}
	}
}

// pingViewer checks viewer liveness during idle periods.
func pingViewer(ctx context.Context, conn *websocket.Conn, timeout time.Duration) error {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return conn.Ping(pingCtx)
}

// drainLiveEvents flushes sub's buffered events without blocking, so the
// last events aren't lost when the hub drops the viewer.
func drainLiveEvents(ctx context.Context, conn *websocket.Conn, sub *live.Subscriber) {
	for {
		select {
		case line := <-sub.Events():
			if err := conn.Write(ctx, websocket.MessageText, line); err != nil {
				return
			}
		default:
			return
		}
	}
}
