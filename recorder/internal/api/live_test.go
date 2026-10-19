package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	recauth "github.com/netbirdio/netbird/recorder/internal/auth"

	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/storage"
)

const liveTestTimeout = 3 * time.Second

func writeRecordingFixtureSession(t *testing.T, a *API, store *storage.Store, meta metadata.Store, id string) {
	t.Helper()
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
		StartedAt:  time.Now().UTC(),
		CastPath:   path,
		Cols:       80,
		Rows:       24,
		Status:     metadata.StatusRecording,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
}

func TestLiveSession_UnknownIDReturns404(t *testing.T) {
	a, _, _ := newTestAPI(t)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), liveTestTimeout)
	defer cancel()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/sessions/" + storage.NewSessionID() + "/live"
	_, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{liveSubprotocol}})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the dial to fail for an unknown session")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		status := -1
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("expected 404, got %d", status)
	}
}

func TestLiveSession_CompletedSessionReturns409(t *testing.T) {
	a, store, meta := newTestAPI(t)
	id := storage.NewSessionID()
	writeFixtureSession(t, a, store, meta, id, "peer-1", "hello")

	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), liveTestTimeout)
	defer cancel()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/sessions/" + id + "/live"
	_, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{liveSubprotocol}})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the dial to fail for a session that is not currently recording")
	}
	if resp == nil || resp.StatusCode != http.StatusConflict {
		status := -1
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("expected 409, got %d", status)
	}
}

func TestLiveSession_StreamsHeaderThenPublishedEvents(t *testing.T) {
	a, store, meta := newTestAPI(t)
	id := storage.NewSessionID()
	writeRecordingFixtureSession(t, a, store, meta, id)

	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), liveTestTimeout)
	defer cancel()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/sessions/" + id + "/live"
	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{liveSubprotocol}})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("Dial: %v (status %d)", err, statusCodeOrZero(resp))
	}
	defer conn.CloseNow() //nolint:errcheck

	if conn.Subprotocol() != liveSubprotocol {
		t.Fatalf("negotiated subprotocol = %q, want %q", conn.Subprotocol(), liveSubprotocol)
	}

	_, header, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !strings.Contains(string(header), `"cols":80`) || !strings.Contains(string(header), `"rows":24`) {
		t.Fatalf("header = %q, want cols=80 rows=24 from the session's stored size", header)
	}

	// Simulate the gRPC service publishing an event for this session while this viewer is connected.
	a.live.Publish(id, []byte(`[0.2,"o","hi"]`))

	_, event, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}
	if string(event) != `[0.2,"o","hi"]` {
		t.Fatalf("event = %q, want the published line verbatim", event)
	}

	a.live.End(id)

	_, _, err = conn.Read(ctx)
	closeStatus := websocket.CloseStatus(err)
	if closeStatus != websocket.StatusNormalClosure {
		t.Fatalf("close status = %v (err %v), want StatusNormalClosure", closeStatus, err)
	}
}

func TestLiveSession_UnresponsiveViewerIsDisconnectedByPing(t *testing.T) {
	a, store, meta := newTestAPI(t)
	a.livePingInterval = 50 * time.Millisecond
	a.livePingTimeout = 50 * time.Millisecond

	id := storage.NewSessionID()
	writeRecordingFixtureSession(t, a, store, meta, id)

	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), liveTestTimeout)
	defer cancel()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/sessions/" + id + "/live"
	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{liveSubprotocol}})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	if err != nil {
		t.Fatalf("Dial: %v (status %d)", err, statusCodeOrZero(resp))
	}
	defer conn.CloseNow() //nolint:errcheck

	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read header: %v", err)
	}

	time.Sleep(a.livePingInterval + a.livePingTimeout + 200*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for {
		writeCtx, writeCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := conn.Write(writeCtx, websocket.MessageText, []byte("still here?"))
		writeCancel()
		if err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("expected the server to have torn down the connection after the unanswered ping, but writes kept succeeding")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestLiveSession_ClosesWhenSessionCookieExpiresMidConnection(t *testing.T) {
	a, store, meta := newTestAPI(t)
	a.livePingInterval = 300 * time.Millisecond
	a.livePingTimeout = 200 * time.Millisecond

	id := storage.NewSessionID()
	writeRecordingFixtureSession(t, a, store, meta, id)

	const tokenDuration = 2 * time.Second
	signingKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	sessions, err := recauth.NewSessionManager(signingKey, tokenDuration)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	token, err := sessions.Mint(recauth.Identity{Subject: "user-1", Email: "user@example.com"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	srv := httptest.NewServer(recauth.Middleware(sessions)(a.Handler()))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), liveTestTimeout)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/sessions/" + id + "/live"
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{liveSubprotocol},
		HTTPHeader:   http.Header{"Cookie": []string{recauth.SessionCookieName + "=" + token}},
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	if err != nil {
		t.Fatalf("Dial (with a still-valid cookie): %v (status %d)", err, statusCodeOrZero(resp))
	}
	defer conn.CloseNow() //nolint:errcheck

	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read header while the session cookie is still valid: %v", err)
	}

	closeErrCh := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				closeErrCh <- err
				return
			}
		}
	}()

	select {
	case err := <-closeErrCh:
		closeStatus := websocket.CloseStatus(err)
		if closeStatus != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %v (err %v), want StatusPolicyViolation once the session cookie expired mid-connection", closeStatus, err)
		}
	case <-time.After(tokenDuration + 2*time.Second):
		t.Fatal("connection was never closed after the session cookie expired")
	}
}

func statusCodeOrZero(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}
