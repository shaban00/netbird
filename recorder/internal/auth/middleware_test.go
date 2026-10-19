package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestMiddleware_NilSessionManagerIsPassthrough(t *testing.T) {
	mw := Middleware(nil)
	srv := httptest.NewServer(mw(pingHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/sessions")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "auth disabled must never block a request")
}

func TestMiddleware_UnauthenticatedAPIRequestGets401JSON(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	srv := httptest.NewServer(Middleware(sm)(pingHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/sessions")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
}

func TestMiddleware_UnauthenticatedPageRequestRedirectsToLogin(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	srv := httptest.NewServer(Middleware(sm)(pingHandler()))
	defer srv.Close()

	resp, err := client.Get(srv.URL + "/sessions/abc-123")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/auth/login?return_to=")
	assert.Contains(t, loc, "%2Fsessions%2Fabc-123", "return_to must carry the originally requested path")
}

func TestMiddleware_ExemptPathsNeverChallenged(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	srv := httptest.NewServer(Middleware(sm)(pingHandler()))
	defer srv.Close()

	for _, path := range []string{"/auth/login", "/auth/callback", "/auth/logout", "/api/healthz"} {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "path=%s must be exempt from the auth gate", path)
	}
}

func TestMiddleware_ValidSessionPassesThroughWithIdentity(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	want := Identity{Subject: "user-123", Email: "user@example.com"}
	token, err := sm.Mint(want)
	require.NoError(t, err)

	var gotIdentity *Identity
	handler := Middleware(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/sessions", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, gotIdentity)
	assert.Equal(t, want.Subject, gotIdentity.Subject)
	assert.Equal(t, want.Email, gotIdentity.Email)
}

func TestMiddleware_InvalidCookieIsRejected(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	srv := httptest.NewServer(Middleware(sm)(pingHandler()))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/sessions", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-real-token"})

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
