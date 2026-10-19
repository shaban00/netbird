package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type fakeOIDCProvider struct {
	srv                 *httptest.Server
	key                 *rsa.PrivateKey
	clientID            string
	nextIdentity        Identity
	groupsClaim         string
	advertiseEndSession bool
}

func newFakeOIDCProvider(t *testing.T, clientID string) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	f := &fakeOIDCProvider{key: key, clientID: clientID, groupsClaim: "groups"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/jwks", f.jwks)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDCProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                f.srv.URL,
		"authorization_endpoint":                f.srv.URL + "/authorize",
		"token_endpoint":                        f.srv.URL + "/token",
		"jwks_uri":                              f.srv.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	if f.advertiseEndSession {
		doc["end_session_endpoint"] = f.srv.URL + "/end-session"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeOIDCProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	set := josejwt.JSONWebKeySet{Keys: []josejwt.JSONWebKey{{
		Key:       &f.key.PublicKey,
		KeyID:     "test-key",
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (f *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	if r.PostForm.Get("code_verifier") == "" {
		http.Error(w, "missing code_verifier", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("code") == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	idToken := f.signIDToken()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   3600,
	})
}

func (f *fakeOIDCProvider) signIDToken() string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":         f.srv.URL,
		"aud":         f.clientID,
		"sub":         f.nextIdentity.Subject,
		"name":        f.nextIdentity.Name,
		"email":       f.nextIdentity.Email,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Hour).Unix(),
		f.groupsClaim: f.nextIdentity.Groups,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(f.key)
	if err != nil {
		panic(err)
	}
	return signed
}

func newTestHandlers(t *testing.T, provider *fakeOIDCProvider, allowedGroups []string, cookieSecure bool) (*Handlers, *SessionManager) {
	t.Helper()

	oidcProvider, err := NewOIDCProvider(t.Context(), OIDCConfig{
		Issuer:        provider.srv.URL,
		ClientID:      provider.clientID,
		ClientSecret:  "test-secret",
		RedirectURL:   "http://recorder.example/auth/callback",
		Scopes:        []string{"openid", "profile", "email"},
		GroupsClaim:   provider.groupsClaim,
		AllowedGroups: allowedGroups,
	})
	require.NoError(t, err)

	sessions, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	return NewHandlers(oidcProvider, sessions, cookieSecure), sessions
}

func TestLoginCallbackFlow_Succeeds(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client")
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com", Groups: []string{"security-team"}}

	handlers, _ := newTestHandlers(t, provider, nil, false)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	recorderSrv := httptest.NewServer(mux)
	defer recorderSrv.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	loginResp, err := client.Get(recorderSrv.URL + "/auth/login?return_to=" + url.QueryEscape("/sessions/abc-123"))
	require.NoError(t, err)
	loginResp.Body.Close()
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	idpURL, err := url.Parse(loginResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Contains(t, idpURL.String(), provider.srv.URL, "login must redirect to the configured IdP")
	state := idpURL.Query().Get("state")
	require.NotEmpty(t, state)

	recorderURL, err := url.Parse(recorderSrv.URL)
	require.NoError(t, err)
	authPathURL, err := url.Parse(recorderSrv.URL + "/auth/login")
	require.NoError(t, err)
	cookies := jar.Cookies(authPathURL)
	require.NotEmpty(t, cookies, "state cookie must be set after /auth/login")

	callbackURL := recorderSrv.URL + "/auth/callback?code=fake-code&state=" + url.QueryEscape(state)
	callbackResp, err := client.Get(callbackURL)
	require.NoError(t, err)
	callbackResp.Body.Close()
	require.Equal(t, http.StatusFound, callbackResp.StatusCode)
	require.Equal(t, "/sessions/abc-123", callbackResp.Header.Get("Location"), "callback must redirect to the original return_to")

	sessionCookies := jar.Cookies(recorderURL)
	var sessionToken string
	for _, c := range sessionCookies {
		if c.Name == SessionCookieName {
			sessionToken = c.Value
		}
	}
	require.NotEmpty(t, sessionToken, "session cookie must be set after a successful callback")
}

func TestLoginCallbackFlow_StateMismatchRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client")
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com"}
	handlers, _ := newTestHandlers(t, provider, nil, false)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	recorderSrv := httptest.NewServer(mux)
	defer recorderSrv.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loginResp, err := client.Get(recorderSrv.URL + "/auth/login")
	require.NoError(t, err)
	loginResp.Body.Close()

	resp, err := client.Get(recorderSrv.URL + "/auth/callback?code=fake-code&state=attacker-supplied-state")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLoginCallbackFlow_GroupsDeniedRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client")
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com", Groups: []string{"engineering"}}
	handlers, _ := newTestHandlers(t, provider, []string{"security-team"}, false)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	recorderSrv := httptest.NewServer(mux)
	defer recorderSrv.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loginResp, err := client.Get(recorderSrv.URL + "/auth/login")
	require.NoError(t, err)
	loginResp.Body.Close()
	state := extractStateFromRedirect(t, loginResp)

	resp, err := client.Get(recorderSrv.URL + "/auth/callback?code=fake-code&state=" + url.QueryEscape(state))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a user outside the allowed groups must be denied login")
}

func doFullLogin(t *testing.T, provider *fakeOIDCProvider, handlers *Handlers) (*http.Client, *httptest.Server) {
	t.Helper()

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	recorderSrv := httptest.NewServer(mux)
	t.Cleanup(recorderSrv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	loginResp, err := client.Get(recorderSrv.URL + "/auth/login")
	require.NoError(t, err)
	loginResp.Body.Close()
	state := extractStateFromRedirect(t, loginResp)

	callbackResp, err := client.Get(recorderSrv.URL + "/auth/callback?code=fake-code&state=" + url.QueryEscape(state))
	require.NoError(t, err)
	callbackResp.Body.Close()
	require.Equal(t, http.StatusFound, callbackResp.StatusCode, "login must succeed before logout can be tested")

	return client, recorderSrv
}

func TestLogout_EndsIdPSessionWhenSupported(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client")
	provider.advertiseEndSession = true
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com"}
	handlers, _ := newTestHandlers(t, provider, nil, false)

	client, recorderSrv := doFullLogin(t, provider, handlers)

	resp, err := client.Get(recorderSrv.URL + "/auth/logout")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, provider.srv.URL+"/end-session", loc.Scheme+"://"+loc.Host+loc.Path, "logout must redirect to the IdP's end_session_endpoint")
	require.Equal(t, "recorder-client", loc.Query().Get("client_id"))
	require.Equal(t, "http://recorder.example/", loc.Query().Get("post_logout_redirect_uri"))
	require.NotEmpty(t, loc.Query().Get("id_token_hint"), "logout must pass id_token_hint so the IdP can end the right session")
}

func TestLogout_FallsBackToLocalWhenIdPHasNoEndSession(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client") // advertiseEndSession left false
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com"}
	handlers, _ := newTestHandlers(t, provider, nil, false)

	client, recorderSrv := doFullLogin(t, provider, handlers)

	resp, err := client.Get(recorderSrv.URL + "/auth/logout")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "/", resp.Header.Get("Location"))
}

func TestIDTokenCookie_ScopedToAuthPathAndActuallyCleared(t *testing.T) {
	provider := newFakeOIDCProvider(t, "recorder-client")
	provider.nextIdentity = Identity{Subject: "user-123", Email: "user@example.com"}
	handlers, _ := newTestHandlers(t, provider, nil, false)

	client, recorderSrv := doFullLogin(t, provider, handlers)
	jar := client.Jar

	rootURL, err := url.Parse(recorderSrv.URL + "/")
	require.NoError(t, err)
	var sawIDTokenAtRoot bool
	for _, c := range jar.Cookies(rootURL) {
		if c.Name == idTokenCookieName {
			sawIDTokenAtRoot = true
		}
	}
	require.False(t, sawIDTokenAtRoot, "id-token cookie must not be sent on a plain page request outside /auth/")

	authURL, err := url.Parse(recorderSrv.URL + "/auth/logout")
	require.NoError(t, err)
	var sawIDTokenAtAuth bool
	for _, c := range jar.Cookies(authURL) {
		if c.Name == idTokenCookieName {
			sawIDTokenAtAuth = true
		}
	}
	require.True(t, sawIDTokenAtAuth, "id-token cookie must still be present under /auth/ for logout to read it")

	logoutResp, err := client.Get(recorderSrv.URL + "/auth/logout")
	require.NoError(t, err)
	logoutResp.Body.Close()

	var stillHasIDToken bool
	for _, c := range jar.Cookies(authURL) {
		if c.Name == idTokenCookieName {
			stillHasIDToken = true
		}
	}
	require.False(t, stillHasIDToken, "logout must actually clear the id-token cookie, not leave it behind due to a Path mismatch")
}

func TestLogout_ClearsSessionCookie(t *testing.T) {
	sessions, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)
	handlers := NewHandlers(nil, sessions, false)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/auth/logout", nil)
	require.NoError(t, err)
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "logout must clear the session cookie")
}

func TestMe_StandaloneWithoutHandlers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()

	Me(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, false, body["auth_enabled"])
}

func TestMe_ReportsSignedInIdentity(t *testing.T) {
	identity := &Identity{Name: "Test User", Email: "user@example.com", Subject: "sub-123"}
	ctx := context.WithValue(context.Background(), identityContextKey{}, identity)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	Me(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, true, body["auth_enabled"])
	require.Equal(t, "Test User", body["name"])
	require.Equal(t, "user@example.com", body["email"])
	require.Equal(t, "sub-123", body["subject"])
}

func extractStateFromRedirect(t *testing.T, resp *http.Response) string {
	t.Helper()
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)
	return state
}
