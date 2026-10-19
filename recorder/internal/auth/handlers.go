package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/netbirdio/netbird/shared/ratelimit"
)

const (
	stateCookieName   = "nb_recorder_oauth_state"
	idTokenCookieName = "nb_recorder_id_token"
	stateCookieTTL    = 10 * time.Minute
)

type Handlers struct {
	provider     *OIDCProvider
	sessions     *SessionManager
	cookieSecure bool
	rateLimiter  *ratelimit.APIRateLimiter
}

type statePayload struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"return_to"`
}

func NewHandlers(provider *OIDCProvider, sessions *SessionManager, cookieSecure bool) *Handlers {
	return &Handlers{
		provider:     provider,
		sessions:     sessions,
		cookieSecure: cookieSecure,
		rateLimiter: ratelimit.NewAPIRateLimiter(&ratelimit.RateLimiterConfig{
			RequestsPerMinute: 10,
			Burst:             15,
			CleanupInterval:   5 * time.Minute,
			LimiterTTL:        10 * time.Minute,
		}),
	}
}

// RegisterRoutes adds the OIDC login routes to mux.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.login)
	mux.HandleFunc("GET /auth/callback", h.callback)
	mux.HandleFunc("GET /auth/logout", h.logout)
}

// Me reports "who am I" for the web UI's topbar: {"auth_enabled": false}
func Me(w http.ResponseWriter, r *http.Request) {
	identity := IdentityFromContext(r.Context())
	if identity == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"auth_enabled": false})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth_enabled": true,
		"name":         identity.Name,
		"email":        identity.Email,
		"subject":      identity.Subject,
	})
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	state, err := randomToken()
	if err != nil {
		log.WithError(err).Error("recorder: generate OIDC state")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()

	encoded, err := encodeState(statePayload{State: state, Verifier: verifier, ReturnTo: returnTo})
	if err != nil {
		log.WithError(err).Error("recorder: encode OIDC state cookie")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    encoded,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateCookieTTL.Seconds()),
	})

	http.Redirect(w, r, h.provider.AuthCodeURL(state, verifier), http.StatusFound)
}

func (h *Handlers) callback(w http.ResponseWriter, r *http.Request) {
	if !h.rateLimiter.Allow(clientIP(r)) {
		log.Warn("recorder: OIDC callback rate limit exceeded")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	defer http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: "", Path: "/auth/", MaxAge: -1,
	})

	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "missing or expired login state", http.StatusBadRequest)
		return
	}
	payload, err := decodeState(cookie.Value)
	if err != nil {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != payload.State {
		log.Warn("recorder: OIDC callback state mismatch")
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	identity, rawIDToken, err := h.provider.Exchange(r.Context(), code, payload.Verifier)
	if err != nil {
		log.WithError(err).Warn("recorder: OIDC login failed")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	token, err := h.sessions.Mint(identity)
	if err != nil {
		log.WithError(err).Error("recorder: mint session token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.sessions.Duration().Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     idTokenCookieName,
		Value:    rawIDToken,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.sessions.Duration().Seconds()),
	})

	log.WithField("subject", identity.Subject).Info("recorder: web UI login succeeded")
	http.Redirect(w, r, sanitizeReturnTo(payload.ReturnTo), http.StatusFound)
}

// logout clears the recorder's own session, then — when the IdP supports
// RP-Initiated Logout — also ends the IdP's SSO session
func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	var idTokenHint string
	if cookie, err := r.Cookie(idTokenCookieName); err == nil {
		idTokenHint = cookie.Value
	}

	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: idTokenCookieName, Value: "", Path: "/auth/", MaxAge: -1})

	if h.provider != nil {
		if endSessionURL := h.provider.EndSessionURL(idTokenHint); endSessionURL != "" {
			http.Redirect(w, r, endSessionURL, http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encodeState(p statePayload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeState(s string) (statePayload, error) {
	var p statePayload
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return p, fmt.Errorf("decode state: %w", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("unmarshal state: %w", err)
	}
	return p, nil
}
