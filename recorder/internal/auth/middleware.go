package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type identityContextKey struct{}

func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityContextKey{}).(*Identity)
	return id
}

// Middleware gates every request behind a valid session cookie, except /auth/* (the login flow itself) and /api/healthz
func Middleware(sm *SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if sm == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isExemptPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				denyUnauthenticated(w, r)
				return
			}
			identity, err := sm.Validate(cookie.Value)
			if err != nil {
				denyUnauthenticated(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isExemptPath(path string) bool {
	return strings.HasPrefix(path, "/auth/") || path == "/api/healthz"
}

func denyUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
		return
	}

	returnTo := r.URL.Path
	if r.URL.RawQuery != "" {
		returnTo += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
}
