package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	sessionIssuer          = "netbird-recorder"
	SessionCookieName      = "nb_recorder_session"
	DefaultSessionDuration = 12 * time.Hour
)

type Identity struct {
	Subject   string
	Name      string
	Email     string
	Groups    []string
	ExpiresAt time.Time
}

type sessionClaims struct {
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
	jwt.RegisteredClaims
}

type SessionManager struct {
	key      []byte
	duration time.Duration
}

// NewSessionManager builds a SessionManager from a base64 signing key
// (like --encryption-key). Key must be at least 32 bytes for HS256.
func NewSessionManager(base64Key string, duration time.Duration) (*SessionManager, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode session signing key: %w", err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("session signing key must be at least 32 bytes, got %d", len(key))
	}
	if duration <= 0 {
		duration = DefaultSessionDuration
	}
	return &SessionManager{key: key, duration: duration}, nil
}

func (sm *SessionManager) Duration() time.Duration {
	return sm.duration
}

// Mint signs a new session JWT for identity, valid for sm.Duration().
func (sm *SessionManager) Mint(identity Identity) (string, error) {
	now := time.Now()
	claims := sessionClaims{
		Name:   identity.Name,
		Email:  identity.Email,
		Groups: identity.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   identity.Subject,
			Issuer:    sessionIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sm.duration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sm.key)
	if err != nil {
		return "", fmt.Errorf("sign session token: %w", err)
	}
	return signed, nil
}

// Validate verifies a session JWT, rejecting a bad signature, wrong
// method or issuer, or missing/expired exp.
func (sm *SessionManager) Validate(tokenString string) (*Identity, error) {
	var claims sessionClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return sm.key, nil
	}, jwt.WithIssuer(sessionIssuer), jwt.WithExpirationRequired(), jwt.WithStrictDecoding())
	if err != nil {
		return nil, fmt.Errorf("parse session token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid session token")
	}
	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	return &Identity{Subject: claims.Subject, Name: claims.Name, Email: claims.Email, Groups: claims.Groups, ExpiresAt: expiresAt}, nil
}
