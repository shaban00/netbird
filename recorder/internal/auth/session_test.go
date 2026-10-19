package auth

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigningKey(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
}

func TestSessionManager_MintAndValidate_RoundTrip(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	want := Identity{Subject: "user-123", Email: "user@example.com", Groups: []string{"security-team"}}
	beforeMint := time.Now()
	token, err := sm.Mint(want)
	require.NoError(t, err)

	got, err := sm.Validate(token)
	require.NoError(t, err)

	assert.WithinDuration(t, beforeMint.Add(sm.duration), got.ExpiresAt, 2*time.Second)
	gotWithoutExpiry := *got
	gotWithoutExpiry.ExpiresAt = time.Time{}
	assert.Equal(t, want, gotWithoutExpiry)
}

func TestSessionManager_Validate_RejectsExpired(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	key, err := base64.StdEncoding.DecodeString(testSigningKey(t))
	require.NoError(t, err)

	past := time.Now().Add(-time.Hour)
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    sessionIssuer,
			IssuedAt:  jwt.NewNumericDate(past.Add(-time.Hour)),
			ExpiresAt: jwt.NewNumericDate(past),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = sm.Validate(signed)
	assert.Error(t, err, "an expired session token must be rejected")
}

func TestSessionManager_Validate_RejectsWrongKey(t *testing.T) {
	sm1, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)
	sm2, err := NewSessionManager(base64.StdEncoding.EncodeToString([]byte("different-key-32-bytes-long-xxxx")), time.Hour)
	require.NoError(t, err)

	token, err := sm1.Mint(Identity{Subject: "user-123"})
	require.NoError(t, err)

	_, err = sm2.Validate(token)
	assert.Error(t, err, "a token signed with a different key must be rejected")
}

func TestSessionManager_Validate_RejectsWrongIssuer(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	key, err := base64.StdEncoding.DecodeString(testSigningKey(t))
	require.NoError(t, err)

	now := time.Now()
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "not-the-recorder",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = sm.Validate(signed)
	assert.Error(t, err, "a token with the wrong issuer must be rejected")
}

func TestSessionManager_Validate_RejectsWrongSigningMethod(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), time.Hour)
	require.NoError(t, err)

	now := time.Now()
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    sessionIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = sm.Validate(signed)
	assert.Error(t, err, "alg=none must never be accepted")
}

func TestNewSessionManager_RejectsShortKey(t *testing.T) {
	_, err := NewSessionManager(base64.StdEncoding.EncodeToString([]byte("too-short")), time.Hour)
	assert.Error(t, err)
}

func TestNewSessionManager_DefaultsDuration(t *testing.T) {
	sm, err := NewSessionManager(testSigningKey(t), 0)
	require.NoError(t, err)
	assert.Equal(t, DefaultSessionDuration, sm.Duration())
}
