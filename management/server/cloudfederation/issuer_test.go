package cloudfederation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	issuertypes "github.com/netbirdio/netbird/management/server/cloudfederation/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type inMemoryKeyStore struct {
	store.Store
	keys map[string]*issuertypes.SigningKey
}

func newInMemoryKeyStore(t *testing.T) *inMemoryKeyStore {
	t.Helper()
	return &inMemoryKeyStore{
		Store: store.NewMockStore(gomock.NewController(t)),
		keys:  make(map[string]*issuertypes.SigningKey),
	}
}

func (s *inMemoryKeyStore) GetActiveCloudFederationSigningKey(_ context.Context, _ store.LockingStrength) (*issuertypes.SigningKey, error) {
	for _, k := range s.keys {
		if k.RetireAt == nil {
			cp := *k
			return &cp, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "no active signing key")
}

func (s *inMemoryKeyStore) GetCloudFederationJWKSKeys(_ context.Context) ([]*issuertypes.SigningKey, error) {
	now := time.Now().UTC()
	var out []*issuertypes.SigningKey
	for _, k := range s.keys {
		if k.RetireAt == nil || k.RetireAt.After(now) {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *inMemoryKeyStore) SaveCloudFederationSigningKey(_ context.Context, key *issuertypes.SigningKey) error {
	cp := *key
	s.keys[key.ID] = &cp
	return nil
}

func (s *inMemoryKeyStore) ExecuteInTransaction(_ context.Context, f func(tx store.Store) error) error {
	return f(s)
}

func TestIssueAssertion_ClaimsAndSignatureAndDisabledGate(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: false, IssuerURL: "https://netbird.example.com/federation"})

	_, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
	require.Error(t, err, "issuer must refuse to mint assertions when not explicitly enabled")

	iss = NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	before := time.Now().UTC()
	raw, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	jwks, err := iss.GetJWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	var claims jwt.Claims
	require.NoError(t, parsed.Claims(jwks.Keys[0].Key, &claims))

	assert.Equal(t, "https://netbird.example.com/federation", claims.Issuer, "the iss claim must include the /federation segment — it's where the discovery document is actually mounted, and AWS validates the OIDC provider by fetching {Url}/.well-known/openid-configuration directly")
	assert.Equal(t, "user1", claims.Subject)
	assert.Equal(t, jwt.Audience{"sts.amazonaws.com"}, claims.Audience)
	require.NotNil(t, claims.Expiry)
	require.NotNil(t, claims.IssuedAt)

	lifetime := claims.Expiry.Time().Sub(claims.IssuedAt.Time())
	assert.Equal(t, AssertionLifetime, lifetime, "assertion lifetime must match the documented short-lived window")
	assert.WithinDuration(t, before.Add(AssertionLifetime), claims.Expiry.Time(), 5*time.Second)
	assert.NotEmpty(t, claims.ID, "jti should be set for audit correlation")

}

func TestIssuerIdentity_UsesConfiguredURLVerbatim(t *testing.T) {
	iss := NewIssuer(nil, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})
	assert.Equal(t, "https://netbird.example.com/federation", iss.IssuerIdentity())

	iss = NewIssuer(nil, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation/"})
	assert.Equal(t, "https://netbird.example.com/federation", iss.IssuerIdentity())
}

func TestIssueAssertion_RejectsIssuerURLMissingFederationSuffix(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com"})

	_, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
	require.Error(t, err, "a configured issuer URL missing the /federation suffix must be rejected, not silently fixed up")
	assert.Contains(t, err.Error(), "/federation")
}

func TestIssueAssertion_NeverExposesGroupsOrEmail(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	raw, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]interface{}
	require.NoError(t, parsed.UnsafeClaimsWithoutVerification(&rawClaims))

	for _, forbidden := range []string{"email", "groups", "nb_groups", "name"} {
		_, present := rawClaims[forbidden]
		assert.False(t, present, "assertion must never carry claim %q", forbidden)
	}
}

func TestIssueAssertionWithClaims_EmbedsExtraClaims(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	raw, err := iss.IssueAssertionWithClaims(context.Background(), "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/o", "user1", map[string]string{"netbird_role_id": "role-abc"})
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]interface{}
	require.NoError(t, parsed.UnsafeClaimsWithoutVerification(&rawClaims))

	assert.Equal(t, "role-abc", rawClaims["netbird_role_id"], "the extra claim must be present and carry the exact value passed in")
	assert.Equal(t, "user1", rawClaims["sub"])
	assert.NotEmpty(t, rawClaims["jti"])
}

func TestIssueAssertion_NeverGainsExtraClaims(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	_, err := iss.IssueAssertionWithClaims(context.Background(), "aud1", "user1", map[string]string{"netbird_role_id": "role-abc"})
	require.NoError(t, err)

	raw, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user2")
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var rawClaims map[string]interface{}
	require.NoError(t, parsed.UnsafeClaimsWithoutVerification(&rawClaims))

	_, present := rawClaims["netbird_role_id"]
	assert.False(t, present, "plain IssueAssertion must never carry a claim only IssueAssertionWithClaims callers asked for")
}

func TestGetJWKS_IncludesRetiredKeyDuringOverlapWindow(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation", RotationInterval: time.Millisecond})

	_, err := iss.IssueAssertion(context.Background(), "aud", "user1")
	require.NoError(t, err)
	firstJWKS, err := iss.GetJWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, firstJWKS.Keys, 1)
	firstKeyID := firstJWKS.Keys[0].KeyID

	time.Sleep(2 * time.Millisecond) // ensure rotation interval has elapsed

	raw, err := iss.IssueAssertion(context.Background(), "aud", "user2")
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Headers)
	secondKeyID := parsed.Headers[0].KeyID
	assert.NotEqual(t, firstKeyID, secondKeyID, "rotation must mint a new key")

	jwksAfterRotation, err := iss.GetJWKS(context.Background())
	require.NoError(t, err)
	ids := make([]string, 0, len(jwksAfterRotation.Keys))
	for _, k := range jwksAfterRotation.Keys {
		ids = append(ids, k.KeyID)
	}
	assert.Contains(t, ids, firstKeyID, "retired key must remain published during its overlap window")
	assert.Contains(t, ids, secondKeyID)
}

func TestIssueAssertion_ExpiredAssertionFailsValidation(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	raw, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
	require.NoError(t, err)

	jwks, err := iss.GetJWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims jwt.Claims
	require.NoError(t, parsed.Claims(jwks.Keys[0].Key, &claims))

	require.NoError(t, claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 0))

	wellAfterExpiry := time.Now().Add(AssertionLifetime + 5*time.Minute)
	err = claims.ValidateWithLeeway(jwt.Expected{Time: wellAfterExpiry}, 0)
	require.Error(t, err, "an assertion validated after its lifetime must fail validation")
}

func TestIssueAssertion_ConcurrentFirstUseGeneratesExactlyOneActiveKey(t *testing.T) {
	sqlStore, err := store.NewSqliteStore(context.Background(), t.TempDir(), nil, false)
	require.NoError(t, err)

	iss := NewIssuer(sqlStore, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	const concurrency = 8
	var wg sync.WaitGroup
	errs := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := iss.IssueAssertion(context.Background(), "sts.amazonaws.com", "user1")
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	jwks, err := iss.GetJWKS(context.Background())
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 1, "concurrent first-use must generate exactly one active signing key, not one per racing caller")
}

func TestGetOpenIDConfiguration(t *testing.T) {
	st := newInMemoryKeyStore(t)
	iss := NewIssuer(st, Config{Enabled: true, IssuerURL: "https://netbird.example.com/federation"})

	cfg := iss.GetOpenIDConfiguration()
	assert.Equal(t, "https://netbird.example.com/federation", cfg.Issuer, "the discovery document's issuer field must match the iss claim exactly, including /federation")
	assert.Equal(t, "https://netbird.example.com/federation/keys", cfg.JWKSURI)
	assert.Contains(t, cfg.IDTokenSigningAlgValuesSupported, "RS256")
}
