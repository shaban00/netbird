package azureprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
)

type fakeIssuer struct {
	lastAudience string
	lastSubject  string
	assertion    string
	err          error
}

type fakeClient struct {
	lastTenantID  string
	lastClientID  string
	lastAssertion string
	lastScope     string
	err           error
	accessToken   string
	expiresAt     time.Time
	calls         int
}

func (f *fakeIssuer) IssueAssertion(_ context.Context, audience, subject string) (string, error) {
	f.lastAudience = audience
	f.lastSubject = subject
	if f.err != nil {
		return "", f.err
	}
	return f.assertion, nil
}

func (f *fakeClient) ExchangeToken(_ context.Context, tenantID, clientID, assertion, scope string) (string, time.Time, error) {
	f.calls++
	f.lastTenantID = tenantID
	f.lastClientID = clientID
	f.lastAssertion = assertion
	f.lastScope = scope
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.accessToken, f.expiresAt, nil
}

func testResolvedRole(lifetimeSeconds int64) cloudidentity.ResolvedRole {
	return cloudidentity.ResolvedRole{
		RoleID:                    "role1",
		PrincipalRef:              "11111111-1111-1111-1111-111111111111",
		CredentialLifetimeSeconds: lifetimeSeconds,
		Provider:                  cloudaccesstypes.ProviderAzure,
		ProviderAccountID:         "22222222-2222-2222-2222-222222222222",
	}
}

func successClient() *fakeClient {
	return &fakeClient{
		accessToken: "fake-access-token",
		expiresAt:   time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

func TestExchangeIdentity_UsesServerDerivedTenantAndClientID(t *testing.T) {
	issuer := &fakeIssuer{assertion: "fake.jwt.assertion"}
	client := successClient()
	p := NewProvider(issuer, client)

	result, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
		PeerID:      "peer1",
	})
	require.NoError(t, err)

	assert.Equal(t, Audience, issuer.lastAudience)
	assert.Equal(t, "netbird-role-role1", issuer.lastSubject, "the subject must be deterministic from the role's own ID, never the requesting user — Azure's Federated Credential is configured before any request happens")

	assert.Equal(t, "22222222-2222-2222-2222-222222222222", client.lastTenantID)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", client.lastClientID)
	assert.Equal(t, "fake.jwt.assertion", client.lastAssertion)
	assert.Equal(t, defaultScope, client.lastScope)

	assert.Equal(t, "fake-access-token", result.Credentials["AccessToken"])
	assert.Equal(t, "Bearer", result.Credentials["TokenType"])
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", result.ProviderIdentity)
	assert.WithinDuration(t, client.expiresAt, result.ExpiresAt, time.Second)
}

func TestExchangeIdentity_IgnoresCredentialLifetimeSeconds(t *testing.T) {
	for _, lifetime := range []int64{0, 1, 900, 999999} {
		issuer := &fakeIssuer{assertion: "a"}
		client := successClient()
		p := NewProvider(issuer, client)

		_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
			Role:        testResolvedRole(lifetime),
			PrincipalID: "user1",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, client.calls, "the exchange must happen the same way regardless of CredentialLifetimeSeconds")
	}
}

func TestExchangeIdentity_RejectsMissingRequiredField(t *testing.T) {
	cases := []struct {
		name  string
		blank func(*cloudidentity.ResolvedRole)
	}{
		{"empty PrincipalRef", func(r *cloudidentity.ResolvedRole) { r.PrincipalRef = "" }},
		{"empty ProviderAccountID", func(r *cloudidentity.ResolvedRole) { r.ProviderAccountID = "" }},
		{"empty RoleID", func(r *cloudidentity.ResolvedRole) { r.RoleID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakeIssuer{assertion: "a"}
			client := successClient()
			p := NewProvider(issuer, client)

			role := testResolvedRole(900)
			tc.blank(&role)

			_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
				Role:        role,
				PrincipalID: "user1",
			})
			require.Error(t, err)
			assert.Zero(t, client.calls, "the issuer/client must never be called when a required field is missing — the subject would no longer be deterministic")
		})
	}
}

func TestExchangeIdentity_DifferentRolesProduceDifferentSubjects(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	p := NewProvider(issuer, client)

	roleA := testResolvedRole(900)
	roleA.RoleID = "role-a"
	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{Role: roleA, PrincipalID: "user1"})
	require.NoError(t, err)
	subjectA := issuer.lastSubject

	roleB := testResolvedRole(900)
	roleB.RoleID = "role-b"
	_, err = p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{Role: roleB, PrincipalID: "user1"})
	require.NoError(t, err)
	subjectB := issuer.lastSubject

	assert.Equal(t, "netbird-role-role-a", subjectA)
	assert.Equal(t, "netbird-role-role-b", subjectB)
	assert.NotEqual(t, subjectA, subjectB)
}

func TestExchangeIdentity_PropagatesIssuerFailure(t *testing.T) {
	issuer := &fakeIssuer{err: errors.New("issuer not enabled")}
	client := successClient()
	p := NewProvider(issuer, client)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.Zero(t, client.calls, "Microsoft's token endpoint must never be called if minting the assertion failed")
}

func TestExchangeIdentity_PropagatesTokenExchangeRejection(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	client.err = errors.New("invalid_client: AADSTS700213 no matching federated identity record found")
	p := NewProvider(issuer, client)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
}

func TestExchangeIdentity_ErrorsNeverContainSecretMaterial(t *testing.T) {
	issuer := &fakeIssuer{assertion: "super-secret-assertion-value"}
	client := successClient()
	client.err = errors.New("denied")
	p := NewProvider(issuer, client)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-assertion-value")
}

func TestValidate_ReturnsResolvedIdentityOnSuccess(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	p := NewProvider(issuer, client)

	identity, err := p.Validate(context.Background(), testResolvedRole(900))
	require.NoError(t, err)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", identity)
	assert.Equal(t, "netbird-role-role1", issuer.lastSubject)
}

func TestIssueRawAssertion_ReturnsAssertionWithoutCallingMicrosoft(t *testing.T) {
	issuer := &fakeIssuer{assertion: "fake.jwt.assertion"}
	client := successClient()
	p := NewProvider(issuer, client)

	result, err := p.IssueRawAssertion(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.NoError(t, err)
	assert.Equal(t, "fake.jwt.assertion", result.Assertion)
	assert.WithinDuration(t, time.Now().UTC().Add(azureAssertionLifetime), result.ExpiresAt, 2*time.Second)

	assert.Equal(t, Audience, issuer.lastAudience)
	assert.Equal(t, "netbird-role-role1", issuer.lastSubject)

	assert.Zero(t, client.calls, "the raw-assertion path must never call Microsoft's token endpoint")
}

func TestIssueRawAssertion_RejectsEmptyRoleID(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	p := NewProvider(issuer, client)

	role := testResolvedRole(900)
	role.RoleID = ""

	_, err := p.IssueRawAssertion(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        role,
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.Empty(t, issuer.lastAudience, "the issuer must never be called with a missing role ID")
}

func TestIssueRawAssertion_PropagatesIssuerFailure(t *testing.T) {
	issuer := &fakeIssuer{err: errors.New("issuer not enabled")}
	client := successClient()
	p := NewProvider(issuer, client)

	_, err := p.IssueRawAssertion(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
}

func TestSubjectForRole_DeterministicFromRoleIDAlone(t *testing.T) {
	assert.Equal(t, "netbird-role-abc123", subjectForRole("abc123"))
	assert.Equal(t, subjectForRole("abc123"), subjectForRole("abc123"))
	assert.NotEqual(t, subjectForRole("abc123"), subjectForRole("xyz789"))
}
