package gcpprovider

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
	lastAudience    string
	lastSubject     string
	lastExtraClaims map[string]string
	assertion       string
	err             error
}

type fakeClient struct {
	lastExchangeAudience  string
	lastExchangeAssertion string
	exchangeErr           error
	federatedToken        string

	lastGenerateFederatedToken string
	lastGenerateEmail          string
	lastGenerateLifetime       int64
	generateErr                error
	accessToken                string
	expiresAt                  time.Time
}

func (f *fakeIssuer) IssueAssertionWithClaims(_ context.Context, audience, subject string, extraClaims map[string]string) (string, error) {
	f.lastAudience = audience
	f.lastSubject = subject
	f.lastExtraClaims = extraClaims
	if f.err != nil {
		return "", f.err
	}
	return f.assertion, nil
}

func (f *fakeClient) ExchangeToken(_ context.Context, audience, assertion string) (string, error) {
	f.lastExchangeAudience = audience
	f.lastExchangeAssertion = assertion
	if f.exchangeErr != nil {
		return "", f.exchangeErr
	}
	return f.federatedToken, nil
}

func (f *fakeClient) GenerateAccessToken(_ context.Context, federatedToken, serviceAccountEmail string, lifetimeSeconds int64) (string, time.Time, error) {
	f.lastGenerateFederatedToken = federatedToken
	f.lastGenerateEmail = serviceAccountEmail
	f.lastGenerateLifetime = lifetimeSeconds
	if f.generateErr != nil {
		return "", time.Time{}, f.generateErr
	}
	return f.accessToken, f.expiresAt, nil
}

func testResolvedRole(lifetimeSeconds int64) cloudidentity.ResolvedRole {
	return cloudidentity.ResolvedRole{
		RoleID:                    "role1",
		PrincipalRef:              "netbird-developer@my-project-123.iam.gserviceaccount.com",
		CredentialLifetimeSeconds: lifetimeSeconds,
		Provider:                  cloudaccesstypes.ProviderGCP,
		ProviderAccountID:         "123456789012",
	}
}

func successClient() *fakeClient {
	return &fakeClient{
		federatedToken: "fake-federated-token",
		accessToken:    "fake-access-token",
		expiresAt:      time.Now().Add(15 * time.Minute).Truncate(time.Second),
	}
}

func TestExchangeIdentity_UsesOnlyServerDerivedPrincipalAndProject(t *testing.T) {
	issuer := &fakeIssuer{assertion: "fake.jwt.assertion"}
	client := successClient()
	p := NewProvider(issuer, client)

	result, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
		PeerID:      "peer1",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", issuer.lastAudience)
	assert.Equal(t, "user1", issuer.lastSubject)
	assert.Equal(t, "role1", issuer.lastExtraClaims[netbirdRoleIDClaim], "the assertion must carry this exact role's ID, so the deploy script's per-role IAM binding (see gcpdeployscript.go) can actually scope impersonation to it")

	assert.Equal(t, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", client.lastExchangeAudience)
	assert.Equal(t, "fake.jwt.assertion", client.lastExchangeAssertion)

	assert.Equal(t, "fake-federated-token", client.lastGenerateFederatedToken)
	assert.Equal(t, "netbird-developer@my-project-123.iam.gserviceaccount.com", client.lastGenerateEmail)
	assert.EqualValues(t, 900, client.lastGenerateLifetime)

	assert.Equal(t, "fake-access-token", result.Credentials["AccessToken"])
	assert.Equal(t, "Bearer", result.Credentials["TokenType"])
	assert.Equal(t, "netbird-developer@my-project-123.iam.gserviceaccount.com", result.ProviderIdentity)
	assert.WithinDuration(t, client.expiresAt, result.ExpiresAt, time.Second)
}

func TestExchangeIdentity_ClampsLifetimeRegardlessOfStoredValue(t *testing.T) {
	cases := []struct {
		name     string
		stored   int64
		expected int64
	}{
		{"far too low", 1, cloudaccesstypes.MinCredentialLifetimeSecondsGCP},
		{"far too high", 999999, cloudaccesstypes.MaxCredentialLifetimeSeconds},
		{"zero reads as GCP's own floor", 0, cloudaccesstypes.MinCredentialLifetimeSecondsGCP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakeIssuer{assertion: "a"}
			client := successClient()
			p := NewProvider(issuer, client)

			_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
				Role:        testResolvedRole(tc.stored),
				PrincipalID: "user1",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, client.lastGenerateLifetime)
		})
	}
}

func TestExchangeIdentity_RejectsMissingRequiredField(t *testing.T) {
	cases := []struct {
		name  string
		blank func(*cloudidentity.ResolvedRole)
	}{
		{"empty PrincipalRef", func(r *cloudidentity.ResolvedRole) { r.PrincipalRef = "" }},
		{"empty RoleID", func(r *cloudidentity.ResolvedRole) { r.RoleID = "" }},
		{"empty ProviderAccountID", func(r *cloudidentity.ResolvedRole) { r.ProviderAccountID = "" }},
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
			assert.Empty(t, client.lastExchangeAudience, "the issuer must never be called when a required field is missing — an unscoped claim would defeat the per-role IAM binding")
		})
	}
}

func TestExchangeIdentity_DifferentRolesProduceDifferentRoleIDClaims(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	p := NewProvider(issuer, client)

	roleA := testResolvedRole(900)
	roleA.RoleID = "role-a"
	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{Role: roleA, PrincipalID: "user1"})
	require.NoError(t, err)
	claimA := issuer.lastExtraClaims[netbirdRoleIDClaim]

	roleB := testResolvedRole(900)
	roleB.RoleID = "role-b"
	_, err = p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{Role: roleB, PrincipalID: "user1"})
	require.NoError(t, err)
	claimB := issuer.lastExtraClaims[netbirdRoleIDClaim]

	assert.Equal(t, "role-a", claimA)
	assert.Equal(t, "role-b", claimB)
	assert.NotEqual(t, claimA, claimB, "an assertion minted for role A must not carry role B's ID, or the two would be interchangeable for impersonation")
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
	assert.Empty(t, client.lastExchangeAudience, "STS must never be called if minting the assertion failed")
}

func TestExchangeIdentity_PropagatesTokenExchangeRejection(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	client.exchangeErr = errors.New("invalid_target: audience not configured on this provider")
	p := NewProvider(issuer, client)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.Empty(t, client.lastGenerateEmail, "impersonation must never be attempted if the token exchange failed")
}

func TestExchangeIdentity_PropagatesImpersonationRejection(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	client.generateErr = errors.New("PERMISSION_DENIED: caller is not authorized to impersonate this service account")
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
	client.generateErr = errors.New("denied")
	p := NewProvider(issuer, client)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-assertion-value")
	assert.NotContains(t, err.Error(), "fake-federated-token")
}

func TestValidate_ReturnsResolvedIdentityOnSuccess(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	client := successClient()
	p := NewProvider(issuer, client)

	identity, err := p.Validate(context.Background(), testResolvedRole(900))
	require.NoError(t, err)
	assert.Equal(t, "netbird-developer@my-project-123.iam.gserviceaccount.com", identity)
	assert.Equal(t, "netbird-validation", issuer.lastSubject)
}

func TestIssueRawAssertion_ReturnsAssertionWithoutCallingGCP(t *testing.T) {
	issuer := &fakeIssuer{assertion: "fake.jwt.assertion"}
	client := successClient()
	p := NewProvider(issuer, client)

	result, err := p.IssueRawAssertion(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.NoError(t, err)
	assert.Equal(t, "fake.jwt.assertion", result.Assertion)
	assert.WithinDuration(t, time.Now().UTC().Add(gcpAssertionLifetime), result.ExpiresAt, 2*time.Second)

	assert.Equal(t, "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", issuer.lastAudience)
	assert.Equal(t, "user1", issuer.lastSubject)
	assert.Equal(t, "role1", issuer.lastExtraClaims[netbirdRoleIDClaim])

	assert.Empty(t, client.lastExchangeAudience, "the raw-assertion path must never call GCP's STS or IAM Credentials APIs")
	assert.Empty(t, client.lastGenerateEmail, "the raw-assertion path must never call GCP's STS or IAM Credentials APIs")
}

func TestIssueRawAssertion_RejectsMissingRequiredField(t *testing.T) {
	cases := []struct {
		name  string
		blank func(*cloudidentity.ResolvedRole)
	}{
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

			_, err := p.IssueRawAssertion(context.Background(), cloudidentity.ExchangeIdentityRequest{
				Role:        role,
				PrincipalID: "user1",
			})
			require.Error(t, err)
			assert.Empty(t, issuer.lastAudience, "the issuer must never be called when a required field is missing")
		})
	}
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

func TestWorkloadIdentityPoolProviderResourceName_UsesBareForm(t *testing.T) {
	got := workloadIdentityPoolProviderResourceName("123456789012")
	assert.Equal(t, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", got)
}

func TestJWTAudienceClaim_UsesHTTPSForm(t *testing.T) {
	got := jwtAudienceClaim("123456789012")
	assert.Equal(t, "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", got)
	assert.NotEqual(t, workloadIdentityPoolProviderResourceName("123456789012"), got, "the JWT aud claim and the STS audience parameter must be genuinely different strings")
}
