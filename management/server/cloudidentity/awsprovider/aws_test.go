package awsprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
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

type fakeSTS struct {
	lastInput *sts.AssumeRoleWithWebIdentityInput
	output    *sts.AssumeRoleWithWebIdentityOutput
	err       error
}

func (f *fakeIssuer) IssueAssertion(_ context.Context, audience, subject string) (string, error) {
	f.lastAudience = audience
	f.lastSubject = subject
	if f.err != nil {
		return "", f.err
	}
	return f.assertion, nil
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, params *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.lastInput = params
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

func testResolvedRole(lifetimeSeconds int64) cloudidentity.ResolvedRole {
	return cloudidentity.ResolvedRole{
		RoleID:                    "role1",
		PrincipalRef:              "arn:aws:iam::123456789012:role/NetBirdDeveloper",
		CredentialLifetimeSeconds: lifetimeSeconds,
		Provider:                  cloudaccesstypes.ProviderAWS,
	}
}

func successOutput() *sts.AssumeRoleWithWebIdentityOutput {
	expiry := time.Now().Add(15 * time.Minute)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIAFAKE"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      &expiry,
		},
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn: aws.String("arn:aws:sts::123456789012:assumed-role/NetBirdDeveloper/netbird-user1"),
		},
	}
}

func TestExchangeIdentity_UsesOnlyServerDerivedRoleAndSession(t *testing.T) {
	issuer := &fakeIssuer{assertion: "fake.jwt.assertion"}
	stsClient := &fakeSTS{output: successOutput()}
	p := NewProvider(issuer, stsClient)

	result, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
		PeerID:      "peer1",
	})
	require.NoError(t, err)

	assert.Equal(t, Audience, issuer.lastAudience)
	assert.Equal(t, "user1", issuer.lastSubject)

	require.NotNil(t, stsClient.lastInput)
	assert.Equal(t, "arn:aws:iam::123456789012:role/NetBirdDeveloper", aws.ToString(stsClient.lastInput.RoleArn))
	assert.Equal(t, "fake.jwt.assertion", aws.ToString(stsClient.lastInput.WebIdentityToken))
	assert.Contains(t, aws.ToString(stsClient.lastInput.RoleSessionName), "user1")
	assert.EqualValues(t, 900, aws.ToInt32(stsClient.lastInput.DurationSeconds))

	assert.Equal(t, "AKIAFAKE", result.Credentials["AccessKeyId"])
	assert.Equal(t, "secret", result.Credentials["SecretAccessKey"])
	assert.Equal(t, "token", result.Credentials["SessionToken"])
	assert.NotEmpty(t, result.ProviderIdentity)
}

func TestExchangeIdentity_ClampsDurationRegardlessOfStoredValue(t *testing.T) {
	cases := []struct {
		name     string
		stored   int64
		expected int32
	}{
		{"far too low", 1, cloudaccesstypes.MinCredentialLifetimeSecondsAWS},
		{"far too high", 999999, cloudaccesstypes.MaxCredentialLifetimeSeconds},
		{"zero reads as AWS's own floor", 0, cloudaccesstypes.MinCredentialLifetimeSecondsAWS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &fakeIssuer{assertion: "a"}
			stsClient := &fakeSTS{output: successOutput()}
			p := NewProvider(issuer, stsClient)

			_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
				Role:        testResolvedRole(tc.stored),
				PrincipalID: "user1",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, aws.ToInt32(stsClient.lastInput.DurationSeconds))
		})
	}
}

func TestExchangeIdentity_NilCredentialsFailsCleanly(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	stsClient := &fakeSTS{output: &sts.AssumeRoleWithWebIdentityOutput{Credentials: nil}}
	p := NewProvider(issuer, stsClient)

	assert.NotPanics(t, func() {
		_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
			Role:        testResolvedRole(900),
			PrincipalID: "user1",
		})
		require.Error(t, err)
	})
}

func TestExchangeIdentity_PropagatesSTSRejection(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	stsClient := &fakeSTS{err: errors.New("AccessDenied: not authorized to perform sts:AssumeRoleWithWebIdentity")}
	p := NewProvider(issuer, stsClient)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
}

func TestExchangeIdentity_PropagatesIssuerFailure(t *testing.T) {
	issuer := &fakeIssuer{err: errors.New("issuer not enabled")}
	stsClient := &fakeSTS{output: successOutput()}
	p := NewProvider(issuer, stsClient)

	_, err := p.ExchangeIdentity(context.Background(), cloudidentity.ExchangeIdentityRequest{
		Role:        testResolvedRole(900),
		PrincipalID: "user1",
	})
	require.Error(t, err)
	assert.Nil(t, stsClient.lastInput)
}

func TestSessionName_IsAWSLegalAndDerivedFromPrincipal(t *testing.T) {
	name := sessionName("user-ünïcode!@#1")
	assert.LessOrEqual(t, len(name), 64)
	assert.GreaterOrEqual(t, len(name), 2)
	assert.Regexp(t, `^[\w+=,.@-]+$`, name)
}

func TestValidate_ReturnsResolvedIdentityOnSuccess(t *testing.T) {
	issuer := &fakeIssuer{assertion: "a"}
	stsClient := &fakeSTS{output: successOutput()}
	p := NewProvider(issuer, stsClient)

	identity, err := p.Validate(context.Background(), testResolvedRole(900))
	require.NoError(t, err)
	assert.NotEmpty(t, identity)
	assert.Equal(t, "netbird-validation", issuer.lastSubject)
}
