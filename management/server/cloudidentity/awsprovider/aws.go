package awsprovider

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
)

const Audience = "sts.amazonaws.com"

var disallowedSessionNameChars = regexp.MustCompile(`[^\w+=,.@-]`)

type AssertionIssuer interface {
	IssueAssertion(ctx context.Context, audience, subject string) (string, error)
}

type STSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type Provider struct {
	issuer AssertionIssuer
	sts    STSClient
}

func NewProvider(issuer AssertionIssuer, stsClient STSClient) *Provider {
	return &Provider{issuer: issuer, sts: stsClient}
}

func NewDefaultSTSClient(region string) STSClient {
	if region == "" {
		region = "us-east-1"
	}
	return sts.New(sts.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	})
}

func (p *Provider) Name() string { return cloudaccesstypes.ProviderAWS }

// ExchangeIdentity exchanges a fresh assertion for AWS credentials via AssumeRoleWithWebIdentity
func (p *Provider) ExchangeIdentity(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.ExchangeIdentityResult, error) {
	if req.Role.PrincipalRef == "" {
		return nil, fmt.Errorf("exchange identity: role is required")
	}

	assertion, err := p.issuer.IssueAssertion(ctx, Audience, req.PrincipalID)
	if err != nil {
		return nil, fmt.Errorf("issue federation assertion: %w", err)
	}

	duration := int32(cloudaccesstypes.ClampCredentialLifetime(req.Role.CredentialLifetimeSeconds, cloudaccesstypes.ProviderAWS))
	out, err := p.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(req.Role.PrincipalRef),
		RoleSessionName:  aws.String(sessionName(req.PrincipalID)),
		WebIdentityToken: aws.String(assertion),
		DurationSeconds:  aws.Int32(duration),
	})
	if err != nil {
		return nil, fmt.Errorf("AWS STS rejected the assertion: %w", err)
	}

	if out.Credentials == nil {
		return nil, fmt.Errorf("AWS STS returned no credentials")
	}
	creds := out.Credentials
	var assumedArn string
	if out.AssumedRoleUser != nil {
		assumedArn = aws.ToString(out.AssumedRoleUser.Arn)
	}

	return &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{
			"AccessKeyId":     aws.ToString(creds.AccessKeyId),
			"SecretAccessKey": aws.ToString(creds.SecretAccessKey),
			"SessionToken":    aws.ToString(creds.SessionToken),
		},
		ExpiresAt:        aws.ToTime(creds.Expiration),
		ProviderIdentity: assumedArn,
	}, nil
}

// Validate checks the role's trust with an exchange that uses a fixed
// synthetic subject instead of a real peer.
func (p *Provider) Validate(ctx context.Context, role cloudidentity.ResolvedRole) (string, error) {
	result, err := p.ExchangeIdentity(ctx, cloudidentity.ExchangeIdentityRequest{
		Role:        role,
		PrincipalID: "netbird-validation",
	})
	if err != nil {
		return "", err
	}
	return result.ProviderIdentity, nil
}

func sessionName(principalID string) string {
	name := disallowedSessionNameChars.ReplaceAllString("netbird-"+principalID, "-")
	if len(name) > 64 {
		name = name[:64]
	}
	if len(name) < 2 {
		name = name + time.Now().UTC().Format("0102150405")
	}
	return name
}
