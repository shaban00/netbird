package gcpprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
)

const (
	WorkloadIdentityPoolID                     = "netbird-pool"
	WorkloadIdentityProviderID                 = "netbird-oidc"
	netbirdRoleIDClaim                         = "netbird_role_id"
	gcpAssertionLifetime                       = 60 * time.Second
	stsTokenExchangeURL                        = "https://sts.googleapis.com/v1/token"
	iamCredentialsGenerateAccessTokenURLFormat = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	tokenExchangeGrantType                     = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenExchangeRequestedTokenType            = "urn:ietf:params:oauth:token-type:access_token"
	tokenExchangeSubjectTokenType              = "urn:ietf:params:oauth:token-type:jwt"
	tokenExchangeScope                         = "https://www.googleapis.com/auth/cloud-platform"
)

type AssertionIssuer interface {
	IssueAssertionWithClaims(ctx context.Context, audience, subject string, extraClaims map[string]string) (string, error)
}

type Client interface {
	ExchangeToken(ctx context.Context, audience, assertion string) (federatedToken string, err error)
	GenerateAccessToken(ctx context.Context, federatedToken, serviceAccountEmail string, lifetimeSeconds int64) (accessToken string, expiresAt time.Time, err error)
}

type Provider struct {
	issuer AssertionIssuer
	client Client
}

type httpClient struct {
	http *http.Client
}

type stsTokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type generateAccessTokenRequest struct {
	Scope    []string `json:"scope"`
	Lifetime string   `json:"lifetime"`
}

type generateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

func workloadIdentityPoolProviderResourceName(projectNumber string) string {
	return fmt.Sprintf(
		"//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, WorkloadIdentityPoolID, WorkloadIdentityProviderID,
	)
}

func jwtAudienceClaim(projectNumber string) string {
	return fmt.Sprintf(
		"https://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, WorkloadIdentityPoolID, WorkloadIdentityProviderID,
	)
}

func NewProvider(issuer AssertionIssuer, client Client) *Provider {
	return &Provider{issuer: issuer, client: client}
}

func (p *Provider) Name() string { return cloudaccesstypes.ProviderGCP }

// ExchangeIdentity exchanges a fresh assertion via GCP STS, then impersonates the target service account
func (p *Provider) ExchangeIdentity(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.ExchangeIdentityResult, error) {
	if req.Role.PrincipalRef == "" {
		return nil, fmt.Errorf("exchange identity: service account is required")
	}
	if req.Role.ProviderAccountID == "" {
		return nil, fmt.Errorf("exchange identity: GCP project number is required")
	}
	if req.Role.RoleID == "" {
		return nil, fmt.Errorf("exchange identity: role ID is required")
	}

	assertion, err := p.issuer.IssueAssertionWithClaims(ctx, jwtAudienceClaim(req.Role.ProviderAccountID), req.PrincipalID, map[string]string{netbirdRoleIDClaim: req.Role.RoleID})
	if err != nil {
		return nil, fmt.Errorf("issue federation assertion: %w", err)
	}

	federatedToken, err := p.client.ExchangeToken(ctx, workloadIdentityPoolProviderResourceName(req.Role.ProviderAccountID), assertion)
	if err != nil {
		return nil, fmt.Errorf("GCP STS rejected the assertion: %w", err)
	}

	lifetime := cloudaccesstypes.ClampCredentialLifetime(req.Role.CredentialLifetimeSeconds, cloudaccesstypes.ProviderGCP)
	accessToken, expiresAt, err := p.client.GenerateAccessToken(ctx, federatedToken, req.Role.PrincipalRef, lifetime)
	if err != nil {
		return nil, fmt.Errorf("GCP IAM Credentials rejected the impersonation request: %w", err)
	}

	return &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{
			"AccessToken": accessToken,
			"TokenType":   "Bearer",
		},
		ExpiresAt:        expiresAt,
		ProviderIdentity: req.Role.PrincipalRef,
	}, nil
}

// IssueRawAssertion returns an unexchanged assertion for GCP. The client's
// credential config performs the STS exchange and impersonation itself.
func (p *Provider) IssueRawAssertion(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.RawAssertionResult, error) {
	if req.Role.ProviderAccountID == "" {
		return nil, fmt.Errorf("issue raw assertion: GCP project number is required")
	}
	if req.Role.RoleID == "" {
		return nil, fmt.Errorf("issue raw assertion: role ID is required")
	}

	assertion, err := p.issuer.IssueAssertionWithClaims(ctx, jwtAudienceClaim(req.Role.ProviderAccountID), req.PrincipalID, map[string]string{netbirdRoleIDClaim: req.Role.RoleID})
	if err != nil {
		return nil, fmt.Errorf("issue federation assertion: %w", err)
	}

	return &cloudidentity.RawAssertionResult{
		Assertion: assertion,
		ExpiresAt: time.Now().UTC().Add(gcpAssertionLifetime),
	}, nil
}

// Validate checks the role's trust with a synthetic subject instead of a real peer
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

func NewDefaultClient() Client {
	return &httpClient{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *httpClient) ExchangeToken(ctx context.Context, audience, assertion string) (string, error) {
	form := url.Values{
		"grant_type":           {tokenExchangeGrantType},
		"audience":             {audience},
		"scope":                {tokenExchangeScope},
		"requested_token_type": {tokenExchangeRequestedTokenType},
		"subject_token":        {assertion},
		"subject_token_type":   {tokenExchangeSubjectTokenType},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsTokenExchangeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("call GCP STS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read GCP STS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP STS returned status %d: %s", resp.StatusCode, string(body))
	}

	var out stsTokenExchangeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse GCP STS response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("GCP STS returned no access token")
	}
	return out.AccessToken, nil
}

func (c *httpClient) GenerateAccessToken(ctx context.Context, federatedToken, serviceAccountEmail string, lifetimeSeconds int64) (string, time.Time, error) {
	reqBody, err := json.Marshal(generateAccessTokenRequest{
		Scope:    []string{tokenExchangeScope},
		Lifetime: fmt.Sprintf("%ds", lifetimeSeconds),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build impersonation request: %w", err)
	}

	endpoint := fmt.Sprintf(iamCredentialsGenerateAccessTokenURLFormat, serviceAccountEmail)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build impersonation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+federatedToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("call GCP IAM Credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read GCP IAM Credentials response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("GCP IAM Credentials returned status %d: %s", resp.StatusCode, string(body))
	}

	var out generateAccessTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("parse GCP IAM Credentials response: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("GCP IAM Credentials returned no access token")
	}
	expiresAt, err := time.Parse(time.RFC3339, out.ExpireTime)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse GCP IAM Credentials expiry: %w", err)
	}
	return out.AccessToken, expiresAt, nil
}
