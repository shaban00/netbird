package azureprovider

import (
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
	Audience = "api://AzureADTokenExchange"
	// defaultScope is Azure Resource Manager's default scope
	defaultScope           = "https://management.azure.com/.default"
	azureAssertionLifetime = 60 * time.Second
	clientAssertionType    = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type AssertionIssuer interface {
	IssueAssertion(ctx context.Context, audience, subject string) (string, error)
}

type TokenClient interface {
	ExchangeToken(ctx context.Context, tenantID, clientID, assertion, scope string) (accessToken string, expiresAt time.Time, err error)
}

type Provider struct {
	issuer AssertionIssuer
	client TokenClient
}

type httpClient struct {
	http *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func NewProvider(issuer AssertionIssuer, client TokenClient) *Provider {
	return &Provider{issuer: issuer, client: client}
}

func subjectForRole(roleID string) string {
	return "netbird-role-" + roleID
}

func (p *Provider) Name() string { return cloudaccesstypes.ProviderAzure }

func (p *Provider) ExchangeIdentity(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.ExchangeIdentityResult, error) {
	accessToken, expiresAt, err := p.exchange(ctx, req)
	if err != nil {
		return nil, err
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

// IssueRawAssertion returns an unexchanged assertion for Azure. The client
// (WorkloadIdentityCredential or az login) exchanges it with Entra itself.
func (p *Provider) IssueRawAssertion(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.RawAssertionResult, error) {
	if req.Role.RoleID == "" {
		return nil, fmt.Errorf("issue raw assertion: role ID is required")
	}

	assertion, err := p.issuer.IssueAssertion(ctx, Audience, subjectForRole(req.Role.RoleID))
	if err != nil {
		return nil, fmt.Errorf("issue federation assertion: %w", err)
	}

	return &cloudidentity.RawAssertionResult{
		Assertion: assertion,
		ExpiresAt: time.Now().UTC().Add(azureAssertionLifetime),
	}, nil
}

// Validate checks the role's trust without a real peer
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

func (p *Provider) exchange(ctx context.Context, req cloudidentity.ExchangeIdentityRequest) (string, time.Time, error) {
	if req.Role.PrincipalRef == "" {
		return "", time.Time{}, fmt.Errorf("exchange identity: application (client) ID is required")
	}
	if req.Role.ProviderAccountID == "" {
		return "", time.Time{}, fmt.Errorf("exchange identity: tenant ID is required")
	}
	if req.Role.RoleID == "" {
		return "", time.Time{}, fmt.Errorf("exchange identity: role ID is required")
	}

	assertion, err := p.issuer.IssueAssertion(ctx, Audience, subjectForRole(req.Role.RoleID))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("issue federation assertion: %w", err)
	}

	accessToken, expiresAt, err := p.client.ExchangeToken(ctx, req.Role.ProviderAccountID, req.Role.PrincipalRef, assertion, defaultScope)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("Microsoft identity platform rejected the assertion: %w", err)
	}
	return accessToken, expiresAt, nil
}

func NewDefaultClient() TokenClient {
	return &httpClient{http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *httpClient) ExchangeToken(ctx context.Context, tenantID, clientID, assertion, scope string) (string, time.Time, error) {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
		"scope":                 {scope},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("call Microsoft identity platform: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("Microsoft identity platform returned status %d: %s", resp.StatusCode, string(body))
	}

	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("parse token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("Microsoft identity platform returned no access token")
	}
	return out.AccessToken, time.Now().UTC().Add(time.Duration(out.ExpiresIn) * time.Second), nil
}
