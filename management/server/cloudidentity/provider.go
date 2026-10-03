package cloudidentity

import (
	"context"
	"time"
)

type ResolvedRole struct {
	RoleID                    string
	PrincipalRef              string
	CredentialLifetimeSeconds int64
	Provider                  string
	ProviderAccountID         string
}

type ExchangeIdentityRequest struct {
	Role        ResolvedRole
	PrincipalID string
	PeerID      string
}

type ExchangeIdentityResult struct {
	Credentials      map[string]string
	ExpiresAt        time.Time
	ProviderIdentity string
}

type Provider interface {
	Name() string
	ExchangeIdentity(ctx context.Context, req ExchangeIdentityRequest) (*ExchangeIdentityResult, error)
}

type RawAssertionResult struct {
	Assertion string
	ExpiresAt time.Time
}

type RawAssertionIssuer interface {
	IssueRawAssertion(ctx context.Context, req ExchangeIdentityRequest) (*RawAssertionResult, error)
}
