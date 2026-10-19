package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	GroupsClaim   string
	AllowedGroups []string
}

type OIDCProvider struct {
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config
	cfg      OIDCConfig

	endSessionEndpoint    string
	postLogoutRedirectURI string
}

type discoveryExtra struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider at %s: %w", cfg.Issuer, err)
	}

	var extra discoveryExtra
	if err := provider.Claims(&extra); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	return &OIDCProvider{
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		cfg:                   cfg,
		endSessionEndpoint:    extra.EndSessionEndpoint,
		postLogoutRedirectURI: strings.TrimSuffix(cfg.RedirectURL, "/auth/callback") + "/",
	}, nil
}

func (p *OIDCProvider) AuthCodeURL(state, verifier string) string {
	return p.oauth2.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// Exchange redeems the auth code and returns the verified identity and ID token.
func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier string) (Identity, string, error) {
	token, err := p.oauth2.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, "", fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, "", fmt.Errorf("token response has no id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, "", fmt.Errorf("verify id_token: %w", err)
	}

	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return Identity{}, "", fmt.Errorf("parse id_token claims: %w", err)
	}

	name, _ := raw["name"].(string)
	email := trustedEmail(raw)
	groups := extractGroups(raw, p.cfg.GroupsClaim)

	if !groupsAllowed(groups, p.cfg.AllowedGroups) {
		return Identity{}, "", fmt.Errorf("user's groups do not match the configured allow-list")
	}

	return Identity{Subject: idToken.Subject, Name: name, Email: email, Groups: groups}, rawIDToken, nil
}

func (p *OIDCProvider) EndSessionURL(idTokenHint string) string {
	if p.endSessionEndpoint == "" {
		return ""
	}
	v := url.Values{}
	v.Set("client_id", p.cfg.ClientID)
	v.Set("post_logout_redirect_uri", p.postLogoutRedirectURI)
	if idTokenHint != "" {
		v.Set("id_token_hint", idTokenHint)
	}
	return p.endSessionEndpoint + "?" + v.Encode()
}

func trustedEmail(raw map[string]any) string {
	email, _ := raw["email"].(string)
	if verified, ok := raw["email_verified"].(bool); ok && !verified {
		return ""
	}
	return email
}

// extractGroups reads claimName out of raw ID-token claims as a string slice
func extractGroups(raw map[string]any, claimName string) []string {
	val, ok := raw[claimName]
	if !ok {
		return nil
	}
	items, ok := val.([]any)
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

// groupsAllowed reports whether groups satisfies allowedGroups
func groupsAllowed(groups, allowedGroups []string) bool {
	if len(allowedGroups) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(allowedGroups))
	for _, g := range allowedGroups {
		allowed[g] = struct{}{}
	}
	for _, g := range groups {
		if _, ok := allowed[g]; ok {
			return true
		}
	}
	return false
}
