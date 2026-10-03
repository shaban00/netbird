package cloudfederation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	issuertypes "github.com/netbirdio/netbird/management/server/cloudfederation/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// AssertionLifetime is how long a minted federation assertion is valid for.
// The assertion only needs to survive the single STS round trip that consumes it
const AssertionLifetime = 60 * time.Second

// RetirementOverlap is how long a rotated-out key stays in the JWKS. It must
// exceed AssertionLifetime so assertions signed before rotation still verify.
const RetirementOverlap = 10 * time.Minute

// DefaultRotationInterval is the default signing key rotation interval.
const DefaultRotationInterval = 30 * 24 * time.Hour

type Config struct {
	Enabled          bool
	IssuerURL        string
	RotationInterval time.Duration
}

type Issuer struct {
	store  store.Store
	config Config
}

type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func NewIssuer(store store.Store, config Config) *Issuer {
	return &Issuer{store: store, config: config}
}

func (i *Issuer) rotationInterval() time.Duration {
	if i.config.RotationInterval > 0 {
		return i.config.RotationInterval
	}
	return DefaultRotationInterval
}

func (i *Issuer) ensureActiveKey(ctx context.Context) (*issuertypes.SigningKey, *rsa.PrivateKey, error) {
	var resultKey *issuertypes.SigningKey
	var resultPriv *rsa.PrivateKey

	err := i.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		active, err := tx.GetActiveCloudFederationSigningKey(ctx, store.LockingStrengthUpdate)
		switch {
		case err == nil:
			if time.Since(active.CreatedAt) < i.rotationInterval() {
				priv, parseErr := active.ParsePrivateKey()
				if parseErr != nil {
					return fmt.Errorf("parse active signing key: %w", parseErr)
				}
				resultKey, resultPriv = active, priv
				return nil
			}
			retireAt := time.Now().UTC().Add(RetirementOverlap)
			active.RetireAt = &retireAt
			if saveErr := tx.SaveCloudFederationSigningKey(ctx, active); saveErr != nil {
				return fmt.Errorf("retire signing key: %w", saveErr)
			}
		case isNotFound(err):
			// No key has ever been generated — first use.
		default:
			return fmt.Errorf("get active signing key: %w", err)
		}

		fresh, priv, genErr := issuertypes.GenerateSigningKey()
		if genErr != nil {
			return fmt.Errorf("generate signing key: %w", genErr)
		}
		if saveErr := tx.SaveCloudFederationSigningKey(ctx, fresh); saveErr != nil {
			return fmt.Errorf("save new signing key: %w", saveErr)
		}
		resultKey, resultPriv = fresh, priv
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return resultKey, resultPriv, nil
}

func isNotFound(err error) bool {
	var sErr *status.Error
	return errors.As(err, &sErr) && sErr.Type() == status.NotFound
}

func (i *Issuer) IssuerIdentity() string {
	return strings.TrimSuffix(i.config.IssuerURL, "/")
}

func (i *Issuer) IssueAssertion(ctx context.Context, audience, subject string) (string, error) {
	return i.issueAssertion(ctx, audience, subject, nil)
}

func (i *Issuer) IssueAssertionWithClaims(ctx context.Context, audience, subject string, extraClaims map[string]string) (string, error) {
	return i.issueAssertion(ctx, audience, subject, extraClaims)
}

func (i *Issuer) issueAssertion(ctx context.Context, audience, subject string, extraClaims map[string]string) (string, error) {
	if !i.config.Enabled {
		return "", status.Errorf(status.PreconditionFailed, "cloud federation issuer is not enabled")
	}
	if i.config.IssuerURL == "" {
		return "", status.Errorf(status.Internal, "cloud federation issuer URL is not configured")
	}
	if !strings.HasSuffix(i.IssuerIdentity(), "/federation") {
		return "", status.Errorf(status.Internal, "cloud federation issuer URL %q must end in \"/federation\" (e.g. https://netbird.example.com/federation) — that's the only path the discovery and JWKS handlers are mounted at", i.config.IssuerURL)
	}

	key, privKey, err := i.ensureActiveKey(ctx)
	if err != nil {
		return "", fmt.Errorf("ensure active signing key: %w", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID),
	)
	if err != nil {
		return "", fmt.Errorf("construct signer: %w", err)
	}

	now := time.Now().UTC()
	jti, err := randomID()
	if err != nil {
		return "", fmt.Errorf("generate assertion id: %w", err)
	}
	claims := jwt.Claims{
		Issuer:   i.IssuerIdentity(),
		Subject:  subject,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(AssertionLifetime)),
		ID:       jti,
	}

	builder := jwt.Signed(signer).Claims(claims)
	if len(extraClaims) > 0 {
		asInterfaceMap := make(map[string]interface{}, len(extraClaims))
		for k, v := range extraClaims {
			asInterfaceMap[k] = v
		}
		builder = builder.Claims(asInterfaceMap)
	}

	token, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("serialize assertion: %w", err)
	}
	return token, nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (i *Issuer) GetOpenIDConfiguration() OpenIDConfiguration {
	return OpenIDConfiguration{
		Issuer:                           i.IssuerIdentity(),
		JWKSURI:                          i.IssuerIdentity() + "/keys",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
}

func (i *Issuer) GetJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, err := i.store.GetCloudFederationJWKSKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get JWKS keys: %w", err)
	}

	set := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	for _, k := range keys {
		pub, err := k.ParsePublicKey()
		if err != nil {
			return nil, fmt.Errorf("parse public key %s: %w", k.ID, err)
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       pub,
			KeyID:     k.ID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	return set, nil
}
