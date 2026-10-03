package cloudauth

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	"github.com/netbirdio/netbird/management/server/store"
)

type CredentialOutcome struct {
	Allowed    bool
	DenyReason string
	Result     *cloudidentity.ExchangeIdentityResult
}

type CredentialBroker interface {
	RequestCredentials(ctx context.Context, peerPubKey, roleID, expectedProvider string) (*CredentialOutcome, error)
	ListAuthorized(ctx context.Context, peerPubKey string) ([]*cloudaccesstypes.CloudRole, error)
}

type broker struct {
	store          store.Store
	accountManager account.Manager
	providers      map[string]cloudidentity.Provider
}

func NewCredentialBroker(store store.Store, accountManager account.Manager, providers map[string]cloudidentity.Provider) CredentialBroker {
	return &broker{store: store, accountManager: accountManager, providers: providers}
}

func (b *broker) RequestCredentials(ctx context.Context, peerPubKey, roleID, expectedProvider string) (*CredentialOutcome, error) {
	peer, err := b.store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerPubKey)
	if err != nil {
		return &CredentialOutcome{Allowed: false, DenyReason: "peer not recognized"}, nil
	}

	b.accountManager.StoreEvent(ctx, peer.UserID, roleID, peer.AccountID, activity.CloudCredentialRequested, b.bestEffortRoleMeta(ctx, peer.AccountID, roleID))

	decision, err := AuthorizeCloudAccess(ctx, b.store, peer.AccountID, peer.ID, roleID, AccessTypeCloudIdentity)
	if err != nil {
		return nil, fmt.Errorf("authorize cloud access: %w", err)
	}

	resolvedMeta := map[string]any{"integration_id": roleID}
	if decision.RoleName != "" {
		resolvedMeta["name"] = decision.RoleName
	}
	if decision.Provider != "" {
		resolvedMeta["provider"] = decision.Provider
	}
	if !decision.Allowed {
		b.accountManager.StoreEvent(ctx, peer.UserID, roleID, peer.AccountID, activity.CloudAccessDenied, resolvedMeta)
		return &CredentialOutcome{Allowed: false, DenyReason: decision.DenyReason}, nil
	}
	b.accountManager.StoreEvent(ctx, peer.UserID, roleID, peer.AccountID, activity.CloudAccessAllowed, resolvedMeta)

	// Wrong-CLI-for-this-role's-provider mismatch — denied before dispatch.
	if expectedProvider != "" && expectedProvider != decision.Role.Provider {
		log.WithContext(ctx).Warnf("cloud credentials requested for role %s as provider %q but its actual provider is %q", roleID, expectedProvider, decision.Role.Provider)
		return &CredentialOutcome{Allowed: false, DenyReason: "requested provider does not match this role's configured provider"}, nil
	}

	provider, ok := b.providers[decision.Role.Provider]
	if !ok {
		log.WithContext(ctx).Errorf("cloud access allowed for role %s but no provider registered for %q", roleID, decision.Role.Provider)
		return &CredentialOutcome{Allowed: false, DenyReason: "cloud integration is not currently available"}, nil
	}

	exchangeReq := cloudidentity.ExchangeIdentityRequest{
		Role:        decision.Role,
		PrincipalID: decision.PrincipalID,
		PeerID:      peer.ID,
	}

	// Providers implementing cloudidentity.RawAssertionIssuer (e.g. GCP) get the
	// raw assertion. Others, like AWS, use the full ExchangeIdentity below.
	var result *cloudidentity.ExchangeIdentityResult
	if rawIssuer, ok := provider.(cloudidentity.RawAssertionIssuer); ok {
		raw, err := rawIssuer.IssueRawAssertion(ctx, exchangeReq)
		if err != nil {
			log.WithContext(ctx).Warnf("cloud identity raw assertion failed for role %s: %v", roleID, err)
			b.markRoleErrorOnFailedExchange(ctx, peer.AccountID, peer.UserID, roleID, decision.Role.Provider)
			return &CredentialOutcome{Allowed: false, DenyReason: "cloud federation failed"}, nil
		}
		result = &cloudidentity.ExchangeIdentityResult{
			Credentials:      map[string]string{"id_token": raw.Assertion},
			ExpiresAt:        raw.ExpiresAt,
			ProviderIdentity: decision.Role.PrincipalRef,
		}
	} else {
		result, err = provider.ExchangeIdentity(ctx, exchangeReq)
		if err != nil {
			log.WithContext(ctx).Warnf("cloud identity exchange failed for role %s: %v", roleID, err)
			b.markRoleErrorOnFailedExchange(ctx, peer.AccountID, peer.UserID, roleID, decision.Role.Provider)
			return &CredentialOutcome{Allowed: false, DenyReason: "cloud federation failed"}, nil
		}
	}

	b.accountManager.StoreEvent(ctx, peer.UserID, roleID, peer.AccountID, activity.CloudCredentialsIssued, resolvedMeta)
	return &CredentialOutcome{Allowed: true, Result: result}, nil
}

// bestEffortRoleMeta looks up roleID's name and provider to label the CloudCredentialRequested audit event.
func (b *broker) bestEffortRoleMeta(ctx context.Context, accountID, roleID string) map[string]any {
	meta := map[string]any{"integration_id": roleID}
	role, err := b.store.GetCloudRoleByID(ctx, store.LockingStrengthNone, accountID, roleID)
	if err != nil {
		return meta
	}
	access, err := b.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, role.CloudAccessID)
	if err != nil {
		return meta
	}
	meta["name"] = role.Name
	meta["provider"] = access.Provider
	return meta
}

func (b *broker) ListAuthorized(ctx context.Context, peerPubKey string) ([]*cloudaccesstypes.CloudRole, error) {
	peer, err := b.store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerPubKey)
	if err != nil {
		return nil, nil
	}
	return ListAuthorizedCloudRoles(ctx, b.store, peer.AccountID, peer.ID)
}

// markRoleErrorOnFailedExchange marks a role as errored when an authorized provider exchange fails
func (b *broker) markRoleErrorOnFailedExchange(ctx context.Context, accountID, userID, roleID, provider string) {
	role, err := b.store.GetCloudRoleByID(ctx, store.LockingStrengthUpdate, accountID, roleID)
	if err != nil {
		return
	}

	if role.Status == cloudaccesstypes.StatusError {
		return
	}
	role.Status = cloudaccesstypes.StatusError
	role.UpdatedAt = time.Now().UTC()
	if err := b.store.SaveCloudRole(ctx, role); err != nil {
		log.WithContext(ctx).Warnf("mark cloud role %s as error after failed exchange: %v", roleID, err)
		return
	}
	b.accountManager.StoreEvent(ctx, userID, roleID, accountID, activity.CloudRoleValidationFailed, role.EventMeta(provider))
}
