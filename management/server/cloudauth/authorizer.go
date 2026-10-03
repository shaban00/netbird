// Package cloudauth decides, on every credential request, whether a peer may
// obtain a federated identity for a cloud role. It evaluates the same
// Policy/Group/PostureCheck data as the network map, but directly from the
// store, since cloud roles have no IP to precompute.
//
// It is the sole authorization point. Provider adapters (cloudidentity) only
// exchange an authorized Decision for a credential.
package cloudauth

import (
	"context"
	"fmt"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const AccessTypeCloudIdentity AccessType = "cloud_identity"

type AccessType string

type Decision struct {
	Allowed     bool
	DenyReason  string
	Role        cloudidentity.ResolvedRole
	PrincipalID string
	RoleName    string
	Provider    string
}

func NewResolvedRole(access *cloudaccesstypes.CloudAccess, role *cloudaccesstypes.CloudRole) cloudidentity.ResolvedRole {
	return cloudidentity.ResolvedRole{
		RoleID:                    role.ID,
		PrincipalRef:              role.PrincipalRef(access.ProviderAccountID, access.Provider),
		CredentialLifetimeSeconds: role.CredentialLifetimeSeconds,
		Provider:                  access.Provider,
		ProviderAccountID:         access.ProviderAccountID,
	}
}

func deny(reason string) (*Decision, error) {
	return &Decision{Allowed: false, DenyReason: reason}, nil
}

func denyResolved(reason, roleName, provider string) (*Decision, error) {
	return &Decision{Allowed: false, DenyReason: reason, RoleName: roleName, Provider: provider}, nil
}

// principalID is the `sub` claim: the owning user's ID for SSO peers, otherwise the peer ID.
func principalID(peer *nbpeer.Peer) string {
	if peer.AddedWithSSOLogin() {
		return peer.UserID
	}
	return peer.ID
}

func anyGroupMatches(groupIDs []string, peerGroups map[string]struct{}) bool {
	for _, id := range groupIDs {
		if _, ok := peerGroups[id]; ok {
			return true
		}
	}
	return false
}

// AuthorizeCloudAccess decides whether a peer may access a cloud role.
// accountID must come from the authenticated peer, never the client, so IDs
// from other tenants can't resolve.
func AuthorizeCloudAccess(ctx context.Context, tx store.Store, accountID, peerID, roleID string, _ AccessType) (*Decision, error) {
	peer, err := tx.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return deny("peer not found")
	}

	role, err := tx.GetCloudRoleByID(ctx, store.LockingStrengthNone, accountID, roleID)
	if err != nil {
		return deny("cloud role not found")
	}
	access, err := tx.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, role.CloudAccessID)
	if err != nil {
		return deny("cloud access connection not found")
	}

	peerGroupIDs, err := tx.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return denyResolved("peer has no group memberships", role.Name, access.Provider)
	}
	peerGroups := make(map[string]struct{}, len(peerGroupIDs))
	for _, id := range peerGroupIDs {
		peerGroups[id] = struct{}{}
	}

	policies, err := tx.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account policies: %w", err)
	}

	for _, policy := range policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if rule.Action != types.PolicyTrafficActionAccept {
				continue
			}
			if rule.DestinationResource.Type != types.ResourceTypeCloudIntegration || rule.DestinationResource.ID != roleID {
				continue
			}
			if !anyGroupMatches(rule.Sources, peerGroups) {
				continue
			}

			ok, err := passesSourcePostureChecks(ctx, tx, accountID, policy.SourcePostureChecks, peer)
			if err != nil {
				return nil, fmt.Errorf("evaluate posture checks: %w", err)
			}
			if !ok {
				continue
			}

			return &Decision{
				Allowed:     true,
				Role:        NewResolvedRole(access, role),
				PrincipalID: principalID(peer),
				RoleName:    role.Name,
				Provider:    access.Provider,
			}, nil
		}
	}

	return denyResolved("no enabled policy grants this peer access to the requested cloud role", role.Name, access.Provider)
}

// ListAuthorizedCloudRoles returns every role the peer is authorized for, using
// AuthorizeCloudAccess's rules. It is for discovery only: issuing credentials
// must still call AuthorizeCloudAccess.
func ListAuthorizedCloudRoles(ctx context.Context, tx store.Store, accountID, peerID string) ([]*cloudaccesstypes.CloudRole, error) {
	peer, err := tx.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, nil
	}

	peerGroupIDs, err := tx.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, nil
	}
	peerGroups := make(map[string]struct{}, len(peerGroupIDs))
	for _, id := range peerGroupIDs {
		peerGroups[id] = struct{}{}
	}

	policies, err := tx.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account policies: %w", err)
	}

	roles, err := tx.GetAccountCloudRoles(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account cloud roles: %w", err)
	}
	access, err := tx.GetAccountCloudAccess(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account cloud access: %w", err)
	}
	validAccessIDs := make(map[string]struct{}, len(access))
	for _, a := range access {
		validAccessIDs[a.ID] = struct{}{}
	}
	rolesByID := make(map[string]*cloudaccesstypes.CloudRole, len(roles))
	for _, r := range roles {
		if _, ok := validAccessIDs[r.CloudAccessID]; !ok {
			continue
		}
		rolesByID[r.ID] = r
	}

	seen := make(map[string]struct{})
	var authorized []*cloudaccesstypes.CloudRole

	for _, policy := range policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if rule.Action != types.PolicyTrafficActionAccept {
				continue
			}
			if rule.DestinationResource.Type != types.ResourceTypeCloudIntegration {
				continue
			}
			roleID := rule.DestinationResource.ID
			if _, already := seen[roleID]; already {
				continue
			}
			role, ok := rolesByID[roleID]
			if !ok {
				continue
			}
			if !anyGroupMatches(rule.Sources, peerGroups) {
				continue
			}
			passes, err := passesSourcePostureChecks(ctx, tx, accountID, policy.SourcePostureChecks, peer)
			if err != nil {
				return nil, fmt.Errorf("evaluate posture checks: %w", err)
			}
			if !passes {
				continue
			}
			seen[roleID] = struct{}{}
			authorized = append(authorized, role)
		}
	}

	return authorized, nil
}

// passesSourcePostureChecks evaluates the policy's source posture checks against the peer,
// using the network map's logic (admitPolicyPeer) so both apply posture identically.
func passesSourcePostureChecks(ctx context.Context, tx store.Store, accountID string, postureCheckIDs []string, peer *nbpeer.Peer) (bool, error) {
	if len(postureCheckIDs) == 0 {
		return true, nil
	}

	checksByID, err := tx.GetPostureChecksByIDs(ctx, store.LockingStrengthNone, accountID, postureCheckIDs)
	if err != nil {
		return false, fmt.Errorf("get posture checks: %w", err)
	}

	twinnedPeer := types.TwinPeer(peer)
	for _, id := range postureCheckIDs {
		pc, ok := checksByID[id]
		if !ok {
			return false, nil
		}
		if !types.TwinPostureChecks(pc).Passes(twinnedPeer) {
			return false, nil
		}
	}
	return true, nil
}
