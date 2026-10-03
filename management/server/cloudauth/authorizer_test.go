package cloudauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID   = "account1"
	testPeerID      = "peer1"
	testUserID      = "user1"
	testAccessID    = "provider1"
	testRoleID      = "role1"
	testOtherRoleID = "role2"
	testGroupID     = "group-developers"
)

func testPeer() *nbpeer.Peer {
	return &nbpeer.Peer{ID: testPeerID, AccountID: testAccountID, UserID: testUserID}
}

func testCloudAccess() *cloudaccesstypes.CloudAccess {
	return &cloudaccesstypes.CloudAccess{
		ID:                testAccessID,
		AccountID:         testAccountID,
		Name:              "Production",
		Provider:          cloudaccesstypes.ProviderAWS,
		ProviderAccountID: "123456789012",
	}
}

func testRole() *cloudaccesstypes.CloudRole {
	return &cloudaccesstypes.CloudRole{
		ID:            testRoleID,
		AccountID:     testAccountID,
		CloudAccessID: testAccessID,
		Name:          "Developer",
		PrincipalName: "NetBirdDeveloper",
	}
}

func allowRule() *types.PolicyRule {
	return &types.PolicyRule{
		ID:      "rule1",
		Enabled: true,
		Action:  types.PolicyTrafficActionAccept,
		Sources: []string{testGroupID},
		DestinationResource: types.Resource{
			ID:   testRoleID,
			Type: types.ResourceTypeCloudIntegration,
		},
	}
}

func setupMocks(t *testing.T) (*gomock.Controller, *store.MockStore) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(testPeer(), nil).AnyTimes()
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).
		Return(testRole(), nil).AnyTimes()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).
		Return(testCloudAccess(), nil).AnyTimes()
	return ctrl, mockStore
}

func TestAuthorizeCloudAccess_Allow(t *testing.T) {
	ctrl, mockStore := setupMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:      "policy1",
			Enabled: true,
			Rules:   []*types.PolicyRule{allowRule()},
		}}, nil)

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, testRoleID, decision.Role.RoleID)
	assert.Equal(t, "arn:aws:iam::123456789012:role/NetBirdDeveloper", decision.Role.PrincipalRef)
	assert.Equal(t, testUserID, decision.PrincipalID)
	assert.Equal(t, "Developer", decision.RoleName)
	assert.Equal(t, cloudaccesstypes.ProviderAWS, decision.Provider)
}

func TestAuthorizeCloudAccess_DenyWhenPeerNotInSourceGroup(t *testing.T) {
	ctrl, mockStore := setupMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{"some-other-group"}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:      "policy1",
			Enabled: true,
			Rules:   []*types.PolicyRule{allowRule()},
		}}, nil)

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Empty(t, decision.Role.PrincipalRef)
	assert.Equal(t, "Developer", decision.RoleName)
	assert.Equal(t, cloudaccesstypes.ProviderAWS, decision.Provider)
}

func TestAuthorizeCloudAccess_DenyScenarios(t *testing.T) {
	tcs := []struct {
		name         string
		mutatePolicy func(*types.Policy)
		mutateRule   func(*types.PolicyRule)
	}{
		{name: "policy disabled", mutatePolicy: func(p *types.Policy) { p.Enabled = false }},
		{name: "rule disabled", mutateRule: func(r *types.PolicyRule) { r.Enabled = false }},
		{name: "rule action is drop", mutateRule: func(r *types.PolicyRule) { r.Action = types.PolicyTrafficActionDrop }},
		{name: "wrong role", mutateRule: func(r *types.PolicyRule) { r.DestinationResource.ID = "some-other-role" }},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, mockStore := setupMocks(t)
			defer ctrl.Finish()

			rule := allowRule()
			if tc.mutateRule != nil {
				tc.mutateRule(rule)
			}
			policy := &types.Policy{ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{rule}}
			if tc.mutatePolicy != nil {
				tc.mutatePolicy(policy)
			}

			mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
				Return([]string{testGroupID}, nil)
			mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
				Return([]*types.Policy{policy}, nil)

			decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
			require.NoError(t, err)
			assert.False(t, decision.Allowed)
		})
	}
}

func TestAuthorizeCloudAccess_CrossTenantRoleNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, "other-tenants-role").
		Return(nil, status.NewCloudRoleNotFoundError("other-tenants-role"))

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, "other-tenants-role", AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Empty(t, decision.Role.PrincipalRef)
	assert.Empty(t, decision.RoleName)
	assert.Empty(t, decision.Provider)
}

func TestAuthorizeCloudAccess_DenyWhenPostureCheckFails(t *testing.T) {
	ctrl, mockStore := setupMocks(t)
	defer ctrl.Finish()

	minVersion := "99.0.0" // peer has no version set, so this never passes
	postureCheck := &posture.Checks{
		ID:        "posture1",
		AccountID: testAccountID,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: minVersion},
		},
	}

	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:                  "policy1",
			Enabled:             true,
			Rules:               []*types.PolicyRule{allowRule()},
			SourcePostureChecks: []string{"posture1"},
		}}, nil)
	mockStore.EXPECT().GetPostureChecksByIDs(gomock.Any(), gomock.Any(), testAccountID, []string{"posture1"}).
		Return(map[string]*posture.Checks{"posture1": postureCheck}, nil)

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestAuthorizeCloudAccess_AllowForSetupKeyPeerFallsBackToPeerID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	setupKeyPeer := &nbpeer.Peer{ID: testPeerID, AccountID: testAccountID, UserID: ""}
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(setupKeyPeer, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).
		Return(testRole(), nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).
		Return(testCloudAccess(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:      "policy1",
			Enabled: true,
			Rules:   []*types.PolicyRule{allowRule()},
		}}, nil)

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, testPeerID, decision.PrincipalID, "must fall back to the peer's own ID, never an empty sub")
}

func TestAuthorizeCloudAccess_DenyWhenPeerDoesNotBelongToAccount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(nil, status.NewPeerNotFoundError(testPeerID))

	decision, err := AuthorizeCloudAccess(context.Background(), mockStore, testAccountID, testPeerID, testRoleID, AccessTypeCloudIdentity)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func testOtherRole() *cloudaccesstypes.CloudRole {
	return &cloudaccesstypes.CloudRole{
		ID:            testOtherRoleID,
		AccountID:     testAccountID,
		CloudAccessID: testAccessID,
		Name:          "Staging",
		PrincipalName: "NetBirdStaging",
	}
}

func TestListAuthorizedCloudRoles_ReturnsOnlyAuthorizedOnes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountCloudRoles(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudRole{testRole(), testOtherRole()}, nil)
	mockStore.EXPECT().GetAccountCloudAccess(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudAccess{testCloudAccess()}, nil)

	otherRule := &types.PolicyRule{
		ID:      "rule2",
		Enabled: true,
		Action:  types.PolicyTrafficActionAccept,
		Sources: []string{"some-other-group"}, // peer is not in this group
		DestinationResource: types.Resource{
			ID:   testOtherRoleID,
			Type: types.ResourceTypeCloudIntegration,
		},
	}
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:      "policy1",
			Enabled: true,
			Rules:   []*types.PolicyRule{allowRule(), otherRule},
		}}, nil)

	authorized, err := ListAuthorizedCloudRoles(context.Background(), mockStore, testAccountID, testPeerID)
	require.NoError(t, err)
	require.Len(t, authorized, 1)
	assert.Equal(t, testRoleID, authorized[0].ID)
}

func TestListAuthorizedCloudRoles_DeduplicatesWhenMultipleRulesMatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountCloudRoles(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudRole{testRole()}, nil)
	mockStore.EXPECT().GetAccountCloudAccess(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudAccess{testCloudAccess()}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{
			{ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()}},
			{ID: "policy2", Enabled: true, Rules: []*types.PolicyRule{allowRule()}},
		}, nil)

	authorized, err := ListAuthorizedCloudRoles(context.Background(), mockStore, testAccountID, testPeerID)
	require.NoError(t, err)
	require.Len(t, authorized, 1, "a role granted by more than one matching rule must appear exactly once")
}

func TestListAuthorizedCloudRoles_ExcludesRoleWhoseParentAccessNoLongerExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountCloudRoles(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudRole{testRole()}, nil)
	mockStore.EXPECT().GetAccountCloudAccess(gomock.Any(), gomock.Any(), testAccountID).
		Return(nil, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{
			{ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()}},
		}, nil)

	authorized, err := ListAuthorizedCloudRoles(context.Background(), mockStore, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Empty(t, authorized, "a role whose parent connection no longer exists must never be listed, even if a policy rule still names it")
}

func TestListAuthorizedCloudRoles_ReturnsRolesForSetupKeyPeer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	setupKeyPeer := &nbpeer.Peer{ID: testPeerID, AccountID: testAccountID, UserID: ""}
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(setupKeyPeer, nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountCloudRoles(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudRole{testRole()}, nil)
	mockStore.EXPECT().GetAccountCloudAccess(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*cloudaccesstypes.CloudAccess{testCloudAccess()}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.Policy{{
			ID:      "policy1",
			Enabled: true,
			Rules:   []*types.PolicyRule{allowRule()},
		}}, nil)

	authorized, err := ListAuthorizedCloudRoles(context.Background(), mockStore, testAccountID, testPeerID)
	require.NoError(t, err)
	require.Len(t, authorized, 1)
	assert.Equal(t, testRoleID, authorized[0].ID)
}

func TestListAuthorizedCloudRoles_EmptyWhenPeerNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).
		Return(nil, status.NewPeerNotFoundError(testPeerID))

	authorized, err := ListAuthorizedCloudRoles(context.Background(), mockStore, testAccountID, testPeerID)
	require.NoError(t, err, "an unrecognized peer must read as an empty list, not an error")
	assert.Empty(t, authorized)
}
