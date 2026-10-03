package cloudaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	servertypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const testAccountID = "account1"
const testUserID = "user1"

type permMockManager struct {
	*permissions.MockManager
}

type fakeValidator struct {
	identity string
	err      error
}

func (f *fakeValidator) Validate(_ context.Context, _ cloudidentity.ResolvedRole) (string, error) {
	return f.identity, f.err
}

func policiesReferencing(roleID string) []*servertypes.Policy {
	return []*servertypes.Policy{{
		ID:      "policy1",
		Name:    "Developers to Production",
		Enabled: true,
		Rules: []*servertypes.PolicyRule{{
			Enabled:             true,
			DestinationResource: servertypes.Resource{ID: roleID, Type: servertypes.ResourceTypeCloudIntegration},
		}},
	}}
}

func newPermMockManager(t *testing.T, ctrl *gomock.Controller) *permMockManager {
	t.Helper()
	return &permMockManager{MockManager: permissions.NewMockManager(ctrl)}
}

func (p *permMockManager) expectValidate(accountID, userID string, module modules.Module, op operations.Operation, allowed bool, err error) {
	p.EXPECT().
		ValidateUserPermissions(gomock.Any(), accountID, userID, module, op).
		Return(allowed, context.Background(), err)
}

func testValidCloudAccess() *types.CloudAccess {
	a := types.NewCloudAccess(testAccountID)
	a.Name = "Production"
	a.Provider = types.ProviderAWS
	a.ProviderAccountID = "123456789012"
	return a
}

func testValidRole(providerID string) *types.CloudRole {
	r := types.NewCloudRole(testAccountID, providerID)
	r.Name = "Developer"
	r.PrincipalName = "NetBirdDeveloper"
	return r
}

func newTestAccessManager(t *testing.T) (*accessManagerImpl, *store.MockStore, *permMockManager, *account.MockManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockPerms := newPermMockManager(t, ctrl)
	mockAccount := account.NewMockManager(ctrl)
	mgr := &accessManagerImpl{
		store:               mockStore,
		accountManager:      mockAccount,
		permissionsManager:  mockPerms,
		federationEnabled:   true,
		federationIssuerURL: "https://netbird.example.com/federation",
	}
	mockStore.EXPECT().
		ExecuteInTransaction(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f func(store.Store) error) error {
			return f(mockStore)
		}).
		AnyTimes()
	return mgr, mockStore, mockPerms, mockAccount
}

func newTestRoleManager(t *testing.T) (*roleManagerImpl, *store.MockStore, *permMockManager, *account.MockManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockPerms := newPermMockManager(t, ctrl)
	mockAccount := account.NewMockManager(ctrl)
	mgr := &roleManagerImpl{
		store:               mockStore,
		accountManager:      mockAccount,
		permissionsManager:  mockPerms,
		validators:          map[string]Validator{},
		federationEnabled:   true,
		federationIssuerURL: "https://netbird.example.com/federation",
	}
	mockStore.EXPECT().
		ExecuteInTransaction(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f func(store.Store) error) error {
			return f(mockStore)
		}).
		AnyTimes()
	return mgr, mockStore, mockPerms, mockAccount
}

func TestCreateCloudAccess_DeniesWithoutPermission(t *testing.T) {
	mgr, _, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, false, nil)

	_, err := mgr.CreateCloudAccess(context.Background(), testUserID, testValidCloudAccess())
	require.Error(t, err)
}

func TestCreateCloudAccess_RejectsUnsupportedProvider(t *testing.T) {
	mgr, _, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	p := testValidCloudAccess()
	p.Provider = "digitalocean"
	_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
	require.Error(t, err)
}

func TestCreateCloudAccess_RejectsInvalidAccountID(t *testing.T) {
	mgr, _, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	p := testValidCloudAccess()
	p.ProviderAccountID = "not-12-digits"
	_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
	require.Error(t, err)
}

func TestCreateCloudAccess_RejectsInvalidGCPProjectNumber(t *testing.T) {
	cases := []string{"", "0123", "abc123", "-123", "0", "12345", "1234567890123"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, _, perms, _ := newTestAccessManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

			p := testValidCloudAccess()
			p.Provider = types.ProviderGCP
			p.ProviderAccountID = id
			_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
			require.Error(t, err)
		})
	}
}

func TestCreateCloudAccess_AcceptsValidGCPProjectNumber(t *testing.T) {
	cases := []string{"123456", "123456789012"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)
			mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
			mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

			p := testValidCloudAccess()
			p.Provider = types.ProviderGCP
			p.ProviderAccountID = id
			p.ProviderProjectID = "my-project-123"
			_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
			require.NoError(t, err)
		})
	}
}

func TestCreateCloudAccess_RejectsMissingOrInvalidGCPProjectID(t *testing.T) {
	cases := []string{"", "My-Project-123", "1project", "-project", "project-", "abcde", "a" + strings.Repeat("b", 29) + "c"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, _, perms, _ := newTestAccessManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

			p := testValidCloudAccess()
			p.Provider = types.ProviderGCP
			p.ProviderAccountID = "123456789012"
			p.ProviderProjectID = id
			_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
			require.Error(t, err)
		})
	}
}

func TestCreateCloudAccess_ClearsGCPProjectIDForAWS(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)
	mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	p := testValidCloudAccess()
	p.ProviderProjectID = "my-project-123"
	created, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
	require.NoError(t, err)
	assert.Empty(t, created.ProviderProjectID)
}

func TestCreateCloudAccess_AcceptsGCPProjectIDBoundaryLengths(t *testing.T) {
	cases := []string{"abcdef", "a" + strings.Repeat("b", 28) + "c"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)
			mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
			mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

			p := testValidCloudAccess()
			p.Provider = types.ProviderGCP
			p.ProviderAccountID = "123456789012"
			p.ProviderProjectID = id
			_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
			require.NoError(t, err)
		})
	}
}

func TestUpdateCloudAccess_RejectsInvalidGCPProjectID(t *testing.T) {
	mgr, mockStore, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	existing := testValidCloudAccess()
	existing.Provider = types.ProviderGCP
	existing.ProviderAccountID = "123456789012"
	existing.ProviderProjectID = "my-project-123"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)

	update := testValidCloudAccess()
	update.ID = existing.ID
	update.Provider = types.ProviderGCP
	update.ProviderAccountID = "123456789012"
	update.ProviderProjectID = "My-Invalid-Project"

	_, err := mgr.UpdateCloudAccess(context.Background(), testUserID, update)
	require.Error(t, err)
}

func TestUpdateCloudAccess_ClearsGCPProjectIDForAWS(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	existing := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)

	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, existing.ID, testAccountID, gomock.Any(), gomock.Any())

	update := testValidCloudAccess()
	update.ID = existing.ID
	update.ProviderProjectID = "my-project-123" // AWS provider — must be cleared, not stored

	updated, err := mgr.UpdateCloudAccess(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Empty(t, updated.ProviderProjectID)
}

func TestCreateCloudAccess_AcceptsValidAzureTenantID(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)
	mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	p := testValidCloudAccess()
	p.Provider = types.ProviderAzure
	p.ProviderAccountID = "22222222-2222-2222-2222-222222222222"
	_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
	require.NoError(t, err)
}

func TestCreateCloudAccess_RejectsInvalidAzureTenantID(t *testing.T) {
	cases := []string{"", "not-a-guid", "22222222-2222-2222-2222", "gggggggg-2222-2222-2222-222222222222", "22222222222222222222222222222222"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, _, perms, _ := newTestAccessManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

			p := testValidCloudAccess()
			p.Provider = types.ProviderAzure
			p.ProviderAccountID = id
			_, err := mgr.CreateCloudAccess(context.Background(), testUserID, p)
			require.Error(t, err)
		})
	}
}

func TestCreateCloudAccess_SucceedsAndStartsAsPending(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)
	mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	created, err := mgr.CreateCloudAccess(context.Background(), testUserID, testValidCloudAccess())
	require.NoError(t, err)
	assert.Equal(t, types.CloudAccessStatusPending, created.Status)
}

func TestDeleteCloudAccess_BlockedWhileRolesExist(t *testing.T) {
	mgr, mockStore, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Delete, true, nil)

	access := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{testValidRole(access.ID)}, nil)

	err := mgr.DeleteCloudAccess(context.Background(), testAccountID, testUserID, access.ID)
	require.Error(t, err)
}

func TestDeleteCloudAccess_SucceedsWhenNoRoles(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Delete, true, nil)

	access := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().DeleteCloudAccess(gomock.Any(), testAccountID, access.ID).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, access.ID, testAccountID, gomock.Any(), gomock.Any())

	err := mgr.DeleteCloudAccess(context.Background(), testAccountID, testUserID, access.ID)
	require.NoError(t, err)
}

func TestUpdateCloudAccess_RejectsProviderChangeWhenRolesExist(t *testing.T) {
	mgr, mockStore, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	existing := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).
		Return([]*types.CloudRole{testValidRole(existing.ID)}, nil)

	update := testValidCloudAccess()
	update.ID = existing.ID
	update.Provider = types.ProviderGCP // existing.Provider is ProviderAWS
	update.ProviderProjectID = "my-project-123"

	_, err := mgr.UpdateCloudAccess(context.Background(), testUserID, update)
	require.Error(t, err)
}

func TestUpdateCloudAccess_AllowsProviderChangeWhenNoRolesExist(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	existing := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).
		Return(nil, nil).Times(2) // once for the guard, once for the post-save rollup
	mockStore.EXPECT().SaveCloudAccess(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, existing.ID, testAccountID, gomock.Any(), gomock.Any())

	update := testValidCloudAccess()
	update.ID = existing.ID
	update.Provider = types.ProviderGCP
	update.ProviderAccountID = "123456789" // GCP project number shape
	update.ProviderProjectID = "my-project-123"

	updated, err := mgr.UpdateCloudAccess(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, types.ProviderGCP, updated.Provider)
}

func TestRollupStatus_ConnectedWhenAnyRoleConnected(t *testing.T) {
	mgr, mockStore, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)

	access := testValidCloudAccess()
	pending := testValidRole(access.ID)
	pending.Status = types.StatusPending
	connected := testValidRole(access.ID)
	connected.Status = types.StatusConnected

	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{pending, connected}, nil)

	got, err := mgr.GetCloudAccess(context.Background(), testAccountID, testUserID, access.ID)
	require.NoError(t, err)
	assert.Equal(t, types.CloudAccessStatusConnected, got.Status)
}

func TestRollupStatus_PendingWhenNoRoleConnected(t *testing.T) {
	mgr, mockStore, perms, _ := newTestAccessManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)

	access := testValidCloudAccess()
	pending := testValidRole(access.ID)
	pending.Status = types.StatusPending

	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{pending}, nil)

	got, err := mgr.GetCloudAccess(context.Background(), testAccountID, testUserID, access.ID)
	require.NoError(t, err)
	assert.Equal(t, types.CloudAccessStatusPending, got.Status)
}

func TestCreateRole_DeniesWithoutPermission(t *testing.T) {
	mgr, _, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, false, nil)

	_, err := mgr.CreateRole(context.Background(), testUserID, testValidRole("provider1"))
	require.Error(t, err)
}

func TestCreateRole_RejectsInvalidRoleName(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	r := testValidRole(access.ID)
	r.PrincipalName = "not a valid role name!"
	_, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.Error(t, err)
}

func TestCreateRole_RejectsUnsupportedProvider(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	access.Provider = "digitalocean"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	r := testValidRole(access.ID)
	_, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.Error(t, err)
}

func TestCreateRole_RejectsInvalidGCPServiceAccountEmail(t *testing.T) {
	cases := []string{
		"",
		"not-an-email",
		"short@my-project-123.iam.gserviceaccount.com",         // local part < 6 chars
		"netbird-dev@my-project-123.wrong-domain.com",          // wrong domain suffix
		"NetbirdDev123@my-project-123.iam.gserviceaccount.com", // uppercase not allowed
		"1netbird-dev@my-project-123.iam.gserviceaccount.com",  // must start with a letter
		"netbird-dev@1my-project.iam.gserviceaccount.com",      // project id must start with a letter
	}
	for _, email := range cases {
		t.Run(email, func(t *testing.T) {
			mgr, mockStore, perms, _ := newTestRoleManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

			access := testValidCloudAccess()
			access.Provider = types.ProviderGCP
			access.ProviderAccountID = "123456789012"
			mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

			r := testValidRole(access.ID)
			r.PrincipalName = email
			_, err := mgr.CreateRole(context.Background(), testUserID, r)
			require.Error(t, err)
		})
	}
}

func TestCreateRole_AcceptsValidGCPServiceAccountEmail(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderGCP
	access.ProviderAccountID = "123456789012"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	r := testValidRole(access.ID)
	r.PrincipalName = "netbird-developer@my-project-123.iam.gserviceaccount.com"
	created, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.NoError(t, err)
	assert.Equal(t, types.StatusPending, created.Status)
}

func TestCreateRole_RejectsInvalidAzureClientID(t *testing.T) {
	cases := []string{"not-a-guid", "11111111-1111-1111-1111", "gggggggg-1111-1111-1111-111111111111"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			mgr, mockStore, perms, _ := newTestRoleManager(t)
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

			access := testValidCloudAccess()
			access.Provider = types.ProviderAzure
			access.ProviderAccountID = "22222222-2222-2222-2222-222222222222"
			mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

			r := testValidRole(access.ID)
			r.PrincipalName = id
			_, err := mgr.CreateRole(context.Background(), testUserID, r)
			require.Error(t, err)
		})
	}
}

func TestCreateRole_AcceptsValidAzureClientID(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderAzure
	access.ProviderAccountID = "22222222-2222-2222-2222-222222222222"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	r := testValidRole(access.ID)
	r.PrincipalName = "11111111-1111-1111-1111-111111111111"
	created, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.NoError(t, err)
	assert.Equal(t, types.StatusPending, created.Status)
}

func TestCreateRole_AllowsEmptyPrincipalNameForAzureCreateMode(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderAzure
	access.ProviderAccountID = "22222222-2222-2222-2222-222222222222"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	setupModeCreate := api.CloudRoleRequestSetupModeCreate
	r := testValidRole(access.ID)
	r.PrincipalName = ""
	r.FromAPIRequest(&api.CloudRoleRequest{Name: r.Name, SetupMode: &setupModeCreate})

	created, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.NoError(t, err)
	assert.Empty(t, created.PrincipalName)
	assert.Equal(t, types.StatusPending, created.Status)
}

func TestCreateRole_RejectsEmptyPrincipalNameForAzureImportMode(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderAzure
	access.ProviderAccountID = "22222222-2222-2222-2222-222222222222"
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	setupModeImport := api.CloudRoleRequestSetupModeImport
	r := testValidRole(access.ID)
	r.PrincipalName = ""
	r.FromAPIRequest(&api.CloudRoleRequest{Name: r.Name, SetupMode: &setupModeImport})

	_, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.Error(t, err)
}

func TestCreateRole_SucceedsAndStartsAsPending(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	r := testValidRole(access.ID)
	created, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.NoError(t, err)
	assert.Equal(t, types.StatusPending, created.Status)
	assert.Nil(t, created.LastValidatedAt)
}

func TestCreateRole_PersistsSetupMode(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	r := testValidRole(access.ID)
	r.SetupMode = "import"
	created, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.NoError(t, err)
	assert.Equal(t, "import", created.SetupMode)
}

func TestUpdateRole_SetupModeIsImmutable(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	existing.SetupMode = "create"
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, existing.ID, testAccountID, gomock.Any(), gomock.Any())

	update := &types.CloudRole{ID: existing.ID, AccountID: testAccountID, CloudAccessID: access.ID, Name: existing.Name, PrincipalName: existing.PrincipalName}
	update.SetupMode = "import" // must be ignored — existing.SetupMode wins
	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, "create", updated.SetupMode)
}

func TestUpdateRole_AllowsUnrelatedEditOnStillPendingAzureCreateModeRole(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderAzure
	access.ProviderAccountID = "22222222-2222-2222-2222-222222222222"

	existing := testValidRole(access.ID)
	existing.SetupMode = "create"
	existing.PrincipalName = "" // still pending its Client ID
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, existing.ID, testAccountID, gomock.Any(), gomock.Any())

	update := &types.CloudRole{ID: existing.ID, AccountID: testAccountID, CloudAccessID: access.ID, Name: "Renamed", PrincipalName: ""}
	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", updated.Name)
	assert.Equal(t, "create", updated.SetupMode)
	assert.Empty(t, updated.PrincipalName)
}

func TestCreateRole_RejectsDuplicateNameUnderSameAccess(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)

	r := testValidRole(access.ID)
	r.Name = "developer" // same as existing.Name, different case
	r.PrincipalName = "SomeOtherRole"
	_, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.Error(t, err)
}

func TestCreateRole_RejectsDuplicateIAMRoleNameUnderSameAccess(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Create, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)

	r := testValidRole(access.ID)
	r.Name = "Security"
	r.PrincipalName = "netbirddeveloper" // same as existing.PrincipalName, different case
	_, err := mgr.CreateRole(context.Background(), testUserID, r)
	require.Error(t, err)
}

func TestGetAllRolesInAccount_ExcludesRoleWhoseParentAccessNoLongerExists(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)

	access := testValidCloudAccess()
	orphanRole := testValidRole("an-access-id-that-no-longer-exists")
	liveRole := testValidRole(access.ID)

	mockStore.EXPECT().GetAccountCloudRoles(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.CloudRole{orphanRole, liveRole}, nil)
	mockStore.EXPECT().GetAccountCloudAccess(gomock.Any(), gomock.Any(), testAccountID).
		Return([]*types.CloudAccess{access}, nil)

	roles, err := mgr.GetAllRolesInAccount(context.Background(), testAccountID, testUserID)
	require.NoError(t, err)
	require.Len(t, roles, 1, "the role whose parent access no longer exists must be excluded")
	assert.Equal(t, liveRole.ID, roles[0].ID)
}

func TestUpdateRole_RoleNameChangeResetsToPending(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	existing.Status = types.StatusConnected
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	update := testValidRole(access.ID)
	update.ID = existing.ID
	update.PrincipalName = "SomeOtherRole"

	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, types.StatusPending, updated.Status)
}

func TestUpdateRole_NoRoleNameChangePreservesStatus(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	existing.Status = types.StatusConnected
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	update := testValidRole(access.ID)
	update.ID = existing.ID
	update.Name = "Developer (renamed)"

	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, types.StatusConnected, updated.Status)
}

func TestUpdateRole_RejectsMismatchedCloudAccessID(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	realAccess := testValidCloudAccess()
	existing := testValidRole(realAccess.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)

	update := testValidRole("some-other-cloud-access-id")
	update.ID = existing.ID

	_, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.Error(t, err)
}

func TestUpdateRole_OmittedCredentialLifetimePreservesExisting(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	existing := testValidRole(access.ID)
	existing.CredentialLifetimeSeconds = 3600 // a non-default value an admin chose explicitly
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	update := &types.CloudRole{
		ID:            existing.ID,
		AccountID:     testAccountID,
		CloudAccessID: access.ID,
		Name:          "Developer (renamed)",
		PrincipalName: existing.PrincipalName,
	}

	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.EqualValues(t, 3600, updated.CredentialLifetimeSeconds)
}

func TestUpdateRole_ClampsExplicitOutOfRangeCredentialLifetime(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	access.Provider = types.ProviderGCP
	existing := testValidRole(access.ID)
	existing.PrincipalName = "netbird-developer@my-project-123.iam.gserviceaccount.com"
	existing.CredentialLifetimeSeconds = 3600
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, existing.ID).Return(existing, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return([]*types.CloudRole{existing}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, gomock.Any(), testAccountID, gomock.Any(), gomock.Any())

	update := &types.CloudRole{
		ID:                        existing.ID,
		AccountID:                 testAccountID,
		CloudAccessID:             access.ID,
		Name:                      existing.Name,
		PrincipalName:             existing.PrincipalName,
		CredentialLifetimeSeconds: 1, // below GCP's 600s floor
	}

	updated, err := mgr.UpdateRole(context.Background(), testUserID, update)
	require.NoError(t, err)
	assert.EqualValues(t, types.MinCredentialLifetimeSecondsGCP, updated.CredentialLifetimeSeconds)
}

func TestDeleteRole_BlockedWhilePolicyReferencesIt(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Delete, true, nil)

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return(policiesReferencing(role.ID), nil)

	err := mgr.DeleteRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.Error(t, err)
}

func TestDeleteRole_IgnoresSameIDOnDifferentResourceType(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Delete, true, nil)

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*servertypes.Policy{{
		ID:      "policy1",
		Name:    "Unrelated host policy",
		Enabled: true,
		Rules: []*servertypes.PolicyRule{{
			Enabled:             true,
			DestinationResource: servertypes.Resource{ID: role.ID, Type: servertypes.ResourceTypeHost},
		}},
	}}, nil)
	mockStore.EXPECT().DeleteCloudRole(gomock.Any(), testAccountID, role.ID).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, role.ID, testAccountID, gomock.Any(), gomock.Any())

	err := mgr.DeleteRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.NoError(t, err)
}

func TestDeleteRole_SucceedsWhenUnreferenced(t *testing.T) {
	mgr, mockStore, perms, mockAccount := newTestRoleManager(t)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Delete, true, nil)

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return(nil, nil)
	mockStore.EXPECT().DeleteCloudRole(gomock.Any(), testAccountID, role.ID).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, role.ID, testAccountID, gomock.Any(), gomock.Any())

	err := mgr.DeleteRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.NoError(t, err)
}

func TestValidateRole_SuccessMarksConnectedAndDoesNotLeakResolvedIdentityIntoEventMeta(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockPerms := newPermMockManager(t, ctrl)
	mockAccount := account.NewMockManager(ctrl)
	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	const resolvedIdentity = "arn:aws:sts::123456789012:assumed-role/NetBirdDeveloper/x"
	mgr := &roleManagerImpl{
		store:               mockStore,
		accountManager:      mockAccount,
		permissionsManager:  mockPerms,
		validators:          map[string]Validator{types.ProviderAWS: &fakeValidator{identity: resolvedIdentity}},
		federationEnabled:   true,
		federationIssuerURL: "https://netbird.example.com/federation",
	}
	mockPerms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)

	var capturedMeta map[string]any
	mockAccount.EXPECT().
		StoreEvent(gomock.Any(), testUserID, role.ID, testAccountID, activity.CloudRoleValidationSucceeded, gomock.Any()).
		Do(func(_ context.Context, _, _, _ string, _ activity.ActivityDescriber, meta map[string]any) {
			capturedMeta = meta
		})

	updated, err := mgr.ValidateRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.NoError(t, err)
	assert.Equal(t, types.StatusConnected, updated.Status)
	require.NotNil(t, updated.LastValidatedAt)

	for k, v := range capturedMeta {
		assert.NotContains(t, fmt.Sprintf("%v", v), resolvedIdentity, "event meta key %q must never contain the resolved cloud identity", k)
	}
	_, hasKey := capturedMeta["resolved_identity"]
	assert.False(t, hasKey, "resolved_identity must not be a key in the user-visible audit event")
}

func TestValidateRole_FailureMarksError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockPerms := newPermMockManager(t, ctrl)
	mockAccount := account.NewMockManager(ctrl)
	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mgr := &roleManagerImpl{
		store:               mockStore,
		accountManager:      mockAccount,
		permissionsManager:  mockPerms,
		validators:          map[string]Validator{types.ProviderAWS: &fakeValidator{err: errors.New("AWS STS rejected the assertion")}},
		federationEnabled:   true,
		federationIssuerURL: "https://netbird.example.com/federation",
	}
	mockPerms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), testUserID, role.ID, testAccountID, gomock.Any(), gomock.Any())

	updated, err := mgr.ValidateRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.NoError(t, err, "a failed validation is reported via Status=error, not a returned error")
	assert.Equal(t, types.StatusError, updated.Status)
}

func TestValidateRole_RejectsWhenFederationDisabled(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = false
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	_, err := mgr.ValidateRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloud federation")
}

func TestValidateRole_RejectsIssuerURLMissingFederationSuffix(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com" // missing /federation

	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Update, true, nil)

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	_, err := mgr.ValidateRole(context.Background(), testAccountID, testUserID, access.ID, role.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/federation")
}
