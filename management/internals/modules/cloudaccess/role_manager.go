package cloudaccess

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	servertypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type RoleManager interface {
	GetAllRolesInAccess(ctx context.Context, accountID, userID, cloudAccessID string) ([]*types.CloudRole, error)
	GetAllRolesInAccount(ctx context.Context, accountID, userID string) ([]*types.CloudRole, error)
	GetRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) (*types.CloudRole, error)
	CreateRole(ctx context.Context, userID string, role *types.CloudRole) (*types.CloudRole, error)
	UpdateRole(ctx context.Context, userID string, role *types.CloudRole) (*types.CloudRole, error)
	DeleteRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) error
	ValidateRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) (*types.CloudRole, error)
	GetAWSDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error)
	GetGCPDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error)
	GetAzureDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error)
}

type roleManagerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	validators         map[string]Validator

	federationEnabled   bool
	federationIssuerURL string
}

// NewRoleManager returns the cloud role manager
func NewRoleManager(store store.Store, permissionsManager permissions.Manager, accountManager account.Manager, validators map[string]Validator, federationEnabled bool, federationIssuerURL string) RoleManager {
	return &roleManagerImpl{
		store:               store,
		accountManager:      accountManager,
		permissionsManager:  permissionsManager,
		validators:          validators,
		federationEnabled:   federationEnabled,
		federationIssuerURL: federationIssuerURL,
	}
}

func (m *roleManagerImpl) requirePermission(ctx context.Context, accountID, userID string, op operations.Operation) error {
	ok, _, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.CloudAccess, op)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}
	return nil
}

// accessProviderLikelyExists checks whether the connection's trust provider
// likely exists: true if any sibling role is connected.
func (m *roleManagerImpl) accessProviderLikelyExists(ctx context.Context, accountID, cloudAccessID string) (bool, error) {
	roles, err := m.store.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Status == types.StatusConnected {
			return true, nil
		}
	}
	return false, nil
}

// requireFederationEnabled gates every CloudRole operation — see the shared
// requireFederationEnabled free function in manager.go for why.
func (m *roleManagerImpl) requireFederationEnabled() error {
	return requireFederationEnabled(m.federationEnabled, m.federationIssuerURL)
}

func (m *roleManagerImpl) GetAllRolesInAccess(ctx context.Context, accountID, userID, cloudAccessID string) ([]*types.CloudRole, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}
	return m.store.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
}

func (m *roleManagerImpl) GetAllRolesInAccount(ctx context.Context, accountID, userID string) ([]*types.CloudRole, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	roles, err := m.store.GetAccountCloudRoles(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	access, err := m.store.GetAccountCloudAccess(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	validAccessIDs := make(map[string]struct{}, len(access))
	for _, a := range access {
		validAccessIDs[a.ID] = struct{}{}
	}

	live := make([]*types.CloudRole, 0, len(roles))
	for _, r := range roles {
		if _, ok := validAccessIDs[r.CloudAccessID]; ok {
			live = append(live, r)
		}
	}
	return live, nil
}

func (m *roleManagerImpl) GetRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) (*types.CloudRole, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}
	role, err := m.store.GetCloudRoleByID(ctx, store.LockingStrengthNone, accountID, roleID)
	if err != nil {
		return nil, err
	}
	if role.CloudAccessID != cloudAccessID {
		return nil, status.NewCloudRoleNotFoundError(roleID)
	}
	return role, nil
}

func (m *roleManagerImpl) CreateRole(ctx context.Context, userID string, role *types.CloudRole) (*types.CloudRole, error) {
	if err := m.requirePermission(ctx, role.AccountID, userID, operations.Create); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	var access *types.CloudAccess
	err := m.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		var err error
		access, err = tx.GetCloudAccessByID(ctx, store.LockingStrengthUpdate, role.AccountID, role.CloudAccessID)
		if err != nil {
			return fmt.Errorf("get cloud access: %w", err)
		}

		if err := validateRole(role, access.Provider); err != nil {
			return err
		}
		if err := m.ensureRoleNamesUnique(ctx, tx, role, ""); err != nil {
			return err
		}

		if access.Provider != types.ProviderAWS && access.Provider != types.ProviderGCP && access.Provider != types.ProviderAzure {
			role.SetupMode = ""
		}

		role.CredentialLifetimeSeconds = types.ClampCredentialLifetime(role.CredentialLifetimeSeconds, access.Provider)

		if role.ID == "" {
			fresh := types.NewCloudRole(role.AccountID, role.CloudAccessID)
			role.ID = fresh.ID
			role.CreatedAt = fresh.CreatedAt
			role.UpdatedAt = fresh.UpdatedAt
		}
		role.Status = types.StatusPending
		role.LastValidatedAt = nil

		if err := tx.SaveCloudRole(ctx, role); err != nil {
			return fmt.Errorf("save cloud role: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, role.ID, role.AccountID, activity.CloudRoleCreated, role.EventMeta(access.Provider))

	return role, nil
}

func (m *roleManagerImpl) UpdateRole(ctx context.Context, userID string, role *types.CloudRole) (*types.CloudRole, error) {
	if err := m.requirePermission(ctx, role.AccountID, userID, operations.Update); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	var access *types.CloudAccess
	err := m.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		existing, err := tx.GetCloudRoleByID(ctx, store.LockingStrengthUpdate, role.AccountID, role.ID)
		if err != nil {
			return fmt.Errorf("get cloud role: %w", err)
		}

		if existing.CloudAccessID != role.CloudAccessID {
			return status.NewCloudRoleNotFoundError(role.ID)
		}

		access, err = tx.GetCloudAccessByID(ctx, store.LockingStrengthNone, role.AccountID, role.CloudAccessID)
		if err != nil {
			return fmt.Errorf("get cloud access: %w", err)
		}

		if role.CredentialLifetimeSeconds == 0 {
			role.CredentialLifetimeSeconds = existing.CredentialLifetimeSeconds
		}
		role.CredentialLifetimeSeconds = types.ClampCredentialLifetime(role.CredentialLifetimeSeconds, access.Provider)

		role.SetupMode = existing.SetupMode

		if err := validateRole(role, access.Provider); err != nil {
			return err
		}
		if err := m.ensureRoleNamesUnique(ctx, tx, role, existing.ID); err != nil {
			return err
		}

		role.CreatedAt = existing.CreatedAt
		role.UpdatedAt = time.Now().UTC()

		if role.PrincipalName != existing.PrincipalName {
			role.Status = types.StatusPending
			role.LastValidatedAt = nil
		} else {
			role.Status = existing.Status
			role.LastValidatedAt = existing.LastValidatedAt
		}

		if err := tx.SaveCloudRole(ctx, role); err != nil {
			return fmt.Errorf("save cloud role: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, role.ID, role.AccountID, activity.CloudRoleUpdated, role.EventMeta(access.Provider))

	return role, nil
}

func (m *roleManagerImpl) DeleteRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) error {
	if err := m.requirePermission(ctx, accountID, userID, operations.Delete); err != nil {
		return err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return err
	}

	role, err := m.store.GetCloudRoleByID(ctx, store.LockingStrengthUpdate, accountID, roleID)
	if err != nil {
		return fmt.Errorf("get cloud role: %w", err)
	}
	if role.CloudAccessID != cloudAccessID {
		return status.NewCloudRoleNotFoundError(roleID)
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return fmt.Errorf("get cloud access: %w", err)
	}

	policies, err := m.store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("get account policies: %w", err)
	}
	var blocking []string
	for _, p := range policies {
		for _, rule := range p.Rules {
			if rule.DestinationResource.Type == servertypes.ResourceTypeCloudIntegration && rule.DestinationResource.ID == roleID {
				blocking = append(blocking, p.Name)
				break
			}
		}
	}
	if len(blocking) > 0 {
		return status.Errorf(status.InvalidArgument,
			"cloud role is referenced by %d polic%s (%s); detach it before deleting",
			len(blocking), pluralY(len(blocking)), strings.Join(blocking, ", "))
	}

	if err := m.store.DeleteCloudRole(ctx, accountID, roleID); err != nil {
		return fmt.Errorf("delete cloud role: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, roleID, accountID, activity.CloudRoleDeleted, role.EventMeta(access.Provider))

	return nil
}

func (m *roleManagerImpl) ValidateRole(ctx context.Context, accountID, userID, cloudAccessID, roleID string) (*types.CloudRole, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Update); err != nil {
		return nil, err
	}

	role, err := m.store.GetCloudRoleByID(ctx, store.LockingStrengthUpdate, accountID, roleID)
	if err != nil {
		return nil, fmt.Errorf("get cloud role: %w", err)
	}
	if role.CloudAccessID != cloudAccessID {
		return nil, status.NewCloudRoleNotFoundError(roleID)
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("get cloud access: %w", err)
	}

	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	validator, ok := m.validators[access.Provider]
	if !ok {
		return nil, status.Errorf(status.InvalidArgument, "no validator registered for provider %q", access.Provider)
	}

	resolved := cloudidentity.ResolvedRole{
		RoleID:                    role.ID,
		PrincipalRef:              role.PrincipalRef(access.ProviderAccountID, access.Provider),
		CredentialLifetimeSeconds: role.CredentialLifetimeSeconds,
		Provider:                  access.Provider,
		ProviderAccountID:         access.ProviderAccountID,
	}

	now := time.Now().UTC()
	resolvedIdentity, valErr := validator.Validate(ctx, resolved)
	meta := role.EventMeta(access.Provider)
	if valErr != nil {
		log.WithContext(ctx).Warnf("cloud role validation failed for role %s: %v", role.ID, valErr)
		role.Status = types.StatusError
		m.accountManager.StoreEvent(ctx, userID, role.ID, accountID, activity.CloudRoleValidationFailed, meta)
	} else {
		role.Status = types.StatusConnected
		role.LastValidatedAt = &now
		log.WithContext(ctx).Infof("cloud role validation succeeded for role %s: resolved identity %s", role.ID, resolvedIdentity)
		m.accountManager.StoreEvent(ctx, userID, role.ID, accountID, activity.CloudRoleValidationSucceeded, meta)
	}
	role.UpdatedAt = now

	if err := m.store.SaveCloudRole(ctx, role); err != nil {
		return nil, fmt.Errorf("save cloud role: %w", err)
	}

	return role, nil
}

func (m *roleManagerImpl) ensureRoleNamesUnique(ctx context.Context, tx store.Store, role *types.CloudRole, excludeRoleID string) error {
	siblings, err := tx.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthUpdate, role.AccountID, role.CloudAccessID)
	if err != nil {
		return fmt.Errorf("get cloud roles: %w", err)
	}

	name := strings.ToLower(strings.TrimSpace(role.Name))
	principalName := strings.ToLower(strings.TrimSpace(role.PrincipalName))
	for _, sibling := range siblings {
		if sibling.ID == excludeRoleID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(sibling.Name)) == name {
			return status.Errorf(status.InvalidArgument, "a role named %q already exists under this cloud access connection", role.Name)
		}

		if principalName != "" && strings.ToLower(strings.TrimSpace(sibling.PrincipalName)) == principalName {
			return status.Errorf(status.InvalidArgument, "a role with principal name %q already exists under this cloud access connection", role.PrincipalName)
		}
	}
	return nil
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func validateRole(role *types.CloudRole, provider string) error {
	if strings.TrimSpace(role.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}

	principalName := strings.TrimSpace(role.PrincipalName)
	if principalName == "" {
		// In create mode the Azure client ID may be empty until `az ad app create` generates it
		if provider == types.ProviderAzure && role.SetupMode == azureDeployModeCreate {
			return nil
		}
		return status.Errorf(status.InvalidArgument, "principal name is required")
	}

	validatePrincipalName, ok := principalNameValidators[provider]
	if !ok {
		return status.Errorf(status.InvalidArgument, "unsupported cloud provider %q", provider)
	}
	return validatePrincipalName(principalName)
}
