package cloudaccess

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// gcpServiceAccountEmailPattern matches
// <service-account-id>@<project-id>.iam.gserviceaccount.com per GCP's
// naming rules (6-30 chars, lowercase alphanumeric/dashes, starts with a letter).
// gcpProjectIDChars is shared with gcpProjectIDPattern so the two can't drift apart.
const gcpProjectIDChars = `[a-z][a-z0-9-]{4,28}[a-z0-9]`

var (
	awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)
	// awsIAMRoleNamePattern matches valid IAM role names.
	awsIAMRoleNamePattern = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	// gcpProjectNumberPattern matches 6–12 digits with no leading zero.
	gcpProjectNumberPattern       = regexp.MustCompile(`^[1-9]\d{5,11}$`)
	gcpServiceAccountEmailPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{5,29}@` + gcpProjectIDChars + `\.iam\.gserviceaccount\.com$`)

	// gcpProjectIDPattern matches a standalone GCP project ID.
	gcpProjectIDPattern = regexp.MustCompile(`^` + gcpProjectIDChars + `$`)

	// azureGUIDPattern matches a GUID, used for Azure tenant and client IDs.
	azureGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

var providerAccountIDValidators = map[string]func(string) error{
	types.ProviderAWS:   validateAWSAccountID,
	types.ProviderGCP:   validateGCPProjectNumber,
	types.ProviderAzure: validateAzureTenantID,
}

var principalNameValidators = map[string]func(string) error{
	types.ProviderAWS:   validateAWSPrincipalName,
	types.ProviderGCP:   validateGCPPrincipalName,
	types.ProviderAzure: validateAzurePrincipalName,
}

type Validator interface {
	Validate(ctx context.Context, role cloudidentity.ResolvedRole) (resolvedIdentity string, err error)
}

type AccessManager interface {
	GetAllCloudAccess(ctx context.Context, accountID, userID string) ([]*types.CloudAccess, error)
	GetCloudAccess(ctx context.Context, accountID, userID, cloudAccessID string) (*types.CloudAccess, error)
	CreateCloudAccess(ctx context.Context, userID string, access *types.CloudAccess) (*types.CloudAccess, error)
	UpdateCloudAccess(ctx context.Context, userID string, access *types.CloudAccess) (*types.CloudAccess, error)
	DeleteCloudAccess(ctx context.Context, accountID, userID, cloudAccessID string) error
}

type accessManagerImpl struct {
	store               store.Store
	accountManager      account.Manager
	permissionsManager  permissions.Manager
	federationEnabled   bool
	federationIssuerURL string
}

// NewAccessManager returns the cloud access connection manager
func NewAccessManager(store store.Store, permissionsManager permissions.Manager, accountManager account.Manager, federationEnabled bool, federationIssuerURL string) AccessManager {
	return &accessManagerImpl{
		store:               store,
		accountManager:      accountManager,
		permissionsManager:  permissionsManager,
		federationEnabled:   federationEnabled,
		federationIssuerURL: federationIssuerURL,
	}
}

func (m *accessManagerImpl) requirePermission(ctx context.Context, accountID, userID string, op operations.Operation) error {
	ok, _, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.CloudAccess, op)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}
	return nil
}

func (m *accessManagerImpl) requireFederationEnabled() error {
	return requireFederationEnabled(m.federationEnabled, m.federationIssuerURL)
}

// requireFederationEnabled gates every CloudAccess/CloudRole operation, read or write
func requireFederationEnabled(federationEnabled bool, federationIssuerURL string) error {
	if !federationEnabled || federationIssuerURL == "" {
		return status.Errorf(status.PreconditionFailed, "this NetBird deployment has not enabled cloud federation; an administrator must set CloudFederation.Enabled and CloudFederation.Issuer before cloud access can be configured")
	}
	if !strings.HasSuffix(strings.TrimSuffix(federationIssuerURL, "/"), "/federation") {
		return status.Errorf(status.PreconditionFailed, "CloudFederation.Issuer %q must end in \"/federation\" (e.g. https://netbird.example.com/federation)", federationIssuerURL)
	}
	return nil
}

func (m *accessManagerImpl) GetAllCloudAccess(ctx context.Context, accountID, userID string) ([]*types.CloudAccess, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	access, err := m.store.GetAccountCloudAccess(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	for _, a := range access {
		rollup, err := m.rollupStatus(ctx, accountID, a.ID)
		if err != nil {
			return nil, err
		}
		a.Status = rollup
	}

	return access, nil
}

func (m *accessManagerImpl) GetCloudAccess(ctx context.Context, accountID, userID, cloudAccessID string) (*types.CloudAccess, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return nil, err
	}

	rollup, err := m.rollupStatus(ctx, accountID, cloudAccessID)
	if err != nil {
		return nil, err
	}
	access.Status = rollup

	return access, nil
}

// rollupStatus returns "connected" if any role is connected, else "pending"
func (m *accessManagerImpl) rollupStatus(ctx context.Context, accountID, cloudAccessID string) (types.CloudAccessStatus, error) {
	roles, err := m.store.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return "", err
	}
	for _, r := range roles {
		if r.Status == types.StatusConnected {
			return types.CloudAccessStatusConnected, nil
		}
	}
	return types.CloudAccessStatusPending, nil
}

func (m *accessManagerImpl) CreateCloudAccess(ctx context.Context, userID string, access *types.CloudAccess) (*types.CloudAccess, error) {
	if err := m.requirePermission(ctx, access.AccountID, userID, operations.Create); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	if err := validateCloudAccess(access); err != nil {
		return nil, err
	}

	if access.ID == "" {
		fresh := types.NewCloudAccess(access.AccountID)
		access.ID = fresh.ID
		access.CreatedAt = fresh.CreatedAt
		access.UpdatedAt = fresh.UpdatedAt
	}
	access.Status = types.CloudAccessStatusPending

	if err := m.store.SaveCloudAccess(ctx, access); err != nil {
		return nil, fmt.Errorf("save cloud access: %w", err)
	}

	m.accountManager.StoreEvent(ctx, userID, access.ID, access.AccountID, activity.CloudAccessCreated, access.EventMeta())

	return access, nil
}

func (m *accessManagerImpl) UpdateCloudAccess(ctx context.Context, userID string, access *types.CloudAccess) (*types.CloudAccess, error) {
	if err := m.requirePermission(ctx, access.AccountID, userID, operations.Update); err != nil {
		return nil, err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	err := m.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		existing, err := tx.GetCloudAccessByID(ctx, store.LockingStrengthUpdate, access.AccountID, access.ID)
		if err != nil {
			return fmt.Errorf("get cloud access: %w", err)
		}

		if err := validateCloudAccess(access); err != nil {
			return err
		}

		if access.Provider != existing.Provider {
			roles, err := tx.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthUpdate, access.AccountID, access.ID)
			if err != nil {
				return err
			}
			if len(roles) > 0 {
				return status.Errorf(status.InvalidArgument,
					"cloud access has %d role%s configured; delete them before changing the provider",
					len(roles), pluralS(len(roles)))
			}
		}

		access.CreatedAt = existing.CreatedAt

		if err := tx.SaveCloudAccess(ctx, access); err != nil {
			return fmt.Errorf("save cloud access: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, access.ID, access.AccountID, activity.CloudAccessUpdated, access.EventMeta())

	rollup, err := m.rollupStatus(ctx, access.AccountID, access.ID)
	if err != nil {
		return nil, err
	}
	access.Status = rollup

	return access, nil
}

func (m *accessManagerImpl) DeleteCloudAccess(ctx context.Context, accountID, userID, cloudAccessID string) error {
	if err := m.requirePermission(ctx, accountID, userID, operations.Delete); err != nil {
		return err
	}
	if err := m.requireFederationEnabled(); err != nil {
		return err
	}

	var access *types.CloudAccess
	err := m.store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		var err error
		access, err = tx.GetCloudAccessByID(ctx, store.LockingStrengthUpdate, accountID, cloudAccessID)
		if err != nil {
			return fmt.Errorf("get cloud access: %w", err)
		}

		roles, err := tx.GetCloudRolesByCloudAccessID(ctx, store.LockingStrengthUpdate, accountID, cloudAccessID)
		if err != nil {
			return err
		}
		if len(roles) > 0 {
			return status.Errorf(status.InvalidArgument,
				"cloud access has %d role%s configured; delete them before deleting the connection",
				len(roles), pluralS(len(roles)))
		}

		if err := tx.DeleteCloudAccess(ctx, accountID, cloudAccessID); err != nil {
			return fmt.Errorf("delete cloud access: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	m.accountManager.StoreEvent(ctx, userID, cloudAccessID, accountID, activity.CloudAccessDeleted, access.EventMeta())

	return nil
}

// shellSingleQuote returns a safely single-quoted POSIX shell literal.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// issuerIdentityAndHostPath returns the issuer URL and its scheme-less
// host+path for AWS's "{host}{path}:aud" condition.
func issuerIdentityAndHostPath(federationIssuerURL string) (issuerIdentity, issuerHostAndPath string) {
	issuerIdentity = strings.TrimSuffix(federationIssuerURL, "/")
	issuerHostAndPath = strings.TrimPrefix(strings.TrimPrefix(issuerIdentity, "https://"), "http://")
	return issuerIdentity, issuerHostAndPath
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func validateCloudAccess(access *types.CloudAccess) error {
	if strings.TrimSpace(access.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}

	validateAccountID, ok := providerAccountIDValidators[access.Provider]
	if !ok {
		return status.Errorf(status.InvalidArgument, "unsupported cloud provider %q", access.Provider)
	}
	if strings.TrimSpace(access.ProviderAccountID) == "" {
		return status.Errorf(status.InvalidArgument, "account identifier is required")
	}
	if err := validateAccountID(access.ProviderAccountID); err != nil {
		return err
	}

	// GCP only — cleared for any other provider, required for GCP.
	if access.Provider != types.ProviderGCP {
		access.ProviderProjectID = ""
		return nil
	}
	if strings.TrimSpace(access.ProviderProjectID) == "" {
		return status.Errorf(status.InvalidArgument, "GCP project ID is required")
	}
	return validateGCPProjectID(access.ProviderProjectID)
}

func validateAWSAccountID(id string) error {
	if !awsAccountIDPattern.MatchString(id) {
		return status.Errorf(status.InvalidArgument, "account identifier must be a 12-digit AWS account ID")
	}
	return nil
}

func validateGCPProjectNumber(id string) error {
	if !gcpProjectNumberPattern.MatchString(id) {
		return status.Errorf(status.InvalidArgument, "account identifier must be a GCP project number (6-12 digits, no leading zero)")
	}
	return nil
}

func validateAWSPrincipalName(name string) error {
	if !awsIAMRoleNamePattern.MatchString(name) {
		return status.Errorf(status.InvalidArgument, "principal name must match AWS IAM's role name format: letters, digits, and + = , . @ _ - , up to 64 characters")
	}
	return nil
}

func validateGCPPrincipalName(name string) error {
	if !gcpServiceAccountEmailPattern.MatchString(name) {
		return status.Errorf(status.InvalidArgument, "principal name must be a full GCP service account email address, e.g. my-service-account@my-project-123.iam.gserviceaccount.com")
	}
	return nil
}

func validateGCPProjectID(id string) error {
	if !gcpProjectIDPattern.MatchString(id) {
		return status.Errorf(status.InvalidArgument, "GCP project ID must be 6-30 characters, lowercase letters/digits/hyphens, starting with a letter and not ending with a hyphen")
	}
	return nil
}

func validateAzureTenantID(id string) error {
	if !azureGUIDPattern.MatchString(id) {
		return status.Errorf(status.InvalidArgument, "account identifier must be an Azure AD Tenant (Directory) ID, a GUID")
	}
	return nil
}

func validateAzurePrincipalName(name string) error {
	if !azureGUIDPattern.MatchString(name) {
		return status.Errorf(status.InvalidArgument, "principal name must be an Azure AD Application (Client) ID, a GUID")
	}
	return nil
}
