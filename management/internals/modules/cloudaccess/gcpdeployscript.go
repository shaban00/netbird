package cloudaccess

import (
	"context"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	gcpWorkloadIdentityPoolID     = "netbird-pool"
	gcpWorkloadIdentityProviderID = "netbird-oidc"
	gcpRoleIDClaimName            = "netbird_role_id"
	gcpDeployModeCreate           = "create"
	gcpDeployModeImport           = "import"
)

// GetGCPDeployScript renders the gcloud setup steps for a role, including
// Workload Identity Pool setup if it likely doesn't exist.
func (m *roleManagerImpl) GetGCPDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}

	if mode == "" {
		mode = gcpDeployModeCreate
	}
	if mode != gcpDeployModeCreate && mode != gcpDeployModeImport {
		return nil, status.Errorf(status.InvalidArgument, "unsupported deploy script mode %q", mode)
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("get cloud access: %w", err)
	}
	if access.Provider != types.ProviderGCP {
		return nil, status.Errorf(status.InvalidArgument, "the GCP deploy script is only available for GCP providers")
	}
	if access.ProviderProjectID == "" {
		return nil, status.Errorf(status.InvalidArgument, "this connection is missing its GCP Project ID; add it before deploying a role")
	}

	role, err := m.store.GetCloudRoleByID(ctx, store.LockingStrengthNone, accountID, roleID)
	if err != nil {
		return nil, fmt.Errorf("get cloud role: %w", err)
	}
	if role.CloudAccessID != cloudAccessID {
		return nil, status.NewCloudRoleNotFoundError(roleID)
	}

	if err := m.requireFederationEnabled(); err != nil {
		return nil, err
	}

	poolExists, err := m.accessProviderLikelyExists(ctx, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("check for an existing workload identity pool: %w", err)
	}

	issuerIdentity, _ := issuerIdentityAndHostPath(m.federationIssuerURL)
	projectIDQuoted := shellSingleQuote(access.ProviderProjectID)

	serviceAccountID, _, found := strings.Cut(role.PrincipalName, "@")
	if !found {
		return nil, fmt.Errorf("role principal %q is not a valid service account email", role.PrincipalName)
	}
	serviceAccountEmailQuoted := shellSingleQuote(role.PrincipalName)
	memberQuoted := shellSingleQuote(fmt.Sprintf(
		"principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/attribute.%s/%s",
		access.ProviderAccountID, gcpWorkloadIdentityPoolID, gcpRoleIDClaimName, role.ID,
	))

	var steps []CloudDeployStep
	if !poolExists {
		cmd := fmt.Sprintf(
			"gcloud services enable iamcredentials.googleapis.com \\\n  --project=%s\n\n"+
				"gcloud iam workload-identity-pools create %s \\\n  --project=%s \\\n  --location=global \\\n  --display-name='NetBird' \\\n  --description='Workload identity pool trusting NetBird'\n\n"+
				"gcloud iam workload-identity-pools providers create-oidc %s \\\n  --project=%s \\\n  --location=global \\\n  --workload-identity-pool=%s \\\n  --issuer-uri=%s \\\n  --attribute-mapping=\"google.subject=assertion.sub,attribute.%s=assertion.%s\"",
			projectIDQuoted,
			shellSingleQuote(gcpWorkloadIdentityPoolID), projectIDQuoted,
			shellSingleQuote(gcpWorkloadIdentityProviderID), projectIDQuoted, shellSingleQuote(gcpWorkloadIdentityPoolID),
			shellSingleQuote(issuerIdentity),
			gcpRoleIDClaimName, gcpRoleIDClaimName,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Create the Workload Identity Pool",
			Description: "Creates the trust relationship between GCP and NetBird. Only needed once per GCP project — later roles skip this step.",
			Command:     cmd,
		})
	}

	switch mode {
	case gcpDeployModeCreate:
		cmd := fmt.Sprintf(
			"gcloud iam service-accounts create %s \\\n  --project=%s \\\n  --display-name=%s\n\n"+
				"gcloud iam service-accounts add-iam-policy-binding %s \\\n  --project=%s \\\n  --role='roles/iam.workloadIdentityUser' \\\n  --member=%s",
			shellSingleQuote(serviceAccountID), projectIDQuoted, shellSingleQuote("NetBird: "+role.Name),
			serviceAccountEmailQuoted, projectIDQuoted, memberQuoted,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Create the service account",
			Description: "Creates the service account NetBird will federate into.",
			Command:     cmd,
		})
	case gcpDeployModeImport:
		cmd := fmt.Sprintf(
			"gcloud iam service-accounts add-iam-policy-binding %s \\\n  --project=%s \\\n  --role='roles/iam.workloadIdentityUser' \\\n  --member=%s",
			serviceAccountEmailQuoted, projectIDQuoted, memberQuoted,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Bind the existing service account",
			Description: "Grants NetBird permission to impersonate this existing service account.",
			Command:     cmd,
		})
	}

	return &CloudDeploySteps{Steps: steps}, nil
}
