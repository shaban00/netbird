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
	// federationAudience is the fixed OIDC audience for AWS federation
	federationAudience  = "sts.amazonaws.com"
	awsDeployModeCreate = "create"
	awsDeployModeImport = "import"
	awsTrustSid         = "NetBirdFederationTrust"
)

type CloudDeployStep struct {
	Title       string
	Description string
	Command     string
}

type CloudDeploySteps struct {
	Steps []CloudDeployStep
}

// awsResourceNameTag turns an issuer host into a display Name tag, e.g. "netbird.example.com" -> "NETBIRD_EXAMPLE_COM"
func awsResourceNameTag(host string) string {
	return strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(host))
}

// awsTrustPolicyJSON returns a trust policy allowing oidcProviderARN tokens
// with the given audience. Scoped by audience only, not per role.
func awsTrustPolicyJSON(sid, oidcProviderARN, issuerHostAndPathAudCondition, audience string) string {
	return fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[{"Sid":%q,"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{%q:%q}}}]}`,
		sid, oidcProviderARN, issuerHostAndPathAudCondition, audience,
	)
}

// GetAWSDeployScript renders the step-by-step setup walkthrough for an AWS-provider role.
// If the OIDC provider likely doesn't exist yet (per accessProviderLikelyExists),
// the first step creates it; later roles skip straight to their own trust relationship.
func (m *roleManagerImpl) GetAWSDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}

	if mode == "" {
		mode = awsDeployModeCreate
	}
	if mode != awsDeployModeCreate && mode != awsDeployModeImport {
		return nil, status.Errorf(status.InvalidArgument, "unsupported deploy script mode %q", mode)
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("get cloud access: %w", err)
	}
	if access.Provider != types.ProviderAWS {
		return nil, status.Errorf(status.InvalidArgument, "the AWS deploy script is only available for AWS providers")
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

	providerExists, err := m.accessProviderLikelyExists(ctx, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("check for an existing OIDC provider: %w", err)
	}

	// AWS-documented OIDC provider ARN format: arn:aws:iam::{account-id}:oidc-provider/{host+path}
	issuerIdentity, issuerHostAndPath := issuerIdentityAndHostPath(m.federationIssuerURL)
	oidcProviderARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", access.ProviderAccountID, issuerHostAndPath)

	roleNameQuoted := shellSingleQuote(role.PrincipalName)

	var steps []CloudDeployStep
	if !providerExists {
		bareIssuerHost := strings.TrimSuffix(issuerHostAndPath, "/federation")
		cmd := fmt.Sprintf(
			"aws iam create-open-id-connect-provider \\\n  --url %s \\\n  --client-id-list %s \\\n  --tags %s",
			shellSingleQuote(issuerIdentity), shellSingleQuote(federationAudience), shellSingleQuote(fmt.Sprintf("Key=Name,Value=%s", awsResourceNameTag(bareIssuerHost))),
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Create the OIDC identity provider",
			Description: "Creates the trust relationship between AWS and NetBird. Only needed once per AWS account — later roles skip this step. If it already exists, AWS will say so — just continue.",
			Command:     cmd,
		})
	}

	switch mode {
	case awsDeployModeCreate:
		trustJSON := awsTrustPolicyJSON(awsTrustSid, oidcProviderARN, issuerHostAndPath+":aud", federationAudience)
		cmd := fmt.Sprintf(
			"aws iam create-role \\\n  --role-name %s \\\n  --assume-role-policy-document %s",
			roleNameQuoted, shellSingleQuote(trustJSON),
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Create the IAM role",
			Description: "Creates the IAM role NetBird will federate into, trusting this connection's OIDC provider.",
			Command:     cmd,
		})
	case awsDeployModeImport:
		newStatementArrayJSON := fmt.Sprintf(
			`[{"Sid":%q,"Effect":"Allow","Principal":{"Federated":%q},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{%q:%q}}}]`,
			awsTrustSid, oidcProviderARN, issuerHostAndPath+":aud", federationAudience,
		)
		cmd := fmt.Sprintf(
			"aws iam update-assume-role-policy \\\n  --role-name %s \\\n  --policy-document \"$(aws iam get-role --role-name %s --query Role.AssumeRolePolicyDocument --output json | jq --argjson new %s '.Statement |= ([.[] | select(.Sid != %q)] + $new)')\"",
			roleNameQuoted, roleNameQuoted, shellSingleQuote(newStatementArrayJSON), awsTrustSid,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Update the role's trust policy",
			Description: "Adds NetBird's trust statement to this role without touching any trust relationship it already has.",
			Command:     cmd,
		})
	}

	return &CloudDeploySteps{Steps: steps}, nil
}
