package cloudaccess

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// azureFederatedCredentialAudience is fixed for Azure federated identity
	azureFederatedCredentialAudience = "api://AzureADTokenExchange"
	azureDeployModeCreate            = "create"
	azureDeployModeImport            = "import"
)

func azureSubjectForRole(roleID string) string {
	return "netbird-role-" + roleID
}

func azureFederatedCredentialDescription(role *types.CloudRole) string {
	return fmt.Sprintf("Managed by NetBird — role: %s (%s)", role.Name, role.ID)
}

// azureFederatedCredentialJSON returns the JSON body for `az ad app federated-credential create --parameters`
func azureFederatedCredentialJSON(issuer, subject, audience, description string) string {
	return fmt.Sprintf(
		`{"name":"netbird","issuer":%q,"subject":%q,"description":%q,"audiences":[%q]}`,
		issuer, subject, description, audience,
	)
}

// GetAzureDeployScript renders the az CLI setup steps. Each role gets its own
// App Registration, so there's no shared trust step.
func (m *roleManagerImpl) GetAzureDeployScript(ctx context.Context, accountID, userID, cloudAccessID, roleID, mode string) (*CloudDeploySteps, error) {
	if err := m.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}

	if mode == "" {
		mode = azureDeployModeCreate
	}
	if mode != azureDeployModeCreate && mode != azureDeployModeImport {
		return nil, status.Errorf(status.InvalidArgument, "unsupported deploy script mode %q", mode)
	}

	access, err := m.store.GetCloudAccessByID(ctx, store.LockingStrengthNone, accountID, cloudAccessID)
	if err != nil {
		return nil, fmt.Errorf("get cloud access: %w", err)
	}
	if access.Provider != types.ProviderAzure {
		return nil, status.Errorf(status.InvalidArgument, "the Azure deploy script is only available for Azure providers")
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

	issuerIdentity, _ := issuerIdentityAndHostPath(m.federationIssuerURL)
	credentialJSON := azureFederatedCredentialJSON(issuerIdentity, azureSubjectForRole(role.ID), azureFederatedCredentialAudience, azureFederatedCredentialDescription(role))
	credentialJSONQuoted := shellSingleQuote(credentialJSON)

	var steps []CloudDeployStep
	switch mode {
	case azureDeployModeCreate:
		cmd := fmt.Sprintf(
			"APP_ID=$(az ad app create --display-name %s --query appId -o tsv) && \\\n"+
				"az ad app federated-credential create --id \"$APP_ID\" --parameters %s && \\\n"+
				"az ad sp create --id \"$APP_ID\" && \\\n"+
				"echo \"Application (Client) ID: $APP_ID\"",
			shellSingleQuote("NetBird: "+role.Name), credentialJSONQuoted,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Create the App Registration",
			Description: "Creates the App Registration NetBird will federate into. Copy the printed Application (Client) ID into this role's Client ID field.",
			Command:     cmd,
		})
	case azureDeployModeImport:
		clientIDQuoted := shellSingleQuote(role.PrincipalName)
		cmd := fmt.Sprintf(
			"az ad app federated-credential create \\\n  --id %s \\\n  --parameters %s",
			clientIDQuoted, credentialJSONQuoted,
		)
		steps = append(steps, CloudDeployStep{
			Title:       "Add the federated credential",
			Description: "Grants NetBird permission to request tokens for this existing App Registration.",
			Command:     cmd,
		})
	}

	return &CloudDeploySteps{Steps: steps}, nil
}
