package cloudaccess

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
)

func TestShellSingleQuote_HandlesEmbeddedNULByte(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}

	in := "before\x00; touch /tmp/netbird-shellquote-poc; echo after"
	quoted := shellSingleQuote(in)
	assert.Equal(t, "'"+in+"'", quoted, "shellSingleQuote must not special-case or strip a NUL byte")
}

func testValidGCPCloudAccess() *types.CloudAccess {
	a := testValidCloudAccess()
	a.Provider = types.ProviderGCP
	a.ProviderAccountID = "123456789012"
	a.ProviderProjectID = "my-project-123"
	return a
}

func testValidGCPRole(cloudAccessID string) *types.CloudRole {
	r := testValidRole(cloudAccessID)
	r.PrincipalName = "netbird-developer@my-project-123.iam.gserviceaccount.com"
	return r
}

func TestGetGCPDeployScript_RejectsNonGCPProvider(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess() // AWS, not GCP
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	_, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, "role1", "")
	require.Error(t, err)
}

func TestGetGCPDeployScript_RejectsMissingProviderProjectID(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	access.ProviderProjectID = ""
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	_, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, "role1", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GCP Project ID")
}

func TestGetGCPDeployScript_RequiresFederationIssuerConfigured(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = false

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)

	_, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "")
	require.Error(t, err)
}

func TestGetGCPDeployScript_RejectsUnsupportedMode(t *testing.T) {
	mgr, _, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)

	_, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, "role1", "delete-everything")
	require.Error(t, err)
}

func TestGetGCPDeployScript_FirstRoleIncludesPoolCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)

	steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 2)

	pool := steps.Steps[0]
	assert.Contains(t, pool.Command, "gcloud services enable iamcredentials.googleapis.com", "enabling the API is folded into the one-time pool step — a fresh GCP project doesn't have it enabled by default and nothing else exercises it before Validate")
	assert.Contains(t, pool.Command, "workload-identity-pools create 'netbird-pool'")
	assert.Contains(t, pool.Command, "providers create-oidc 'netbird-oidc'")
	assert.Contains(t, pool.Command, "--issuer-uri='https://netbird.example.com/federation'")
	assert.Contains(t, pool.Command, "attribute.netbird_role_id=assertion.netbird_role_id", "the attribute mapping must expose the role-scoping claim gcpprovider embeds in every assertion")
	assert.NotContains(t, pool.Command, "--allowed-audiences", "omitting this flag is deliberate")
	assert.Contains(t, pool.Command, "--project='my-project-123'")
	assert.NotContains(t, pool.Command, "$(gcloud config get-value project)", "the project ID is now stored on CloudAccess and substituted literally")

	sa := steps.Steps[1]
	assert.Contains(t, sa.Command, "service-accounts create 'netbird-developer'")
}

func TestGetGCPDeployScript_LaterRoleSkipsPoolCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	connectedSibling := testValidGCPRole(access.ID)
	connectedSibling.PrincipalName = "netbird-admin@my-project-123.iam.gserviceaccount.com"
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	for _, step := range steps.Steps {
		assert.NotContains(t, step.Command, "workload-identity-pools create")
		assert.NotContains(t, step.Command, "providers create-oidc")
		assert.NotContains(t, step.Command, "iamcredentials.googleapis.com")
	}
	assert.Contains(t, steps.Steps[0].Command, "service-accounts create 'netbird-developer'")
}

func TestGetGCPDeployScript_CreateModeIncludesServiceAccountCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	connectedSibling := testValidGCPRole(access.ID)
	connectedSibling.PrincipalName = "netbird-admin@my-project-123.iam.gserviceaccount.com"
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	cmd := steps.Steps[0].Command
	assert.Contains(t, cmd, "service-accounts create 'netbird-developer'", "the service account ID must be the local part of the email, split off before the '@'")
	assert.Contains(t, cmd, "'netbird-developer@my-project-123.iam.gserviceaccount.com'")
	assert.Contains(t, cmd, "roles/iam.workloadIdentityUser")
	assert.Contains(t, cmd,
		"principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/attribute.netbird_role_id/"+role.ID,
		"the --member binding must reference this role's own ID literally, through the attribute mapping, not a pool-wide wildcard",
	)
	assert.NotContains(t, cmd, "workloadIdentityPools/netbird-pool/*", "the binding must never fall back to a pool-wide wildcard — see the critical finding this test guards against")
	assert.NotContains(t, cmd, "$ROLE_ID", "the role ID must already be substituted literally, not left as a persisted shell variable")
	assert.NotContains(t, cmd, "$PROJECT_NUMBER", "the project number must already be substituted literally, not left as a persisted shell variable")
}

func TestGetGCPDeployScript_ImportModeSkipsServiceAccountCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	connectedSibling := testValidGCPRole(access.ID)
	connectedSibling.PrincipalName = "netbird-admin@my-project-123.iam.gserviceaccount.com"
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "import")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	cmd := steps.Steps[0].Command
	assert.NotContains(t, cmd, "service-accounts create")
	assert.Contains(t, cmd, "add-iam-policy-binding 'netbird-developer@my-project-123.iam.gserviceaccount.com'")
	assert.Contains(t, cmd, "roles/iam.workloadIdentityUser")
}

func TestGetGCPDeployScript_DifferentRolesGetDifferentMemberBindings(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	roleA := testValidGCPRole(access.ID)
	roleB := testValidGCPRole(access.ID)
	roleB.PrincipalName = "netbird-admin@my-project-123.iam.gserviceaccount.com"
	require.NotEqual(t, roleA.ID, roleB.ID, "test fixture sanity check")

	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil).Times(2)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, roleA.ID).Return(roleA, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, roleB.ID).Return(roleB, nil)

	roleA.Status = types.StatusConnected
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{roleA}, nil).Times(2)

	stepsA, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, roleA.ID, "create")
	require.NoError(t, err)
	stepsB, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, roleB.ID, "create")
	require.NoError(t, err)
	require.Len(t, stepsA.Steps, 1)
	require.Len(t, stepsB.Steps, 1)

	memberA := "attribute.netbird_role_id/" + roleA.ID
	memberB := "attribute.netbird_role_id/" + roleB.ID
	require.NotEqual(t, memberA, memberB, "test fixture sanity check")

	assert.Contains(t, stepsA.Steps[0].Command, memberA)
	assert.NotContains(t, stepsA.Steps[0].Command, memberB, "role A's step must never bind to role B's ID")

	assert.Contains(t, stepsB.Steps[0].Command, memberB)
	assert.NotContains(t, stepsB.Steps[0].Command, memberA, "role B's step must never bind to role A's ID")
}

func TestGetGCPDeployScript_RejectsMalformedPrincipalName(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	role.PrincipalName = "not-an-email"
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return(nil, nil)

	_, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.Error(t, err)
}

func TestShellSingleQuote_HandlesEmbeddedSingleQuote(t *testing.T) {
	got := shellSingleQuote(`it's a test`)
	assert.Equal(t, `'it'"'"'s a test'`, got)
}

func TestShellSingleQuote_NeutralizesShellMetacharacters(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}

	dangerous := []struct {
		name string
		in   string
	}{
		{`$(touch ...)`, `$(touch /tmp/netbird-shellquote-poc)`},
		{"backtick command substitution", "`touch /tmp/netbird-shellquote-poc`"},
		{"bare semicolon", `; touch /tmp/netbird-shellquote-poc`},
		{"single-quote breakout", `' ; touch /tmp/netbird-shellquote-poc ; echo '`},
		{"double-quote breakout", `"; touch /tmp/netbird-shellquote-poc; echo "`},
		{"embedded newline must never act as a statement separator", "first line\ntouch /tmp/netbird-shellquote-poc\nthird line"},
		{"escaping must not degrade or truncate at scale", strings.Repeat("a'; touch /tmp/netbird-shellquote-poc; echo '", 500)},
	}

	for _, tc := range dangerous {
		t.Run(tc.name, func(t *testing.T) {
			quoted := shellSingleQuote(tc.in)
			cmd := exec.Command("bash", "-c", "echo "+quoted)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "quoted value must be valid, executable shell syntax on its own: %s", quoted)
			assert.Equal(t, tc.in, strings.TrimSuffix(string(out), "\n"),
				"echo must reproduce the input literally — any deviation means something in it was expanded or executed rather than treated as inert text")
		})
	}
}

func TestGetGCPDeployScript_RoleNameWithShellMetacharactersIsNeutralized(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}

	for _, mode := range []string{"create", "import"} {
		t.Run(mode, func(t *testing.T) {
			canary := filepath.Join(t.TempDir(), "netbird-shellquote-poc")

			mgr, mockStore, perms, _ := newTestRoleManager(t)
			mgr.federationEnabled = true
			mgr.federationIssuerURL = "https://netbird.example.com/federation"

			access := testValidGCPCloudAccess()
			role := testValidGCPRole(access.ID)
			role.Name = "Developer'; touch " + canary + "; echo '"
			connectedSibling := testValidGCPRole(access.ID)
			connectedSibling.PrincipalName = "netbird-admin@my-project-123.iam.gserviceaccount.com"
			connectedSibling.Status = types.StatusConnected
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
			mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
			mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
			mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
				Return([]*types.CloudRole{connectedSibling}, nil)

			steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, mode)
			require.NoError(t, err)
			require.Len(t, steps.Steps, 1)

			cmd := exec.Command("bash", "-n")
			cmd.Stdin = strings.NewReader(steps.Steps[0].Command)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "generated command must be syntactically valid bash even with shell metacharacters in role.Name: %s\ncommand:\n%s", string(out), steps.Steps[0].Command)

			assertShellPayloadNeverExecutes(t, steps.Steps[0].Command, canary)
		})
	}
}

func TestGetGCPDeployScript_FirstRolePoolStepIsSyntacticallyValid(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}

	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess()
	role := testValidGCPRole(access.ID)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)

	steps, err := mgr.GetGCPDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 2)

	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(steps.Steps[0].Command)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "the pool-creation step must be syntactically valid bash: %s\ncommand:\n%s", string(out), steps.Steps[0].Command)
}
