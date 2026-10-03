package cloudaccess

import (
	"context"
	"encoding/json"
	"os"
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

func TestGetAWSDeployScript_RejectsNonAWSProvider(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidGCPCloudAccess() // GCP, not AWS
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)

	_, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, "role1", "")
	require.Error(t, err)
}

func TestGetAWSDeployScript_RequiresFederationIssuerConfigured(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = false

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)

	_, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "")
	require.Error(t, err)
}

func TestGetAWSDeployScript_RejectsUnsupportedMode(t *testing.T) {
	mgr, _, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)

	_, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, "role1", "delete-everything")
	require.Error(t, err)
}

func TestGetAWSDeployScript_FirstRoleIncludesProviderCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(nil, nil)

	steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 2)

	provider := steps.Steps[0]
	assert.Contains(t, provider.Command, "aws iam create-open-id-connect-provider")
	assert.Contains(t, provider.Command, "--client-id-list 'sts.amazonaws.com'")
	assert.NotContains(t, provider.Command, "--thumbprint-list", "deliberately omitted — AWS auto-verifies well-known CAs")
	assert.Contains(t, provider.Command, "'https://netbird.example.com/federation'")
	assert.NotContains(t, provider.Command, "$", "every value must already be substituted — no shell variables")

	role2 := steps.Steps[1]
	assert.Contains(t, role2.Command, "aws iam create-role")
	assert.Contains(t, role2.Command, "--role-name 'NetBirdDeveloper'")
}

func TestGetAWSDeployScript_LaterRoleSkipsProviderCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	connectedSibling := testValidRole(access.ID)
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	for _, step := range steps.Steps {
		assert.NotContains(t, step.Command, "create-open-id-connect-provider")
	}
	assert.Contains(t, steps.Steps[0].Command, "arn:aws:iam::123456789012:oidc-provider/netbird.example.com/federation")
}

func TestGetAWSDeployScript_CreateModeIncludesRoleCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	connectedSibling := testValidRole(access.ID)
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "create")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	cmd := steps.Steps[0].Command
	assert.Contains(t, cmd, "aws iam create-role")
	assert.Contains(t, cmd, "--role-name 'NetBirdDeveloper'")
	assert.NotContains(t, cmd, "get-role")
	assert.NotContains(t, cmd, "update-assume-role-policy")
	assert.NotContains(t, cmd, "$", "every value must already be substituted — no shell variables")
}

func TestGetAWSDeployScript_ImportModeSkipsRoleCreation(t *testing.T) {
	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	connectedSibling := testValidRole(access.ID)
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "import")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)

	cmd := steps.Steps[0].Command
	assert.NotContains(t, cmd, "aws iam create-role")
	assert.Contains(t, cmd, "aws iam get-role")
	assert.Contains(t, cmd, "aws iam update-assume-role-policy")
	assert.Contains(t, cmd, "jq ")
}

func TestGetAWSDeployScript_ImportModeMergesNotReplaces(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available on this system")
	}

	mgr, mockStore, perms, _ := newTestRoleManager(t)
	mgr.federationEnabled = true
	mgr.federationIssuerURL = "https://netbird.example.com/federation"

	access := testValidCloudAccess()
	role := testValidRole(access.ID)
	connectedSibling := testValidRole(access.ID)
	connectedSibling.Status = types.StatusConnected
	perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
	mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
		Return([]*types.CloudRole{connectedSibling}, nil)

	steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, "import")
	require.NoError(t, err)
	require.Len(t, steps.Steps, 1)
	command := steps.Steps[0].Command

	tmpDir := t.TempDir()
	fakeAWS := filepath.Join(tmpDir, "aws")
	fakeAWSScript := "#!/usr/bin/env bash\n" +
		"if [ \"$1\" = \"iam\" ] && [ \"$2\" = \"get-role\" ]; then\n" +
		"  cat \"$FAKE_CURRENT_POLICY_FILE\"\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"iam\" ] && [ \"$2\" = \"update-assume-role-policy\" ]; then\n" +
		"  prev=\"\"\n" +
		"  for arg in \"$@\"; do\n" +
		"    if [ \"$prev\" = \"--policy-document\" ]; then\n" +
		"      printf '%s' \"$arg\" > \"$FAKE_OUTPUT_FILE\"\n" +
		"    fi\n" +
		"    prev=\"$arg\"\n" +
		"  done\n" +
		"  exit 0\n" +
		"fi\n" +
		"echo \"unexpected aws invocation: $*\" >&2\n" +
		"exit 1\n"
	require.NoError(t, os.WriteFile(fakeAWS, []byte(fakeAWSScript), 0755))

	existingPolicyWithEC2 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	buildEnv := func(extra ...string) []string {
		env := make([]string, 0, len(os.Environ())+len(extra)+1)
		for _, e := range os.Environ() {
			if strings.HasPrefix(e, "PATH=") {
				continue
			}
			env = append(env, e)
		}
		env = append(env, "PATH="+tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		env = append(env, extra...)
		return env
	}

	runOnce := func(currentPolicyFile, outputFile string) string {
		cmd := exec.Command("bash", "-c", command)
		cmd.Env = buildEnv(
			"FAKE_CURRENT_POLICY_FILE="+currentPolicyFile,
			"FAKE_OUTPUT_FILE="+outputFile,
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "generated command must succeed: %s", string(out))
		result, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		return string(result)
	}

	currentFile := filepath.Join(tmpDir, "current.json")
	outputFile := filepath.Join(tmpDir, "output.json")
	require.NoError(t, os.WriteFile(currentFile, []byte(existingPolicyWithEC2), 0600))

	firstResult := runOnce(currentFile, outputFile)

	var parsed struct {
		Statement []map[string]interface{} `json:"Statement"`
	}
	require.NoError(t, json.Unmarshal([]byte(firstResult), &parsed))

	countBySid := func(statements []map[string]interface{}, sid string) int {
		n := 0
		for _, s := range statements {
			if s["Sid"] == sid {
				n++
			}
		}
		return n
	}
	hasEC2 := func(statements []map[string]interface{}) bool {
		for _, s := range statements {
			if principal, ok := s["Principal"].(map[string]interface{}); ok && principal["Service"] == "ec2.amazonaws.com" {
				return true
			}
		}
		return false
	}

	assert.True(t, hasEC2(parsed.Statement), "the role's pre-existing EC2 trust statement must survive the merge")
	assert.Equal(t, 1, countBySid(parsed.Statement, "NetBirdFederationTrust"), "NetBird's statement must be added exactly once")

	secondCurrentFile := filepath.Join(tmpDir, "current2.json")
	require.NoError(t, os.WriteFile(secondCurrentFile, []byte(firstResult), 0600))
	secondOutputFile := filepath.Join(tmpDir, "output2.json")
	secondResult := runOnce(secondCurrentFile, secondOutputFile)

	var parsed2 struct {
		Statement []map[string]interface{} `json:"Statement"`
	}
	require.NoError(t, json.Unmarshal([]byte(secondResult), &parsed2))
	assert.True(t, hasEC2(parsed2.Statement), "EC2 statement must still be present after a second merge run")
	assert.Equal(t, 1, countBySid(parsed2.Statement, "NetBirdFederationTrust"), "a second merge run must not duplicate NetBird's statement")
}

func TestGetAWSDeployScript_RoleNameWithShellMetacharactersIsNeutralized(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this system")
	}

	for _, mode := range []string{"create", "import"} {
		t.Run(mode, func(t *testing.T) {
			canary := filepath.Join(t.TempDir(), "netbird-shellquote-poc")

			mgr, mockStore, perms, _ := newTestRoleManager(t)
			mgr.federationEnabled = true
			mgr.federationIssuerURL = "https://netbird.example.com/federation"

			access := testValidCloudAccess()
			role := testValidRole(access.ID)
			role.PrincipalName = "x'; touch " + canary + "; echo 'y"
			connectedSibling := testValidRole(access.ID)
			connectedSibling.Status = types.StatusConnected
			perms.expectValidate(testAccountID, testUserID, modules.CloudAccess, operations.Read, true, nil)
			mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, access.ID).Return(access, nil)
			mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, role.ID).Return(role, nil)
			mockStore.EXPECT().GetCloudRolesByCloudAccessID(gomock.Any(), gomock.Any(), testAccountID, access.ID).
				Return([]*types.CloudRole{connectedSibling}, nil)

			steps, err := mgr.GetAWSDeployScript(context.Background(), testAccountID, testUserID, access.ID, role.ID, mode)
			require.NoError(t, err)
			require.Len(t, steps.Steps, 1)

			assertBashSyntaxValid(t, steps.Steps[0].Command)
			assertShellPayloadNeverExecutes(t, steps.Steps[0].Command, canary)
		})
	}
}

func assertBashSyntaxValid(t *testing.T, command string) {
	t.Helper()
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(command)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "generated command must be syntactically valid bash: %s\ncommand:\n%s", string(out), command)
}

func assertShellPayloadNeverExecutes(t *testing.T, command, canaryPath string) {
	t.Helper()
	_ = os.Remove(canaryPath)
	t.Cleanup(func() { _ = os.Remove(canaryPath) })

	cmd := exec.Command("bash", "-c", command)
	_ = cmd.Run() // exit status is irrelevant — the outer binary isn't real

	_, err := os.Stat(canaryPath)
	assert.True(t, os.IsNotExist(err), "shell metacharacter payload escaped quoting and actually executed — canary file was created")
}
