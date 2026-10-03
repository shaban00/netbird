package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

func TestGCPExecutableCredentialJSON_Allowed(t *testing.T) {
	expiry := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	resp := &proto.GetCloudCredentialsResponse{
		Allowed: true,
		Credentials: map[string]string{
			"id_token": "fake.jwt.assertion",
		},
		ExpiresAt: timestamppb.New(expiry),
	}

	encoded, err := gcpExecutableCredentialJSON(resp)
	require.NoError(t, err)

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(encoded), &out))
	assert.EqualValues(t, 1, out["version"])
	assert.Equal(t, true, out["success"])
	assert.Equal(t, "urn:ietf:params:oauth:token-type:id_token", out["token_type"])
	assert.Equal(t, "fake.jwt.assertion", out["id_token"])
	assert.EqualValues(t, expiry.Unix(), out["expiration_time"])
	assert.Nil(t, out["code"], "a successful response must never carry the failure schema's fields")
	assert.Nil(t, out["message"])
}

func TestGCPExecutableCredentialJSON_DeniedWithEmptyReasonStillErrors(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{Allowed: false}

	encoded, err := gcpExecutableCredentialJSON(resp)
	require.Error(t, err)

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(encoded), &out))
	assert.Equal(t, "access denied", out["message"])
}

func TestGCPWorkloadIdentityPoolProviderAudience_UsesBareForm(t *testing.T) {
	got := gcpWorkloadIdentityPoolProviderAudience("123456789012")
	assert.Equal(t, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", got)
}

func testGCPIntegration() *proto.CloudIntegrationSummary {
	return &proto.CloudIntegrationSummary{
		Id:                "clin_gcp1",
		Name:              "Production",
		Provider:          "gcp",
		ProviderAccountId: "123456789012",
		PrincipalName:     "netbird-developer@my-project-123.iam.gserviceaccount.com",
	}
}

func TestGCPExecutableCommand_QuotesWindowsPathWithSpaces(t *testing.T) {
	got := gcpExecutableCommand(`C:\Program Files\NetBird\netbird.exe`, "clin_gcp1")
	assert.Equal(t, `'C:\Program Files\NetBird\netbird.exe' gcp credentials clin_gcp1`, got)
}

func TestGCPExecutableCommand_LeavesSimplePathUnquoted(t *testing.T) {
	got := gcpExecutableCommand("/usr/bin/netbird", "clin_gcp1")
	assert.Equal(t, "/usr/bin/netbird gcp credentials clin_gcp1", got)
}

func TestBuildGCPCredentialConfig_MatchesAIP4117Shape(t *testing.T) {
	config := buildGCPCredentialConfig(testGCPIntegration(), "/usr/bin/netbird")

	assert.Equal(t, "external_account", config.Type)
	assert.Equal(t, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/netbird-pool/providers/netbird-oidc", config.Audience)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", config.SubjectTokenType)
	assert.Equal(t, "https://sts.googleapis.com/v1/token", config.TokenURL)
	assert.Equal(t, "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/netbird-developer@my-project-123.iam.gserviceaccount.com:generateAccessToken", config.ServiceAccountImpersonationURL)
	assert.Equal(t, "/usr/bin/netbird gcp credentials clin_gcp1", config.CredentialSource.Executable.Command)
	assert.EqualValues(t, 600, config.ServiceAccountImpersonation.TokenLifetimeSeconds)
	assert.NotEqual(t, gcpIDTokenType, config.SubjectTokenType)
}

func TestGCPClampTokenLifetimeSeconds(t *testing.T) {
	assert.EqualValues(t, 600, gcpClampTokenLifetimeSeconds(0))
	assert.EqualValues(t, 600, gcpClampTokenLifetimeSeconds(-1))
	assert.EqualValues(t, 600, gcpClampTokenLifetimeSeconds(300))
	assert.EqualValues(t, 1800, gcpClampTokenLifetimeSeconds(1800))
	assert.EqualValues(t, 3600, gcpClampTokenLifetimeSeconds(7200))
}

func TestBuildGCPCredentialConfig_RoleCredentialLifetime(t *testing.T) {
	integration := testGCPIntegration()
	integration.CredentialLifetimeSeconds = 1800

	config := buildGCPCredentialConfig(integration, "/usr/bin/netbird")

	assert.EqualValues(t, 1800, config.ServiceAccountImpersonation.TokenLifetimeSeconds)
}

func TestGCPCredentialConfigIsForeign(t *testing.T) {
	bom := "\xEF\xBB\xBF"
	unrelated := `{
		"type": "external_account",
		"audience": "//iam.googleapis.com/projects/999/locations/global/workloadIdentityPools/other-pool/providers/other-provider",
		"credential_source": {
			"executable": {
				"command": "/usr/local/bin/some-other-tool get-token"
			}
		}
	}`
	netbirdWritten, err := json.Marshal(buildGCPCredentialConfig(testGCPIntegration(), "/usr/bin/netbird"))
	require.NoError(t, err)

	cases := []struct {
		name     string
		content  string // empty means the file is never written
		expected bool
	}{
		{"missing file is not foreign", "", false},
		{"unparseable file is not foreign", "not json at all", false},
		{"NetBird-written file is not foreign", string(netbirdWritten), false},
		{"unrelated external_account file is foreign", unrelated, true},
		{"service_account key file is foreign", `{"type": "service_account", "project_id": "my-project-123"}`, true},
		{"BOM-prefixed foreign config is still foreign", bom + unrelated, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "application_default_credentials.json")
			if tc.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0600))
			}

			foreign, err := gcpCredentialConfigIsForeign(path)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, foreign)
		})
	}
}

func TestGCPCredentialConfigIsForeign_QuotedWindowsPathIsNotForeign(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "application_default_credentials.json")

	config := buildGCPCredentialConfig(testGCPIntegration(), `C:\Program Files\NetBird\netbird.exe`)
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encoded, 0600))

	foreign, err := gcpCredentialConfigIsForeign(path)
	require.NoError(t, err)
	assert.False(t, foreign)

	id, err := gcpConfiguredIntegrationID(path)
	require.NoError(t, err)
	assert.Equal(t, testGCPIntegration().GetId(), id)
}

func TestGCPConfiguredIntegrationID(t *testing.T) {
	netbirdWritten, err := json.Marshal(buildGCPCredentialConfig(testGCPIntegration(), "/usr/bin/netbird"))
	require.NoError(t, err)

	cases := []struct {
		name       string
		content    string // empty means the file is never written
		expectedID string
	}{
		{"missing file returns empty", "", ""},
		{"NetBird-written file returns its integration ID", string(netbirdWritten), testGCPIntegration().GetId()},
		{"missing credential_source returns empty", `{"type": "external_account"}`, ""},
		{
			"trailing whitespace in command returns empty (the pattern requires the ID to be the exact end of the command string)",
			`{
				"type": "external_account",
				"credential_source": {
					"executable": {
						"command": "/usr/bin/netbird gcp credentials clin_gcp1 "
					}
				}
			}`,
			"",
		},
		{
			"foreign file returns empty",
			`{
				"type": "external_account",
				"credential_source": {
					"executable": {
						"command": "/usr/local/bin/some-other-tool get-token"
					}
				}
			}`,
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "application_default_credentials.json")
			if tc.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0600))
			}

			id, err := gcpConfiguredIntegrationID(path)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedID, id)
		})
	}
}

func TestGCPADCFilePath_UsesGoogleApplicationCredentialsEnvVar(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom-creds.json")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", customPath)

	got, err := gcpADCFilePath()
	require.NoError(t, err)
	assert.Equal(t, customPath, got)
}

func TestGCPADCFilePath_FallsBackToDefaultLocation(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	got, err := gcpADCFilePath()
	require.NoError(t, err)
	assert.Contains(t, got, filepath.Join(".config", "gcloud", "application_default_credentials.json"))
}

func TestGCPEnvVarInstructions_UsesShellSyntaxMatchingOS(t *testing.T) {
	windows := gcpEnvVarInstructions("windows")
	assert.Contains(t, windows, "set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1")
	assert.Contains(t, windows, `$env:GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = "1"`)
	assert.NotContains(t, windows, "export ")

	assert.Contains(t, gcpEnvVarInstructions("linux"), "export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1")
	assert.NotContains(t, gcpEnvVarInstructions("linux"), "$env:")
}
