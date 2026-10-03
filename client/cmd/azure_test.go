package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func fakeJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]int64{"exp": exp.Unix()})
	require.NoError(t, err)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestAzureConfigureInstructions_WindowsUsesBothCmdAndPowerShellSyntax(t *testing.T) {
	out := azureConfigureInstructions("windows", `C:\Users\shab\.azure\netbird-default-federated-token.jwt`, "133e00c0-6cfa-4c16-ad93-a86ed91d1c91", "509f2a5a-0a57-4708-a718-63425cac4786")

	// cmd.exe form — no quotes, "set" not "export".
	assert.Contains(t, out, "set AZURE_CLIENT_ID=133e00c0-6cfa-4c16-ad93-a86ed91d1c91")
	assert.Contains(t, out, "set AZURE_TENANT_ID=509f2a5a-0a57-4708-a718-63425cac4786")
	assert.Contains(t, out, `set AZURE_FEDERATED_TOKEN_FILE=C:\Users\shab\.azure\netbird-default-federated-token.jwt`)

	// cmd.exe az login, built from the just-set env vars (not repeated literals).
	assert.Contains(t, out, `for /f "delims=" %i in (%AZURE_FEDERATED_TOKEN_FILE%) do set "AZURE_FEDERATED_TOKEN=%i"`)
	assert.Contains(t, out, `az login --federated-token "%AZURE_FEDERATED_TOKEN%" --service-principal -u "%AZURE_CLIENT_ID%" -t "%AZURE_TENANT_ID%"`)

	// PowerShell form.
	assert.Contains(t, out, `$env:AZURE_CLIENT_ID="133e00c0-6cfa-4c16-ad93-a86ed91d1c91"`)
	assert.Contains(t, out, `$env:AZURE_TENANT_ID="509f2a5a-0a57-4708-a718-63425cac4786"`)
	assert.Contains(t, out, `$env:AZURE_FEDERATED_TOKEN_FILE="C:\Users\shab\.azure\netbird-default-federated-token.jwt"`)
	assert.Contains(t, out, `az login --federated-token (Get-Content $env:AZURE_FEDERATED_TOKEN_FILE -Raw) --service-principal -u $env:AZURE_CLIENT_ID -t $env:AZURE_TENANT_ID`)

	assert.NotContains(t, out, "export ")
	assert.NotContains(t, out, "$(cat")
}

func TestAzureConfigureInstructions_LinuxUsesPOSIXShellSyntax(t *testing.T) {
	out := azureConfigureInstructions("linux", "/home/shab/.azure/netbird-default-federated-token.jwt", "133e00c0-6cfa-4c16-ad93-a86ed91d1c91", "509f2a5a-0a57-4708-a718-63425cac4786")

	assert.Contains(t, out, "export AZURE_CLIENT_ID=133e00c0-6cfa-4c16-ad93-a86ed91d1c91")
	assert.Contains(t, out, "export AZURE_TENANT_ID=509f2a5a-0a57-4708-a718-63425cac4786")
	assert.Contains(t, out, `export AZURE_FEDERATED_TOKEN_FILE="/home/shab/.azure/netbird-default-federated-token.jwt"`)
	assert.Contains(t, out, `az login --federated-token "$(cat "$AZURE_FEDERATED_TOKEN_FILE")" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID`)
	assert.NotContains(t, out, "$env:")
	assert.NotContains(t, out, "Get-Content")
}

func TestAzureConfigureInstructions_DarwinUsesPOSIXShellSyntax(t *testing.T) {
	out := azureConfigureInstructions("darwin", "/Users/shab/.azure/netbird-default-federated-token.jwt", "133e00c0-6cfa-4c16-ad93-a86ed91d1c91", "509f2a5a-0a57-4708-a718-63425cac4786")

	assert.Contains(t, out, "export AZURE_CLIENT_ID=133e00c0-6cfa-4c16-ad93-a86ed91d1c91")
	assert.Contains(t, out, "export AZURE_TENANT_ID=509f2a5a-0a57-4708-a718-63425cac4786")
	assert.Contains(t, out, `export AZURE_FEDERATED_TOKEN_FILE="/Users/shab/.azure/netbird-default-federated-token.jwt"`)
	assert.Contains(t, out, `az login --federated-token "$(cat "$AZURE_FEDERATED_TOKEN_FILE")" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID`)
}

func TestAzureConfigureInstructions_QuotesTokenPathAgainstSpaces(t *testing.T) {
	out := azureConfigureInstructions("linux", "/home/shab/My Documents/federated-token.jwt", "client-id", "tenant-id")

	assert.Contains(t, out, `export AZURE_FEDERATED_TOKEN_FILE="/home/shab/My Documents/federated-token.jwt"`)
	assert.Contains(t, out, `$(cat "$AZURE_FEDERATED_TOKEN_FILE")`)
}

func TestAzureConfigureInstructions_AlwaysIncludesRefreshReminder(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		out := azureConfigureInstructions(goos, "/path/token.jwt", "client-id", "tenant-id")
		assert.Contains(t, out, "is not refreshed automatically", "goos=%s", goos)
	}
}

func TestAzureAssertionFromResponse_Allowed(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{
		Allowed: true,
		Credentials: map[string]string{
			"id_token": "fake.jwt.assertion",
		},
	}

	assertion, err := azureAssertionFromResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, "fake.jwt.assertion", assertion)
}

func TestAzureAssertionFromResponse_DeniedReturnsNoAssertion(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{
		Allowed:    false,
		DenyReason: "no enabled policy grants this peer access",
	}

	assertion, err := azureAssertionFromResponse(resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no enabled policy grants this peer access")
	assert.Empty(t, assertion)
}

func TestAzureAssertionFromResponse_DeniedWithEmptyReasonStillErrors(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{Allowed: false}

	_, err := azureAssertionFromResponse(resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestAzureAssertionFromResponse_AllowedWithNoTokenErrors(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{
		Allowed:     true,
		Credentials: map[string]string{},
	}

	_, err := azureAssertionFromResponse(resp)
	require.Error(t, err)
}

func TestAzureFederatedTokenFilePath_UsesEnvVar(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom-token.jwt")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", customPath)

	got, err := azureFederatedTokenFilePath("default")
	require.NoError(t, err)
	assert.Equal(t, customPath, got)
}

func TestAzureFederatedTokenFilePath_FallsBackToAzureCLIDirectory(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	got, err := azureFederatedTokenFilePath("default")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, ".azure", "netbird-default-federated-token.jwt"), got)
}

func TestAzureFederatedTokenFilePath_FoldsInNetBirdProfile(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	work, err := azureFederatedTokenFilePath("Work Account")
	require.NoError(t, err)
	personal, err := azureFederatedTokenFilePath("Personal")
	require.NoError(t, err)

	assert.NotEqual(t, work, personal)
	assert.Equal(t, filepath.Join(dir, ".azure", "netbird-work-account-federated-token.jwt"), work)
	assert.Equal(t, filepath.Join(dir, ".azure", "netbird-personal-federated-token.jwt"), personal)
}

func TestAzureFederatedTokenFilePath_EmptyProfileOmitsSlug(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	got, err := azureFederatedTokenFilePath("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, ".azure", "netbird-federated-token.jwt"), got)
}

func TestAzureTokenFileMarkerPath_SwapsExtensionRatherThanAppending(t *testing.T) {
	got := azureTokenFileMarkerPath("/home/shab/.azure/netbird-default-federated-token.jwt")
	assert.Equal(t, "/home/shab/.azure/netbird-default-federated-token.integration", got)
}

func TestAzureTokenFileIsForeign(t *testing.T) {
	cases := []struct {
		name     string
		write    func(t *testing.T, path string) // nil means the file is never written
		expected bool
	}{
		{"missing file is not foreign", nil, false},
		{"NetBird-written file is not foreign", func(t *testing.T, path string) {
			require.NoError(t, writeAzureFederatedTokenFile(path, "fake.jwt.assertion", "clin_azure1"))
		}, false},
		{"unrelated file is foreign", func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte("someone.elses.token\n"), 0600))
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "federated-token.jwt")
			if tc.write != nil {
				tc.write(t, path)
			}

			foreign, err := azureTokenFileIsForeign(path)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, foreign)
		})
	}
}

func TestAzureConfiguredIntegrationID(t *testing.T) {
	cases := []struct {
		name       string
		write      func(t *testing.T, path string) // nil means the file is never written
		expectedID string
	}{
		{"missing file returns empty", nil, ""},
		{"NetBird-written file returns its integration ID", func(t *testing.T, path string) {
			require.NoError(t, writeAzureFederatedTokenFile(path, fakeJWT(t, time.Now().Add(time.Hour)), "clin_azure1"))
		}, "clin_azure1"},
		{"foreign file returns empty", func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte("someone.elses.token\n"), 0600))
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "federated-token.jwt")
			if tc.write != nil {
				tc.write(t, path)
			}

			id, err := azureConfiguredIntegrationID(path)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedID, id)
		})
	}
}

func TestAzureConfiguredIntegrationID_ExpiredTokenReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "federated-token.jwt")
	require.NoError(t, writeAzureFederatedTokenFile(path, fakeJWT(t, time.Now().Add(-time.Hour)), "clin_azure1"))

	id, err := azureConfiguredIntegrationID(path)
	require.NoError(t, err)
	assert.Empty(t, id)

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "expired token file must be deleted")
	_, err = os.Stat(azureTokenFileMarkerPath(path))
	assert.True(t, os.IsNotExist(err), "expired token's marker file must be deleted")
}

func TestAzureTokenFileExpired(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.jwt")
	require.NoError(t, os.WriteFile(valid, []byte(fakeJWT(t, time.Now().Add(time.Hour))), 0600))
	assert.False(t, azureTokenFileExpired(valid))

	expired := filepath.Join(dir, "expired.jwt")
	require.NoError(t, os.WriteFile(expired, []byte(fakeJWT(t, time.Now().Add(-time.Hour))), 0600))
	assert.True(t, azureTokenFileExpired(expired))

	malformed := filepath.Join(dir, "malformed.jwt")
	require.NoError(t, os.WriteFile(malformed, []byte("not-a-jwt"), 0600))
	assert.True(t, azureTokenFileExpired(malformed), "an unparseable token must be treated as expired, not error out")

	assert.True(t, azureTokenFileExpired(filepath.Join(dir, "missing.jwt")))
}

func TestWriteAzureFederatedTokenFile_TokenFileContentIsExactlyTheAssertion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "federated-token.jwt")
	require.NoError(t, writeAzureFederatedTokenFile(path, "fake.jwt.assertion", "clin_azure1"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "fake.jwt.assertion\n", string(content))
}
