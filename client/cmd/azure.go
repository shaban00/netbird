package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	azureConfigureIntegrationID string
	azureConfigureYes           bool
)

var azureProfileNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Azure cloud access commands",
}

var azureCredentialsCmd = &cobra.Command{
	Use:     "credentials <integration-id>",
	Short:   "Print a federation assertion for a configured cloud integration",
	Example: "  netbird azure credentials dakbbe33gajg009bvaqg",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := azureCredentialsFunc(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
}

var azureConfigureCmd = &cobra.Command{
	Use:     "configure",
	Short:   "Discover an authorized Azure cloud integration and write its federated token file",
	Example: "  netbird azure configure\n  netbird azure configure --integration dakbbe33gajg009bvaqg\n  netbird azure configure --yes",
	RunE:    azureConfigureFunc,
}

func init() {
	azureCmd.AddCommand(azureCredentialsCmd)
	azureConfigureCmd.Flags().StringVar(&azureConfigureIntegrationID, "integration", "", "cloud integration ID to use (skips the picker when you're authorized for more than one)")
	azureConfigureCmd.Flags().BoolVar(&azureConfigureYes, "yes", false, "overwrite an existing federated token file that NetBird didn't create, without prompting")
	azureCmd.AddCommand(azureConfigureCmd)
}

func azureCredentialsFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	integrationID := args[0]

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	resp, err := client.GetCloudCredentials(ctx, &proto.GetCloudCredentialsRequest{
		IntegrationId: integrationID,
		Provider:      "azure",
	})
	if err != nil {
		return fmt.Errorf("request cloud credentials: %w", err)
	}

	assertion, err := azureAssertionFromResponse(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, assertion)
	return err
}

// azureAssertionFromResponse extracts the raw assertion (Credentials["id_token"]).
func azureAssertionFromResponse(resp *proto.GetCloudCredentialsResponse) (string, error) {
	if !resp.GetAllowed() {
		reason := resp.GetDenyReason()
		if reason == "" {
			reason = "access denied"
		}
		return "", fmt.Errorf("NetBird denied cloud access because %s", reason)
	}

	assertion := resp.GetCredentials()["id_token"]
	if assertion == "" {
		return "", fmt.Errorf("daemon returned no federation assertion")
	}
	return assertion, nil
}

func azureConfigureFunc(cmd *cobra.Command, _ []string) error {
	daemonCtx, err := loadCloudDaemonContext(cmd)
	if err != nil {
		return err
	}

	azureIntegrations := filterIntegrationsByProvider(daemonCtx.authorized, "azure")

	tokenPath, err := azureFederatedTokenFilePath(daemonCtx.netbirdProfile)
	if err != nil {
		return fmt.Errorf("determine federated token file location: %w", err)
	}

	activeID, err := azureConfiguredIntegrationID(tokenPath)
	if err != nil {
		return fmt.Errorf("inspect existing federated token file: %w", err)
	}
	var configured map[string][]string
	if activeID != "" {
		configured = map[string][]string{activeID: {"default"}}
	}

	stdin := bufio.NewReader(cmd.InOrStdin())
	integration, err := selectCloudIntegration(azureIntegrations, azureConfigureIntegrationID, stdin, cmd.OutOrStdout(), configured)
	if err != nil {
		return err
	}
	if integration.GetProviderAccountId() == "" || integration.GetPrincipalName() == "" {
		return fmt.Errorf("cloud integration %q is missing its Azure Tenant ID or Application (Client) ID; ask an administrator to check its configuration", integration.GetName())
	}

	foreign, err := azureTokenFileIsForeign(tokenPath)
	if err != nil {
		return fmt.Errorf("inspect existing federated token file: %w", err)
	}
	if foreign && !azureConfigureYes {
		confirmed, err := confirmOverwriteForeignDefault(stdin, cmd.OutOrStdout())
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted; federated token file left unchanged.")
			return nil
		}
	}

	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	resp, err := client.GetCloudCredentials(ctx, &proto.GetCloudCredentialsRequest{
		IntegrationId: integration.GetId(),
		Provider:      "azure",
	})
	if err != nil {
		return fmt.Errorf("request cloud credentials: %w", err)
	}
	assertion, err := azureAssertionFromResponse(resp)
	if err != nil {
		return err
	}

	if err := writeAzureFederatedTokenFile(tokenPath, assertion, integration.GetId()); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Wrote a federated token for %q to %s\n", integration.GetName(), tokenPath)
	fmt.Fprint(cmd.OutOrStdout(), azureConfigureInstructions(runtime.GOOS, tokenPath, integration.GetPrincipalName(), integration.GetProviderAccountId()))
	return nil
}

// azureConfigureInstructions renders the post-write shell guidance
func azureConfigureInstructions(goos, tokenPath, clientID, tenantID string) string {
	var b strings.Builder
	if goos == "windows" {
		fmt.Fprintln(&b, "Set these and Azure SDKs (WorkloadIdentityCredential) will pick it up automatically; each block also logs in the az CLI itself in one step:")
		fmt.Fprintln(&b, "  cmd.exe:")
		fmt.Fprintf(&b, "    set AZURE_CLIENT_ID=%s\n", clientID)
		fmt.Fprintf(&b, "    set AZURE_TENANT_ID=%s\n", tenantID)
		fmt.Fprintf(&b, "    set AZURE_FEDERATED_TOKEN_FILE=%s\n", tokenPath)
		fmt.Fprintln(&b, `    for /f "delims=" %i in (%AZURE_FEDERATED_TOKEN_FILE%) do set "AZURE_FEDERATED_TOKEN=%i"`)
		fmt.Fprintln(&b, `    az login --federated-token "%AZURE_FEDERATED_TOKEN%" --service-principal -u "%AZURE_CLIENT_ID%" -t "%AZURE_TENANT_ID%"`)
		fmt.Fprintln(&b, "  PowerShell:")
		fmt.Fprintf(&b, "    $env:AZURE_CLIENT_ID=\"%s\"\n", clientID)
		fmt.Fprintf(&b, "    $env:AZURE_TENANT_ID=\"%s\"\n", tenantID)
		fmt.Fprintf(&b, "    $env:AZURE_FEDERATED_TOKEN_FILE=\"%s\"\n", tokenPath)
		fmt.Fprintln(&b, `    az login --federated-token (Get-Content $env:AZURE_FEDERATED_TOKEN_FILE -Raw) --service-principal -u $env:AZURE_CLIENT_ID -t $env:AZURE_TENANT_ID`)
	} else {
		fmt.Fprintln(&b, "Export these and Azure SDKs (WorkloadIdentityCredential) will pick it up automatically:")
		fmt.Fprintf(&b, "    export AZURE_CLIENT_ID=%s\n", clientID)
		fmt.Fprintf(&b, "    export AZURE_TENANT_ID=%s\n", tenantID)
		fmt.Fprintf(&b, "    export AZURE_FEDERATED_TOKEN_FILE=\"%s\"\n", tokenPath)
		fmt.Fprintln(&b, "For the az CLI itself, run:")
		fmt.Fprintf(&b, `    az login --federated-token "$(cat "$AZURE_FEDERATED_TOKEN_FILE")" --service-principal -u $AZURE_CLIENT_ID -t $AZURE_TENANT_ID`)
	}
	fmt.Fprintln(&b, "NOTE: This file is not refreshed automatically. Re-run \"netbird azure configure\" periodically and after policy changes; revocations apply only on the next run.")
	return b.String()
}

// azureFederatedTokenFilePath uses AZURE_FEDERATED_TOKEN_FILE if set
// and falls back to NetBird-owned file under ~/.azure
func azureFederatedTokenFilePath(netbirdProfile string) (string, error) {
	if p := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	filename := "netbird-federated-token.jwt"
	if profileSlug := strings.Trim(azureProfileNameSanitizer.ReplaceAllString(strings.ToLower(netbirdProfile), "-"), "-"); profileSlug != "" {
		filename = "netbird-" + profileSlug + "-federated-token.jwt"
	}
	return filepath.Join(home, ".azure", filename), nil
}

// azureTokenFileMarkerPath is the ".integration" sidecar that records which integration configured tokenPath
func azureTokenFileMarkerPath(tokenPath string) string {
	return strings.TrimSuffix(tokenPath, filepath.Ext(tokenPath)) + ".integration"
}

// writeAzureFederatedTokenFile writes the token file and its marker.
// Chmod follows each write since WriteFile only sets mode on create.
func writeAzureFederatedTokenFile(tokenPath, assertion, integrationID string) error {
	dir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := writeCredentialFile(tokenPath, []byte(assertion+"\n"), 0600); err != nil {
		return fmt.Errorf("write %s: %w", tokenPath, err)
	}
	if err := os.Chmod(tokenPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", tokenPath, err)
	}
	markerPath := azureTokenFileMarkerPath(tokenPath)
	if err := writeCredentialFile(markerPath, []byte(integrationID+"\n"), 0600); err != nil {
		return fmt.Errorf("write %s: %w", markerPath, err)
	}
	if err := os.Chmod(markerPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", markerPath, err)
	}
	return nil
}

// azureTokenFileIsForeign reports whether tokenPath exists but wasn't
// written by netbird azure configure (detected via the marker file).
func azureTokenFileIsForeign(tokenPath string) (bool, error) {
	if _, err := os.Stat(tokenPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", tokenPath, err)
	}
	if _, err := os.Stat(azureTokenFileMarkerPath(tokenPath)); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("stat %s: %w", azureTokenFileMarkerPath(tokenPath), err)
	}
	return false, nil
}

// azureTokenFileExpired reports whether the JWT at tokenPath is past its "exp"
// claim. Read or parse errors count as expired. This only affects display.
func azureTokenFileExpired(tokenPath string) bool {
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return true
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return true
	}
	return !time.Now().Before(time.Unix(claims.Exp, 0))
}

// azureConfiguredIntegrationID returns the integration ID from tokenPath's
// marker, or "" if none. Expired NetBird tokens are deleted here.
func azureConfiguredIntegrationID(tokenPath string) (string, error) {
	foreign, err := azureTokenFileIsForeign(tokenPath)
	if err != nil {
		return "", err
	}
	if foreign {
		return "", nil
	}
	if azureTokenFileExpired(tokenPath) {
		_ = os.Remove(tokenPath)
		_ = os.Remove(azureTokenFileMarkerPath(tokenPath))
		return "", nil
	}
	content, err := os.ReadFile(azureTokenFileMarkerPath(tokenPath))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", azureTokenFileMarkerPath(tokenPath), err)
	}
	return strings.TrimSpace(string(content)), nil
}
