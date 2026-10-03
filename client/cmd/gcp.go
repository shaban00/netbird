package cmd

import (
	"bufio"
	"context"
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
	gcpConfigureIntegrationID string
	gcpConfigureYes           bool
)

// gcpCredentialsCommandPattern matches a credential_source executable command
var gcpCredentialsCommandPattern = regexp.MustCompile(`(^|[/\\])netbird(\.exe)?'? gcp credentials (\S+)$`)

const (
	gcpWorkloadIdentityPoolID               = "netbird-pool"
	gcpWorkloadIdentityProviderID           = "netbird-oidc"
	gcpIDTokenType                          = "urn:ietf:params:oauth:token-type:id_token"
	gcpSubjectTokenTypeJWT                  = "urn:ietf:params:oauth:token-type:jwt"
	gcpSTSTokenURL                          = "https://sts.googleapis.com/v1/token"
	gcpServiceAccountImpersonationURLFormat = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	gcpMinTokenLifetimeSeconds              = 600
	gcpMaxTokenLifetimeSeconds              = 3600
)

type gcpExecutableCredentialResponse struct {
	Version        int    `json:"version"`
	Success        bool   `json:"success"`
	TokenType      string `json:"token_type,omitempty"`
	IDToken        string `json:"id_token,omitempty"`
	ExpirationTime int64  `json:"expiration_time,omitempty"`
	Code           string `json:"code,omitempty"`
	Message        string `json:"message,omitempty"`
}

// gcpCredentialConfig is a GCP external-account credential configuration file (AIP-4117). https://google.aip.dev/auth/4117
type gcpCredentialConfig struct {
	Type                           string                             `json:"type"`
	Audience                       string                             `json:"audience"`
	SubjectTokenType               string                             `json:"subject_token_type"`
	ServiceAccountImpersonationURL string                             `json:"service_account_impersonation_url"`
	ServiceAccountImpersonation    gcpServiceAccountImpersonationJSON `json:"service_account_impersonation"`
	TokenURL                       string                             `json:"token_url"`
	CredentialSource               gcpCredentialSourceJSON            `json:"credential_source"`
}

type gcpServiceAccountImpersonationJSON struct {
	TokenLifetimeSeconds int64 `json:"token_lifetime_seconds"`
}

type gcpCredentialSourceJSON struct {
	Executable gcpExecutableSourceJSON `json:"executable"`
}

type gcpExecutableSourceJSON struct {
	Command string `json:"command"`
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "GCP cloud access commands",
}

var gcpCredentialsCmd = &cobra.Command{
	Use:     "credentials <integration-id>",
	Short:   "Print a federation assertion for a configured cloud integration",
	Example: "  netbird gcp credentials dakbbe33gajg009bvaqg",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := gcpCredentialsFunc(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
}

var gcpConfigureCmd = &cobra.Command{
	Use:     "configure",
	Short:   "Discover an authorized GCP cloud integration and set up Application Default Credentials for it",
	Example: "  netbird gcp configure\n  netbird gcp configure --integration dakbbe33gajg009bvaqg\n  netbird gcp configure --yes",
	RunE:    gcpConfigureFunc,
}

func init() {
	gcpCmd.AddCommand(gcpCredentialsCmd)
	gcpConfigureCmd.Flags().StringVar(&gcpConfigureIntegrationID, "integration", "", "cloud integration ID to use (skips the picker when you're authorized for more than one)")
	gcpConfigureCmd.Flags().BoolVar(&gcpConfigureYes, "yes", false, "overwrite an existing Application Default Credentials file that NetBird didn't create, without prompting")
	gcpCmd.AddCommand(gcpConfigureCmd)
}

// gcpWorkloadIdentityPoolProviderAudience returns the pool provider's resource
// name for use as the credential config audience.
func gcpWorkloadIdentityPoolProviderAudience(projectNumber string) string {
	return fmt.Sprintf(
		"//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
		projectNumber, gcpWorkloadIdentityPoolID, gcpWorkloadIdentityProviderID,
	)
}

func gcpCredentialsFunc(cmd *cobra.Command, args []string) error {
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
		Provider:      "gcp",
	})
	if err != nil {
		return fmt.Errorf("request cloud credentials: %w", err)
	}

	encoded, err := gcpExecutableCredentialJSON(resp)
	if _, printErr := fmt.Fprintln(os.Stdout, encoded); printErr != nil {
		return printErr
	}
	return err
}

// gcpExecutableCredentialJSON renders response per AIP-4117. https://google.aip.dev/auth/4117
func gcpExecutableCredentialJSON(resp *proto.GetCloudCredentialsResponse) (string, error) {
	if !resp.GetAllowed() {
		reason := resp.GetDenyReason()
		if reason == "" {
			reason = "access denied"
		}
		// Per AIP-4117, a failed executable must still emit the version/success/
		// code/message schema on stdout so the GCP SDK can surface a real error
		// instead of failing to parse an empty response.
		out := gcpExecutableCredentialResponse{
			Version: 1,
			Success: false,
			Code:    "403",
			Message: reason,
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return "", fmt.Errorf("encode credentials: %w", err)
		}
		return string(encoded), fmt.Errorf("NetBird denied cloud access because %s", reason)
	}

	out := gcpExecutableCredentialResponse{
		Version:   1,
		Success:   true,
		TokenType: gcpIDTokenType,
		IDToken:   resp.GetCredentials()["id_token"],
	}
	if exp := resp.GetExpiresAt(); exp != nil {
		out.ExpirationTime = exp.AsTime().Unix()
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("encode credentials: %w", err)
	}
	return string(encoded), nil
}

func gcpClampTokenLifetimeSeconds(seconds int64) int64 {
	if seconds <= 0 {
		return gcpMinTokenLifetimeSeconds
	}
	if seconds < gcpMinTokenLifetimeSeconds {
		return gcpMinTokenLifetimeSeconds
	}
	if seconds > gcpMaxTokenLifetimeSeconds {
		return gcpMaxTokenLifetimeSeconds
	}
	return seconds
}

// gcpExecutableCommand builds the credential_source.executable.command string
func gcpExecutableCommand(command, integrationID string) string {
	if strings.ContainsAny(command, ` \`) {
		command = "'" + command + "'"
	}
	return fmt.Sprintf("%s gcp credentials %s", command, integrationID)
}

// buildGCPCredentialConfig renders the credential configuration file's content for integration
func buildGCPCredentialConfig(integration *proto.CloudIntegrationSummary, command string) gcpCredentialConfig {
	return gcpCredentialConfig{
		Type:                           "external_account",
		Audience:                       gcpWorkloadIdentityPoolProviderAudience(integration.GetProviderAccountId()),
		SubjectTokenType:               gcpSubjectTokenTypeJWT,
		ServiceAccountImpersonationURL: fmt.Sprintf(gcpServiceAccountImpersonationURLFormat, integration.GetPrincipalName()),
		ServiceAccountImpersonation: gcpServiceAccountImpersonationJSON{
			TokenLifetimeSeconds: gcpClampTokenLifetimeSeconds(integration.GetCredentialLifetimeSeconds()),
		},
		TokenURL: gcpSTSTokenURL,
		CredentialSource: gcpCredentialSourceJSON{
			Executable: gcpExecutableSourceJSON{
				Command: gcpExecutableCommand(command, integration.GetId()),
			},
		},
	}
}

func gcpConfigureFunc(cmd *cobra.Command, _ []string) error {
	daemonCtx, err := loadCloudDaemonContext(cmd)
	if err != nil {
		return err
	}

	gcpIntegrations := filterIntegrationsByProvider(daemonCtx.authorized, "gcp")

	configPath, err := gcpADCFilePath()
	if err != nil {
		return fmt.Errorf("determine Application Default Credentials file location: %w", err)
	}

	activeID, err := gcpConfiguredIntegrationID(configPath)
	if err != nil {
		return fmt.Errorf("inspect existing Application Default Credentials file: %w", err)
	}
	var configured map[string][]string
	if activeID != "" {
		configured = map[string][]string{activeID: {"default"}}
	}

	stdin := bufio.NewReader(cmd.InOrStdin())
	integration, err := selectCloudIntegration(gcpIntegrations, gcpConfigureIntegrationID, stdin, cmd.OutOrStdout(), configured)
	if err != nil {
		return err
	}
	if integration.GetProviderAccountId() == "" || integration.GetPrincipalName() == "" {
		return fmt.Errorf("cloud integration %q is missing its GCP project number or service account email; ask an administrator to check its configuration", integration.GetName())
	}

	foreign, err := gcpCredentialConfigIsForeign(configPath)
	if err != nil {
		return fmt.Errorf("inspect existing Application Default Credentials file: %w", err)
	}
	if foreign && !gcpConfigureYes {
		confirmed, err := confirmOverwriteForeignDefault(stdin, cmd.OutOrStdout())
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted; Application Default Credentials (ADC) file left unchanged.")
			return nil
		}
	}

	command := "netbird"
	if exe, err := os.Executable(); err == nil {
		command = exe
	}

	config := buildGCPCredentialConfig(integration, command)

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credential configuration: %w", err)
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := writeCredentialFile(configPath, append(encoded, '\n'), 0600); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", configPath, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Configured Application Default Credentials for %q at %s\n", integration.GetName(), configPath)
	fmt.Fprint(cmd.OutOrStdout(), gcpEnvVarInstructions(runtime.GOOS))
	fmt.Fprintln(cmd.OutOrStdout(), "NOTE: Revocation may take a few minutes to apply because gcloud caches access tokens.")
	return nil
}

// gcpEnvVarInstructions shows how to set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 in the user's OS shell syntax.
func gcpEnvVarInstructions(goos string) string {
	var b strings.Builder
	fmt.Fprintln(&b, "GCP requires GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 to run an executable-sourced credential — add this to your shell profile:")
	if goos == "windows" {
		fmt.Fprintln(&b, "    cmd.exe:    set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1")
		fmt.Fprintln(&b, "    PowerShell: $env:GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = \"1\"")
	} else {
		fmt.Fprintln(&b, "    export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1")
	}
	return b.String()
}

// gcpADCFilePath uses GOOGLE_APPLICATION_CREDENTIALS and fallbacks to ADC default location
func gcpADCFilePath() (string, error) {
	if p := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "gcloud", "application_default_credentials.json"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"), nil
}

// readGCPCredentialConfig reads and parses the ADC file at path
func readGCPCredentialConfig(path string) (*gcpCredentialConfig, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	existing = trimConfigBOM(existing)

	var config gcpCredentialConfig
	if err := json.Unmarshal(existing, &config); err != nil {
		return nil, nil
	}
	return &config, nil
}

func gcpCredentialConfigIsForeign(path string) (bool, error) {
	config, err := readGCPCredentialConfig(path)
	if err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	if config.Type != "external_account" {
		return true, nil
	}
	return !gcpCredentialsCommandPattern.MatchString(config.CredentialSource.Executable.Command), nil
}

// gcpConfiguredIntegrationID returns the role ID in the ADC file
func gcpConfiguredIntegrationID(path string) (string, error) {
	config, err := readGCPCredentialConfig(path)
	if err != nil {
		return "", err
	}
	if config == nil || config.Type != "external_account" {
		return "", nil
	}
	match := gcpCredentialsCommandPattern.FindStringSubmatch(config.CredentialSource.Executable.Command)
	if match == nil {
		return "", nil
	}
	return match[len(match)-1], nil
}
