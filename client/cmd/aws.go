package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var (
	awsConfigureIntegrationID string
	awsConfigureProfile       string
	awsConfigureRegion        string
	awsConfigureDefault       bool
	awsConfigureYes           bool
)

var (
	awsProfileNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	// netbirdCredentialProcessLine is how pruning recognizes a NetBird-managed profile section, regardless of name.
	netbirdCredentialProcessLine = regexp.MustCompile(`^credential_process\s*=\s*netbird aws credentials\s+(\S+)$`)
)

// awsCredentialProcessOutput is the exact JSON schema the AWS CLI/SDK's
// credential_process protocol requires on stdout. https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type awsCredentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS cloud access commands",
}

var awsCredentialsCmd = &cobra.Command{
	Use:     "credentials <integration-id>",
	Short:   "Print short-lived AWS credentials for a configured cloud integration",
	Example: "  netbird aws credentials dakbbe33gajg009bvaqg",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := awsCredentialsFunc(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	},
}

var awsConfigureCmd = &cobra.Command{
	Use:     "configure",
	Short:   "Discover an authorized cloud integration and set up an AWS CLI profile for it",
	Example: "  netbird aws configure\n  netbird aws configure --integration dakbbe33gajg009bvaqg --profile netbird-production\n  netbird aws configure --default\n  netbird aws configure --default --region us-east-1",
	RunE:    awsConfigureFunc,
}

func init() {
	awsCmd.AddCommand(awsCredentialsCmd)
	awsConfigureCmd.Flags().StringVar(&awsConfigureIntegrationID, "integration", "", "cloud integration ID to use (skips the picker when you're authorized for more than one)")
	awsConfigureCmd.Flags().StringVar(&awsConfigureProfile, "profile", "", "AWS CLI profile name to create/update (defaults to a name derived from the integration); ignored with --default")
	awsConfigureCmd.Flags().StringVar(&awsConfigureRegion, "region", "", "AWS region to set on this profile (e.g. us-east-1); left untouched if omitted")
	awsConfigureCmd.Flags().BoolVar(&awsConfigureDefault, "default", false, "point AWS CLI's [default] profile at this integration, instead of a named profile")
	awsConfigureCmd.Flags().BoolVar(&awsConfigureYes, "yes", false, "with --default, overwrite an existing [default] profile that NetBird didn't create, without prompting")
	awsCmd.AddCommand(awsConfigureCmd)
}

func awsCredentialsFunc(cmd *cobra.Command, args []string) error {
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
		Provider:      "aws",
	})
	if err != nil {
		return fmt.Errorf("request cloud credentials: %w", err)
	}

	if !resp.GetAllowed() {
		_ = pruneAWSProfileOnDenial(integrationID)
	}

	encoded, err := awsCredentialProcessJSON(resp)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, encoded)
	return err
}

// pruneAWSProfileOnDenial removes any AWS CLI profile (named or [default])
// whose credential_process invokes integrationID, after a live denial for it
func pruneAWSProfileOnDenial(integrationID string) error {
	configPath, err := awsConfigFilePath()
	if err != nil {
		return err
	}
	return pruneAWSConfigSections(configPath, true, func(id string) bool {
		return id == integrationID
	})
}

// awsCredentialProcessJSON renders response per the AWS credential_process
func awsCredentialProcessJSON(resp *proto.GetCloudCredentialsResponse) (string, error) {
	if !resp.GetAllowed() {
		reason := resp.GetDenyReason()
		if reason == "" {
			reason = "access denied"
		}
		return "", fmt.Errorf("NetBird denied cloud access because %s", reason)
	}

	creds := resp.GetCredentials()
	out := awsCredentialProcessOutput{
		Version:         1,
		AccessKeyID:     creds["AccessKeyId"],
		SecretAccessKey: creds["SecretAccessKey"],
		SessionToken:    creds["SessionToken"],
	}
	if exp := resp.GetExpiresAt(); exp != nil {
		out.Expiration = exp.AsTime().UTC().Format(time.RFC3339)
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("encode credentials: %w", err)
	}
	return string(encoded), nil
}

func awsConfigureFunc(cmd *cobra.Command, _ []string) error {
	if awsConfigureDefault && awsConfigureProfile != "" {
		return errors.New("cannot use --profile together with --default")
	}

	daemonCtx, err := loadCloudDaemonContext(cmd)
	if err != nil {
		return err
	}

	awsIntegrations := filterIntegrationsByProvider(daemonCtx.authorized, "aws")

	configPath, err := awsConfigFilePath()
	if err != nil {
		return fmt.Errorf("determine AWS config file location: %w", err)
	}
	configured, err := configuredAWSProfileNames(configPath)
	if err != nil {
		return fmt.Errorf("inspect existing AWS profiles: %w", err)
	}

	stdin := bufio.NewReader(cmd.InOrStdin())
	integration, err := selectCloudIntegration(awsIntegrations, awsConfigureIntegrationID, stdin, cmd.OutOrStdout(), configured)
	if err != nil {
		return err
	}

	profileName := "default"
	if !awsConfigureDefault {
		profileName = awsConfigureProfile
		if profileName == "" {
			profileName = defaultAWSProfileName(daemonCtx.netbirdProfile, integration)
		}
	} else {
		foreign, err := defaultProfileIsForeign(configPath)
		if err != nil {
			return fmt.Errorf("inspect existing [default] profile: %w", err)
		}
		if foreign && !awsConfigureYes {
			confirmed, err := confirmOverwriteForeignDefault(stdin, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if !confirmed {
				fmt.Fprintln(cmd.OutOrStdout(), "Aborted; [default] left unchanged.")
				return nil
			}
		}
	}

	if err := pruneNetBirdManagedAWSProfiles(configPath, awsIntegrations); err != nil {
		return fmt.Errorf("prune stale AWS profiles: %w", err)
	}

	if err := upsertAWSConfigProfile(configPath, profileName, integration.GetId(), awsConfigureRegion); err != nil {
		return fmt.Errorf("write AWS profile: %w", err)
	}

	if awsConfigureDefault {
		fmt.Fprintf(cmd.OutOrStdout(), "Set the AWS CLI default profile to %q.\n", integration.GetName())
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Configured AWS CLI profile %q.\n", profileName)
	}
	return nil
}

// defaultProfileIsForeign reports whether [default] exists but wasn't created by netbird
func defaultProfileIsForeign(path string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	existing = trimConfigBOM(existing)
	lines := strings.Split(strings.TrimRight(string(existing), "\n"), "\n")

	defaultHeader := false
	inDefault := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inDefault = trimmed == "[default]"
			if inDefault {
				defaultHeader = true
			}
			continue
		}
		if inDefault && netbirdCredentialProcessLine.MatchString(trimmed) {
			return false, nil
		}
	}
	return defaultHeader, nil
}

// defaultAWSProfileName derives a "netbird-<profile>-<role>" name when --profile isn't given;
func defaultAWSProfileName(netbirdProfile string, integration *proto.CloudIntegrationSummary) string {
	roleSlug := strings.Trim(awsProfileNameSanitizer.ReplaceAllString(strings.ToLower(integration.GetName()), "-"), "-")
	if roleSlug == "" {
		roleSlug = integration.GetId()
	}
	netbirdProfileSlug := strings.Trim(awsProfileNameSanitizer.ReplaceAllString(strings.ToLower(netbirdProfile), "-"), "-")
	if netbirdProfileSlug == "" {
		return "netbird-" + roleSlug
	}
	return "netbird-" + netbirdProfileSlug + "-" + roleSlug
}

// awsConfigFilePath uses AWS_CONFIG_FILE and falls back to the standard ~/.aws/config location.
func awsConfigFilePath() (string, error) {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "config"), nil
}

// configuredAWSProfileNames maps integration ID -> NetBird-managed profile name(s)
func configuredAWSProfileNames(path string) (map[string][]string, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	existing = trimConfigBOM(existing)
	lines := strings.Split(strings.TrimRight(string(existing), "\n"), "\n")

	result := make(map[string][]string)
	currentName := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if trimmed == "[default]" {
				currentName = "default"
			} else {
				currentName = strings.TrimSuffix(strings.TrimPrefix(trimmed, "[profile "), "]")
			}
			continue
		}
		if m := netbirdCredentialProcessLine.FindStringSubmatch(trimmed); m != nil {
			result[m[1]] = append(result[m[1]], currentName)
		}
	}
	return result, nil
}

// pruneAWSConfigSections removes every NetBird-managed section
// (per netbirdCredentialProcessLine) for which shouldRemove(integrationID) is true.
func pruneAWSConfigSections(path string, includeDefault bool, shouldRemove func(integrationID string) bool) error {
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	existing = trimConfigBOM(existing)
	if len(existing) == 0 {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(existing), "\n"), "\n")

	type section struct {
		start, end int
		isDefault  bool
		remove     bool
	}
	var sections []section
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
			continue
		}
		if len(sections) > 0 {
			sections[len(sections)-1].end = i
		}
		sections = append(sections, section{start: i, end: len(lines), isDefault: trimmed == "[default]"})
	}

	changed := false
	for si := range sections {
		s := &sections[si]
		if s.isDefault && !includeDefault {
			continue
		}
		for i := s.start + 1; i < s.end; i++ {
			m := netbirdCredentialProcessLine.FindStringSubmatch(strings.TrimSpace(lines[i]))
			if m == nil {
				continue
			}
			if shouldRemove(m[1]) {
				s.remove = true
				changed = true
			}
			break
		}
	}
	if !changed {
		return nil
	}

	preambleEnd := len(lines)
	if len(sections) > 0 {
		preambleEnd = sections[0].start
	}
	newLines := append([]string{}, lines[:preambleEnd]...)
	for _, s := range sections {
		if s.remove {
			continue
		}
		newLines = append(newLines, lines[s.start:s.end]...)
	}
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	if err := writeCredentialFile(path, []byte(strings.Join(newLines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	// WriteFile doesn't change the mode of an existing file, so set it explicitly.
	return os.Chmod(path, 0600)
}

// pruneNetBirdManagedAWSProfiles removes NetBird-managed `[profile ...]` sections whose integration ID isn't in authorized.
func pruneNetBirdManagedAWSProfiles(path string, authorized []*proto.CloudIntegrationSummary) error {
	authorizedIDs := make(map[string]struct{}, len(authorized))
	for _, integration := range authorized {
		authorizedIDs[integration.GetId()] = struct{}{}
	}
	return pruneAWSConfigSections(path, false, func(id string) bool {
		_, ok := authorizedIDs[id]
		return !ok
	})
}

// upsertAWSConfigProfile creates or updates a `[profile <name>]` (or `[default]`) section,
// setting credential_process and, if region is non-empty, region
func upsertAWSConfigProfile(path, profileName, integrationID, region string) error {
	header := "[profile " + profileName + "]"
	if profileName == "default" {
		header = "[default]"
	}
	credLine := fmt.Sprintf("credential_process = netbird aws credentials %s", integrationID)
	regionLine := ""
	if region != "" {
		regionLine = fmt.Sprintf("region = %s", region)
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	existing = trimConfigBOM(existing)

	var lines []string
	if len(existing) > 0 {
		lines = strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	}

	sectionStart := -1
	sectionEnd := len(lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
			continue
		}
		if sectionStart == -1 {
			if trimmed == header {
				sectionStart = i
			}
			continue
		}
		sectionEnd = i
		break
	}

	var newLines []string
	if sectionStart == -1 {
		newLines = append(newLines, lines...)
		if len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) != "" {
			newLines = append(newLines, "")
		}
		newLines = append(newLines, header, credLine)
		if regionLine != "" {
			newLines = append(newLines, regionLine)
		}
	} else {
		newLines = append(newLines, lines[:sectionStart+1]...)
		foundCred := false
		foundRegion := false
		var body []string
		for i := sectionStart + 1; i < sectionEnd; i++ {
			key, _, hasEq := strings.Cut(strings.TrimSpace(lines[i]), "=")
			trimmedKey := strings.TrimSpace(key)
			if hasEq && trimmedKey == "credential_process" {
				body = append(body, credLine)
				foundCred = true
				continue
			}
			if regionLine != "" && hasEq && trimmedKey == "region" {
				body = append(body, regionLine)
				foundRegion = true
				continue
			}
			body = append(body, lines[i])
		}

		// New keys must land before trailing blank lines, not after.
		trailingBlanks := len(body)
		for trailingBlanks > 0 && strings.TrimSpace(body[trailingBlanks-1]) == "" {
			trailingBlanks--
		}
		var newKeys []string
		if !foundCred {
			newKeys = append(newKeys, credLine)
		}
		if regionLine != "" && !foundRegion {
			newKeys = append(newKeys, regionLine)
		}

		newLines = append(newLines, body[:trailingBlanks]...)
		newLines = append(newLines, newKeys...)
		newLines = append(newLines, body[trailingBlanks:]...)
		newLines = append(newLines, lines[sectionEnd:]...)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := writeCredentialFile(path, []byte(strings.Join(newLines, "\n")+"\n"), 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile doesn't change the mode of an existing file, so set it explicitly.
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
