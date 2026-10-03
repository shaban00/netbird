package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

// cloudDaemonContext holds the active profile and the peer's authorized cloud integrations
type cloudDaemonContext struct {
	netbirdProfile string
	authorized     []*proto.CloudIntegrationSummary
}

// loadCloudDaemonContext fetches the active profile and the peer's authorized cloud integrations from the daemon
func loadCloudDaemonContext(cmd *cobra.Command) (*cloudDaemonContext, error) {
	SetFlagsFromEnvVars(rootCmd)

	conn, err := getClient(cmd)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	profileResp, err := client.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return nil, fmt.Errorf("get active netbird profile: %w", err)
	}

	integrationResp, err := client.ListCloudIntegrations(ctx, &proto.ListCloudIntegrationsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list cloud integrations: %w", err)
	}

	return &cloudDaemonContext{
		netbirdProfile: profileResp.GetProfileName(),
		authorized:     integrationResp.GetIntegrations(),
	}, nil
}

// filterIntegrationsByProvider returns only the integrations matching provider (e.g. "aws", "gcp", "azure")
func filterIntegrationsByProvider(integrations []*proto.CloudIntegrationSummary, provider string) []*proto.CloudIntegrationSummary {
	filtered := make([]*proto.CloudIntegrationSummary, 0, len(integrations))
	for _, integration := range integrations {
		if integration.GetProvider() == provider {
			filtered = append(filtered, integration)
		}
	}
	return filtered
}

// selectCloudIntegration picks explicitID if set and authorized, else the only
// authorized integration, else prompts. configured only affects display.
func selectCloudIntegration(integrations []*proto.CloudIntegrationSummary, explicitID string, in *bufio.Reader, out io.Writer, configured map[string][]string) (*proto.CloudIntegrationSummary, error) {
	if len(integrations) == 0 {
		return nil, errors.New("you are not currently authorized for any cloud access; ask an administrator to grant your peer/group access to one via a NetBird policy")
	}

	if explicitID != "" {
		for _, integration := range integrations {
			if integration.GetId() == explicitID {
				return integration, nil
			}
		}
		return nil, fmt.Errorf("you are not authorized for cloud integration %q (or it doesn't exist)", explicitID)
	}

	if len(integrations) == 1 {
		return integrations[0], nil
	}

	fmt.Fprintln(out, "You are authorized for more than one cloud integration:")
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "   NAME\tACTIVE")
	for i, integration := range integrations {
		mark := ""
		for _, name := range configured[integration.GetId()] {
			if name == "default" {
				mark = "  *"
				break
			}
		}
		fmt.Fprintf(tw, "%d) %s\t%s\n", i+1, integration.GetName(), mark)
	}
	_ = tw.Flush()
	fmt.Fprint(out, "\nChoose a number: ")

	line, err := in.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read selection: %w", err)
	}
	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(integrations) {
		return nil, fmt.Errorf("invalid selection %q", strings.TrimSpace(line))
	}
	return integrations[choice-1], nil
}

// confirmOverwriteForeignDefault prompts on out, reads y/n from in.
func confirmOverwriteForeignDefault(in *bufio.Reader, out io.Writer) (bool, error) {
	fmt.Fprint(out, "[default] is already configured and wasn't set by NetBird. Overwrite it? [y/N] ")
	line, err := in.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// trimConfigBOM strips a leading UTF-8 BOM
func trimConfigBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

// writeCredentialFile writes data to path
func writeCredentialFile(path string, data []byte, perm os.FileMode) error {
	f, err := openCredentialFileNoFollow(path, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
