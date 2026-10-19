package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/recorder"
	recordergrpc "github.com/netbirdio/netbird/recorder/internal/grpc"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/util"
)

const DefaultManagementURL = "https://api.netbird.io:443"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	GoVersion = "unknown"
)

var (
	logLevel      string
	logFile       string
	deviceName    string
	mgmtURL       string
	setupKey      string
	preSharedKey  string
	dataDir       string
	grpcPort      uint16
	httpAddress   string
	storeEngine   string
	encryptionKey string

	// Web UI login — all optional, see recorder.Config's doc comment. Setting oidcIssuer is what turns login on.
	oidcIssuer          string
	oidcClientID        string
	oidcClientSecret    string
	oidcRedirectURL     string
	oidcScopes          []string
	oidcGroupsClaim     string
	oidcAllowedGroups   []string
	sessionSigningKey   string
	sessionCookieSecure bool
	sessionDuration     time.Duration

	maxSessionBytes       int64
	maxSessionDuration    time.Duration
	maxConcurrentSessions int
	maxSessionsPerPeer    int
	retentionDays         int
)

var rootCmd = &cobra.Command{
	Use:          "recorder",
	Short:        "NetBird SSH session recorder",
	Long:         "Standalone NetBird peer that records SSH sessions streamed to it by peers configured with --ssh-session-recorder.",
	Version:      Version,
	SilenceUsage: true,
	RunE:         runServer,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level: panic, fatal, error, warn, info, debug, trace")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "console", "Log file path, or \"console\" to log to stdout")
	rootCmd.PersistentFlags().StringVar(&deviceName, "device-name", "netbird-recorder", "This peer's device name")
	rootCmd.PersistentFlags().StringVar(&mgmtURL, "management-url", DefaultManagementURL, "Management server address")
	rootCmd.PersistentFlags().StringVar(&setupKey, "setup-key", "", "Setup key used to register this peer")
	rootCmd.PersistentFlags().StringVar(&preSharedKey, "preshared-key", "", "Pre-shared key for the tunnel")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "/var/lib/netbird-recorder", "Directory for the metadata database (sqlite), recording files, and this peer's own NetBird client config")
	rootCmd.PersistentFlags().Uint16Var(&grpcPort, "grpc-port", 22023, "Tunnel-bound port SSH server peers stream recordings to")
	rootCmd.PersistentFlags().StringVar(&httpAddress, "http-address", ":8080", "Tunnel-bound address serving the JSON API and web UI")
	rootCmd.PersistentFlags().StringVar(&storeEngine, "store-engine", "sqlite", "Metadata store engine: sqlite or postgres")
	rootCmd.PersistentFlags().StringVar(&encryptionKey, "encryption-key", "", "Base64-encoded 32-byte key encrypting metadata fields and .cast file contents at rest (required; generate with: openssl rand -base64 32)")

	rootCmd.PersistentFlags().StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL for the web UI's own login (optional; unset means no login, access controlled purely by network/ACL reachability). Setting this requires --oidc-client-id, --oidc-client-secret, --oidc-redirect-url, and --session-signing-key")
	rootCmd.PersistentFlags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID for the recorder's own OAuth client registration (required if --oidc-issuer is set)")
	rootCmd.PersistentFlags().StringVar(&oidcClientSecret, "oidc-client-secret", "", "OIDC client secret (required if --oidc-issuer is set)")
	rootCmd.PersistentFlags().StringVar(&oidcRedirectURL, "oidc-redirect-url", "", "OAuth callback URL registered with the IdP, e.g. http://<recorder-ip>:8080/auth/callback (required if --oidc-issuer is set)")
	rootCmd.PersistentFlags().StringSliceVar(&oidcScopes, "oidc-scopes", []string{"openid", "profile", "email"}, "OIDC scopes to request")
	rootCmd.PersistentFlags().StringVar(&oidcGroupsClaim, "oidc-groups-claim", "groups", "ID token claim carrying the user's group memberships, checked against --oidc-allowed-groups")
	rootCmd.PersistentFlags().StringSliceVar(&oidcAllowedGroups, "oidc-allowed-groups", nil, "Comma-separated group names/IDs allowed to log in (optional; unset means any authenticated user from the IdP is allowed). A user whose token has none of these groups — including one with no groups claim at all — is denied. This gates login only, not individual sessions: anyone it admits can see every session this recorder holds")
	rootCmd.PersistentFlags().StringVar(&sessionSigningKey, "session-signing-key", "", "Base64-encoded 32-byte key signing the web UI's session cookie (required if --oidc-issuer is set; generate with: openssl rand -base64 32)")
	rootCmd.PersistentFlags().BoolVar(&sessionCookieSecure, "session-cookie-secure", false, "Set the Secure flag on login/session cookies. Leave false for the default direct-tunnel HTTP access; set true only behind a reverse proxy terminating real TLS")
	rootCmd.PersistentFlags().DurationVar(&sessionDuration, "session-duration", 12*time.Hour, "How long a web UI login session lasts before re-authentication is required")

	rootCmd.PersistentFlags().Int64Var(&maxSessionBytes, "max-session-bytes", recordergrpc.DefaultMaxSessionBytes, "Maximum recorded output (bytes) for a single SSH session before the recorder cuts it off. Deliberately generous: recording is mandatory when configured, so hitting this ends the SSH session, not just the recording — raise it if legitimate sessions in your environment are hitting the default")
	rootCmd.PersistentFlags().DurationVar(&maxSessionDuration, "max-session-duration", recordergrpc.DefaultMaxSessionDuration, "Maximum wall-clock duration for a single SSH session recording before the recorder cuts it off. Same tradeoff as --max-session-bytes")
	rootCmd.PersistentFlags().IntVar(&maxConcurrentSessions, "max-concurrent-sessions", recordergrpc.DefaultMaxConcurrentSessions, "Maximum recording sessions open at once across all producers combined, bounding total disk use independent of --max-session-bytes (which only bounds one session). A producer beyond this limit is rejected, not queued")
	rootCmd.PersistentFlags().IntVar(&maxSessionsPerPeer, "max-sessions-per-peer", recordergrpc.DefaultMaxSessionsPerPeer, "Maximum concurrent recording sessions from one verified peer identity, independent of --max-concurrent-sessions. Without this, a single compromised or misbehaving peer could claim the entire --max-concurrent-sessions pool by itself, denying every other peer's mandatory recording")

	rootCmd.PersistentFlags().IntVar(&retentionDays, "retention-days", 0, "Delete a FINISHED session's metadata and recording file this many days after it started; a still-recording session is never deleted regardless of age. 0 (default) keeps recordings forever")

	setFlagsFromEnvVars(rootCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SetVersionInfo sets version information for the CLI.
func SetVersionInfo(version, commit, buildDate, goVersion string) {
	Version = version
	Commit = commit
	BuildDate = buildDate
	GoVersion = goVersion
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("Version: {{.Version}}, Commit: " + Commit + ", BuildDate: " + BuildDate + ", Go: " + GoVersion + "\n")
}

func runServer(cmd *cobra.Command, args []string) error {
	if err := util.InitLog(logLevel, logFile); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	if encryptionKey == "" {
		return fmt.Errorf("--encryption-key (or NB_ENCRYPTION_KEY) is required")
	}

	engine := metadata.Engine(storeEngine)
	if engine != metadata.EngineSQLite && engine != metadata.EnginePostgres {
		return fmt.Errorf("invalid --store-engine %q: must be sqlite or postgres", storeEngine)
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv, err := recorder.New(recorder.Config{
		Logger:        log.StandardLogger(),
		DeviceName:    deviceName,
		ManagementURL: mgmtURL,
		SetupKey:      setupKey,
		PreSharedKey:  preSharedKey,
		ConfigPath:    filepath.Join(dataDir, "recorder.json"),
		GRPCPort:      grpcPort,
		HTTPAddress:   httpAddress,
		DataDir:       dataDir,
		StoreEngine:   engine,
		EncryptionKey: encryptionKey,

		MaxSessionBytes:       maxSessionBytes,
		MaxSessionDuration:    maxSessionDuration,
		MaxConcurrentSessions: maxConcurrentSessions,
		MaxSessionsPerPeer:    maxSessionsPerPeer,
		RetentionDays:         retentionDays,

		OIDCIssuer:          oidcIssuer,
		OIDCClientID:        oidcClientID,
		OIDCClientSecret:    oidcClientSecret,
		OIDCRedirectURL:     oidcRedirectURL,
		OIDCScopes:          oidcScopes,
		OIDCGroupsClaim:     oidcGroupsClaim,
		OIDCAllowedGroups:   oidcAllowedGroups,
		SessionSigningKey:   sessionSigningKey,
		SessionCookieSecure: sessionCookieSecure,
		SessionDuration:     sessionDuration,
	})
	if err != nil {
		return fmt.Errorf("create recorder: %w", err)
	}

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("start recorder: %w", err)
	}

	<-ctx.Done()
	log.Info("shutting down recorder")

	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Stop(stopCtx)
}
