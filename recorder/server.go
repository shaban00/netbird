package recorder

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/recorder/internal/api"
	recauth "github.com/netbirdio/netbird/recorder/internal/auth"
	reccrypt "github.com/netbirdio/netbird/recorder/internal/crypt"
	recordergrpc "github.com/netbirdio/netbird/recorder/internal/grpc"
	"github.com/netbirdio/netbird/recorder/internal/live"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/metadata/factory"
	"github.com/netbirdio/netbird/recorder/internal/storage"
	recorderproto "github.com/netbirdio/netbird/recorder/proto"
	"github.com/netbirdio/netbird/recorder/web"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	// retentionSweepInterval is the purge interval (daily).
	retentionSweepInterval = 24 * time.Hour
	// maxConcurrentStreamsPerConn limits streams per connection.
	maxConcurrentStreamsPerConn = 256
)

type Config struct {
	Logger        *log.Logger
	DeviceName    string
	ManagementURL string
	SetupKey      string
	PreSharedKey  string
	ConfigPath    string
	// GRPCPort is the tunnel port SSH peers stream recordings to. Must match
	// sshSessionRecorderPort (22023) in client/internal/engine_ssh.go.
	GRPCPort uint16
	// HTTPAddress (e.g. ":8080") serves the API and web UI over the tunnel
	HTTPAddress string

	DataDir     string
	StoreEngine metadata.Engine
	// EncryptionKey is a required base64 32-byte key encrypting .cast files and stored DB metadata
	EncryptionKey string
	// MaxSessionBytes/MaxSessionDuration cap one recording (0 = defaults).
	// Exceeding them ends the SSH session.
	MaxSessionBytes    int64
	MaxSessionDuration time.Duration
	// MaxConcurrentSessions caps total recordings (0 = default); excess is rejected.
	MaxConcurrentSessions int
	// MaxSessionsPerPeer caps sessions per peer (0 = default).
	MaxSessionsPerPeer int

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	// OIDCScopes defaults to {"openid", "profile", "email"} when empty.
	OIDCScopes []string
	// OIDCGroupsClaim defaults to "groups" when empty.
	OIDCGroupsClaim string
	// OIDCAllowedGroups limits login by group; empty allows all users.
	OIDCAllowedGroups []string
	// SessionSigningKey is a base64 key (32+ bytes) for signing the session
	// cookie JWT. Required when OIDCIssuer is set.
	SessionSigningKey string
	// SessionCookieSecure sets the Secure cookie flag. False by default since
	// the recorder uses plain HTTP over WireGuard; set true behind a
	// TLS-terminating NetBird reverse proxy.
	SessionCookieSecure bool
	// SessionDuration defaults to recauth.DefaultSessionDuration when zero.
	SessionDuration time.Duration
	// RetentionDays deletes finished sessions' metadata and recordings after
	// this many days from StartedAt. Zero keeps them forever. Live sessions
	// (StatusRecording) are never deleted, even if they outlast the window
	// (see recordergrpc.DeleteSessionsBefore).
	RetentionDays int
}

type Server struct {
	cfg    Config
	logger *log.Logger

	embedClient *embed.Client
	meta        metadata.Store
	storage     *storage.Store
	gcm         cipher.AEAD

	sessions *recauth.SessionManager

	grpcServer *grpc.Server
	httpServer *http.Server
}

func New(cfg Config) (*Server, error) {
	if cfg.EncryptionKey == "" {
		return nil, fmt.Errorf("EncryptionKey is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.StandardLogger()
	}
	if cfg.GRPCPort == 0 {
		cfg.GRPCPort = 22023
	}
	if cfg.HTTPAddress == "" {
		cfg.HTTPAddress = ":8080"
	}

	fieldEnc, err := crypt.NewFieldEncrypt(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("init field encryption: %w", err)
	}
	gcm, err := reccrypt.NewCipher(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("init recording encryption: %w", err)
	}

	store, err := storage.New(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("init storage: %w", err)
	}

	meta, err := factory.New(context.Background(), cfg.StoreEngine, cfg.DataDir, fieldEnc)
	if err != nil {
		return nil, fmt.Errorf("init metadata store: %w", err)
	}

	sessions, err := newSessionManagerIfConfigured(cfg)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:      cfg,
		logger:   cfg.Logger,
		meta:     meta,
		storage:  store,
		gcm:      gcm,
		sessions: sessions,
	}, nil
}

func newSessionManagerIfConfigured(cfg Config) (*recauth.SessionManager, error) {
	if cfg.OIDCIssuer == "" {
		return nil, nil //nolint:nilnil
	}

	var missing []string
	if cfg.OIDCClientID == "" {
		missing = append(missing, "OIDCClientID (--oidc-client-id)")
	}
	if cfg.OIDCClientSecret == "" {
		missing = append(missing, "OIDCClientSecret (--oidc-client-secret)")
	}
	if cfg.OIDCRedirectURL == "" {
		missing = append(missing, "OIDCRedirectURL (--oidc-redirect-url)")
	}
	if cfg.SessionSigningKey == "" {
		missing = append(missing, "SessionSigningKey (--session-signing-key)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("OIDCIssuer is set but missing required config: %s", strings.Join(missing, ", "))
	}

	sessions, err := recauth.NewSessionManager(cfg.SessionSigningKey, cfg.SessionDuration)
	if err != nil {
		return nil, fmt.Errorf("init session manager: %w", err)
	}
	return sessions, nil
}

// Start connects the NetBird client and binds the gRPC and HTTP listeners,
// returning once bound; serving runs in the background.
func (s *Server) Start(ctx context.Context) error {
	n, err := s.meta.MarkAllRecordingAsInterrupted(ctx)
	if err != nil {
		return fmt.Errorf("reconcile interrupted sessions: %w", err)
	}
	if n > 0 {
		s.logger.Warnf("recorder: marked %d session(s) interrupted after restart", n)
	}

	embedClient, err := embed.New(embed.Options{
		DeviceName:    s.cfg.DeviceName,
		SetupKey:      s.cfg.SetupKey,
		ManagementURL: s.cfg.ManagementURL,
		PreSharedKey:  s.cfg.PreSharedKey,
		ConfigPath:    s.cfg.ConfigPath,
		LogOutput:     nil,
	})
	if err != nil {
		return fmt.Errorf("create embedded client: %w", err)
	}
	if err := embedClient.Start(ctx); err != nil {
		return fmt.Errorf("start embedded client: %w", err)
	}
	s.embedClient = embedClient

	grpcLn, err := embedClient.ListenTCP(fmt.Sprintf(":%d", s.cfg.GRPCPort))
	if err != nil {
		return fmt.Errorf("listen for recording stream on port %d: %w", s.cfg.GRPCPort, err)
	}
	httpLn, err := embedClient.ListenTCP(s.cfg.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen for HTTP on %s: %w", s.cfg.HTTPAddress, err)
	}

	liveHub := live.NewHub()

	svc := recordergrpc.New(embedClient, s.storage, s.meta, s.gcm, liveHub, s.logger, recordergrpc.Limits{
		MaxSessionBytes:       s.cfg.MaxSessionBytes,
		MaxSessionDuration:    s.cfg.MaxSessionDuration,
		MaxConcurrentSessions: s.cfg.MaxConcurrentSessions,
		MaxSessionsPerPeer:    s.cfg.MaxSessionsPerPeer,
	})
	s.grpcServer = grpc.NewServer(
		grpc.MaxConcurrentStreams(maxConcurrentStreamsPerConn),
		grpc.StreamInterceptor(recordergrpc.RecoveryStreamInterceptor(s.logger)),
	)
	recorderproto.RegisterRecorderServiceServer(s.grpcServer, svc)

	mux := http.NewServeMux()
	mux.Handle("/api/", api.New(s.meta, s.storage, s.gcm, liveHub, s.logger).Handler())
	mux.Handle("/", web.Handler())
	mux.HandleFunc("GET /api/me", recauth.Me)

	if s.sessions != nil {
		oidcProvider, err := s.newOIDCProvider(ctx)
		if err != nil {
			return fmt.Errorf("init OIDC provider: %w", err)
		}
		handlers := recauth.NewHandlers(oidcProvider, s.sessions, s.cfg.SessionCookieSecure)
		handlers.RegisterRoutes(mux)
		s.logger.Info("recorder: web UI login enabled")
	}

	s.httpServer = &http.Server{
		Handler:           recauth.Middleware(s.sessions)(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.grpcServer.Serve(grpcLn); err != nil {
			s.logger.Errorf("recorder: gRPC server stopped: %v", err)
		}
	}()
	go func() {
		if err := s.httpServer.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Errorf("recorder: HTTP server stopped: %v", err)
		}
	}()

	if s.cfg.RetentionDays > 0 {
		go s.runRetentionSweep(ctx)
	}

	s.logger.Infof("recorder: gRPC listening on tunnel port %d, HTTP listening on tunnel %s", s.cfg.GRPCPort, s.cfg.HTTPAddress)
	return nil
}

// runRetentionSweep periodically purges expired sessions until ctx ends
func (s *Server) runRetentionSweep(ctx context.Context) {
	s.sweepExpiredSessions(ctx)

	ticker := time.NewTicker(retentionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepExpiredSessions(ctx)
		}
	}
}

// sweepExpiredSessions purges sessions past RetentionDays
func (s *Server) sweepExpiredSessions(ctx context.Context) {
	cutoff := time.Now().UTC().AddDate(0, 0, -s.cfg.RetentionDays)

	castPaths, err := s.meta.DeleteSessionsBefore(ctx, cutoff)
	if err != nil {
		s.logger.Errorf("recorder: retention sweep: delete expired session metadata: %v", err)
		return
	}
	if len(castPaths) == 0 {
		return
	}

	var failed int
	for _, path := range castPaths {
		if err := s.storage.Delete(path); err != nil {
			s.logger.Warnf("recorder: retention sweep: delete recording file %s: %v", path, err)
			failed++
		}
	}
	s.logger.Infof("recorder: retention sweep deleted %d expired session(s) (%d recording file(s) failed to delete)", len(castPaths), failed)
}

func (s *Server) newOIDCProvider(ctx context.Context) (*recauth.OIDCProvider, error) {
	scopes := s.cfg.OIDCScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	groupsClaim := s.cfg.OIDCGroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	return recauth.NewOIDCProvider(ctx, recauth.OIDCConfig{
		Issuer:        s.cfg.OIDCIssuer,
		ClientID:      s.cfg.OIDCClientID,
		ClientSecret:  s.cfg.OIDCClientSecret,
		RedirectURL:   s.cfg.OIDCRedirectURL,
		Scopes:        scopes,
		GroupsClaim:   groupsClaim,
		AllowedGroups: s.cfg.OIDCAllowedGroups,
	})
}

func (s *Server) Stop(ctx context.Context) error {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Warnf("recorder: HTTP server shutdown: %v", err)
		}
	}
	if s.embedClient != nil {
		if err := s.embedClient.Stop(ctx); err != nil {
			s.logger.Warnf("recorder: embedded client stop: %v", err)
		}
	}
	if s.meta != nil {
		if err := s.meta.Close(); err != nil {
			s.logger.Warnf("recorder: close metadata store: %v", err)
		}
	}
	return nil
}
