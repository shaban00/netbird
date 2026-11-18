package acme

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
)

const prefetchTestDomain = "prefetch.example.test"

type recordingNotifier struct {
	mu    sync.Mutex
	calls []string
}

func (n *recordingNotifier) NotifyCertificateIssued(_ context.Context, _ types.AccountID, serviceID types.ServiceID, domain string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, string(serviceID)+" "+domain)
	return nil
}

func (n *recordingNotifier) Calls() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls...)
}

func newPrefetchManager(t *testing.T, certDir string, ca *fakeCA, notifier certificateNotifier) (*Manager, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	logger := log.New()
	logger.SetOutput(logs)
	logger.SetLevel(log.DebugLevel)
	mgr, err := NewManager(ManagerConfig{CertDir: certDir, ACMEURL: ca.srv.URL + "/dir"}, notifier, logger, nil)
	require.NoError(t, err)
	mgr.Manager.Client.HTTPClient = ca.srv.Client()
	return mgr, logs
}

// A prefetch whose ACME order fails because another issuance already
// finalized it (the CA answers orderNotReady) must still pick up that
// certificate from the cache, mark the domain ready and tell management.
// Before the fix the domain was marked failed and management was never told,
// so the dashboard showed "Issuing certificate" for a service serving a valid
// certificate.
func TestPrefetch_CertificateIssuedElsewhereIsReported(t *testing.T) {
	certDir := t.TempDir()
	staging := t.TempDir()
	writeCachedCert(t, staging, prefetchTestDomain, 60*24*time.Hour)

	ca := newFakeCA(t)
	// The competing issuance lands its certificate in the cache while the
	// prefetch's own order is being rejected.
	ca.onOrder = func() {
		_ = os.Rename(filepath.Join(staging, prefetchTestDomain), filepath.Join(certDir, prefetchTestDomain))
	}

	notifier := &recordingNotifier{}
	mgr, logs := newPrefetchManager(t, certDir, ca, notifier)
	mgr.AddDomain(domain.Domain(prefetchTestDomain), types.AccountID("acc"), types.ServiceID("svc"))

	require.Eventually(t, func() bool { return len(mgr.ReadyDomains()) == 1 }, 5*time.Second, 20*time.Millisecond,
		"the domain should be ready with the cached certificate; failed=%v logs:\n%s", mgr.FailedDomains(), logs.String())
	assert.Equal(t, []string{"svc " + prefetchTestDomain}, notifier.Calls(), "management must be told the certificate is issued")
	assert.Contains(t, logs.String(), "a certificate is cached; using it")
	assert.GreaterOrEqual(t, ca.orders.Load(), int32(1), "the prefetch should have tried ACME first")
}

// The prefetch and the first visitor must share one ACME order. The prefetch
// used to ask for an RSA certificate while browsers ask for ECDSA, which
// autocert treats as two certificates: two orders per domain (doubling
// Let's Encrypt rate-limit use), racing each other for the same order.
func TestPrefetch_SharesTheVisitorsOrder(t *testing.T) {
	ca := newFakeCA(t)
	// Keep the first order in flight long enough for both to ask.
	ca.onOrder = func() { time.Sleep(time.Second) }

	mgr, logs := newPrefetchManager(t, t.TempDir(), ca, nil)

	// The visitor connects through a listener configured like server.go.
	tlsConfig := mgr.TLSConfig()
	tlsConfig.GetCertificate = mgr.GetCertificate
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()

	mgr.AddDomain(domain.Domain(prefetchTestDomain), types.AccountID("acc"), types.ServiceID("svc"))

	// A browser-like client (Go's default offers ECDSA) arrives at once.
	visitorDone := make(chan struct{})
	go func() {
		defer close(visitorDone)
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", ln.Addr().String(),
			&tls.Config{ServerName: prefetchTestDomain, InsecureSkipVerify: true}) //nolint:gosec // the fake CA issues nothing
		if err == nil {
			_ = conn.Close()
		}
	}()

	require.Eventually(t, func() bool { return len(mgr.FailedDomains()) == 1 }, 10*time.Second, 20*time.Millisecond,
		"the prefetch should finish (the fake CA rejects every order); logs:\n%s", logs.String())
	select {
	case <-visitorDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the visitor's handshake did not finish")
	}

	assert.Equal(t, int32(1), ca.orders.Load(), "the prefetch and the visitor should share one ACME order")
}
