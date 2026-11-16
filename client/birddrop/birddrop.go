package birddrop

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

var (
	maxArchiveEntries         = 1 << 17  // files and directories per folder transfer
	maxArchiveNameLen         = 4096     // bytes per entry name
	maxArchiveNameBytes int64 = 32 << 20 // total entry-name bytes per archive

	peerDialTimeout           = 15 * time.Second
	peerResponseHeaderTimeout = 60 * time.Second

	errTransferStalled    = errors.New("transfer stalled")
	errArchiveExceedsSize = errors.New("archive contents exceed the archive size")
	errArchiveTooLarge    = errors.New("folder archive exceeds the transfer limit")
	errPartReplaced       = errors.New("the received data was moved or replaced before it could be saved")

	linkEntry = func(r *os.Root, oldname, newname string) error { return r.Link(oldname, newname) }
)

const (
	// DefaultPort is the overlay port used by the Birddrop HTTP endpoint.
	DefaultPort = 47474

	// DefaultSendTimeout is how long a pending offer waits for the receiver to act.
	DefaultSendTimeout = 30 * time.Minute

	// Protocol routes.
	pathOffer    = "/birddrop/offer"
	pathFetch    = "/birddrop/fetch"
	pathReject   = "/birddrop/reject"
	pathWithdraw = "/birddrop/withdraw"
	pathPing     = "/birddrop/ping"
	pathStatus   = "/birddrop/status"
	pathComplete = "/birddrop/complete"
	pathFail     = "/birddrop/fail"

	// Wire and transfer limits.
	maxOfferBody                           = 64 << 10 // 64 KiB
	maxOfferLifetime                       = 24 * time.Hour
	completionTombstoneTTL                 = 30 * time.Second
	maxIncomingOffers                      = 256
	maxIncomingOffersPerPeer               = 32
	maxOutgoingOffers                      = 256
	maxOutgoingOffersPerPeer               = 32
	maxConcurrentHTTPHandlers              = 64
	maxConcurrentHTTPHandlersPerPeer       = 16
	maxOfferSize                     int64 = 64 << 30 // 64 GiB
	maxExtractBytes                  int64 = 64 << 30 // 64 GiB
	maxClipboardSize                 int64 = 1 << 20  // 1 MiB

	hdrSha256 = "X-NetBird-Sha256"

	StateWaiting      SendState = "waiting"      // offer delivered, awaiting accept/reject
	StateTransferring SendState = "transferring" // receiver is pulling bytes
	StateDelivered    SendState = "delivered"
	StateDeclined     SendState = "declined"
	StateTimedOut     SendState = "timed_out"
	StateCanceled     SendState = "canceled"
	StateError        SendState = "error"

	PayloadFile      PayloadType = "file"
	PayloadDirectory PayloadType = "directory"
	PayloadClipboard PayloadType = "clipboard"
)

type SendState string

type PayloadType string

type SendEvent struct {
	State       SendState
	Name        string
	Type        PayloadType
	IsDir       bool
	Transferred int64
	Total       int64
	PeerFQDN    string
	PeerIP      string
	Message     string
}

type Item struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	From     string      `json:"from"`
	Size     int64       `json:"size"`
	Type     PayloadType `json:"type,omitempty"`
	IsDir    bool        `json:"is_dir"`
	Received time.Time   `json:"received"`
	fetchURL string      // internal: where to pull bytes from
	senderIP string      // internal: source overlay IP of the sender (for withdraw auth)
	expires  time.Time   // internal: when this offer self-expires (from the sender)
}

type ReceiveProgress struct {
	ID          string
	Name        string
	Type        PayloadType
	IsDir       bool
	Transferred int64
	Total       int64
}

type recvProgress struct {
	r     io.Reader
	read  int64
	total int64
	it    *Item
	cb    func(ReceiveProgress)
	last  time.Time
}

type ReceiveResult struct {
	ID            string
	SavedAs       string
	ClipboardText string
	Bytes         int64 // bytes transferred over the wire (matches the size shown in `list`)
	Type          PayloadType
	IsDir         bool
	Files         int // for a folder: how many files were extracted
}

type AllowPeer func(remoteIP string) (fqdn string, ok bool)

type offerMeta struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Size        int64       `json:"size"`
	Type        PayloadType `json:"type,omitempty"`
	IsDir       bool        `json:"is_dir"`
	From        string      `json:"from"`
	Port        int         `json:"port"`
	ExpiresUnix int64       `json:"expires_unix"`
}

type completionTombstone struct {
	targetIP string
	expires  time.Time
}

type outOffer struct {
	id           string
	path         string
	file         *os.File
	clipboard    []byte
	sendCtx      context.Context
	name         string
	size         int64
	payloadType  PayloadType
	isDir        bool
	targetIP     string
	mu           sync.Mutex
	done         bool
	fetching     bool
	fetchStarted chan struct{} // closed when the intended receiver starts its first fetch
	pub          chan SendEvent
	terminated   chan struct{}
	serveCancel  chan struct{}
	cleanupOnce  sync.Once
}

type OfferRejectedError struct {
	Peer   string
	Status string
	Reason string
}

type Manager struct {
	selfName           string
	selfPort           int
	boundAddrs         []string
	allowPeer          AllowPeer
	allowOffers        bool
	receiveIdleTimeout time.Duration
	sendIdleTimeout    time.Duration

	mu               sync.Mutex
	activeHTTP       int
	activeHTTPByPeer map[string]int
	outgoing         map[string]*outOffer
	incoming         map[string]*Item
	completed        map[string]completionTombstone
	servers          []*http.Server
	stopSweep        chan struct{}
	sweptOnce        bool
	sweepStarted     bool

	mux       *http.ServeMux
	serveDone chan struct{}
	serving   bool
}

type wireReader struct {
	r   io.Reader
	n   int64
	err error
}

type captureWriteErr struct {
	w   io.Writer
	err error
}

type countingWriter struct {
	n     int64
	limit int64
}

type deadOfferError struct{ err error }

type completionAckError struct {
	err error
}

type abortReader struct {
	r    io.Reader
	ctx  context.Context
	gone chan struct{}
}

type idleTimeoutReader struct {
	r       io.ReadCloser
	timeout time.Duration
}

type idleTimeoutWriter struct {
	w       http.ResponseWriter
	timeout time.Duration
}

type NotAcceptingError struct {
	Peer string
	err  error
}

type cancelWriter struct {
	ctx    context.Context
	cancel <-chan struct{}
	w      io.Writer
}

type ctxReader struct {
	ctx    context.Context
	cancel <-chan struct{}
	r      io.Reader
}

type progressWriter struct {
	w       io.Writer
	total   int64
	written int64
	o       *outOffer
	last    time.Time
}

func requireMethod(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method == want {
		return true
	}

	w.Header().Set("Allow", want)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (p *recvProgress) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if time.Since(p.last) > 150*time.Millisecond {
		p.last = time.Now()
		p.cb(ReceiveProgress{
			ID: p.it.ID, Name: p.it.Name, Type: p.it.Type, IsDir: p.it.IsDir,
			Transferred: p.read, Total: p.total,
		})
	}
	return n, err
}

func (o *outOffer) emit(ev SendEvent) {
	o.mu.Lock()
	if !o.done {
		select {
		case o.pub <- ev:
		default:
		}
	}
	o.mu.Unlock()
}

func (e *OfferRejectedError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("peer %s is not accepting files: %s", e.Peer, e.Reason)
	}
	return fmt.Sprintf("peer %s is not accepting files", e.Peer)
}

func (o *outOffer) finish(ev SendEvent) {
	o.mu.Lock()
	if !o.done {
		o.done = true
		o.pub <- ev
		close(o.pub)
		close(o.terminated)
	}
	o.mu.Unlock()
}

func NewManager(selfName string, allow AllowPeer) (*Manager, error) {
	return &Manager{
		selfName:           selfName,
		selfPort:           DefaultPort,
		allowPeer:          allow,
		allowOffers:        true,
		receiveIdleTimeout: 30 * time.Second,
		sendIdleTimeout:    30 * time.Second,
		activeHTTPByPeer:   make(map[string]int),
		outgoing:           make(map[string]*outOffer),
		incoming:           make(map[string]*Item),
		completed:          make(map[string]completionTombstone),
		stopSweep:          make(chan struct{}),
		serveDone:          make(chan struct{}),
	}, nil
}

// SetSelfName updates the FQDN advertised as the sender ("From").
func (m *Manager) SetSelfName(name string) { m.mu.Lock(); m.selfName = name; m.mu.Unlock() }

// Serve starts the endpoint on bindIP:port. Blocks; run in a goroutine.
func (m *Manager) Serve(bindIPs []string, port int) error {
	if port == 0 {
		port = DefaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc(pathPing, func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(pathStatus, m.handleStatus)
	mux.HandleFunc(pathOffer, m.handleOffer)
	mux.HandleFunc(pathFetch, m.handleFetch)
	mux.HandleFunc(pathReject, m.handleReject)
	mux.HandleFunc(pathWithdraw, m.handleWithdraw)
	mux.HandleFunc(pathComplete, m.handleComplete)
	mux.HandleFunc(pathFail, m.handleFail)

	m.mu.Lock()
	m.selfPort = port
	m.mux = mux
	m.serving = true
	firstServe := !m.sweptOnce && !m.sweepStarted
	m.sweepStarted = true
	m.mu.Unlock()

	if firstServe {
		go m.sweepLoop()
	}

	var bound int
	for _, ip := range bindIPs {
		if err := m.AddListener(ip); err == nil {
			bound++
		}
	}
	if bound == 0 {
		m.mu.Lock()
		m.serving = false
		m.mu.Unlock()
		return fmt.Errorf("birddrop: could not bind any of %v on port %d", bindIPs, port)
	}

	<-m.serveDone
	return nil
}

// SetAllowOffers controls whether this peer accepts new inbound Birddrop offers.
// It changes only the /offer gate; the daemon owns transport start/stop policy.
func (m *Manager) SetAllowOffers(allow bool) {
	m.mu.Lock()
	m.allowOffers = allow
	m.mu.Unlock()
}

// AddListener binds one more address to the running endpoint. It exists because an
// overlay address may not be assignable when Serve first runs -- notably an IPv6
// address still completing Duplicate Address Detection after a cold boot -- and
// binding it later is the difference between a dual-stack endpoint and a v4-only one
// for the rest of the process's life.
//
// It is idempotent: an address already bound is a no-op, so a caller can poll without
// tracking state. Returns an error if the endpoint is not serving or the bind fails.
func (m *Manager) AddListener(ip string) error {
	m.mu.Lock()
	if !m.serving || m.mux == nil {
		m.mu.Unlock()
		return errors.New("birddrop: endpoint is not serving")
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(m.selfPort))
	for _, a := range m.boundAddrs {
		if a == addr {
			m.mu.Unlock()
			return nil // already listening here
		}
	}
	mux := m.mux
	m.mu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           m.limitHTTP(mux),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	m.mu.Lock()

	if !m.serving {
		m.mu.Unlock()
		_ = ln.Close()
		return errors.New("birddrop: endpoint is not serving")
	}
	m.servers = append(m.servers, srv)
	m.boundAddrs = append(m.boundAddrs, addr)
	m.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()
	return nil
}

func (m *Manager) sweepExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, it := range m.incoming {
		if !it.expires.IsZero() && now.After(it.expires) {
			delete(m.incoming, id)
		}
	}

	for id, tombstone := range m.completed {
		if now.After(tombstone.expires) {
			delete(m.completed, id)
		}
	}
}

func (m *Manager) sweepLoop() {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-m.stopSweep:
			return
		case now := <-t.C:
			m.sweepExpired(now)
		}
	}
}

// BoundAddrs returns the host:port addresses that successfully bound
func (m *Manager) BoundAddrs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.boundAddrs))
	copy(out, m.boundAddrs)
	return out
}

// Shutdown stops all listeners and background maintenance.
func (m *Manager) Shutdown() error {
	m.mu.Lock()
	servers := m.servers
	m.serving = false
	if !m.sweptOnce {
		m.sweptOnce = true
		close(m.stopSweep)
		close(m.serveDone)
	}
	m.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Close()
	}
	return nil
}

// validateOfferMeta rejects wire metadata that cannot represent a valid transfer.
func validateOfferMeta(meta *offerMeta) error {
	if meta.ID == "" {
		return errors.New("missing offer id")
	}

	if len(meta.ID) != 32 {
		return errors.New("invalid offer id")
	}

	if _, err := hex.DecodeString(meta.ID); err != nil {
		return errors.New("invalid offer id")
	}

	if meta.Size < 0 {
		return errors.New("invalid offer size")
	}

	if meta.Size > maxOfferSize {
		return errors.New("offer size too large")
	}

	switch meta.Type {
	case PayloadFile:
		if meta.IsDir {
			return errors.New("file offer cannot be a directory")
		}

	case PayloadDirectory:
		if !meta.IsDir {
			return errors.New("directory offer must set is_dir")
		}

	case PayloadClipboard:
		if meta.IsDir {
			return errors.New("clipboard offer cannot be a directory")
		}
		if meta.Size > maxClipboardSize {
			return errors.New("clipboard offer too large")
		}

	default:
		return errors.New("invalid offer type")
	}

	// Port 0 means "use the default Birddrop port".
	if meta.Port < 0 || meta.Port > 65535 {
		return errors.New("invalid offer port")
	}

	if meta.ExpiresUnix > 0 {
		nowUnix := time.Now().Unix()

		// expires_unix has one-second precision, so the current second is valid.
		if meta.ExpiresUnix < nowUnix {
			return errors.New("offer already expired")
		}

		// Compare Unix seconds directly so extreme timestamps cannot overflow time.Time comparisons
		maxExpiresUnix := nowUnix + int64(maxOfferLifetime/time.Second)
		if meta.ExpiresUnix > maxExpiresUnix {
			return errors.New("offer expiry too far in the future")
		}
	}

	return nil
}

func rejectDuplicateJSONFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("offer must be a JSON object")
	}

	seen := make(map[string]struct{})

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		key, ok := tok.(string)
		if !ok {
			return errors.New("invalid JSON object key")
		}

		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON field %q", key)
		}
		seen[key] = struct{}{}

		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}

	_, err = dec.Token()
	return err
}

func decodeOffer(r io.Reader, meta *offerMeta) error {
	body, err := io.ReadAll(io.LimitReader(r, maxOfferBody+1))
	if err != nil {
		return err
	}

	if len(body) > maxOfferBody {
		return errors.New("offer body too large")
	}

	if err := rejectDuplicateJSONFields(body); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(meta); err != nil {
		return err
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON")
		}
		return err
	}

	return nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: peerDialTimeout}).DialContext,
			ResponseHeaderTimeout: peerResponseHeaderTimeout,
		},
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func birddropURL(host, path, id string) string {
	u := url.URL{
		Scheme: "http",
		Host:   host,
		Path:   path,
	}

	if id != "" {
		q := u.Query()
		q.Set("id", id)
		u.RawQuery = q.Encode()
	}

	return u.String()
}

func offerPeerKey(it *Item) string {
	if it.From != "" {
		return it.From
	}
	return it.senderIP
}

func (m *Manager) limitHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerIP := hostOf(r.RemoteAddr)

		m.mu.Lock()

		if m.activeHTTP >= maxConcurrentHTTPHandlers {
			m.mu.Unlock()
			http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
			return
		}

		if m.activeHTTPByPeer[peerIP] >= maxConcurrentHTTPHandlersPerPeer {
			m.mu.Unlock()
			http.Error(w, "too many concurrent requests from this peer", http.StatusTooManyRequests)
			return
		}

		m.activeHTTP++
		m.activeHTTPByPeer[peerIP]++
		m.mu.Unlock()

		defer func() {
			m.mu.Lock()
			m.activeHTTP--
			m.activeHTTPByPeer[peerIP]--
			if m.activeHTTPByPeer[peerIP] == 0 {
				delete(m.activeHTTPByPeer, peerIP)
			}
			m.mu.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}

func (m *Manager) handleOffer(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	m.mu.Lock()
	allowOffers := m.allowOffers
	m.mu.Unlock()

	if !allowOffers {
		http.Error(w, "birddrop is disabled on this peer", http.StatusForbidden)
		return
	}
	remoteIP := hostOf(r.RemoteAddr)
	from := remoteIP
	if m.allowPeer != nil {
		fqdn, ok := m.allowPeer(remoteIP)
		if !ok {
			http.Error(w, "sender is not an authorized peer", http.StatusForbidden)
			return
		}
		if fqdn != "" {
			from = fqdn
		}
	}

	var meta offerMeta
	if err := decodeOffer(r.Body, &meta); err != nil {
		http.Error(w, "bad offer", http.StatusBadRequest)
		return
	}
	if err := validateOfferMeta(&meta); err != nil {
		http.Error(w, "bad offer", http.StatusBadRequest)
		return
	}
	port := meta.Port
	if port == 0 {
		port = DefaultPort
	}
	expires := time.Now().Add(DefaultSendTimeout)
	if meta.ExpiresUnix > 0 {
		expires = time.Unix(meta.ExpiresUnix, 0)
	}
	item := &Item{
		ID: meta.ID, Name: sanitizeName(meta.Name), From: from,
		Size:  meta.Size,
		Type:  meta.Type,
		IsDir: meta.IsDir, Received: time.Now(),
		senderIP: remoteIP, expires: expires,
		fetchURL: birddropURL(
			net.JoinHostPort(remoteIP, strconv.Itoa(port)),
			pathFetch,
			meta.ID,
		),
	}
	m.mu.Lock()

	if existing := m.incoming[item.ID]; existing != nil {
		sameOffer :=
			existing.senderIP == item.senderIP &&
				existing.Name == item.Name &&
				existing.Size == item.Size &&
				existing.IsDir == item.IsDir &&
				existing.fetchURL == item.fetchURL

		m.mu.Unlock()

		if sameOffer {
			// Treat an identical retry from the same sender as idempotent.
			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "offer id already exists", http.StatusConflict)
		return
	}

	// Count per peer, not per address: a dual-stack peer has two overlay IPs
	// and must not get twice the budget.
	pendingFromPeer := 0
	for _, existing := range m.incoming {
		if offerPeerKey(existing) == offerPeerKey(item) {
			pendingFromPeer++
		}
	}

	if pendingFromPeer >= maxIncomingOffersPerPeer {
		m.mu.Unlock()
		http.Error(w, "too many pending offers from this peer", http.StatusTooManyRequests)
		return
	}

	if len(m.incoming) >= maxIncomingOffers {
		m.mu.Unlock()
		http.Error(w, "too many pending offers", http.StatusTooManyRequests)
		return
	}

	m.incoming[item.ID] = item
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (m *Manager) List() []Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Item, 0, len(m.incoming))
	for _, it := range m.incoming {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Received.After(out[j].Received) })
	return out
}

// RequiresDestination reports whether any selected item writes to the filesystem.
func (m *Manager) RequiresDestination(ids []string) (bool, error) {
	targets, err := m.selectItems(ids)
	if err != nil {
		return false, err
	}

	for _, it := range targets {
		if it.Type != PayloadClipboard {
			return true, nil
		}
	}

	return false, nil
}

// Receive pulls the bytes for the given ids (or all when empty) into destDir,
// verifying SHA-256 and untarring folders. Written files are handed to the
// invoking CLI user: chowned to uid/gid when both are >= 0 (Unix), or owned by
// and granted to the account given with WithOwnerSID (Windows).
func (m *Manager) Receive(
	ctx context.Context,
	ids []string,
	destDir string,
	destRoot *os.Root,
	uid, gid int,
	onProgress func(ReceiveProgress),
	opts ...ReceiveOption,
) ([]ReceiveResult, error) {
	own := owner{uid: uid, gid: gid}
	for _, opt := range opts {
		opt(&own)
	}

	targets, err := m.selectItems(ids)
	if err != nil {
		return nil, err
	}

	needsDest := false
	for _, it := range targets {
		if it.Type != PayloadClipboard {
			needsDest = true
			break
		}
	}

	if needsDest {
		if destDir == "" {
			destDir = "."
		}

		if destRoot == nil {
			return nil, errors.New("receive destination was not authorized")
		}
	}

	if len(targets) == 0 {
		return nil, errors.New(
			"no pending files to receive (an offer may have been withdrawn by the sender, or already received); run `netbird drop list`",
		)
	}

	var results []ReceiveResult
	var evicted []string
	var firstErr error

	for _, it := range targets {
		res, gone, err := m.pull(
			ctx,
			it,
			destDir,
			destRoot,
			own,
			onProgress,
		)
		if gone {
			// The sender no longer has this offer, so remove the stale entry from
			// the incoming queue rather than making the user retry it indefinitely.
			m.mu.Lock()
			delete(m.incoming, it.ID)
			m.mu.Unlock()

			evicted = append(evicted, it.ID)
			continue
		}

		if err != nil {

			var ackErr *completionAckError
			if errors.As(err, &ackErr) {
				m.mu.Lock()
				delete(m.incoming, it.ID)
				m.mu.Unlock()

				return results, err
			}

			// A dead offer can never be fetched again, so remove it while allowing
			// --all to continue processing the remaining pending offers.
			var dead *deadOfferError
			if errors.As(err, &dead) {
				m.mu.Lock()
				delete(m.incoming, it.ID)
				m.mu.Unlock()

				if firstErr == nil {
					firstErr = err
				}
				continue
			}

			return results, err
		}

		results = append(results, res)

		m.mu.Lock()
		delete(m.incoming, it.ID)
		m.mu.Unlock()
	}

	if len(results) == 0 && firstErr != nil {
		return results, firstErr
	}

	if len(results) == 0 && len(evicted) > 0 {
		return results, fmt.Errorf(
			"the sender no longer has %s on offer (it was withdrawn or it expired); "+
				"run `netbird drop list` to see current offers",
			strings.Join(evicted, ", "),
		)
	}

	return results, nil
}

func (m *Manager) selectItems(ids []string) ([]*Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(ids) == 0 {
		out := make([]*Item, 0, len(m.incoming))
		for _, it := range m.incoming {
			out = append(out, it)
		}
		return out, nil
	}

	var out []*Item

	for _, id := range ids {
		if len(id) < 12 {
			return nil, fmt.Errorf(
				"item id %q is too short; use at least 12 characters from `netbird drop list`",
				id,
			)
		}

		if it, ok := m.incoming[id]; ok {
			out = append(out, it)
			continue
		}

		var match *Item
		var matches int

		for fullID, it := range m.incoming {
			if strings.HasPrefix(fullID, id) {
				match = it
				matches++

				if matches > 1 {
					break
				}
			}
		}

		switch matches {
		case 0:
			return nil, fmt.Errorf(
				"no pending item with id %q (try `netbird drop list`)",
				id,
			)

		case 1:
			out = append(out, match)

		default:
			return nil, fmt.Errorf(
				"pending item id %q is ambiguous; use more characters from `netbird drop list`",
				id,
			)
		}
	}

	return out, nil
}

// watchSender polls the sender for this offer during a transfer. When the offer
// disappears (the sender canceled -> withdrew it), it signals senderGone and cancels
// the copy so the receiver stops promptly instead of draining TCP buffers.
func (m *Manager) watchSender(ctx context.Context, it *Item, gone chan struct{}) {
	statusURL := strings.Replace(it.fetchURL, pathFetch, pathStatus, 1)
	client := newHTTPClient(2 * time.Second)
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue // transient; the copy itself will catch a real break
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				close(gone)
				return
			}
		}
	}
}

func (w *wireReader) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	w.n += int64(n)
	if err != nil && err != io.EOF && w.err == nil {
		w.err = err
	}
	return n, err
}

func (c *captureWriteErr) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil && c.err == nil {
		c.err = err
	}
	return n, err
}

func (e *deadOfferError) Error() string { return e.err.Error() }
func (e *deadOfferError) Unwrap() error { return e.err }

func (e *completionAckError) Error() string {
	return e.err.Error()
}

func (e *completionAckError) Unwrap() error {
	return e.err
}

func writeFailure(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err
	}
	return err
}

func remoteWriteReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return fmt.Sprintf("receiver could not write the file: %v", pe.Err)
	}
	return "receiver could not write the file"
}

func (a *abortReader) Read(p []byte) (int, error) {
	if err := a.ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-a.gone:
		return 0, context.Canceled
	default:
	}
	return a.r.Read(p)
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}

	ch := make(chan result, 1)

	go func() {
		n, err := r.r.Read(p)
		ch <- result{n: n, err: err}
	}()

	timer := time.NewTimer(r.timeout)
	defer timer.Stop()

	select {
	case result := <-ch:
		return result.n, result.err

	case <-timer.C:
		_ = r.r.Close()
		return 0, errTransferStalled
	}
}

func (w *idleTimeoutWriter) Write(p []byte) (int, error) {
	if w.timeout > 0 {
		rc := http.NewResponseController(w.w)
		if err := rc.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil &&
			!errors.Is(err, http.ErrNotSupported) {
			return 0, err
		}
	}

	return w.w.Write(p)
}

func (w *idleTimeoutWriter) clearDeadline() {
	rc := http.NewResponseController(w.w)
	_ = rc.SetWriteDeadline(time.Time{})
}

// postReject tells the sender an offer was declined
func (m *Manager) postReject(it *Item, reason string) {
	postToSender(it, pathReject, reason)
}

// postFail tells the sender a transfer it served could not be completed
func (m *Manager) postFail(it *Item, reason string) {
	postToSender(it, pathFail, reason)
}

// postToSender delivers a reject or failure notice for an offer to its sender.
func postToSender(it *Item, path, reason string) {
	u := strings.Replace(it.fetchURL, pathFetch, path, 1)
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(reason))
	if err != nil {
		return
	}
	if resp, err := newHTTPClient(10 * time.Second).Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// postComplete tells the sender that the received item passed verification and
// was successfully committed to its final destination.
func (m *Manager) postComplete(it *Item) error {
	u := strings.Replace(it.fetchURL, pathFetch, pathComplete, 1)

	const attempts = 3

	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequest(http.MethodPost, u, nil)
		if err != nil {
			return err
		}

		client := newHTTPClient(5 * time.Second)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}

			lastErr = fmt.Errorf("completion acknowledgement returned %s", resp.Status)
		} else {
			lastErr = err
		}

		if i+1 < attempts {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return lastErr
}

func (m *Manager) pull(
	ctx context.Context,
	it *Item,
	destDir string,
	destRoot *os.Root,
	own owner,
	onProgress func(ReceiveProgress),
) (res ReceiveResult, gone bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, it.fetchURL, nil)
	if err != nil {
		return ReceiveResult{}, false, err
	}
	client := newHTTPClient(0)
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ReceiveResult{}, false, errors.New("transfer canceled")
		}

		return ReceiveResult{}, false, fmt.Errorf(
			"%s is unreachable (it may be offline, or have disabled birddrop)", it.From)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ReceiveResult{}, true, fmt.Errorf("offer no longer available (withdrawn by the sender)")
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		reason := strings.TrimSpace(SanitizeRemoteText(string(b)))
		if reason == "" {
			reason = resp.Status
		}
		err := fmt.Errorf("%s refused to send %q: %s", it.From, it.Name, reason)
		if resp.StatusCode == http.StatusInternalServerError {
			return ReceiveResult{}, false, &deadOfferError{err}
		}
		return ReceiveResult{}, false, err
	}

	copyCtx, copyCancel := context.WithCancel(ctx)
	defer copyCancel()
	senderGone := make(chan struct{})
	go m.watchSender(copyCtx, it, senderGone)

	h := sha256.New()

	var source io.Reader = &idleTimeoutReader{
		r:       resp.Body,
		timeout: m.receiveIdleTimeout,
	}
	if it.Size < math.MaxInt64 {
		source = io.LimitReader(source, it.Size+1)
	}

	var body io.Reader = &abortReader{
		r:    source,
		ctx:  copyCtx,
		gone: senderGone,
	}
	if onProgress != nil {
		body = &recvProgress{r: body, total: it.Size, it: it, cb: onProgress}
	}
	wire := &wireReader{r: body}
	stream := io.TeeReader(wire, h)

	var (
		clip      bytes.Buffer
		part      *os.File
		partDir   *os.Root
		hidden    string
		nfiles    int
		sinkErr   error
		committed bool
	)
	switch {
	case it.Type == PayloadClipboard:
		_, sinkErr = io.Copy(&clip, stream)

	case it.IsDir:
		hidden, partDir, err = createPartDir(destRoot, it.ID)
		if err != nil {
			m.postFail(it, remoteWriteReason(err))
			return ReceiveResult{}, false, &deadOfferError{writeFailure(err)}
		}
		defer func() {
			if !committed {
				removeCreatedDir(destRoot, partDir, hidden)
			}
		}()
		nfiles, _, sinkErr = untarIntoRoot(stream, it.Size, partDir)
		if sinkErr == nil {
			_, sinkErr = io.Copy(io.Discard, stream)
		}

	default:
		part, hidden, err = createPartFile(destRoot, it.ID)
		if err != nil {
			m.postFail(it, remoteWriteReason(err))
			return ReceiveResult{}, false, &deadOfferError{writeFailure(err)}
		}
		defer func() {
			if !committed {
				_ = part.Close()
				_ = destRoot.Remove(hidden)
			}
		}()
		dst := &captureWriteErr{w: part}
		_, sinkErr = io.CopyBuffer(dst, stream, make([]byte, 1<<20))
		if werr := dst.err; werr != nil {
			m.postFail(it, remoteWriteReason(werr))
			return ReceiveResult{}, false, &deadOfferError{writeFailure(werr)}
		}
	}
	n := wire.n

	select {
	case <-senderGone:
		return ReceiveResult{}, true, fmt.Errorf("%s canceled the transfer", it.From)
	default:
	}
	if err := wire.err; err != nil {
		if errors.Is(err, errTransferStalled) {
			m.postFail(it, "receiver stopped the transfer because it stalled")
			return ReceiveResult{}, false, &deadOfferError{errTransferStalled}
		}

		if ctx.Err() != nil {
			m.postReject(it, "receiver canceled the transfer")
			return ReceiveResult{}, false, &deadOfferError{errors.New("transfer canceled")}
		}

		return ReceiveResult{}, false, fmt.Errorf("%s canceled the transfer", it.From)
	}
	if errors.Is(sinkErr, errArchiveExceedsSize) {
		err := fmt.Errorf("%q size mismatch: the sender sent more than the declared %d bytes", it.Name, it.Size)
		m.postFail(it, err.Error())
		return ReceiveResult{}, false, &deadOfferError{err}
	}
	if sinkErr != nil {
		m.postFail(it, sinkErr.Error())
		return ReceiveResult{}, false, sinkErr
	}

	if n != it.Size {
		err := fmt.Errorf(
			"%q size mismatch: expected %d bytes, received %d",
			it.Name,
			it.Size,
			n,
		)
		m.postFail(it, err.Error())
		return ReceiveResult{}, false, &deadOfferError{err}
	}

	values := resp.Trailer.Values(hdrSha256)
	if len(values) == 0 {
		err := fmt.Errorf(
			"%q arrived without an integrity checksum; refusing it",
			it.Name,
		)
		m.postFail(it, err.Error())
		return ReceiveResult{}, false, err
	}
	if len(values) != 1 {
		err := fmt.Errorf(
			"%q arrived with ambiguous integrity metadata; refusing it",
			it.Name,
		)
		m.postFail(it, err.Error())
		return ReceiveResult{}, false, err
	}

	want := strings.TrimSpace(values[0])
	if hex.EncodeToString(h.Sum(nil)) != want {
		err := fmt.Errorf(
			"%q failed its integrity check (checksum mismatch); nothing was written",
			it.Name,
		)
		m.postFail(it, err.Error())
		return ReceiveResult{}, false, err
	}

	var result ReceiveResult
	switch {
	case it.Type == PayloadClipboard:
		data := clip.Bytes()
		if int64(len(data)) > maxClipboardSize {
			err := errors.New("received clipboard exceeds the clipboard transfer limit")
			m.postFail(it, err.Error())
			return ReceiveResult{}, false, &deadOfferError{err}
		}
		if !utf8.Valid(data) {
			err := errors.New("received clipboard is not valid UTF-8")
			m.postFail(it, err.Error())
			return ReceiveResult{}, false, &deadOfferError{err}
		}
		result = ReceiveResult{ID: it.ID, ClipboardText: string(data), Bytes: n, Type: PayloadClipboard}

	case it.IsDir:
		savedAs, err := commitPartDir(destRoot, partDir, hidden, destDir, it.Name, own)
		if err != nil {
			committed = errors.Is(err, errPartReplaced)
			m.postFail(it, err.Error())
			return ReceiveResult{}, false, err
		}
		committed = true
		result = ReceiveResult{ID: it.ID, SavedAs: savedAs, Bytes: n, Type: PayloadDirectory, IsDir: true, Files: nfiles}

	default:
		savedAs, err := commitPartFile(destRoot, part, hidden, destDir, it.Name, own)
		if err != nil {
			committed = errors.Is(err, errPartReplaced)
			m.postFail(it, err.Error())
			return ReceiveResult{}, false, err
		}
		committed = true
		result = ReceiveResult{ID: it.ID, SavedAs: savedAs, Bytes: n, Type: PayloadFile}
	}

	if err := m.postComplete(it); err != nil {
		what := fmt.Sprintf("%q", it.Name)
		if it.Type == PayloadClipboard {
			what = "clipboard"
		}
		return ReceiveResult{}, false, &completionAckError{
			err: fmt.Errorf("received %s successfully but could not confirm delivery to sender: %w", what, err),
		}
	}
	return result, false, nil
}

// DiscardIncoming drops every pending incoming offer and tells each sender it was rejected.
func (m *Manager) DiscardIncoming() int {
	m.mu.Lock()
	items := make([]*Item, 0, len(m.incoming))
	for id, it := range m.incoming {
		items = append(items, it)
		delete(m.incoming, id)
	}
	m.mu.Unlock()

	for _, it := range items {
		go m.postReject(it, "")
	}
	return len(items)
}

func (m *Manager) Reject(ids []string) (int, error) {
	targets, err := m.selectItems(ids)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, errors.New("no pending files to reject; run `netbird drop list`")
	}
	for _, it := range targets {
		m.postReject(it, "")
		m.mu.Lock()
		delete(m.incoming, it.ID)
		m.mu.Unlock()
	}
	return len(targets), nil
}

// SendFile registers and advertises an already-authorized regular file.
func (m *Manager) SendFile(
	ctx context.Context,
	targetIP string,
	targetPort int,
	targetFQDN string,
	file *os.File,
	timeout time.Duration,
) (<-chan SendEvent, error) {
	if file == nil {
		return nil, errors.New("nil source file")
	}

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file.Name())
	}

	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}

	if timeout > maxOfferLifetime {
		return nil, fmt.Errorf("send timeout cannot exceed %s", maxOfferLifetime)
	}

	o := &outOffer{
		targetIP:     targetIP,
		pub:          make(chan SendEvent, 8),
		terminated:   make(chan struct{}),
		serveCancel:  make(chan struct{}),
		fetchStarted: make(chan struct{}),
		file:         file,
		path:         file.Name(),
		name:         filepath.Base(file.Name()),
		size:         info.Size(),
		payloadType:  PayloadFile,
		isDir:        false,
	}

	o.id, err = newID()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if err := m.checkOutgoingLimitLocked(targetIP); err != nil {
		m.mu.Unlock()
		return nil, err
	}

	self, selfPort := m.selfName, m.selfPort
	m.outgoing[o.id] = o
	m.mu.Unlock()

	if targetPort == 0 {
		targetPort = DefaultPort
	}

	expiresUnix := time.Now().Add(timeout).Unix()

	if err := m.postOffer(
		targetIP,
		targetPort,
		selfPort,
		self,
		expiresUnix,
		o,
	); err != nil {
		m.dropOffer(o.id)
		m.cleanupOffer(o)

		var na *NotAcceptingError
		if errors.As(err, &na) {
			return nil, err
		}

		var rejected *OfferRejectedError
		if errors.As(err, &rejected) {
			return nil, err
		}

		return nil, fmt.Errorf("could not reach peer %s: %w", targetIP, err)
	}

	o.emit(SendEvent{
		State:    StateWaiting,
		Name:     o.name,
		Type:     o.payloadType,
		IsDir:    false,
		Total:    o.size,
		PeerFQDN: targetFQDN,
		PeerIP:   targetIP,
	})

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		timeoutC := timer.C
		fetchStarted := o.fetchStarted

		for {
			select {
			case <-timeoutC:
				o.stopServing()
				o.finish(SendEvent{
					State:   StateTimedOut,
					Name:    o.name,
					Message: "peer did not respond in time",
				})
				m.withdraw(targetIP, targetPort, o.id)
				m.dropOffer(o.id)
				m.cleanupOffer(o)
				return

			case <-fetchStarted:
				timer.Stop()
				timeoutC = nil
				fetchStarted = nil

			case <-ctx.Done():
				o.stopServing()
				o.finish(SendEvent{
					State:   StateCanceled,
					Name:    o.name,
					Message: "canceled",
				})
				m.withdraw(targetIP, targetPort, o.id)
				m.dropOffer(o.id)
				m.cleanupOffer(o)
				return

			case <-o.terminated:
				return
			}
		}
	}()

	return o.pub, nil
}

func (m *Manager) SendClipboard(
	ctx context.Context,
	targetIP string,
	targetPort int,
	targetFQDN string,
	text string,
	timeout time.Duration,
) (<-chan SendEvent, error) {
	if text == "" {
		return nil, errors.New("clipboard is empty")
	}

	if !utf8.ValidString(text) {
		return nil, errors.New("clipboard text is not valid UTF-8")
	}

	data := []byte(text)
	size := int64(len(data))

	if size > maxClipboardSize {
		return nil, fmt.Errorf(
			"clipboard is too large: %s exceeds the %s transfer limit",
			humanSize(size),
			humanSize(maxClipboardSize),
		)
	}

	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}

	if timeout > maxOfferLifetime {
		return nil, fmt.Errorf("send timeout cannot exceed %s", maxOfferLifetime)
	}

	o := &outOffer{
		targetIP:     targetIP,
		pub:          make(chan SendEvent, 8),
		terminated:   make(chan struct{}),
		serveCancel:  make(chan struct{}),
		fetchStarted: make(chan struct{}),
		clipboard:    data,
		name:         "clipboard",
		size:         size,
		payloadType:  PayloadClipboard,
		isDir:        false,
	}

	var err error
	o.id, err = newID()
	if err != nil {
		return nil, err
	}

	// Reserve an outgoing slot before advertising the offer.
	m.mu.Lock()
	if err := m.checkOutgoingLimitLocked(targetIP); err != nil {
		m.mu.Unlock()
		return nil, err
	}

	self, selfPort := m.selfName, m.selfPort
	m.outgoing[o.id] = o
	m.mu.Unlock()

	if targetPort == 0 {
		targetPort = DefaultPort
	}

	expiresUnix := time.Now().Add(timeout).Unix()

	if err := m.postOffer(
		targetIP,
		targetPort,
		selfPort,
		self,
		expiresUnix,
		o,
	); err != nil {
		m.dropOffer(o.id)
		m.cleanupOffer(o)

		var na *NotAcceptingError
		if errors.As(err, &na) {
			return nil, err
		}

		var rejected *OfferRejectedError
		if errors.As(err, &rejected) {
			return nil, err
		}

		return nil, fmt.Errorf("could not reach peer %s: %w", targetIP, err)
	}

	o.emit(SendEvent{
		State:    StateWaiting,
		Name:     o.name,
		Type:     o.payloadType,
		IsDir:    false,
		Total:    o.size,
		PeerFQDN: targetFQDN,
		PeerIP:   targetIP,
	})

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		timeoutC := timer.C
		fetchStarted := o.fetchStarted

		for {
			select {
			case <-timeoutC:
				o.stopServing()
				o.finish(SendEvent{
					State:   StateTimedOut,
					Name:    o.name,
					Type:    o.payloadType,
					IsDir:   false,
					Message: "peer did not respond in time",
				})
				m.withdraw(targetIP, targetPort, o.id)
				m.dropOffer(o.id)
				m.cleanupOffer(o)
				return

			case <-fetchStarted:
				timer.Stop()
				timeoutC = nil
				fetchStarted = nil

			case <-ctx.Done():
				o.stopServing()
				o.finish(SendEvent{
					State:   StateCanceled,
					Name:    o.name,
					Type:    o.payloadType,
					IsDir:   false,
					Message: "canceled",
				})
				m.withdraw(targetIP, targetPort, o.id)
				m.dropOffer(o.id)
				m.cleanupOffer(o)
				return

			case <-o.terminated:
				return
			}
		}
	}()

	return o.pub, nil
}

// Send registers and advertises a directory offer, then returns an event channel
// that closes when the transfer reaches a terminal state.
func (m *Manager) Send(
	ctx context.Context,
	targetIP string,
	targetPort int,
	targetFQDN string,
	path string,
	timeout time.Duration,
) (<-chan SendEvent, error) {
	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}

	if timeout > maxOfferLifetime {
		return nil, fmt.Errorf("send timeout cannot exceed %s", maxOfferLifetime)
	}

	m.mu.Lock()
	err := m.checkOutgoingLimitLocked(targetIP)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}

	o := &outOffer{
		targetIP:     targetIP,
		pub:          make(chan SendEvent, 8),
		terminated:   make(chan struct{}),
		serveCancel:  make(chan struct{}),
		fetchStarted: make(chan struct{}),
		name:         filepath.Base(path),
		payloadType:  PayloadDirectory,
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	o.isDir = info.IsDir()

	if !o.isDir {
		return nil, errors.New("regular files must be sent with SendFile")
	}

	counter := &countingWriter{limit: maxOfferSize}
	err = tarDir(ctx, path, counter)
	if err != nil && !errors.Is(err, errArchiveTooLarge) {
		return nil, err
	}

	if errors.Is(err, errArchiveTooLarge) || counter.n > maxOfferSize {
		return nil, fmt.Errorf(
			"folder archive is too large: %s exceeds the %s transfer limit",
			humanSize(counter.n),
			humanSize(maxOfferSize),
		)
	}

	o.path = path
	o.size = counter.n
	o.sendCtx = ctx

	o.id, err = newID()
	if err != nil {
		m.cleanupOffer(o)
		return nil, err
	}

	m.mu.Lock()
	if err := m.checkOutgoingLimitLocked(targetIP); err != nil {
		m.mu.Unlock()
		m.cleanupOffer(o)
		return nil, err
	}

	self, selfPort := m.selfName, m.selfPort
	m.outgoing[o.id] = o
	m.mu.Unlock()

	if targetPort == 0 {
		targetPort = DefaultPort
	}

	expiresUnix := time.Now().Add(timeout).Unix()

	if err := m.postOffer(
		targetIP,
		targetPort,
		selfPort,
		self,
		expiresUnix,
		o,
	); err != nil {
		m.dropOffer(o.id)
		m.cleanupOffer(o)

		var na *NotAcceptingError
		if errors.As(err, &na) {
			return nil, err
		}

		return nil, fmt.Errorf("could not reach peer %s: %w", targetIP, err)
	}

	o.emit(SendEvent{
		State:    StateWaiting,
		Name:     o.name,
		Type:     o.payloadType,
		IsDir:    o.isDir,
		Total:    o.size,
		PeerFQDN: targetFQDN,
		PeerIP:   targetIP,
	})

	go func() {
		select {
		case <-time.After(timeout):
			o.stopServing()
			o.finish(SendEvent{
				State:   StateTimedOut,
				Name:    o.name,
				Message: "peer did not respond in time",
			})
			m.withdraw(targetIP, targetPort, o.id)
			m.dropOffer(o.id)
			m.cleanupOffer(o)

		case <-ctx.Done():
			o.stopServing()
			o.finish(SendEvent{
				State:   StateCanceled,
				Name:    o.name,
				Message: "canceled",
			})
			m.withdraw(targetIP, targetPort, o.id)
			m.dropOffer(o.id)
			m.cleanupOffer(o)

		case <-o.terminated:
			// Terminal state reached by /complete, /fail, or /reject.
		}
	}()

	return o.pub, nil
}

func (m *Manager) postOffer(targetIP string, targetPort, advertisePort int, self string, expiresUnix int64, o *outOffer) error {
	meta := offerMeta{
		ID:          o.id,
		Name:        o.name,
		Size:        o.size,
		Type:        o.payloadType,
		IsDir:       o.isDir,
		From:        self,
		Port:        advertisePort,
		ExpiresUnix: expiresUnix,
	}
	body, _ := json.Marshal(meta)
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(targetIP, strconv.Itoa(targetPort)), pathOffer)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := newHTTPClient(20 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return &NotAcceptingError{Peer: targetIP, err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return &OfferRejectedError{
			Peer:   targetIP,
			Status: resp.Status,
			Reason: strings.TrimSpace(string(b)),
		}
	}
	return nil
}

func (e *NotAcceptingError) Error() string {
	return fmt.Sprintf("peer %s is not accepting files: it needs to enable birddrop with "+
		"`netbird up --allow-birddrop` (or it may be offline)", e.Peer)
}

func (e *NotAcceptingError) Unwrap() error { return e.err }

// handleStatus reports whether a given offer is still live (200) or gone (404).
// The receiver polls this during a transfer so it can stop promptly when the sender
// cancels, instead of waiting for buffered TCP bytes to drain.
func (m *Manager) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	id := r.URL.Query().Get("id")
	m.mu.Lock()
	o := m.outgoing[id]
	m.mu.Unlock()

	if o == nil {
		http.Error(w, "offer gone", http.StatusNotFound)
		return
	}

	if hostOf(r.RemoteAddr) != o.targetIP {
		http.Error(w, "not the intended recipient", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleFetch streams the offered bytes to the authorized receiver.
func (m *Manager) handleFetch(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	id := r.URL.Query().Get("id")

	m.mu.Lock()
	o := m.outgoing[id]
	m.mu.Unlock()

	if o == nil {
		http.Error(w, "unknown or withdrawn offer", http.StatusNotFound)
		return
	}

	if hostOf(r.RemoteAddr) != o.targetIP {
		http.Error(w, "not the intended recipient", http.StatusForbidden)
		return
	}

	o.mu.Lock()
	if o.fetching {
		o.mu.Unlock()
		http.Error(w, "offer is already being fetched", http.StatusConflict)
		return
	}
	o.fetching = true

	if o.fetchStarted == nil {
		o.fetchStarted = make(chan struct{})
	}

	select {
	case <-o.fetchStarted:
	default:
		close(o.fetchStarted)
	}

	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.fetching = false
		o.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", hdrSha256)

	h := sha256.New()

	tw := &idleTimeoutWriter{
		w:       w,
		timeout: m.sendIdleTimeout,
	}
	defer tw.clearDeadline()

	pw := &progressWriter{
		w:     io.MultiWriter(tw, h),
		total: o.size,
		o:     o,
	}

	var err error

	switch o.payloadType {
	case PayloadDirectory:
		err = tarDir(o.sendCtx, o.path, &cancelWriter{
			ctx:    r.Context(),
			cancel: o.serveCancel,
			w:      pw,
		})

	case PayloadClipboard:
		src := &ctxReader{
			ctx:    r.Context(),
			cancel: o.serveCancel,
			r:      bytes.NewReader(o.clipboard),
		}

		_, err = io.Copy(pw, src)

	default:
		reader := io.NewSectionReader(o.file, 0, o.size)
		src := &ctxReader{
			ctx:    r.Context(),
			cancel: o.serveCancel,
			r:      reader,
		}

		_, err = io.Copy(pw, src)
	}

	if err != nil {
		switch {
		case r.Context().Err() != nil:
			o.finish(SendEvent{
				State:   StateCanceled,
				Name:    o.name,
				Message: "receiver canceled the transfer",
			})

		case isServeCanceled(o.serveCancel):
			m.dropOffer(id)
			m.cleanupOffer(o)
			panic(http.ErrAbortHandler)

		default:
			o.finish(SendEvent{
				State:   StateError,
				Name:    o.name,
				Message: err.Error(),
			})
		}

		m.dropOffer(id)
		m.cleanupOffer(o)
		return
	}

	w.Header().Set(hdrSha256, hex.EncodeToString(h.Sum(nil)))
}

func (m *Manager) handleReject(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	id := r.URL.Query().Get("id")
	m.mu.Lock()
	o := m.outgoing[id]
	m.mu.Unlock()
	if o == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	if hostOf(r.RemoteAddr) != o.targetIP {
		http.Error(w, "not the intended recipient", http.StatusForbidden)
		return
	}

	reason, _ := io.ReadAll(io.LimitReader(r.Body, 256))
	msg := "peer declined"
	state := StateDeclined
	if len(reason) > 0 {
		msg, state = strings.TrimSpace(SanitizeRemoteText(string(reason))), StateCanceled
	}
	o.stopServing()
	o.finish(SendEvent{State: state, Name: o.name, Message: msg})
	m.dropOffer(id)
	m.cleanupOffer(o)
	w.WriteHeader(http.StatusOK)
}

func (m *Manager) handleComplete(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	id := r.URL.Query().Get("id")

	remoteIP := hostOf(r.RemoteAddr)

	m.mu.Lock()
	o := m.outgoing[id]

	if o == nil {
		tombstone, ok := m.completed[id]
		if ok && time.Now().After(tombstone.expires) {
			delete(m.completed, id)
			ok = false
		}
		m.mu.Unlock()

		if !ok {
			http.Error(w, "offer gone", http.StatusNotFound)
			return
		}

		if remoteIP != tombstone.targetIP {
			http.Error(w, "not the intended recipient", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	m.mu.Unlock()

	if remoteIP != o.targetIP {
		http.Error(w, "not the intended recipient", http.StatusForbidden)
		return
	}

	o.finish(SendEvent{
		State:       StateDelivered,
		Name:        o.name,
		Type:        o.payloadType,
		IsDir:       o.isDir,
		Transferred: o.size,
		Total:       o.size,
		PeerIP:      o.targetIP,
	})

	m.mu.Lock()
	m.completed[id] = completionTombstone{
		targetIP: o.targetIP,
		expires:  time.Now().Add(completionTombstoneTTL),
	}
	m.mu.Unlock()

	m.dropOffer(id)
	m.cleanupOffer(o)

	w.WriteHeader(http.StatusOK)
}

func (m *Manager) handleFail(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	id := r.URL.Query().Get("id")

	m.mu.Lock()
	o := m.outgoing[id]
	m.mu.Unlock()

	if o == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	if hostOf(r.RemoteAddr) != o.targetIP {
		http.Error(w, "not the intended recipient", http.StatusForbidden)
		return
	}

	reason, _ := io.ReadAll(io.LimitReader(r.Body, 256))
	msg := strings.TrimSpace(SanitizeRemoteText(string(reason)))
	if msg == "" {
		msg = "receiver failed to complete the transfer"
	}

	o.stopServing()
	o.finish(SendEvent{
		State:   StateError,
		Name:    o.name,
		Message: msg,
	})
	m.dropOffer(id)
	m.cleanupOffer(o)

	w.WriteHeader(http.StatusOK)
}

func (m *Manager) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	id := r.URL.Query().Get("id")

	m.mu.Lock()
	if it := m.incoming[id]; it != nil && hostOf(r.RemoteAddr) == it.senderIP {
		delete(m.incoming, id)
	}
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (m *Manager) withdraw(targetIP string, targetPort int, id string) {
	url := birddropURL(
		net.JoinHostPort(targetIP, strconv.Itoa(targetPort)),
		pathWithdraw,
		id,
	)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return
	}
	client := newHTTPClient(10 * time.Second)
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func (m *Manager) checkOutgoingLimitLocked(targetIP string) error {
	pendingToPeer := 0

	for _, existing := range m.outgoing {
		if existing.targetIP == targetIP {
			pendingToPeer++
		}
	}

	if pendingToPeer >= maxOutgoingOffersPerPeer {
		return fmt.Errorf("too many pending sends to peer %s", targetIP)
	}

	if len(m.outgoing) >= maxOutgoingOffers {
		return errors.New("too many pending outgoing offers")
	}

	return nil
}

func (m *Manager) dropOffer(id string) { m.mu.Lock(); delete(m.outgoing, id); m.mu.Unlock() }

func (m *Manager) cleanupOffer(o *outOffer) {
	if o == nil {
		return
	}

	o.cleanupOnce.Do(func() {
		if o.file != nil {
			_ = o.file.Close()
			o.file = nil
		}

		for i := range o.clipboard {
			o.clipboard[i] = 0
		}
		o.clipboard = nil
	})
}

func (o *outOffer) stopServing() {
	o.mu.Lock()
	defer o.mu.Unlock()
	select {
	case <-o.serveCancel:
	default:
		close(o.serveCancel)
	}
}

func (c *cancelWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}

	select {
	case <-c.cancel:
		return 0, context.Canceled
	default:
	}

	return c.w.Write(p)
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-c.cancel:
		return 0, context.Canceled
	default:
	}
	return c.r.Read(p)
}

func isServeCanceled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.written += int64(n)
	if time.Since(p.last) > 150*time.Millisecond {
		p.last = time.Now()
		p.o.emit(SendEvent{
			State:       StateTransferring,
			Name:        p.o.name,
			Type:        p.o.payloadType,
			IsDir:       p.o.isDir,
			Transferred: p.written,
			Total:       p.total,
			PeerIP:      p.o.targetIP,
		})
	}
	return n, err
}

func hostOf(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func isUnsafeDisplayRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

func SanitizeRemoteText(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if isUnsafeDisplayRune(r) {
			return '?'
		}
		return r
	}, s)
}

func EscapeForTerminal(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", s[0])
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case isUnsafeDisplayRune(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return b.String()
}

func sanitizeName(name string) string {
	name = filepath.Base(filepath.FromSlash(name))
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ToValidUTF8(name, "")
	name = strings.Map(func(r rune) rune {
		if isUnsafeDisplayRune(r) {
			return -1
		}
		return r
	}, name)

	name = strings.TrimSpace(name)

	if name == "" ||
		name == "." ||
		name == ".." ||
		!validWindowsName(name) {
		return fmt.Sprintf("netbird-file-%d", time.Now().Unix())
	}

	return name
}

func validWindowsName(name string) bool {
	if name == "" {
		return false
	}

	if strings.Contains(name, ":") {
		return false
	}

	trimmed := strings.TrimRight(name, " .")
	if trimmed == "" || trimmed != name {
		return false
	}

	base := trimmed
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}

	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return false
	}

	return true
}

func partName(id string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	if len(id) > 12 {
		id = id[:12]
	}
	return ".birddrop-" + id + "-" + hex.EncodeToString(b) + ".part", nil
}

func createPartFile(parent *os.Root, id string) (*os.File, string, error) {
	for {
		name, err := partName(id)
		if err != nil {
			return nil, "", err
		}
		f, err := parent.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return f, name, nil
	}
}

func createPartDir(parent *os.Root, id string) (string, *os.Root, error) {
	for {
		name, err := partName(id)
		if err != nil {
			return "", nil, err
		}
		err = parent.Mkdir(name, 0o700)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		child, err := parent.OpenRoot(name)
		if err != nil {
			_ = parent.Remove(name)
			return "", nil, err
		}
		return name, child, nil
	}
}

func uniqueNames(name string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		if !yield(name) {
			return
		}
		for i := 1; ; i++ {
			if !yield(fmt.Sprintf("%s (%d)%s", stem, i, ext)) {
				return
			}
		}
	}
}

func commitPart(parent *os.Root, part, destDir, name string, isDir bool, expect os.FileInfo) (string, error) {
	cur, err := parent.Lstat(part)
	if err != nil || !os.SameFile(cur, expect) {
		return "", errPartReplaced
	}

	for candidate := range uniqueNames(name) {
		if isDir {
			err = renameIfAbsent(parent, part, candidate)
		} else {
			err = linkOrRename(parent, part, candidate)
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		return filepath.Join(destDir, candidate), nil
	}
	return "", errors.New("no free name for the received item")
}

func commitPartFile(parent *os.Root, f *os.File, hidden, destDir, name string, own owner) (string, error) {
	if err := f.Chmod(0o644); err != nil {
		return "", fmt.Errorf("set permissions of received file: %w", err)
	}
	if err := handOverFile(f, own); err != nil {
		return "", fmt.Errorf("hand received file to user: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return commitPart(parent, hidden, destDir, name, false, info)
}

func commitPartDir(parent, dir *os.Root, hidden, destDir, name string, own owner) (string, error) {
	if err := chownRootedTree(dir, own); err != nil {
		return "", err
	}
	top, err := dir.Open(".")
	if err != nil {
		return "", err
	}
	info, err := top.Stat()
	if err == nil {
		err = top.Chmod(0o755)
	}
	_ = top.Close()
	if err != nil {
		return "", fmt.Errorf("set permissions of received folder: %w", err)
	}
	if err := dir.Close(); err != nil {
		return "", err
	}
	return commitPart(parent, hidden, destDir, name, true, info)
}

func linkOrRename(parent *os.Root, oldname, newname string) error {
	err := linkEntry(parent, oldname, newname)
	if err == nil {
		return parent.Remove(oldname)
	}
	if errors.Is(err, os.ErrExist) {
		return err
	}
	return renameIfAbsent(parent, oldname, newname)
}

func renameIfAbsent(parent *os.Root, oldname, newname string) error {
	if _, err := parent.Lstat(newname); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return parent.Rename(oldname, newname)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	if w.limit > 0 && w.n > w.limit {
		return 0, errArchiveTooLarge
	}
	return len(p), nil
}

func tarDir(ctx context.Context, srcDir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	base := filepath.Clean(srcDir)

	return filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}

		switch {
		case info.IsDir():
			dir, err := ipcauth.OpenReadableDir(ctx, path)
			if err != nil {
				return fmt.Errorf("cannot read directory %s: %w", path, err)
			}
			dirInfo, statErr := dir.Stat()
			_ = dir.Close()
			if statErr != nil {
				return statErr
			}
			if rel == "." {
				return nil
			}
			return writeTarHeader(tw, dirInfo, rel)

		case info.Mode().IsRegular():
			f, err := ipcauth.OpenReadableFile(ctx, path)
			if err != nil {
				return fmt.Errorf("cannot read file %s: %w", path, err)
			}
			defer f.Close()

			fileInfo, err := f.Stat()
			if err != nil {
				return err
			}
			if err := writeTarHeader(tw, fileInfo, rel); err != nil {
				return err
			}
			if _, err := io.CopyN(tw, &ctxReader{ctx: ctx, r: f}, fileInfo.Size()); err != nil {
				return err
			}
			return f.Close()

		default:
			return nil
		}
	})
}

func writeTarHeader(tw *tar.Writer, info os.FileInfo, rel string) error {
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = filepath.ToSlash(rel)
	if info.IsDir() {
		hdr.Name += "/"
	}
	hdr.Uid, hdr.Gid = 0, 0
	hdr.Uname, hdr.Gname = "", ""
	return tw.WriteHeader(hdr)
}

// humanSize renders a byte count the way a person reads it (used in errors shown
// to the user; the CLI has its own formatter for progress output).
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func safeTarName(name string) error {
	if name == "" {
		return errors.New("refusing empty archive entry name")
	}

	if filepath.IsAbs(name) ||
		strings.HasPrefix(name, "/") ||
		strings.HasPrefix(name, `\`) {
		return fmt.Errorf("refusing absolute archive entry %q", name)
	}

	normalized := strings.ReplaceAll(name, `\`, "/")

	for _, part := range strings.Split(normalized, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			return fmt.Errorf("refusing path traversal entry %q", name)
		}

		if !validWindowsName(part) {
			return fmt.Errorf(
				"refusing Windows-invalid archive entry %q",
				name,
			)
		}
	}

	return nil
}

func isSparseEntry(hdr *tar.Header) bool {
	if hdr.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

func untarIntoRoot(r io.Reader, archiveSize int64, root *os.Root) (files int, written int64, err error) {
	limit := min(archiveSize, maxExtractBytes)

	tr := tar.NewReader(r)
	var total int64
	var entries int
	var nameBytes int64

	seenNames := make(map[string]string)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files, total, err
		}

		entries++
		if entries > maxArchiveEntries {
			return files, total, fmt.Errorf("archive has more than %d entries", maxArchiveEntries)
		}
		if len(hdr.Name) > maxArchiveNameLen {
			return files, total, fmt.Errorf("archive entry name longer than %d bytes", maxArchiveNameLen)
		}
		nameBytes += int64(len(hdr.Name))
		if nameBytes > maxArchiveNameBytes {
			return files, total, errors.New("archive entry names are too large in total")
		}
		if isSparseEntry(hdr) {
			return files, total, fmt.Errorf("archive entry %q uses an unsupported sparse format", hdr.Name)
		}

		if err := safeTarName(hdr.Name); err != nil {
			return files, total, err
		}

		normalizedName := strings.ReplaceAll(hdr.Name, `\`, "/")
		normalizedName = path.Clean(normalizedName)

		caseKey := strings.ToLower(normalizedName)
		if previous, ok := seenNames[caseKey]; ok && previous != normalizedName {
			return files, total, fmt.Errorf(
				"archive contains case-insensitive filename collision between %q and %q",
				previous,
				hdr.Name,
			)
		}
		seenNames[caseKey] = normalizedName

		name := filepath.Clean(filepath.FromSlash(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return files, total, fmt.Errorf(
					"create directory %q: %w",
					hdr.Name,
					err,
				)
			}

		case tar.TypeReg:
			if hdr.Size < 0 {
				return files, total, fmt.Errorf(
					"invalid negative size for archive entry %q",
					hdr.Name,
				)
			}

			if hdr.Size > limit-total {
				return files, total, fmt.Errorf(
					"archive entry %q is larger than the archive allows (%d bytes): %w",
					hdr.Name,
					limit,
					errArchiveExceedsSize,
				)
			}

			parent := filepath.Dir(name)
			if parent != "." {
				if err := root.MkdirAll(parent, 0o755); err != nil {
					return files, total, fmt.Errorf(
						"create parent directory for %q: %w",
						hdr.Name,
						err,
					)
				}
			}

			out, err := root.OpenFile(
				name,
				os.O_WRONLY|os.O_CREATE|os.O_EXCL,
				os.FileMode(hdr.Mode)&0o777,
			)
			if err != nil {
				return files, total, fmt.Errorf(
					"create archive entry %q: %w",
					hdr.Name,
					err,
				)
			}

			n, copyErr := io.CopyN(out, tr, hdr.Size)
			closeErr := out.Close()

			total += n

			if copyErr != nil {
				return files, total, fmt.Errorf(
					"extract archive entry %q: %w",
					hdr.Name,
					copyErr,
				)
			}

			if closeErr != nil {
				return files, total, fmt.Errorf(
					"close archive entry %q: %w",
					hdr.Name,
					closeErr,
				)
			}

			if n != hdr.Size {
				return files, total, fmt.Errorf(
					"short archive entry %q: expected %d bytes, wrote %d",
					hdr.Name,
					hdr.Size,
					n,
				)
			}

			files++

		case tar.TypeSymlink,
			tar.TypeLink,
			tar.TypeChar,
			tar.TypeBlock,
			tar.TypeFifo:
			continue

		default:
			continue
		}
	}

	return files, total, nil
}

func removeCreatedDir(parent, created *os.Root, name string) {
	_ = clearRoot(created)
	_ = created.Close()
	if err := parent.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = parent.RemoveAll(name)
	}
}

func clearRoot(root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}

	return nil
}
