package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/birddrop"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

var birdDrop birdDropState

const (
	birdDropReadyTimeout = 10 * time.Second
	birdDropIdleTimeout  = 5 * time.Second
)

type birdDropState struct {
	mu      sync.Mutex
	startMu sync.Mutex

	mgr         *birddrop.Manager
	gen         int
	enabled     bool // inbound offers allowed by --allow-birddrop
	activeSends int  // outbound sends currently requiring the transport
	idleTimer   *time.Timer
}

// birdDropEnabled reports whether this peer currently accepts inbound Birddrop offers
func birdDropEnabled() bool {
	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()
	return birdDrop.enabled
}

// getFileMgr returns the live Birddrop transport manager.
func getFileMgr() *birddrop.Manager {
	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()
	return birdDrop.mgr
}

func discardBirdDropOffers() {
	if mgr := getFileMgr(); mgr != nil {
		if n := mgr.DiscardIncoming(); n > 0 {
			log.Infof("birddrop: discarded %d pending offer(s) at end of session", n)
		}
	}
}

func fileNotReadyErr() error {
	return status.Error(
		codes.Unavailable,
		"file transfer is not ready yet (is the client connected?)",
	)
}

// birddropPayloadTypeToProto converts the internal payload type to the daemon API enum.
func birddropPayloadTypeToProto(t birddrop.PayloadType) proto.BirddropPayloadType {
	switch t {
	case birddrop.PayloadFile:
		return proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_FILE
	case birddrop.PayloadDirectory:
		return proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_DIRECTORY
	case birddrop.PayloadClipboard:
		return proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD
	default:
		return proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_UNSPECIFIED
	}
}

// sameIP compares an overlay address from the status recorder (which may carry a
// /prefix) with a remote address seen on a connection.
func sameIP(peerAddr, remoteIP string) bool {
	peerAddr = stripCIDR(peerAddr)
	if peerAddr == "" || remoteIP == "" {
		return false
	}
	a, b := net.ParseIP(peerAddr), net.ParseIP(remoteIP)
	if a == nil || b == nil {
		return peerAddr == remoteIP
	}
	return a.Equal(b)
}

// startBirdDrop reconciles the Birddrop receiver with the current config
func (s *Server) startBirdDrop() {
	birdDrop.startMu.Lock()
	defer birdDrop.startMu.Unlock()

	want := s.config != nil &&
		s.config.AllowBirdDrop != nil &&
		*s.config.AllowBirdDrop

	birdDrop.mu.Lock()
	birdDrop.enabled = want

	if birdDrop.mgr != nil {
		mgr := birdDrop.mgr
		mgr.SetAllowOffers(want)

		if want {
			if birdDrop.idleTimer != nil {
				birdDrop.idleTimer.Stop()
				birdDrop.idleTimer = nil
			}
			birdDrop.mu.Unlock()
			return
		}

		if birdDrop.activeSends == 0 {
			s.scheduleBirdDropShutdownLocked()
		}

		birdDrop.mu.Unlock()
		return
	}

	if !want {
		// Peers that have not opted in and are not actively sending should not
		// expose the Birddrop listener.
		birdDrop.mu.Unlock()
		return
	}

	birdDrop.gen++
	gen := birdDrop.gen
	birdDrop.mu.Unlock()

	s.startBirdDropTransport(gen, true)
}

// startBirdDropTransport constructs the manager for one transport generation
func (s *Server) startBirdDropTransport(gen int, allowOffers bool) {
	sr := s.statusRecorder

	allow := func(remoteIP string) (fqdn string, ok bool) {
		fs := sr.GetFullStatus()

		for _, p := range fs.Peers {
			if sameIP(p.IP, remoteIP) || sameIP(p.IPv6, remoteIP) {
				return p.FQDN, true
			}
		}

		if lp := sr.GetLocalPeerState(); sameIP(lp.IP, remoteIP) ||
			sameIP(lp.IPv6, remoteIP) {
			return lp.FQDN, true
		}

		return "", false
	}

	mgr, err := birddrop.NewManager("", allow)
	if err != nil {
		log.Warnf("birddrop: initialization failed: %v", err)
		return
	}

	mgr.SetAllowOffers(allowOffers)

	birdDrop.mu.Lock()
	if birdDrop.gen != gen {
		birdDrop.mu.Unlock()
		_ = mgr.Shutdown()
		return
	}

	if birdDrop.mgr != nil {
		birdDrop.mu.Unlock()
		_ = mgr.Shutdown()
		return
	}

	birdDrop.mgr = mgr
	birdDrop.mu.Unlock()

	go s.superviseBirdDrop(mgr, gen, allow)
}

// scheduleBirdDropShutdownLocked tears down an unused sending-only transport
// after a short grace period
func (s *Server) scheduleBirdDropShutdownLocked() {
	if birdDrop.enabled ||
		birdDrop.activeSends != 0 ||
		birdDrop.mgr == nil {
		return
	}

	if birdDrop.idleTimer != nil {
		birdDrop.idleTimer.Stop()
	}

	mgr := birdDrop.mgr
	gen := birdDrop.gen

	birdDrop.idleTimer = time.AfterFunc(birdDropIdleTimeout, func() {
		birdDrop.startMu.Lock()
		defer birdDrop.startMu.Unlock()

		birdDrop.mu.Lock()

		if birdDrop.gen != gen ||
			birdDrop.mgr != mgr ||
			birdDrop.enabled ||
			birdDrop.activeSends != 0 {
			birdDrop.idleTimer = nil
			birdDrop.mu.Unlock()
			return
		}

		birdDrop.gen++
		birdDrop.mgr = nil
		birdDrop.idleTimer = nil

		birdDrop.mu.Unlock()

		_ = mgr.Shutdown()
	})
}

// waitBirdDropTransport waits until the current generation has bound at least
// one overlay address.
func waitBirdDropTransport(
	ctx context.Context,
	gen int,
) (*birddrop.Manager, error) {
	timer := time.NewTimer(birdDropReadyTimeout)
	defer timer.Stop()

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		birdDrop.mu.Lock()
		currentGen := birdDrop.gen
		mgr := birdDrop.mgr
		birdDrop.mu.Unlock()

		if currentGen != gen {
			return nil, errors.New("birddrop transport was replaced while starting")
		}

		if mgr != nil && len(mgr.BoundAddrs()) != 0 {
			return mgr, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-timer.C:
			return nil, errors.New(
				"timed out waiting for the Birddrop transport to bind to the NetBird interface",
			)

		case <-ticker.C:
		}
	}
}

// acquireBirdDropTransport keeps the transport alive for one outbound send.
func (s *Server) acquireBirdDropTransport(
	ctx context.Context,
) (*birddrop.Manager, error) {
	birdDrop.startMu.Lock()

	birdDrop.mu.Lock()

	if birdDrop.idleTimer != nil {
		birdDrop.idleTimer.Stop()
		birdDrop.idleTimer = nil
	}

	birdDrop.activeSends++

	if birdDrop.mgr != nil {
		gen := birdDrop.gen
		birdDrop.mu.Unlock()
		birdDrop.startMu.Unlock()

		mgr, err := waitBirdDropTransport(ctx, gen)
		if err != nil {
			s.releaseBirdDropTransport()
			return nil, err
		}
		return mgr, nil
	}

	birdDrop.gen++
	gen := birdDrop.gen
	allowOffers := birdDrop.enabled

	birdDrop.mu.Unlock()

	s.startBirdDropTransport(gen, allowOffers)

	birdDrop.startMu.Unlock()

	mgr, err := waitBirdDropTransport(ctx, gen)
	if err != nil {
		s.releaseBirdDropTransport()
		return nil, err
	}

	return mgr, nil
}

// releaseBirdDropTransport releases one outbound-send reference and schedules
// shutdown when the transport is no longer needed for inbound offers or sends.
func (s *Server) releaseBirdDropTransport() {
	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()

	if birdDrop.activeSends > 0 {
		birdDrop.activeSends--
	}

	if birdDrop.activeSends == 0 && !birdDrop.enabled {
		s.scheduleBirdDropShutdownLocked()
	}
}

func (s *Server) superviseBirdDrop(mgr *birddrop.Manager, gen int, allow birddrop.AllowPeer) {
	defer func() {
		birdDrop.mu.Lock()
		if birdDrop.gen == gen {
			birdDrop.mgr = nil // let the next `up` start a fresh generation
		}
		birdDrop.mu.Unlock()
		_ = mgr.Shutdown() // idempotent; ensures sockets are closed
	}()

	sr := s.statusRecorder
	for {
		birdDrop.mu.Lock()
		current := birdDrop.gen == gen
		birdDrop.mu.Unlock()
		if !current {
			return
		}
		lp := sr.GetLocalPeerState()
		var ips []string
		if v4 := stripCIDR(lp.IP); v4 != "" {
			ips = append(ips, v4)
		}
		if v6 := stripCIDR(lp.IPv6); v6 != "" {
			ips = append(ips, v6)
		}

		if len(ips) == 1 && stripCIDR(lp.IPv6) == "" {
			time.Sleep(1 * time.Second)
			birdDrop.mu.Lock()
			stillCurrent := birdDrop.gen == gen &&
				(birdDrop.enabled || birdDrop.activeSends > 0)
			birdDrop.mu.Unlock()
			if !stillCurrent {
				return
			}
			lp = sr.GetLocalPeerState()
			ips = ips[:0]
			if v4 := stripCIDR(lp.IP); v4 != "" {
				ips = append(ips, v4)
			}
			if v6 := stripCIDR(lp.IPv6); v6 != "" {
				ips = append(ips, v6)
			}
		}
		if len(ips) > 0 {
			mgr.SetSelfName(lp.FQDN)

			done := make(chan struct{})

			go func(m *birddrop.Manager) {
				t := time.NewTicker(1 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-done:
						return
					case <-t.C:
						birdDrop.mu.Lock()
						superseded := birdDrop.gen != gen
						birdDrop.mu.Unlock()
						if superseded {
							_ = m.Shutdown()
							return
						}
					}
				}
			}(mgr)

			go func(m *birddrop.Manager) {
				time.Sleep(200 * time.Millisecond)
				if bound := m.BoundAddrs(); len(bound) > 0 {
					log.Infof("birddrop: listening on %v", bound)
					if len(bound) < len(ips) {
						log.Warnf("birddrop: only %d of %d addresses bound (asked for %v); "+
							"some address families may be unavailable", len(bound), len(ips), ips)
					}
				}
			}(mgr)

			go func(m *birddrop.Manager) {
				t := time.NewTicker(2 * time.Second)
				defer t.Stop()
				deadline := time.Now().Add(2 * time.Minute)
				for {
					select {
					case <-done:
						return
					case <-t.C:
						if time.Now().After(deadline) {
							return
						}
						birdDrop.mu.Lock()
						superseded := birdDrop.gen != gen
						birdDrop.mu.Unlock()
						if superseded {
							return
						}
						before := len(m.BoundAddrs())
						cur := sr.GetLocalPeerState()
						for _, ip := range []string{stripCIDR(cur.IP), stripCIDR(cur.IPv6)} {
							if ip == "" {
								continue
							}
							_ = m.AddListener(ip) // best effort; still tentative is fine
						}
						if now := m.BoundAddrs(); len(now) > before {
							log.Infof("birddrop: attached a late listener; now listening on %v", now)
						}
					}
				}
			}(mgr)
			err := mgr.Serve(ips, birddrop.DefaultPort)
			close(done)
			if err != nil {

				log.Debugf("birddrop: no address bound yet, retrying with a fresh manager: %v", err)
				_ = mgr.Shutdown()
				fresh, nerr := birddrop.NewManager("", allow)
				if nerr != nil {
					log.Warnf("birddrop: could not create a new manager for retry: %v", nerr)
					return
				}

				birdDrop.mu.Lock()
				if birdDrop.gen != gen ||
					(!birdDrop.enabled && birdDrop.activeSends == 0) {
					birdDrop.mu.Unlock()
					_ = fresh.Shutdown()
					return
				}

				fresh.SetAllowOffers(birdDrop.enabled)

				birdDrop.mgr = fresh
				mgr = fresh
				birdDrop.mu.Unlock()

				time.Sleep(2 * time.Second)
				continue
			}

			return
		}
		time.Sleep(2 * time.Second) // overlay IP not up yet; wait and retry
	}
}

func birdDropCaller(ctx context.Context) (ipcauth.Identity, error) {
	if ipcauth.IsForwarded(ctx) {
		return ipcauth.Identity{}, status.Error(codes.PermissionDenied,
			"BirdDrop transfers are not available through the JSON gateway; use the netbird CLI")
	}
	id, ok := ipcauth.CallerIdentity(ctx)
	if !ok {
		return ipcauth.Identity{}, status.Error(codes.PermissionDenied, "unable to authenticate local caller")
	}
	return id, nil
}

// receiveOwner returns the Unix owner for received files. Windows identities
// carry a SID instead (their UID and GID are zero), and Windows has no chown, so
// no Unix ownership change is requested there.
func receiveOwner(goos string, caller ipcauth.Identity) (uid, gid int) {
	if goos == "windows" {
		return -1, -1
	}
	return int(caller.UID), int(caller.GID)
}

// forwardSendEvents relays a transfer's progress events to the CLI.
func forwardSendEvents(stream proto.DaemonService_BirddropSendServer, evc <-chan birddrop.SendEvent) error {
	for ev := range evc {
		if err := stream.Send(&proto.BirddropSendEvent{
			State:       string(ev.State),
			Name:        ev.Name,
			Type:        birddropPayloadTypeToProto(ev.Type),
			IsDir:       ev.IsDir,
			Transferred: ev.Transferred,
			Total:       ev.Total,
			PeerFqdn:    ev.PeerFQDN,
			PeerIp:      ev.PeerIP,
			Message:     ev.Message,
		}); err != nil {
			return err
		}
	}
	return nil
}

// cannotSendErr is the single reply for any path the caller may not send, so
// the error never distinguishes "missing" from "exists but not yours".
func cannotSendErr(path string) error {
	return status.Errorf(codes.PermissionDenied,
		"cannot send %q: it does not exist, or you are not allowed to send it (files must be owned by you; every file and folder inside a folder must be readable by you)",
		path)
}

func (s *Server) BirddropSend(req *proto.BirddropSendRequest, stream proto.DaemonService_BirddropSendServer) error {
	fs := s.statusRecorder.GetFullStatus()
	ip, fqdn, err := resolvePeer(fs, req.GetPeer())
	if err != nil {
		return status.Error(codes.NotFound, err.Error())
	}

	caller, err := birdDropCaller(stream.Context())
	if err != nil {
		return err
	}

	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second

	if req.GetType() == proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD {
		mgr, err := s.acquireBirdDropTransport(stream.Context())
		if err != nil {
			return status.Error(codes.Unavailable, err.Error())
		}
		defer s.releaseBirdDropTransport()

		evc, err := mgr.SendClipboard(
			stream.Context(),
			ip,
			birddrop.DefaultPort,
			fqdn,
			req.GetClipboardText(),
			timeout,
		)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}

		if err := forwardSendEvents(stream, evc); err != nil {
			return err
		}

		return nil
	}

	if req.GetType() != proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_UNSPECIFIED {
		return status.Error(
			codes.InvalidArgument,
			"file and folder payload types are determined from the source path",
		)
	}

	if err := validateTransferPath(req.GetPath()); err != nil {
		return err
	}

	file, openErr := ipcauth.OpenOwnedFile(caller, req.GetPath())
	if openErr == nil {
		mgr, err := s.acquireBirdDropTransport(stream.Context())
		if err != nil {
			_ = file.Close()
			return status.Error(codes.Unavailable, err.Error())
		}
		defer s.releaseBirdDropTransport()

		evc, err := mgr.SendFile(
			stream.Context(),
			ip,
			birddrop.DefaultPort,
			fqdn,
			file,
			timeout,
		)
		if err != nil {
			_ = file.Close()
			return status.Error(codes.Internal, err.Error())
		}

		if err := forwardSendEvents(stream, evc); err != nil {
			return err
		}
		return nil
	}

	dir, dirErr := ipcauth.OpenReadableDir(stream.Context(), req.GetPath())
	if dirErr != nil {
		return cannotSendErr(req.GetPath())
	}
	_ = dir.Close()

	mgr, err := s.acquireBirdDropTransport(stream.Context())
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	defer s.releaseBirdDropTransport()

	evc, err := mgr.Send(
		stream.Context(),
		ip,
		birddrop.DefaultPort,
		fqdn,
		req.GetPath(),
		timeout,
	)
	if err != nil {
		return cannotSendErr(req.GetPath())
	}
	if err := forwardSendEvents(stream, evc); err != nil {
		return err
	}
	return nil
}

// BirddropList returns pending incoming offers.
func (s *Server) BirddropList(_ context.Context, _ *proto.BirddropListRequest) (*proto.BirddropListResponse, error) {
	mgr := getFileMgr()
	if mgr == nil {
		return nil, fileNotReadyErr()
	}
	resp := &proto.BirddropListResponse{}
	for _, it := range mgr.List() {
		resp.Items = append(resp.Items, &proto.BirddropOffer{
			Id:           it.ID,
			Name:         it.Name,
			From:         it.From,
			Size:         it.Size,
			Type:         birddropPayloadTypeToProto(it.Type),
			IsDir:        it.IsDir,
			ReceivedUnix: it.Received.Unix(),
		})
	}
	return resp, nil
}

// BirddropReceive pulls accepted offers into a caller-authorized destination and streams receive progress.
func (s *Server) BirddropReceive(req *proto.BirddropReceiveRequest, stream proto.DaemonService_BirddropReceiveServer) error {
	mgr := getFileMgr()
	if mgr == nil {
		return fileNotReadyErr()
	}

	caller, err := birdDropCaller(stream.Context())
	if err != nil {
		return err
	}

	uid, gid := receiveOwner(runtime.GOOS, caller)

	needsDest, err := mgr.RequiresDestination(req.GetIds())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	dest := req.GetDest()
	var destRoot *os.Root

	if needsDest {
		if err := validateTransferPath(dest); err != nil {
			return err
		}

		dir, err := ipcauth.OpenWritableDir(stream.Context(), dest)
		if err != nil {
			return status.Errorf(
				codes.PermissionDenied,
				"cannot receive files into %s: you don't have permission to write to this directory",
				dest,
			)
		}
		defer dir.Close()

		destRoot, err = os.OpenRoot(dest)
		if err != nil {
			return status.Errorf(
				codes.PermissionDenied,
				"cannot open receive directory %s: %v",
				dest,
				err,
			)
		}
		defer destRoot.Close()

		authorizedInfo, err := dir.Stat()
		if err != nil {
			return status.Errorf(codes.Internal, "stat authorized receive directory: %v", err)
		}

		rootInfo, err := destRoot.Stat(".")
		if err != nil {
			return status.Errorf(codes.Internal, "stat receive root: %v", err)
		}

		if !os.SameFile(authorizedInfo, rootInfo) {
			return status.Error(
				codes.PermissionDenied,
				"receive directory changed after authorization",
			)
		}
	}

	onProgress := func(p birddrop.ReceiveProgress) {
		_ = stream.Send(&proto.BirddropReceiveEvent{
			State:       "receiving",
			Id:          p.ID,
			Name:        p.Name,
			Type:        birddropPayloadTypeToProto(p.Type),
			IsDir:       p.IsDir,
			Transferred: p.Transferred,
			Total:       p.Total,
		})
	}
	results, err := mgr.Receive(
		stream.Context(),
		req.GetIds(),
		dest,
		destRoot,
		uid,
		gid,
		onProgress,
		// Windows: hand received files to the caller's account (empty on Unix).
		birddrop.WithOwnerSID(caller.SID),
	)
	if err != nil {
		_ = stream.Send(&proto.BirddropReceiveEvent{State: "error", Message: err.Error()})
		return status.Error(codes.Internal, err.Error())
	}
	for _, r := range results {
		name := ""
		if r.SavedAs != "" {
			name = filepath.Base(r.SavedAs)
		}

		if err := stream.Send(&proto.BirddropReceiveEvent{
			State:         "done",
			Id:            r.ID,
			Name:          name,
			SavedAs:       r.SavedAs,
			Bytes:         r.Bytes,
			IsDir:         r.IsDir,
			Files:         int32(r.Files),
			Type:          birddropPayloadTypeToProto(r.Type),
			ClipboardText: r.ClipboardText,
		}); err != nil {
			return err
		}
	}
	return nil
}

// BirddropReject declines pending incoming offers.
func (s *Server) BirddropReject(_ context.Context, req *proto.BirddropRejectRequest) (*proto.BirddropRejectResponse, error) {
	mgr := getFileMgr()
	if mgr == nil {
		return nil, fileNotReadyErr()
	}
	n, err := mgr.Reject(req.GetIds())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &proto.BirddropRejectResponse{Rejected: int32(n)}, nil
}

// resolvePeer maps a hostname/FQDN/IP to a peer's overlay IP + FQDN.
func resolvePeer(fs peer.FullStatus, target string) (ip, fqdn string, err error) {
	target = strings.TrimSpace(target)
	if net.ParseIP(target) != nil {
		return target, target, nil
	}

	if lp := fs.LocalPeerState; strings.EqualFold(lp.FQDN, target) || strings.EqualFold(shortHost(lp.FQDN), target) {
		if ip := stripCIDR(lp.IP); ip != "" {
			return ip, lp.FQDN, nil
		}
		if ip := stripCIDR(lp.IPv6); ip != "" {
			return ip, lp.FQDN, nil
		}
	}
	var matches []peer.State
	for _, p := range fs.Peers {
		if strings.EqualFold(p.FQDN, target) || strings.EqualFold(shortHost(p.FQDN), target) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		lt := strings.ToLower(target)
		for _, p := range fs.Peers {
			if strings.HasPrefix(strings.ToLower(p.FQDN), lt) {
				matches = append(matches, p)
			}
		}
	}
	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("no NetBird peer matches %q (try `netbird status`)", target)
	case 1:
		ip = stripCIDR(matches[0].IP)
		if ip == "" {
			ip = stripCIDR(matches[0].IPv6)
		}
		if ip == "" {
			return "", "", fmt.Errorf("peer %q has no NetBird IP yet", matches[0].FQDN)
		}
		return ip, matches[0].FQDN, nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.FQDN)
		}
		return "", "", fmt.Errorf("%q is ambiguous: %s", target, strings.Join(names, ", "))
	}
}

func shortHost(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

func stripCIDR(ip string) string {
	ip = strings.TrimSpace(ip)
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	return ip
}
