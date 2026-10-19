package grpc

import (
	"context"
	"crypto/cipher"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/recorder/internal/asciicast"
	"github.com/netbirdio/netbird/recorder/internal/crypt"
	"github.com/netbirdio/netbird/recorder/internal/live"
	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/storage"
	recorderproto "github.com/netbirdio/netbird/recorder/proto"
)

const (
	DefaultMaxConcurrentSessions = 128
	DefaultMaxSessionsPerPeer    = 32
	DefaultMaxSessionBytes       = 10 << 30 // 10 GiB
	DefaultMaxSessionDuration    = 7 * 24 * time.Hour
	idleStreamTimeout            = 2 * time.Minute
	idleTimeoutMessage           = "recording session received no events (including heartbeats) within the idle timeout"
	limitExceededMessage         = "recording session exceeded its configured size or duration limit"
	eventRateExceededMessage     = "recording session exceeded its event rate limit"
	DefaultMaxEventsPerSecond    = 500
	DefaultEventBurst            = 5000
	defaultTermCols              = 80
	defaultTermRows              = 24
	maxSaneTermSize              = 10000
)

type IdentityResolver interface {
	IdentityForIP(ip netip.Addr) (pubKey, fqdn string, ok bool)
}

type Limits struct {
	MaxSessionBytes       int64
	MaxSessionDuration    time.Duration
	MaxConcurrentSessions int
	MaxSessionsPerPeer    int
	IdleTimeout           time.Duration
	MaxEventsPerSecond    float64
	EventBurst            int
}

type Service struct {
	recorderproto.UnimplementedRecorderServiceServer

	identity IdentityResolver
	storage  *storage.Store
	meta     metadata.Store
	gcm      cipher.AEAD
	live     *live.Hub
	logger   *log.Logger
	limits   Limits

	sessionSlots chan struct{}

	peerSlotsMu sync.Mutex
	peerSlots   map[string]int
}

type resolvedIdentity struct {
	peerID string
	ip     netip.Addr
	name   string
}

type recordingSession struct {
	id         string
	castWriter *asciicast.Writer
	streamEnc  *crypt.StreamWriter
	file       io.WriteCloser
	live       *live.Hub
	startedAt  time.Time

	maxBytes     int64
	maxDuration  time.Duration
	idleTimeout  time.Duration
	eventLimiter *rate.Limiter

	exitCode      int32
	gotEnd        bool
	writeFailed   bool
	limitExceeded bool
	idleTimedOut  bool
	rateLimited   bool
	bytesWritten  int64
}

func (l Limits) withDefaults() Limits {
	if l.MaxSessionBytes <= 0 {
		l.MaxSessionBytes = DefaultMaxSessionBytes
	}
	if l.MaxSessionDuration <= 0 {
		l.MaxSessionDuration = DefaultMaxSessionDuration
	}
	if l.MaxConcurrentSessions <= 0 {
		l.MaxConcurrentSessions = DefaultMaxConcurrentSessions
	}
	if l.MaxSessionsPerPeer <= 0 {
		l.MaxSessionsPerPeer = DefaultMaxSessionsPerPeer
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = idleStreamTimeout
	}
	if l.MaxEventsPerSecond <= 0 {
		l.MaxEventsPerSecond = DefaultMaxEventsPerSecond
	}
	if l.EventBurst <= 0 {
		l.EventBurst = DefaultEventBurst
	}
	return l
}

func New(identity IdentityResolver, store *storage.Store, meta metadata.Store, gcm cipher.AEAD, liveHub *live.Hub, logger *log.Logger, limits Limits) *Service {
	limits = limits.withDefaults()
	return &Service{
		identity:     identity,
		storage:      store,
		meta:         meta,
		gcm:          gcm,
		live:         liveHub,
		logger:       logger,
		limits:       limits,
		sessionSlots: make(chan struct{}, limits.MaxConcurrentSessions),
		peerSlots:    make(map[string]int),
	}
}

// acquirePeerSlot reserves a slot for peerID if under MaxSessionsPerPeer
func (s *Service) acquirePeerSlot(peerID string) bool {
	s.peerSlotsMu.Lock()
	defer s.peerSlotsMu.Unlock()
	if s.peerSlots[peerID] >= s.limits.MaxSessionsPerPeer {
		return false
	}
	s.peerSlots[peerID]++
	return true
}

func (s *Service) releasePeerSlot(peerID string) {
	s.peerSlotsMu.Lock()
	defer s.peerSlotsMu.Unlock()
	s.peerSlots[peerID]--
	if s.peerSlots[peerID] <= 0 {
		delete(s.peerSlots, peerID)
	}
}

// Stream receives SessionStart, events, then SessionEnd; interrupted
// sessions are kept on disk and marked "interrupted".
func (s *Service) Stream(stream recorderproto.RecorderService_StreamServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive SessionStart: %v", err)
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "first message must be SessionStart")
	}

	identity, err := s.verifyIdentity(ctx, start.GetClaimedPeerId())
	if err != nil {
		s.logger.Warnf("recorder: rejecting session %s: %v", start.GetSessionId(), err)
		return status.Error(codes.PermissionDenied, err.Error())
	}

	select {
	case s.sessionSlots <- struct{}{}:
	default:
		s.logger.Warnf("recorder: rejecting session %s: at the concurrent session limit", start.GetSessionId())
		return status.Error(codes.ResourceExhausted, "recorder is at its concurrent session limit")
	}
	defer func() { <-s.sessionSlots }()

	if !s.acquirePeerSlot(identity.peerID) {
		s.logger.Warnf("recorder: rejecting session %s: peer %s is at its per-peer concurrent session limit", start.GetSessionId(), identity.peerID)
		return status.Error(codes.ResourceExhausted, "producer is at its per-peer concurrent session limit")
	}
	defer s.releasePeerSlot(identity.peerID)

	sess, err := s.openSession(ctx, start, identity)
	if err != nil {
		return status.Errorf(codes.Internal, "open recording session: %v", err)
	}
	defer sess.finalize(ctx, s.meta, s.logger)

	return sess.run(stream)
}

// verifyIdentity ensures claimedPeerID matches the tunnel source, preventing spoofed attribution
func (s *Service) verifyIdentity(ctx context.Context, claimedPeerID string) (resolvedIdentity, error) {
	if claimedPeerID == "" {
		return resolvedIdentity{}, fmt.Errorf("claimed_peer_id is empty")
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return resolvedIdentity{}, fmt.Errorf("no peer address in stream context")
	}
	tcpAddr, ok := p.Addr.(*net.TCPAddr)
	if !ok {
		return resolvedIdentity{}, fmt.Errorf("unexpected peer address type %T", p.Addr)
	}
	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return resolvedIdentity{}, fmt.Errorf("invalid peer IP %v", tcpAddr.IP)
	}
	ip = ip.Unmap()

	resolvedPeerID, fqdn, ok := s.identity.IdentityForIP(ip)
	if !ok {
		return resolvedIdentity{}, fmt.Errorf("no known peer identity for tunnel source %s", ip)
	}
	if resolvedPeerID != claimedPeerID {
		return resolvedIdentity{}, fmt.Errorf("claimed peer id %q does not match resolved identity %q for %s", claimedPeerID, resolvedPeerID, ip)
	}
	return resolvedIdentity{peerID: resolvedPeerID, ip: ip, name: fqdn}, nil
}

// sanitizeTermSize falls back to the default size if cols/rows are zero or too large.
func sanitizeTermSize(cols, rows uint32) (uint32, uint32) {
	if cols == 0 || cols > maxSaneTermSize {
		cols = defaultTermCols
	}
	if rows == 0 || rows > maxSaneTermSize {
		rows = defaultTermRows
	}
	return cols, rows
}

func (s *Service) openSession(ctx context.Context, start *recorderproto.SessionStart, identity resolvedIdentity) (*recordingSession, error) {
	sessionID := storage.NewSessionID()

	file, path, err := s.storage.CreateWriter(sessionID)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	cols, rows := sanitizeTermSize(start.GetCols(), start.GetRows())

	streamEnc := crypt.NewStreamWriter(file, s.gcm)

	liveTee := &live.TeeWriter{Hub: s.live, SessionID: sessionID}
	castWriter, err := asciicast.NewWriter(io.MultiWriter(streamEnc, liveTee), cols, rows, time.Now())
	if err != nil {
		_ = streamEnc.Close()
		_ = file.Close()
		return nil, fmt.Errorf("init asciicast writer: %w", err)
	}

	meta := &metadata.Session{
		ID:             sessionID,
		PeerID:         identity.peerID,
		PeerName:       identity.name,
		PeerIP:         identity.ip.String(),
		SourcePeerID:   start.GetSourcePeerId(),
		SourcePeerName: start.GetSourcePeerName(),
		SourcePeerIP:   start.GetSourcePeerIp(),
		UserIDHash:     start.GetJwtUserIdHash(),
		OSUsername:     start.GetOsUsername(),
		StartedAt:      time.Now().UTC(),
		CastPath:       path,
		Cols:           int(cols),
		Rows:           int(rows),
		Status:         metadata.StatusRecording,
	}
	if err := s.meta.CreateSession(ctx, meta); err != nil {
		_ = streamEnc.Close()
		_ = file.Close()
		return nil, fmt.Errorf("create session metadata: %w", err)
	}

	return &recordingSession{
		id:           sessionID,
		castWriter:   castWriter,
		streamEnc:    streamEnc,
		file:         file,
		live:         s.live,
		startedAt:    time.Now(),
		maxBytes:     s.limits.MaxSessionBytes,
		maxDuration:  s.limits.MaxSessionDuration,
		idleTimeout:  s.limits.IdleTimeout,
		eventLimiter: rate.NewLimiter(rate.Limit(s.limits.MaxEventsPerSecond), s.limits.EventBurst),
	}, nil
}

// run acks events until the stream ends. Returns nil on normal endings and
// codes.ResourceExhausted on limits, which the producer reports distinctly.
func (rs *recordingSession) run(stream recorderproto.RecorderService_StreamServer) error {
	type recvResult struct {
		ev  *recorderproto.RecordEvent
		err error
	}

	recvCh := make(chan recvResult, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			ev, err := stream.Recv()
			select {
			case recvCh <- recvResult{ev, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	idleTimer := time.NewTimer(rs.idleTimeout)
	defer idleTimer.Stop()

	var seq uint64
	for {
		var res recvResult
		select {
		case res = <-recvCh:
		case <-idleTimer.C:
			rs.idleTimedOut = true
			return status.Error(codes.ResourceExhausted, idleTimeoutMessage)
		}
		if res.err != nil {
			return nil //nolint:nilerr
		}

		if !idleTimer.Stop() {
			<-idleTimer.C
		}
		idleTimer.Reset(rs.idleTimeout)

		if time.Since(rs.startedAt) > rs.maxDuration {
			rs.limitExceeded = true
			return status.Error(codes.ResourceExhausted, limitExceededMessage)
		}

		if !rs.eventLimiter.Allow() {
			rs.rateLimited = true
			return status.Error(codes.ResourceExhausted, eventRateExceededMessage)
		}

		now := time.Now()
		switch e := res.ev.Event.(type) {
		case *recorderproto.RecordEvent_Output:
			rs.bytesWritten += int64(len(e.Output.GetData()))
			if rs.bytesWritten > rs.maxBytes {
				rs.limitExceeded = true
				return status.Error(codes.ResourceExhausted, limitExceededMessage)
			}
			if werr := rs.castWriter.Output(now, e.Output.GetData()); werr != nil {
				rs.writeFailed = true
				return nil //nolint:nilerr
			}
		case *recorderproto.RecordEvent_Resize:
			if werr := rs.castWriter.Resize(now, e.Resize.GetCols(), e.Resize.GetRows()); werr != nil {
				rs.writeFailed = true
				return nil //nolint:nilerr
			}
		case *recorderproto.RecordEvent_End:
			rs.exitCode = e.End.GetExitCode()
			rs.gotEnd = true
			_ = rs.castWriter.Exit(now, rs.exitCode)
		case *recorderproto.RecordEvent_Start:
			// Ignore a duplicate Start rather than restart an in-progress recording.
		case *recorderproto.RecordEvent_Heartbeat:
			// Keepalive: only resets the idle timer above.
		}

		seq++
		if sendErr := stream.Send(&recorderproto.RecordEventAck{LastSeq: seq}); sendErr != nil {
			return nil //nolint:nilerr
		}
		if rs.gotEnd {
			return nil
		}
	}
}

// finalize closes the writers and records the final status; deferred once in Stream.
func (rs *recordingSession) finalize(_ context.Context, meta metadata.Store, logger *log.Logger) {
	rs.live.End(rs.id)

	if err := rs.streamEnc.Close(); err != nil {
		logger.Warnf("recorder: close encrypted stream for session %s: %v", rs.id, err)
		rs.writeFailed = true
	}
	if err := rs.file.Close(); err != nil {
		logger.Warnf("recorder: close recording file for session %s: %v", rs.id, err)
		rs.writeFailed = true
	}

	if rs.limitExceeded {
		logger.Warnf("recorder: session %s exceeded its resource limit (%d bytes written) and was cut off", rs.id, rs.bytesWritten)
	}
	if rs.idleTimedOut {
		logger.Warnf("recorder: session %s received no events (including heartbeats) within %s and was cut off", rs.id, rs.idleTimeout)
	}
	if rs.rateLimited {
		logger.Warnf("recorder: session %s exceeded its event rate limit and was cut off", rs.id)
	}

	status := metadata.StatusInterrupted
	if rs.gotEnd && !rs.writeFailed && !rs.limitExceeded && !rs.idleTimedOut && !rs.rateLimited {
		status = metadata.StatusCompleted
	} else if rs.writeFailed || rs.limitExceeded || rs.idleTimedOut || rs.rateLimited {
		status = metadata.StatusFailed
	}

	exitCode := rs.exitCode

	if err := meta.FinalizeSession(context.Background(), rs.id, time.Now().UTC(), &exitCode, status); err != nil {
		logger.Errorf("recorder: finalize session %s: %v", rs.id, err)
	}
}
