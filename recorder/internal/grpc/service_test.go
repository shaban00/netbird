package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	reccrypt "github.com/netbirdio/netbird/recorder/internal/crypt"
	"github.com/netbirdio/netbird/recorder/internal/live"
	recmeta "github.com/netbirdio/netbird/recorder/internal/metadata"
	metasqlite "github.com/netbirdio/netbird/recorder/internal/metadata/sqlite"
	"github.com/netbirdio/netbird/recorder/internal/storage"
	recorderproto "github.com/netbirdio/netbird/recorder/proto"
	"github.com/netbirdio/netbird/util/crypt"
)

type fakeIdentity struct {
	ip     netip.Addr
	pubKey string
	fqdn   string
}

type fakeStream struct {
	ctx  context.Context
	in   []*recorderproto.RecordEvent
	pos  int
	acks []*recorderproto.RecordEventAck
}

type blockingFakeStream struct {
	fakeStream
	unblock chan struct{}
}

type timedEvent struct {
	event *recorderproto.RecordEvent
	delay time.Duration
}

type pacedFakeStream struct {
	fakeStream
	events []timedEvent
	pos    int
}

type multiPeerIdentity map[netip.Addr]fakeIdentity

type alwaysFailingWriteCloser struct{}

func (f fakeIdentity) IdentityForIP(ip netip.Addr) (string, string, bool) {
	if ip != f.ip {
		return "", "", false
	}
	return f.pubKey, f.fqdn, true
}

func newFakeStream(remoteIP string, events ...*recorderproto.RecordEvent) *fakeStream {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 51000},
	})
	return &fakeStream{ctx: ctx, in: events}
}

func (f *fakeStream) Send(ack *recorderproto.RecordEventAck) error {
	f.acks = append(f.acks, ack)
	return nil
}

func (f *fakeStream) Recv() (*recorderproto.RecordEvent, error) {
	if f.pos >= len(f.in) {
		return nil, io.EOF
	}
	ev := f.in[f.pos]
	f.pos++
	return ev, nil
}

func newBlockingFakeStream(remoteIP string, events ...*recorderproto.RecordEvent) *blockingFakeStream {
	return &blockingFakeStream{fakeStream: *newFakeStream(remoteIP, events...), unblock: make(chan struct{})}
}

func (f *blockingFakeStream) Recv() (*recorderproto.RecordEvent, error) {
	if f.pos < len(f.in) {
		ev := f.in[f.pos]
		f.pos++
		return ev, nil
	}
	<-f.unblock
	return nil, io.EOF
}

func newPacedFakeStream(remoteIP string, events ...timedEvent) *pacedFakeStream {
	return &pacedFakeStream{fakeStream: *newFakeStream(remoteIP), events: events}
}

func (f *pacedFakeStream) Recv() (*recorderproto.RecordEvent, error) {
	if f.pos >= len(f.events) {
		return nil, io.EOF
	}
	e := f.events[f.pos]
	f.pos++
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	return e.event, nil
}

func heartbeatEvent() *recorderproto.RecordEvent {
	return &recorderproto.RecordEvent{Event: &recorderproto.RecordEvent_Heartbeat{Heartbeat: &recorderproto.Heartbeat{}}}
}

func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(m interface{}) error  { return nil }
func (f *fakeStream) RecvMsg(m interface{}) error  { return nil }

func startEvent(sessionID, claimedPeerID string, cols, rows uint32) *recorderproto.RecordEvent {
	return &recorderproto.RecordEvent{Event: &recorderproto.RecordEvent_Start{
		Start: &recorderproto.SessionStart{
			SessionId:     sessionID,
			ClaimedPeerId: claimedPeerID,
			JwtUserIdHash: "hash-abc",
			OsUsername:    "ubuntu",
			Cols:          cols,
			Rows:          rows,
			StartedAt:     timestamppb.Now(),
		},
	}}
}

func outputEvent(data string) *recorderproto.RecordEvent {
	return &recorderproto.RecordEvent{Event: &recorderproto.RecordEvent_Output{
		Output: &recorderproto.Output{Data: []byte(data)},
	}}
}

func endEvent(exitCode int32) *recorderproto.RecordEvent {
	return &recorderproto.RecordEvent{Event: &recorderproto.RecordEvent_End{
		End: &recorderproto.SessionEnd{ExitCode: exitCode},
	}}
}

func newTestService(t *testing.T, identity IdentityResolver) (*Service, *storage.Store, recmeta.Store, *live.Hub) {
	t.Helper()
	return newTestServiceWithLimits(t, identity, Limits{})
}

func newTestServiceWithLimits(t *testing.T, identity IdentityResolver, limits Limits) (*Service, *storage.Store, recmeta.Store, *live.Hub) {
	t.Helper()
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}

	fieldKey, err := crypt.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fieldEnc, err := crypt.NewFieldEncrypt(fieldKey)
	if err != nil {
		t.Fatalf("NewFieldEncrypt: %v", err)
	}

	recKey, err := reccrypt.GenerateKey()
	if err != nil {
		t.Fatalf("reccrypt.GenerateKey: %v", err)
	}
	gcm, err := reccrypt.NewCipher(recKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	meta, err := metasqlite.New(t.TempDir(), "test.db", fieldEnc)
	if err != nil {
		t.Fatalf("metasqlite.New: %v", err)
	}
	t.Cleanup(func() { meta.Close() })

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	liveHub := live.NewHub()
	return New(identity, store, meta, gcm, liveHub, logger, limits), store, meta, liveHub
}

func TestStream_RejectsMismatchedClaimedPeerID(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, _, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5", startEvent("sess-1", "attacker-claimed-pubkey", 80, 24))

	err := svc.Stream(stream)
	if err == nil {
		t.Fatal("expected rejection for mismatched claimed_peer_id, got nil error")
	}
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if len(stream.acks) != 0 {
		t.Fatalf("expected no acks for a rejected session, got %d", len(stream.acks))
	}
}

func TestStream_RejectsUnknownSourceIP(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, _, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.99", startEvent("sess-1", "real-peer-pubkey", 80, 24))

	err := svc.Stream(stream)
	if err == nil {
		t.Fatal("expected rejection for unresolvable source IP, got nil error")
	}
	if st, ok := grpcstatus.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestStream_AcceptsMatchingIdentityAndWritesRecording(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, store, meta, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		outputEvent("hello world"),
		endEvent(0),
	)

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if len(stream.acks) != 2 {
		t.Fatalf("expected 2 acks (output, end), got %d", len(stream.acks))
	}

	sessions, total, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 session recorded, got %d", total)
	}
	sess := sessions[0]
	if sess.Status != recmeta.StatusCompleted {
		t.Fatalf("expected status completed, got %q", sess.Status)
	}
	if sess.ExitCode == nil || *sess.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %v", sess.ExitCode)
	}
	if sess.PeerName != "peer.netbird" {
		t.Fatalf("expected peer name %q resolved from the tunnel identity, got %q", "peer.netbird", sess.PeerName)
	}
	if sess.PeerIP != "100.64.0.5" {
		t.Fatalf("expected peer ip %q resolved from the tunnel source, got %q", "100.64.0.5", sess.PeerIP)
	}

	r, err := store.OpenReader(sess.ID)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()

	recKey := svc.gcm
	plain, err := io.ReadAll(reccrypt.NewStreamReader(r, recKey))
	if err != nil {
		t.Fatalf("decrypt recording: %v", err)
	}
	if !bytes.Contains(plain, []byte("hello world")) {
		t.Fatalf("expected recorded output to contain %q, got %q", "hello world", plain)
	}

	lines := bytes.Split(bytes.TrimSpace(plain), []byte("\n"))
	if len(lines) < 1 {
		t.Fatal("expected at least a header line")
	}
	var header map[string]any
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatalf("unmarshal asciicast header: %v", err)
	}
	if header["version"] != float64(3) {
		t.Fatalf("expected asciicast version 3, got %v", header["version"])
	}
}

func TestStream_ClientDisconnectMarksInterrupted(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		outputEvent("partial output"),
	)

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusInterrupted {
		t.Fatalf("expected status interrupted, got %q", sessions[0].Status)
	}
}

func TestStream_RejectsBeyondConcurrentSessionLimit(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{MaxConcurrentSessions: 1})

	first := newBlockingFakeStream("100.64.0.5", startEvent("sess-1", "real-peer-pubkey", 80, 24))
	firstDone := make(chan error, 1)
	go func() { firstDone <- svc.Stream(first) }()

	deadline := time.Now().Add(time.Second)
	for {
		sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first session never reached openSession")
		}
		time.Sleep(time.Millisecond)
	}

	second := newFakeStream("100.64.0.5", startEvent("sess-2", "real-peer-pubkey", 80, 24), endEvent(0))
	err := svc.Stream(second)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted while at the concurrency limit, got %v", err)
	}

	close(first.unblock)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Stream call: %v", err)
	}

	third := newFakeStream("100.64.0.5", startEvent("sess-3", "real-peer-pubkey", 80, 24), endEvent(0))
	if err := svc.Stream(third); err != nil {
		t.Fatalf("expected the released slot to admit a new session, got %v", err)
	}
}

func (m multiPeerIdentity) IdentityForIP(ip netip.Addr) (string, string, bool) {
	id, ok := m[ip]
	if !ok {
		return "", "", false
	}
	return id.pubKey, id.fqdn, true
}

func TestStream_RejectsBeyondPerPeerSessionLimit(t *testing.T) {
	peerA := netip.MustParseAddr("100.64.0.5")
	peerB := netip.MustParseAddr("100.64.0.6")
	identity := multiPeerIdentity{
		peerA: {ip: peerA, pubKey: "peer-a-pubkey", fqdn: "peer-a.netbird"},
		peerB: {ip: peerB, pubKey: "peer-b-pubkey", fqdn: "peer-b.netbird"},
	}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{MaxSessionsPerPeer: 1})

	first := newBlockingFakeStream("100.64.0.5", startEvent("sess-1", "peer-a-pubkey", 80, 24))
	firstDone := make(chan error, 1)
	go func() { firstDone <- svc.Stream(first) }()

	deadline := time.Now().Add(time.Second)
	for {
		sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first session never reached openSession")
		}
		time.Sleep(time.Millisecond)
	}

	second := newFakeStream("100.64.0.5", startEvent("sess-2", "peer-a-pubkey", 80, 24), endEvent(0))
	err := svc.Stream(second)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted for a second session from the same peer, got %v", err)
	}

	other := newFakeStream("100.64.0.6", startEvent("sess-3", "peer-b-pubkey", 80, 24), endEvent(0))
	if err := svc.Stream(other); err != nil {
		t.Fatalf("expected a different peer's session to be admitted, got %v", err)
	}

	close(first.unblock)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Stream call: %v", err)
	}

	fourth := newFakeStream("100.64.0.5", startEvent("sess-4", "peer-a-pubkey", 80, 24), endEvent(0))
	if err := svc.Stream(fourth); err != nil {
		t.Fatalf("expected the released per-peer slot to admit a new session, got %v", err)
	}
}

func TestStream_ByteLimitExceededEndsSessionAsFailedWithResourceExhausted(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{MaxSessionBytes: 10, MaxSessionDuration: time.Hour}) // 10 bytes is trivially exceeded

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		outputEvent("this output is well over ten bytes"),
		endEvent(0),
	)

	err := svc.Stream(stream)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted, got %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusFailed {
		t.Fatalf("expected status failed, got %q", sessions[0].Status)
	}
}

func TestStream_DurationLimitExceededEndsSessionAsFailedWithResourceExhausted(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{MaxSessionBytes: 1 << 30, MaxSessionDuration: time.Nanosecond}) // any time.Since check exceeds this

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		outputEvent("some output"),
		endEvent(0),
	)

	err := svc.Stream(stream)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted, got %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusFailed {
		t.Fatalf("expected status failed, got %q", sessions[0].Status)
	}
}

func TestStream_IdleTimeoutEndsSessionAsFailedWithResourceExhausted(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{IdleTimeout: 20 * time.Millisecond})

	stream := newBlockingFakeStream("100.64.0.5", startEvent("sess-1", "real-peer-pubkey", 80, 24))
	t.Cleanup(func() { close(stream.unblock) })

	err := svc.Stream(stream)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted from the idle timeout, got %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusFailed {
		t.Fatalf("expected status failed, got %q", sessions[0].Status)
	}
}

func TestStream_HeartbeatsKeepIdleSessionAlive(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{IdleTimeout: 50 * time.Millisecond})

	stream := newPacedFakeStream("100.64.0.5",
		timedEvent{startEvent("sess-1", "real-peer-pubkey", 80, 24), 0},
		timedEvent{heartbeatEvent(), 30 * time.Millisecond},
		timedEvent{heartbeatEvent(), 30 * time.Millisecond},
		timedEvent{endEvent(0), 30 * time.Millisecond},
	)
	// Total elapsed (90ms) exceeds the 50ms idle timeout, but no single gap
	// between events does — the session must complete normally.

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("expected heartbeats to keep the session alive past the raw idle timeout, got %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusCompleted {
		t.Fatalf("expected status completed, got %q", sessions[0].Status)
	}
}

func TestStream_EventRateLimitEndsSessionAsFailedWithResourceExhausted(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestServiceWithLimits(t, identity, Limits{MaxEventsPerSecond: 1, EventBurst: 1})

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		heartbeatEvent(),
		heartbeatEvent(),
	)

	err := svc.Stream(stream)
	st, ok := grpcstatus.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected codes.ResourceExhausted from the event rate limit, got %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Status != recmeta.StatusFailed {
		t.Fatalf("expected status failed, got %q", sessions[0].Status)
	}
}

func TestStream_RejectsEmptyClaimedPeerID(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, _, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5", startEvent("sess-1", "", 80, 24))

	err := svc.Stream(stream)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected rejection for empty claimed_peer_id, got %v", err)
	}
}

func TestStream_RecordsEmptyPeerNameWhenNoDNSLabel(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: ""}
	svc, _, meta, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		endEvent(0),
	)

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].PeerID != "real-peer-pubkey" {
		t.Fatalf("expected peer id to still be recorded, got %q", sessions[0].PeerID)
	}
	if sessions[0].PeerName != "" {
		t.Fatalf("expected empty peer name when no DNS label resolves, got %q", sessions[0].PeerName)
	}
}

func TestStream_SanitizesInvalidTermSize(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 0, 0),
		endEvent(0),
	)

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Cols != defaultTermCols || sessions[0].Rows != defaultTermRows {
		t.Fatalf("expected 0x0 to be sanitized to %dx%d, got %dx%d", defaultTermCols, defaultTermRows, sessions[0].Cols, sessions[0].Rows)
	}
}

func TestStream_RecordsSourcePeerIdentity(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestService(t, identity)

	start := &recorderproto.RecordEvent{Event: &recorderproto.RecordEvent_Start{
		Start: &recorderproto.SessionStart{
			SessionId:      "sess-1",
			ClaimedPeerId:  "real-peer-pubkey",
			JwtUserIdHash:  "hash-abc",
			OsUsername:     "ubuntu",
			Cols:           80,
			Rows:           24,
			StartedAt:      timestamppb.Now(),
			SourcePeerId:   "source-pubkey",
			SourcePeerName: "laptop-01.netbird.cloud",
			SourcePeerIp:   "100.64.0.9",
		},
	}}
	stream := newFakeStream("100.64.0.5", start, endEvent(0))

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	sess := sessions[0]
	if sess.SourcePeerID != "source-pubkey" {
		t.Fatalf("expected source peer id %q, got %q", "source-pubkey", sess.SourcePeerID)
	}
	if sess.SourcePeerName != "laptop-01.netbird.cloud" {
		t.Fatalf("expected source peer name %q, got %q", "laptop-01.netbird.cloud", sess.SourcePeerName)
	}
	if sess.SourcePeerIP != "100.64.0.9" {
		t.Fatalf("expected source peer ip %q, got %q", "100.64.0.9", sess.SourcePeerIP)
	}
}

func TestStream_EmptySourcePeerFieldsWhenUnresolved(t *testing.T) {
	identity := fakeIdentity{ip: netip.MustParseAddr("100.64.0.5"), pubKey: "real-peer-pubkey", fqdn: "peer.netbird"}
	svc, _, meta, _ := newTestService(t, identity)

	stream := newFakeStream("100.64.0.5",
		startEvent("sess-1", "real-peer-pubkey", 80, 24),
		endEvent(0),
	)

	if err := svc.Stream(stream); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	sessions, _, err := meta.ListSessions(context.Background(), recmeta.ListFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	sess := sessions[0]
	if sess.SourcePeerID != "" || sess.SourcePeerName != "" || sess.SourcePeerIP != "" {
		t.Fatalf("expected empty source peer fields, got id=%q name=%q ip=%q", sess.SourcePeerID, sess.SourcePeerName, sess.SourcePeerIP)
	}
}

func (alwaysFailingWriteCloser) Write([]byte) (int, error) {
	return 0, errors.New("simulated disk full")
}
func (alwaysFailingWriteCloser) Close() error { return nil }

func TestFinalize_WriteFailureOnCloseIsReportedAsFailed(t *testing.T) {
	recKey, err := reccrypt.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	gcm, err := reccrypt.NewCipher(recKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	fieldKey, err := crypt.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fieldEnc, err := crypt.NewFieldEncrypt(fieldKey)
	if err != nil {
		t.Fatalf("NewFieldEncrypt: %v", err)
	}
	meta, err := metasqlite.New(t.TempDir(), "test.db", fieldEnc)
	if err != nil {
		t.Fatalf("metasqlite.New: %v", err)
	}
	t.Cleanup(func() { meta.Close() })

	ctx := context.Background()
	const id = "sess-finalize-close-failure"
	if err := meta.CreateSession(ctx, &recmeta.Session{
		ID:        id,
		PeerID:    "peer-1",
		StartedAt: time.Now().UTC(),
		CastPath:  "unused",
		Status:    recmeta.StatusRecording,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	failing := alwaysFailingWriteCloser{}
	rs := &recordingSession{
		id:        id,
		streamEnc: reccrypt.NewStreamWriter(failing, gcm),
		file:      failing,
		live:      live.NewHub(),
		gotEnd:    true, // a clean SessionEnd was received — nothing else went wrong upstream
	}

	if _, err := rs.streamEnc.Write([]byte("hello")); err != nil {
		t.Fatalf("buffer write (should not itself fail, under chunkSize): %v", err)
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	rs.finalize(ctx, meta, logger)

	got, err := meta.GetSession(ctx, id)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != recmeta.StatusFailed {
		t.Fatalf("status = %q, want %q (a write failure on close must not be reported as a completed recording)", got.Status, recmeta.StatusFailed)
	}
}
