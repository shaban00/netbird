package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/birddrop"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"

	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	grpcpeer "google.golang.org/grpc/peer"
)

type birddropSendTestStream struct {
	grpc.ServerStream
	ctx    context.Context
	events []*proto.BirddropSendEvent
}

type birddropReceiveTestStream struct {
	grpc.ServerStream
	ctx    context.Context
	events []*proto.BirddropReceiveEvent
}

func freeBirddropPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	return port
}

func waitBirddropReady(t *testing.T, port int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf(
			"http://127.0.0.1:%d/birddrop/ping",
			port,
		))
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("birddrop listener did not become ready")
}

func (s *birddropSendTestStream) Context() context.Context {
	return s.ctx
}

func (s *birddropSendTestStream) Send(ev *proto.BirddropSendEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func (s *birddropReceiveTestStream) Context() context.Context {
	return s.ctx
}

func (s *birddropReceiveTestStream) Send(ev *proto.BirddropReceiveEvent) error {
	s.events = append(s.events, ev)
	return nil
}

func birddropCallerContext(t *testing.T) context.Context {
	t.Helper()

	id, err := ipcauth.CurrentProcessIdentity()
	require.NoError(t, err)

	return grpcpeer.NewContext(
		context.Background(),
		&grpcpeer.Peer{
			AuthInfo: ipcauth.AuthInfo{
				Identity: id,
			},
		},
	)
}

func TestBirddropListAndRejectRPC(t *testing.T) {
	port := freeBirddropPort(t)

	mgr, err := birddrop.NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	go func() {
		_ = mgr.Serve([]string{"127.0.0.1"}, port)
	}()

	waitBirddropReady(t, port)

	t.Cleanup(func() {
		_ = mgr.Shutdown()
	})

	installBirdDropManager(t, mgr)

	offer := map[string]any{
		"id":   "0123456789abcdef0123456789abcdef",
		"name": "rpc-test.txt",
		"size": 5,
		"type": "file", "is_dir": false,
		"from":         "sender.netbird.cloud",
		"port":         birddrop.DefaultPort,
		"expires_unix": time.Now().Add(time.Minute).Unix(),
	}

	body, err := json.Marshal(offer)
	require.NoError(t, err)

	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/birddrop/offer", port),
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	s := &Server{}

	list, err := s.BirddropList(
		context.Background(),
		&proto.BirddropListRequest{},
	)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	require.Equal(
		t,
		"0123456789abcdef0123456789abcdef",
		list.Items[0].Id,
	)
	require.Equal(t, "rpc-test.txt", list.Items[0].Name)
	require.Equal(t, int64(5), list.Items[0].Size)
	require.False(t, list.Items[0].IsDir)

	rejected, err := s.BirddropReject(
		context.Background(),
		&proto.BirddropRejectRequest{
			Ids: []string{
				"0123456789abcdef0123456789abcdef",
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, int32(1), rejected.Rejected)

	list, err = s.BirddropList(
		context.Background(),
		&proto.BirddropListRequest{},
	)
	require.NoError(t, err)
	require.Empty(t, list.Items)
}

func TestBirddropReceiveClipboardDoesNotRequireDestination(t *testing.T) {
	senderPort := freeBirddropPort(t)
	receiverPort := freeBirddropPort(t)

	sender, err := birddrop.NewManager("sender.netbird.cloud", nil)
	require.NoError(t, err)

	receiver, err := birddrop.NewManager("receiver.netbird.cloud", nil)
	require.NoError(t, err)

	go func() {
		_ = sender.Serve([]string{"127.0.0.1"}, senderPort)
	}()

	go func() {
		_ = receiver.Serve([]string{"127.0.0.1"}, receiverPort)
	}()

	waitBirddropReady(t, senderPort)
	waitBirddropReady(t, receiverPort)

	t.Cleanup(func() {
		_ = sender.Shutdown()
		_ = receiver.Shutdown()
	})

	installBirdDropManager(t, receiver)

	const text = "clipboard from server test"

	events, err := sender.SendClipboard(
		context.Background(),
		"127.0.0.1",
		receiverPort,
		"receiver.netbird.cloud",
		text,
		time.Minute,
	)
	require.NoError(t, err)

	select {
	case ev := <-events:
		require.Equal(t, birddrop.StateWaiting, ev.State)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for clipboard offer")
	}

	items := receiver.List()
	require.Len(t, items, 1)
	require.Equal(t, birddrop.PayloadClipboard, items[0].Type)

	stream := &birddropReceiveTestStream{
		ctx: birddropCallerContext(t),
	}

	err = (&Server{}).BirddropReceive(
		&proto.BirddropReceiveRequest{
			Ids: []string{items[0].ID},
		},
		stream,
	)
	require.NoError(t, err)

	require.NotEmpty(t, stream.events)

	final := stream.events[len(stream.events)-1]
	require.Equal(t, "done", final.GetState())
	require.Equal(
		t,
		proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD,
		final.GetType(),
	)
	require.Equal(t, text, final.GetClipboardText())
	require.Empty(t, final.GetSavedAs())
	require.Empty(t, final.GetName())

	var senderFinal birddrop.SendEvent
	for ev := range events {
		senderFinal = ev
	}

	require.Equal(t, birddrop.StateDelivered, senderFinal.State)
	require.Equal(t, birddrop.PayloadClipboard, senderFinal.Type)
}

func TestBirddropSendRoutesClipboardWithoutFilesystemAccess(t *testing.T) {
	resetBirdDropState(t)

	s := &Server{
		rootCtx:        context.Background(),
		statusRecorder: peer.NewRecorder(""),
	}

	s.statusRecorder.UpdateLocalPeerState(peer.LocalPeerState{
		IP:   "127.0.0.1",
		FQDN: "sender.netbird.cloud",
	})

	stream := &birddropSendTestStream{
		ctx: birddropCallerContext(t),
	}

	err := s.BirddropSend(
		&proto.BirddropSendRequest{
			Peer: "127.0.0.1",

			// If the clipboard branch accidentally falls through to the
			// filesystem path, this path must fail.
			Path: "/this/path/must/not/be/opened",

			Type: proto.BirddropPayloadType_BIRDDROP_PAYLOAD_TYPE_CLIPBOARD,

			// Empty clipboard is rejected by SendClipboard before any network
			// offer is made.
			ClipboardText:  "",
			TimeoutSeconds: 30,
		},
		stream,
	)

	require.ErrorContains(t, err, "clipboard is empty")
}

func resetBirdDropState(t *testing.T) {
	t.Helper()
	clearBirdDropState()
	t.Cleanup(clearBirdDropState)
}

func clearBirdDropState() {
	birdDrop.startMu.Lock()
	defer birdDrop.startMu.Unlock()

	birdDrop.mu.Lock()
	mgr := birdDrop.mgr
	timer := birdDrop.idleTimer

	birdDrop.mgr = nil
	birdDrop.gen++
	birdDrop.enabled = false
	birdDrop.activeSends = 0
	birdDrop.idleTimer = nil
	birdDrop.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	if mgr != nil {
		_ = mgr.Shutdown()
	}
}

func installBirdDropManager(t *testing.T, mgr *birddrop.Manager) {
	t.Helper()
	resetBirdDropState(t)
	birdDrop.mu.Lock()
	birdDrop.mgr = mgr
	birdDrop.enabled = true
	birdDrop.mu.Unlock()
}

func TestBirdDropDisabledDoesNotStartTransport(t *testing.T) {
	resetBirdDropState(t)

	s := &Server{}

	s.startBirdDrop()

	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()

	require.False(t, birdDrop.enabled)
	require.Nil(t, birdDrop.mgr)
	require.Equal(t, 0, birdDrop.activeSends)
}

func TestBirdDropReleaseSchedulesShutdownWhenInboundDisabled(t *testing.T) {
	resetBirdDropState(t)

	mgr, err := birddrop.NewManager("", nil)
	require.NoError(t, err)

	birdDrop.mu.Lock()
	birdDrop.mgr = mgr
	birdDrop.enabled = false
	birdDrop.activeSends = 1
	birdDrop.mu.Unlock()

	s := &Server{}
	s.releaseBirdDropTransport()

	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()

	require.Equal(t, 0, birdDrop.activeSends)
	require.NotNil(t, birdDrop.idleTimer)
}

func TestBirdDropReleaseKeepsTransportWhenInboundEnabled(t *testing.T) {
	resetBirdDropState(t)

	mgr, err := birddrop.NewManager("", nil)
	require.NoError(t, err)

	birdDrop.mu.Lock()
	birdDrop.mgr = mgr
	birdDrop.enabled = true
	birdDrop.activeSends = 1
	birdDrop.mu.Unlock()

	s := &Server{}
	s.releaseBirdDropTransport()

	birdDrop.mu.Lock()
	defer birdDrop.mu.Unlock()

	require.Equal(t, 0, birdDrop.activeSends)
	require.Same(t, mgr, birdDrop.mgr)
	require.Nil(t, birdDrop.idleTimer)
}

func TestBirdDropOnDemandTransportStartsAndStops(t *testing.T) {
	resetBirdDropState(t)

	s := &Server{
		rootCtx:        context.Background(),
		statusRecorder: peer.NewRecorder(""),
	}

	s.statusRecorder.UpdateLocalPeerState(peer.LocalPeerState{
		IP: "127.0.0.1",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mgr, err := s.acquireBirdDropTransport(ctx)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotEmpty(t, mgr.BoundAddrs())

	birdDrop.mu.Lock()
	require.False(t, birdDrop.enabled)
	require.Equal(t, 1, birdDrop.activeSends)
	require.Same(t, mgr, birdDrop.mgr)
	birdDrop.mu.Unlock()

	s.releaseBirdDropTransport()

	require.Eventually(t, func() bool {
		birdDrop.mu.Lock()
		defer birdDrop.mu.Unlock()

		return birdDrop.mgr == nil &&
			birdDrop.activeSends == 0
	}, birdDropIdleTimeout+2*time.Second, 25*time.Millisecond)
}
