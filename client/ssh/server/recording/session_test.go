package recording

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	recorderproto "github.com/netbirdio/netbird/recorder/proto"
)

type fakeStreamClient struct {
	sent      []*recorderproto.RecordEvent
	ackDelay  time.Duration
	recvCalls int32
}

type failThenStatusStreamClient struct {
	fakeStreamClient
	recvErr error
}

type blockedRecvStreamClient struct {
	fakeStreamClient
	unblock chan struct{}
}

func (f *fakeStreamClient) Send(ev *recorderproto.RecordEvent) error {
	f.sent = append(f.sent, ev)
	return nil
}

func (f *fakeStreamClient) Recv() (*recorderproto.RecordEventAck, error) {
	n := atomic.AddInt32(&f.recvCalls, 1)
	if n == 1 {
		time.Sleep(f.ackDelay)
		return &recorderproto.RecordEventAck{LastSeq: 1}, nil
	}
	return nil, io.EOF
}

func (f *fakeStreamClient) Header() (metadata.MD, error) { return nil, nil } //nolint:nilnil // unused stub method; Close never calls Header
func (f *fakeStreamClient) Trailer() metadata.MD         { return nil }
func (f *fakeStreamClient) CloseSend() error             { return nil }
func (f *fakeStreamClient) Context() context.Context     { return context.Background() }
func (f *fakeStreamClient) SendMsg(m any) error          { return nil }
func (f *fakeStreamClient) RecvMsg(m any) error          { return nil }

func newInertConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///fake", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "constructing an unconnected ClientConn must succeed")
	return conn
}

func newTestSession(t *testing.T, stream recorderproto.RecorderService_StreamClient) *Session {
	t.Helper()
	s := &Session{conn: newInertConn(t), stream: stream, recvDone: make(chan struct{}), heartbeatStop: make(chan struct{})}
	go s.recvLoop()
	return s
}

func TestSession_Close_WaitsForRecorderAck(t *testing.T) {
	fake := &fakeStreamClient{ackDelay: 100 * time.Millisecond}
	s := newTestSession(t, fake)

	start := time.Now()
	s.Close(0)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, fake.ackDelay, "Close returned before the recorder's ack arrived")
	require.Len(t, fake.sent, 1, "expected exactly one event sent")
	assert.NotNil(t, fake.sent[0].GetEnd(), "the single sent event must be SessionEnd")
}

func TestSession_Close_TimesOutIfRecorderNeverResponds(t *testing.T) {
	fake := &fakeStreamClient{ackDelay: closeDrainTimeout + 2*time.Second}
	s := newTestSession(t, fake)

	done := make(chan struct{})
	go func() {
		s.Close(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(closeDrainTimeout + time.Second):
		t.Fatal("Close did not return within closeDrainTimeout")
	}
}

func TestSession_Close_Idempotent(t *testing.T) {
	fake := &fakeStreamClient{}
	s := newTestSession(t, fake)

	s.Close(0)
	s.Close(1)

	assert.Len(t, fake.sent, 1, "a second Close must not send another SessionEnd")
}

func (f *failThenStatusStreamClient) Send(*recorderproto.RecordEvent) error {
	return io.EOF
}

func (f *failThenStatusStreamClient) Recv() (*recorderproto.RecordEventAck, error) {
	return nil, f.recvErr
}

func TestSession_Write_SurfacesRealStatusFromRecvAfterSendEOF(t *testing.T) {
	want := status.Error(codes.ResourceExhausted, "recording session exceeded its configured size or duration limit")
	fake := &failThenStatusStreamClient{recvErr: want}
	s := newTestSession(t, fake)

	_, err := s.Write([]byte("some output"))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "Write must surface the real status code from Recv, not bare io.EOF")
}

func (f *blockedRecvStreamClient) Send(*recorderproto.RecordEvent) error {
	return io.EOF
}

func (f *blockedRecvStreamClient) Recv() (*recorderproto.RecordEventAck, error) {
	<-f.unblock
	return nil, io.EOF
}

func TestSession_Write_DoesNotBlockIndefinitelyWhenRecvNeverReturns(t *testing.T) {
	fake := &blockedRecvStreamClient{unblock: make(chan struct{})}
	defer close(fake.unblock)
	s := newTestSession(t, fake)

	done := make(chan struct{})
	go func() {
		_, _ = s.Write([]byte("some output"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(recvStatusWait + 2*time.Second):
		t.Fatal("Write did not return within recvStatusWait even though Recv never returns")
	}
}

func TestSession_Close_NotBlockedByConcurrentWriteOnDeadStream(t *testing.T) {
	fake := &blockedRecvStreamClient{unblock: make(chan struct{})}
	defer close(fake.unblock)
	s := newTestSession(t, fake)

	go func() { _, _ = s.Write([]byte("some output")) }()
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		s.Close(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(recvStatusWait + closeDrainTimeout + 2*time.Second):
		t.Fatal("Close did not complete within a bounded time despite a concurrent Write stalled on a dead stream")
	}
}
