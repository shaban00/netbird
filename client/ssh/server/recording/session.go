package recording

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	recorderproto "github.com/netbirdio/netbird/recorder/proto"
)

// dialTimeout bounds the recorder dial so an unreachable recorder fails fast.
// Generous because the dial itself wakes NetBird's lazy peer connection and
// must cover a cold start; pre-waiting for readiness never triggers it.
const dialTimeout = 20 * time.Second

// closeDrainTimeout bounds the SessionEnd ack wait in Close.
const closeDrainTimeout = 5 * time.Second

// heartbeatInterval keeps idle sessions alive so the recorder can drop abandoned
// streams (a DoS vector). Must stay well under recordergrpc.idleStreamTimeout.
const heartbeatInterval = 30 * time.Second

// recvStatusWait bounds Write's wait for recvLoop's terminal status after a
// Send failure. Short, since recvLoop usually has it already.
const recvStatusWait = 2 * time.Second

// Session streams one SSH session's PTY output (never input) to the recorder.
type Session struct {
	conn          *grpc.ClientConn
	stream        recorderproto.RecorderService_StreamClient
	mu            sync.Mutex
	closed        bool
	recvErr       error
	recvDone      chan struct{}
	heartbeatStop chan struct{}
}

type SessionStartInfo struct {
	SessionID      string
	ClaimedPeerID  string
	JWTUserIDHash  string
	OSUsername     string
	Cols, Rows     uint32
	SourcePeerID   string
	SourcePeerName string
	SourcePeerIP   string
}

// Dial opens a recording stream to addr and starts the session.
func Dial(ctx context.Context, addr string, info SessionStartInfo) (*Session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial recorder %s: %w", addr, err)
	}

	client := recorderproto.NewRecorderServiceClient(conn)
	stream, err := client.Stream(ctx) // stream outlives dialCtx; session-lifetime context
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open recording stream to %s: %w", addr, err)
	}

	start := &recorderproto.RecordEvent{
		Event: &recorderproto.RecordEvent_Start{
			Start: &recorderproto.SessionStart{
				SessionId:      info.SessionID,
				ClaimedPeerId:  info.ClaimedPeerID,
				JwtUserIdHash:  info.JWTUserIDHash,
				OsUsername:     info.OSUsername,
				Cols:           info.Cols,
				Rows:           info.Rows,
				StartedAt:      timestamppb.Now(),
				SourcePeerId:   info.SourcePeerID,
				SourcePeerName: info.SourcePeerName,
				SourcePeerIp:   info.SourcePeerIP,
			},
		},
	}
	if err := sendWithDeadline(dialCtx, stream, start); err != nil {
		_ = stream.CloseSend()
		_ = conn.Close()
		return nil, fmt.Errorf("send SessionStart to %s: %w", addr, err)
	}

	sess := &Session{conn: conn, stream: stream, recvDone: make(chan struct{}), heartbeatStop: make(chan struct{})}
	go sess.recvLoop()
	go sess.heartbeatLoop()
	return sess, nil
}

// heartbeatLoop sends periodic Heartbeats until Close; errors are left to Write/Close to surface.
func (s *Session) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.heartbeatStop:
			return
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

func (s *Session) sendHeartbeat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if err := s.stream.Send(&recorderproto.RecordEvent{
		Event: &recorderproto.RecordEvent_Heartbeat{Heartbeat: &recorderproto.Heartbeat{}},
	}); err != nil {
		log.Debugf("recording: send heartbeat: %v", err)
	}
}

func (s *Session) recvLoop() {
	for {
		if _, err := s.stream.Recv(); err != nil {
			s.recvErr = err
			close(s.recvDone)
			return
		}
	}
}

// sendWithDeadline sends SessionStart within Dial's timeout. Later sends are unbounded, since sessions may idle.
func sendWithDeadline(ctx context.Context, stream recorderproto.RecorderService_StreamClient, ev *recorderproto.RecordEvent) error {
	done := make(chan error, 1)
	go func() { done <- stream.Send(ev) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Write sends p as an Output event. PTY output only, never client input.
func (s *Session) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}

	err := s.stream.Send(&recorderproto.RecordEvent{
		Event: &recorderproto.RecordEvent_Output{
			Output: &recorderproto.Output{Data: p},
		},
	})
	if err != nil {
		select {
		case <-s.recvDone:
			err = s.recvErr
		case <-time.After(recvStatusWait):
		}
		return 0, fmt.Errorf("send recording output: %w", err)
	}
	return len(p), nil
}

// Resize sends a terminal resize event.
func (s *Session) Resize(cols, rows uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}

	err := s.stream.Send(&recorderproto.RecordEvent{
		Event: &recorderproto.RecordEvent_Resize{
			Resize: &recorderproto.Resize{Cols: cols, Rows: rows},
		},
	})
	if err != nil {
		return fmt.Errorf("send recording resize: %w", err)
	}
	return nil
}

// Close ends the recording stream. Idempotent; errors are only logged.
func (s *Session) Close(exitCode int32) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	close(s.heartbeatStop)

	if err := s.stream.Send(&recorderproto.RecordEvent{
		Event: &recorderproto.RecordEvent_End{
			End: &recorderproto.SessionEnd{ExitCode: exitCode},
		},
	}); err != nil {
		log.Debugf("recording: send SessionEnd: %v", err)
	}
	if err := s.stream.CloseSend(); err != nil {
		log.Debugf("recording: close send: %v", err)
	}

	select {
	case <-s.recvDone:
	case <-time.After(closeDrainTimeout):
		log.Debugf("recording: timed out waiting for recorder to ack SessionEnd")
	}

	if err := s.conn.Close(); err != nil {
		log.Debugf("recording: close connection: %v", err)
	}
}
