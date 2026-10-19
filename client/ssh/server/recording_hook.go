package server

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ssh/server/recording"
	sshuserhash "github.com/netbirdio/netbird/shared/sshauth"
)

const (
	maxConcurrentRecorderDials     = 32
	recordingRequiredDeniedMessage = "SSH session recording is required but unavailable; access denied\r\n"
	recordingLimitExceededMessage  = "SSH session recording exceeded its configured size or duration limit; access denied\r\n"
)

type recordingFailWriter struct {
	rec    *recording.Session
	once   sync.Once
	failed chan struct{}
	err    error
}

// acquireRecorderDialSlot reserves a dial slot; on !ok, fail the session. release is valid only if ok.
func (s *Server) acquireRecorderDialSlot() (release func(), ok bool) {
	if s.recorderDialSlots == nil {
		return func() {}, true
	}
	select {
	case s.recorderDialSlots <- struct{}{}:
		return func() { <-s.recorderDialSlots }, true
	default:
		return nil, false
	}
}

// recordingRequired reports server-wide recording status, independent of
// auth, so --disable-ssh-auth can't bypass it.
func (s *Server) recordingRequired() (required bool, recorderAddr string) {
	s.mu.RLock()
	authorizer := s.authorizer
	s.mu.RUnlock()
	if authorizer == nil {
		return false, ""
	}
	return authorizer.RecordingRequired()
}

func denyRecordingRequired(logger *log.Entry, session ssh.Session) {
	if _, err := fmt.Fprint(session.Stderr(), recordingRequiredDeniedMessage); err != nil {
		logger.Debugf(errWriteSession, err)
	}
	if err := session.Exit(1); err != nil {
		logSessionExitError(logger, err)
	}
}

func denyRecordingLost(logger *log.Entry, session ssh.Session, cause error) {
	msg := recordingRequiredDeniedMessage
	if status.Code(cause) == codes.ResourceExhausted {
		msg = recordingLimitExceededMessage
	}
	if _, err := fmt.Fprint(session.Stderr(), msg); err != nil {
		logger.Debugf(errWriteSession, err)
	}
	if err := session.Exit(1); err != nil {
		logSessionExitError(logger, err)
	}
}

func newRecordingFailWriter(rec *recording.Session) *recordingFailWriter {
	return &recordingFailWriter{rec: rec, failed: make(chan struct{})}
}

func (w *recordingFailWriter) Write(p []byte) (int, error) {
	n, err := w.rec.Write(p)
	if err != nil {
		w.fail(err)
	}
	return n, err
}

func (w *recordingFailWriter) Resize(cols, rows uint32) error {
	err := w.rec.Resize(cols, rows)
	if err != nil {
		w.fail(err)
	}
	return err
}

func (w *recordingFailWriter) fail(err error) {
	w.once.Do(func() {
		w.err = err
		close(w.failed)
	})
}

func (s *Server) startRecordingIfRequired(logger *log.Entry, session ssh.Session, cols, rows uint32) (*recording.Session, error) {
	requireRecording, recorderAddr := s.recordingRequired()
	if !requireRecording {
		return nil, nil //nolint:nilnil // nil, nil means "recording not required", a normal outcome distinct from a dial/auth failure
	}

	release, ok := s.acquireRecorderDialSlot()
	if !ok {
		logger.Warnf("rejecting session: %d recorder dials already in flight (recorder may be slow or unreachable)", maxConcurrentRecorderDials)
		return nil, errors.New("too many concurrent recording setup attempts in flight")
	}
	defer release()

	jwtUsername := s.sessionJWTUsername(session)

	sessionID := uuid.NewString()
	userHash, err := sshuserhash.HashUserID(jwtUsername)
	if err != nil {
		return nil, err
	}

	logger = logger.WithField("recording_session_id", sessionID)
	logger.Infof("starting SSH session recording via recorder at %s", recorderAddr)

	srcIP := sourceIP(session.RemoteAddr())
	sourcePeerID, sourcePeerName := s.resolveSourcePeerIdentity(srcIP)

	recSession, err := recording.Dial(session.Context(), recorderAddr, recording.SessionStartInfo{
		SessionID:      sessionID,
		ClaimedPeerID:  s.ownPeerID,
		JWTUserIDHash:  userHash.String(),
		OSUsername:     session.User(),
		Cols:           cols,
		Rows:           rows,
		SourcePeerID:   sourcePeerID,
		SourcePeerName: sourcePeerName,
		SourcePeerIP:   srcIP,
	})
	if err != nil {
		logger.Errorf("failed to start required recording: %v", err)
		return nil, err
	}

	return recSession, nil
}

// resolveSourcePeerIdentity returns the client's NetBird peer identity for ip, for recording attribution.
func (s *Server) resolveSourcePeerIdentity(ip string) (peerID, name string) {
	if s.resolveSourcePeer == nil || ip == "" {
		return "", ""
	}
	peerID, name, ok := s.resolveSourcePeer(ip)
	if !ok {
		return "", ""
	}
	return peerID, name
}

func sourceIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func closeRecording(recSession *recording.Session, exitCode int32) {
	if recSession == nil {
		return
	}
	recSession.Close(exitCode)
}
