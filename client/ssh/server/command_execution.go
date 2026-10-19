package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ssh/server/recording"
)

const (
	defaultRecordingCols = 80
	defaultRecordingRows = 24
)

type crlfNormalizingWriter struct {
	w         io.Writer
	lastWasCR bool
}

func (c *crlfNormalizingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	out := make([]byte, 0, len(p))
	for i, b := range p {
		if b == '\n' {
			precededByCR := c.lastWasCR
			if i > 0 {
				precededByCR = p[i-1] == '\r'
			}
			if !precededByCR {
				out = append(out, '\r')
			}
		}
		out = append(out, b)
	}
	c.lastWasCR = p[len(p)-1] == '\r'

	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// sanitizeForRecording escapes control bytes and Unicode format chars
// (bidi, zero-width) in client text, so labels like RawCommand can't forge
// or hide content in the player. Invalid UTF-8 is escaped per byte.
func sanitizeForRecording(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", s[i])
			i++
			continue
		}
		if needsEscape(r) {
			if r <= 0xff {
				fmt.Fprintf(&b, "\\x%02x", r)
			} else {
				fmt.Fprintf(&b, "\\u%04x", r)
			}
			i += size
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

func needsEscape(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r)
}

// handleExecution executes an SSH command or shell with privilege validation
func (s *Server) handleExecution(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	hasPty := winCh != nil

	commandType := "command"
	if hasPty {
		commandType = "Pty command"
	}

	logger.Infof("executing %s: %s", commandType, safeLogCommand(session.Command()))

	execCmd, cleanup, err := s.createCommand(logger, privilegeResult, session, hasPty)
	if err != nil {
		logger.Errorf("%s creation failed: %v", commandType, err)

		errorMsg := fmt.Sprintf("Cannot create %s - platform may not support user switching", commandType)
		if hasPty {
			errorMsg += " with Pty"
		}
		errorMsg += "\n"

		if _, writeErr := fmt.Fprint(session.Stderr(), errorMsg); writeErr != nil {
			logger.Debugf(errWriteSession, writeErr)
		}
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return
	}

	if !hasPty {
		if s.executeCommand(logger, session, execCmd, cleanup) {
			logger.Debugf("%s execution completed", commandType)
		}
		return
	}

	defer cleanup()

	if s.executeCommandWithPty(logger, session, execCmd, privilegeResult, ptyReq, winCh) {
		logger.Debugf("%s execution completed", commandType)
	}
}

func (s *Server) createCommand(logger *log.Entry, privilegeResult PrivilegeCheckResult, session ssh.Session, hasPty bool) (*exec.Cmd, func(), error) {
	localUser := privilegeResult.User
	if localUser == nil {
		return nil, nil, errors.New("no user in privilege result")
	}

	// If PTY requested but su doesn't support --pty, skip su and use executor
	// This ensures PTY functionality is provided (executor runs within our allocated PTY)
	if hasPty && !s.suSupportsPty {
		logger.Debugf("PTY requested but su doesn't support --pty, using executor for PTY functionality")
		cmd, cleanup, err := s.createExecutorCommand(logger, session, localUser, hasPty)
		if err != nil {
			return nil, nil, fmt.Errorf("create command with privileges: %w", err)
		}
		cmd.Env = s.prepareCommandEnv(logger, localUser, session)
		return cmd, cleanup, nil
	}

	// Try su first for system integration (PAM/audit) when privileged
	cmd, err := s.createSuCommand(logger, session, localUser, hasPty) //nolint:staticcheck
	if err != nil || privilegeResult.UsedFallback {                   //nolint:staticcheck // always errors on platforms without su
		logger.Debugf("su command failed, falling back to executor: %v", err)
		cmd, cleanup, err := s.createExecutorCommand(logger, session, localUser, hasPty)
		if err != nil {
			return nil, nil, fmt.Errorf("create command with privileges: %w", err)
		}
		cmd.Env = s.prepareCommandEnv(logger, localUser, session)
		return cmd, cleanup, nil
	}

	cmd.Env = s.prepareCommandEnv(logger, localUser, session)
	return cmd, func() {}, nil
}

// executeCommand executes the command and handles I/O and exit codes
func (s *Server) executeCommand(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, cleanup func()) bool {
	defer cleanup()

	s.setupProcessGroup(execCmd)

	// No PTY, but asciinema-player needs a nonzero size or it renders
	// invisibly. Use the same 80x24 default as ptySize.
	recSession, err := s.startRecordingIfRequired(logger, session, defaultRecordingCols, defaultRecordingRows)
	if err != nil {
		denyRecordingRequired(logger, session)
		return false
	}

	if recSession != nil {
		if cmdLine := session.RawCommand(); cmdLine != "" {
			if _, werr := recSession.Write([]byte("$ " + sanitizeForRecording(cmdLine) + "\r\n")); werr != nil {
				logger.Errorf("write command line to recording: %v", werr)
				closeRecording(recSession, 1)
				denyRecordingLost(logger, session, werr)
				return false
			}
		}
	}

	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		logger.Errorf("create stdin pipe: %v", err)
		closeRecording(recSession, -1)
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	var failWriter *recordingFailWriter
	stdout, stderr := io.Writer(session), io.Writer(session.Stderr())
	if recSession != nil {
		failWriter = newRecordingFailWriter(recSession)
		stdout = io.MultiWriter(session, &crlfNormalizingWriter{w: failWriter})
		stderr = io.MultiWriter(session.Stderr(), &crlfNormalizingWriter{w: failWriter})
	}
	execCmd.Stdout = stdout
	execCmd.Stderr = stderr

	if execCmd.Dir != "" {
		if _, err := os.Stat(execCmd.Dir); err != nil {
			logger.Warnf("working directory does not exist: %s (%v)", execCmd.Dir, err)
			execCmd.Dir = "/"
		}
	}

	if err := execCmd.Start(); err != nil {
		logger.Errorf("command start failed: %v", err)
		closeRecording(recSession, -1)
		// no user message for exec failure, just exit
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	go s.handleCommandIO(logger, stdinPipe, session)
	return s.waitForCommandCleanup(logger, session, execCmd, recSession, failWriter)
}

// handleCommandIO manages stdin/stdout copying in a goroutine
func (s *Server) handleCommandIO(logger *log.Entry, stdinPipe io.WriteCloser, session ssh.Session) {
	defer func() {
		if err := stdinPipe.Close(); err != nil {
			logger.Debugf("stdin pipe close error: %v", err)
		}
	}()
	if _, err := io.Copy(stdinPipe, session); err != nil {
		logger.Debugf("stdin copy error: %v", err)
	}
}

// waitForCommandCleanup waits for command completion with session disconnect handling
func (s *Server) waitForCommandCleanup(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, recSession *recording.Session, failWriter *recordingFailWriter) bool {
	ctx := session.Context()
	done := make(chan error, 1)
	go func() {
		done <- execCmd.Wait()
	}()

	var recordingFailed <-chan struct{}
	if failWriter != nil {
		recordingFailed = failWriter.failed
	}

	select {
	case <-ctx.Done():
		logger.Debugf("session cancelled, terminating command")
		s.killProcessGroup(execCmd)

		select {
		case err := <-done:
			logger.Tracef("command terminated after session cancellation: %v", err)
		case <-time.After(5 * time.Second):
			logger.Warnf("command did not terminate within 5 seconds after session cancellation")
		}

		closeRecording(recSession, 130)
		if err := session.Exit(130); err != nil {
			logSessionExitError(logger, err)
		}
		return false

	case <-recordingFailed:
		logger.Warn("recording connection lost mid-session; terminating session (recording was required)")
		s.killProcessGroup(execCmd)

		select {
		case err := <-done:
			logger.Tracef("command terminated after recording loss: %v", err)
		case <-time.After(5 * time.Second):
			logger.Warnf("command did not terminate within 5 seconds after recording loss")
		}

		closeRecording(recSession, 1)
		denyRecordingLost(logger, session, failWriter.err)
		return false

	case err := <-done:
		closeRecording(recSession, int32(exitCodeFromError(err))) //nolint:gosec // exit codes are small, bounded values
		return s.handleCommandCompletion(logger, session, err)
	}
}

// handleCommandCompletion handles command completion
func (s *Server) handleCommandCompletion(logger *log.Entry, session ssh.Session, err error) bool {
	if err != nil {
		logger.Debugf("command execution failed: %v", err)
		s.handleSessionExit(session, err, logger)
		return false
	}

	s.handleSessionExit(session, nil, logger)
	return true
}

// handleSessionExit handles command errors and sets appropriate exit codes
func (s *Server) handleSessionExit(session ssh.Session, err error, logger *log.Entry) {
	code := exitCodeFromError(err)
	if err != nil && code == 1 {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			logger.Debugf("non-exit error in command execution: %v", err)
		}
	}
	if sessErr := session.Exit(code); sessErr != nil {
		logSessionExitError(logger, sessErr)
	}
}

func exitCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return 1
}
