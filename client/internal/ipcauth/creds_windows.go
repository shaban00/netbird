//go:build windows

package ipcauth

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/credentials"
)

var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

// DefaultPipeSDDL is the security descriptor for the daemon control pipe.
//
//	D:P          protected DACL, no inheritance
//	(A;;GA;;;SY) allow GENERIC_ALL to LocalSystem (the daemon's service account)
//	(A;;GA;;;WD) allow GENERIC_ALL to Everyone
//
// Any local caller may connect, as with a Unix socket at 0666; what a caller may
// actually do is decided from its token, not from the DACL. Remote callers are not
// a concern here: winio.ListenPipe creates the pipe with
// FILE_PIPE_REJECT_REMOTE_CLIENTS, so NPFS rejects connections from other machines
// before the descriptor is consulted.
//
// A deny ACE on the NETWORK SID would not add anything and would break callers:
// that SID is present in any network-logon token, which includes OpenSSH and WinRM
// sessions, so it denies administrators driving the CLI over SSH and denies the
// daemon itself when started from such a session.
func DefaultPipeSDDL() string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;WD)"
}

// RestrictedPipeSDDL returns the security descriptor for a daemon control pipe
// that only the named principals may open, replacing DefaultPipeSDDL's ACE for
// Everyone. Each SID is a user or group SID in string form; the caller is
// expected to have resolved and validated them already. An empty list yields
// the default descriptor, so a missing configuration cannot silently produce a
// pipe nobody can reach.
//
// Three ACEs are always present besides the configured ones:
//
//	SY  LocalSystem, the account the daemon runs as when installed as a service
//	BA  BUILTIN\Administrators, so an elevated caller is never locked out
//	the daemon's own user SID, so a daemon an ordinary user runs themselves can
//	still dial itself, which is what the JSON gateway does
//
// BUILTIN\Administrators carries no access for a UAC-filtered administrator,
// whose token has that group deny-only, which matches the authorization model:
// such a caller is not privileged either.
func RestrictedPipeSDDL(sids []string) string {
	if len(sids) == 0 {
		return DefaultPipeSDDL()
	}

	allowed := []string{"SY", "BA"}
	if selfIdentity.Known() && selfIdentity.SID != "" {
		allowed = append(allowed, selfIdentity.SID)
	}
	for _, sid := range sids {
		if !slices.Contains(allowed, sid) {
			allowed = append(allowed, sid)
		}
	}

	var b strings.Builder
	b.WriteString("D:P")
	for _, sid := range allowed {
		b.WriteString("(A;;GA;;;")
		b.WriteString(sid)
		b.WriteString(")")
	}
	return b.String()
}

// NewTransportCredentials returns gRPC transport credentials that derive the
// caller's identity from the named-pipe client token.
//
// The client connects at SECURITY_IDENTIFICATION. That allows the daemon to
// inspect the caller's token and perform access checks without granting it the
// ability to impersonate the caller.
func NewTransportCredentials() credentials.TransportCredentials {
	return winpipeCreds{}
}

// ConnIdentity extracts the caller's identity from an accepted named-pipe
// connection by impersonating the pipe client and reading its token. It is
// shared by the JSON gateway, which only needs the identity.
func ConnIdentity(conn net.Conn) (Identity, error) {
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Identity{}, fmt.Errorf("connection %T does not expose a pipe handle", conn)
	}

	return pipeClientIdentity(windows.Handle(fdConn.Fd()))
}

type winpipeCreds struct{}

type tokenConn struct {
	net.Conn
	tok *callerToken
}

// Close closes the connection and then the retained token. release waits for
// any access check still using the token and is safe to call more than once.
func (c *tokenConn) Close() error {
	connErr := c.Conn.Close()
	tokenErr := c.tok.release(func(h uintptr) error { return windows.Token(h).Close() })

	if connErr != nil {
		return connErr
	}
	if tokenErr != nil {
		return fmt.Errorf("close client token: %w", tokenErr)
	}

	return nil
}

func connIdentityAndToken(conn net.Conn) (Identity, windows.Token, error) {
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Identity{}, 0, fmt.Errorf("connection %T does not expose a pipe handle", conn)
	}

	return pipeClientIdentityAndToken(windows.Handle(fdConn.Fd()))
}

func (winpipeCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the connecting client's identity and retains an
// identification-level token for local access checks. The token is closed when
// the authenticated connection is closed.
func (winpipeCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	id, token, err := connIdentityAndToken(conn)
	if err != nil {
		return nil, nil, err
	}

	tok := newCallerToken(uintptr(token))
	authConn := &tokenConn{
		Conn: conn,
		tok:  tok,
	}

	return authConn, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       id,
		token:          tok,
	}, nil
}

func (winpipeCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: AuthInfo{}.AuthType()}
}

func (winpipeCreds) Clone() credentials.TransportCredentials { return winpipeCreds{} }

func (winpipeCreds) OverrideServerName(string) error { return nil }

// pipeClientIdentity reads the connecting client's identity and closes the
// temporary duplicate token immediately.
func pipeClientIdentity(handle windows.Handle) (Identity, error) {
	id, token, err := pipeClientIdentityAndToken(handle)
	if err != nil {
		return Identity{}, err
	}

	if err := token.Close(); err != nil {
		log.Debugf("close client token: %v", err)
	}

	return id, nil
}

// pipeClientIdentityAndToken reads the client's identity and retains a duplicate
// of its token at SECURITY_IDENTIFICATION level.
//
// The duplicate deliberately does not request TOKEN_IMPERSONATE and does not
// raise the impersonation level. It is only retained for Windows access checks.
func pipeClientIdentityAndToken(handle windows.Handle) (id Identity, callerToken windows.Token, err error) {
	runtime.LockOSThread()

	clean := false
	defer func() {
		if clean {
			runtime.UnlockOSThread()
		}
	}()

	if err = impersonateNamedPipeClient(handle); err != nil {
		clean = true
		return Identity{}, 0, fmt.Errorf("impersonate named pipe client: %w", err)
	}

	defer func() {
		revErr := windows.RevertToSelf()
		if revErr != nil {
			if err == nil {
				err = fmt.Errorf("revert impersonation: %w", revErr)
			}

			if callerToken != 0 {
				_ = callerToken.Close()
				callerToken = 0
			}
			return
		}
		clean = true
	}()

	var token windows.Token
	if err = windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
		true,
		&token,
	); err != nil {
		return Identity{}, 0, fmt.Errorf("open thread token: %w", err)
	}
	defer func() {
		if cerr := token.Close(); cerr != nil {
			log.Debugf("close client token: %v", cerr)
		}
	}()

	id, err = identityFromToken(token)
	if err != nil {
		return Identity{}, 0, err
	}

	err = windows.DuplicateTokenEx(
		token,
		windows.TOKEN_QUERY,
		nil,
		windows.SecurityIdentification,
		windows.TokenImpersonation,
		&callerToken,
	)
	if err != nil {
		return Identity{}, 0, fmt.Errorf("duplicate client token: %w", err)
	}

	return id, callerToken, nil
}

// identityFromToken reads the user SID, usable group SIDs and elevation state
// out of a Windows token.
func identityFromToken(token windows.Token) (Identity, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("read token user: %w", err)
	}

	groups, err := tokenGroupSIDs(token)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		SID:      user.User.Sid.String(),
		Groups:   groups,
		Elevated: token.IsElevated(),
		known:    true,
	}, nil
}

// tokenGroupSIDs returns the SIDs of the groups the token can actually
// exercise. Groups that are disabled or marked deny-only are skipped: a
// UAC-filtered administrator carries BUILTIN\Administrators as deny-only, and
// treating that as membership would hand every admin account privilege it
// cannot currently use.
func tokenGroupSIDs(token windows.Token) ([]string, error) {
	tg, err := token.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("read token groups: %w", err)
	}

	var sids []string
	for _, g := range tg.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED == 0 {
			continue
		}
		if g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		sids = append(sids, g.Sid.String())
	}
	return sids, nil
}

func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return e
	}
	return nil
}
