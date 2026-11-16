package ipcauth

import (
	"context"
	"errors"

	"google.golang.org/grpc/peer"
)

// directCallerAuth returns the transport credentials of a caller connected
// directly to the daemon socket. File access checks run against these
// credentials (on Windows, the caller's token), so a request forwarded by the
// JSON gateway is refused: its transport peer is the daemon itself.
func directCallerAuth(ctx context.Context) (AuthInfo, error) {
	if IsForwarded(ctx) {
		return AuthInfo{}, errors.New("file access is not available through the JSON gateway")
	}

	p, ok := peer.FromContext(ctx)
	if !ok {
		return AuthInfo{}, errors.New("missing IPC peer")
	}

	auth, ok := p.AuthInfo.(AuthInfo)
	if !ok {
		return AuthInfo{}, errors.New("missing IPC caller identity")
	}
	return auth, nil
}
