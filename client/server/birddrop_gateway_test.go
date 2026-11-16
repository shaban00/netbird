package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestBirdDropCallerRefusesGatewayRequests(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-netbird-fwd", "1"))
	_, err := birdDropCaller(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.ErrorContains(t, err, "JSON gateway")

	_, err = birdDropCaller(context.Background())
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no caller at all must also be refused")
}
