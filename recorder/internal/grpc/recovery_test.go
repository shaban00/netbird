package grpc

import (
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func TestRecoveryStreamInterceptor_RecoversPanic(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	interceptor := RecoveryStreamInterceptor(logger)

	panicking := func(srv any, stream grpc.ServerStream) error {
		panic("simulated handler bug")
	}

	err := interceptor(nil, nil, &grpc.StreamServerInfo{FullMethod: "/RecorderService/Stream"}, panicking)
	if err == nil {
		t.Fatal("expected an error after a recovered panic, got nil")
	}
	st, ok := grpcstatus.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status error, got %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("code = %v, want %v", st.Code(), codes.Internal)
	}
}

func TestRecoveryStreamInterceptor_PassesThroughOnSuccess(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	interceptor := RecoveryStreamInterceptor(logger)

	var called bool
	ok := func(srv any, stream grpc.ServerStream) error {
		called = true
		return nil
	}

	err := interceptor(nil, nil, &grpc.StreamServerInfo{FullMethod: "/RecorderService/Stream"}, ok)
	if err != nil {
		t.Fatalf("expected nil error on the successful path, got %v", err)
	}
	if !called {
		t.Fatal("expected the wrapped handler to actually run")
	}
}
