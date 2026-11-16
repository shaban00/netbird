package ipcauth

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCallerTokenNotUsableAfterRelease(t *testing.T) {
	tok := newCallerToken(42)
	require.NoError(t, tok.use(func(h uintptr) error {
		require.Equal(t, uintptr(42), h)
		return nil
	}))

	require.NoError(t, tok.release(func(uintptr) error { return nil }))

	called := false
	err := tok.use(func(uintptr) error { called = true; return nil })
	require.ErrorIs(t, err, errCallerTokenGone)
	require.False(t, called)
}

func TestCallerTokenReleaseWaitsForUse(t *testing.T) {
	tok := newCallerToken(7)
	inUse := make(chan struct{})
	finish := make(chan struct{})
	var closedDuringUse atomic.Bool
	var using atomic.Bool

	go func() {
		_ = tok.use(func(uintptr) error {
			using.Store(true)
			close(inUse)
			<-finish
			using.Store(false)
			return nil
		})
	}()
	<-inUse

	released := make(chan struct{})
	go func() {
		_ = tok.release(func(uintptr) error {
			if using.Load() {
				closedDuringUse.Store(true)
			}
			return nil
		})
		close(released)
	}()

	select {
	case <-released:
		t.Fatal("release returned while the token was still in use")
	case <-time.After(50 * time.Millisecond):
	}
	close(finish)
	<-released
	require.False(t, closedDuringUse.Load())
}

func TestCallerTokenReleaseIsIdempotent(t *testing.T) {
	tok := newCallerToken(9)
	var closes int
	closeFn := func(uintptr) error { closes++; return nil }
	require.NoError(t, tok.release(closeFn))
	require.NoError(t, tok.release(closeFn))
	require.Equal(t, 1, closes)

	var nilTok *callerToken
	require.ErrorIs(t, nilTok.use(func(uintptr) error { return nil }), errCallerTokenGone)
}
