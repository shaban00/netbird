package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestServer_RecordingRequired covers only the nil-authorizer fail-closed
// case: recordingRequired is a thin lock-and-delegate to
// Authorizer.RecordingRequired, which auth_test.go's
// TestAuthorizer_RecordingRequired already covers for a real authorizer.
func TestServer_RecordingRequired(t *testing.T) {
	s := &Server{}
	required, addr := s.recordingRequired()
	assert.False(t, required)
	assert.Empty(t, addr)
}

func TestServer_AcquireRecorderDialSlot(t *testing.T) {
	t.Run("slot available", func(t *testing.T) {
		s := &Server{recorderDialSlots: make(chan struct{}, 1)}
		release, ok := s.acquireRecorderDialSlot()
		assert.True(t, ok)
		if assert.NotNil(t, release) {
			release()
		}
	})

	t.Run("slots full, then freed by release", func(t *testing.T) {
		s := &Server{recorderDialSlots: make(chan struct{}, 1)}

		release1, ok1 := s.acquireRecorderDialSlot()
		assert.True(t, ok1)

		_, ok2 := s.acquireRecorderDialSlot()
		assert.False(t, ok2, "a second dial must be rejected while the only slot is held")

		release1()

		_, ok3 := s.acquireRecorderDialSlot()
		assert.True(t, ok3, "the slot must be available again once released")
	})

	t.Run("nil recorderDialSlots (bare Server literal): cap disabled, not always-full", func(t *testing.T) {
		s := &Server{}
		release, ok := s.acquireRecorderDialSlot()
		assert.True(t, ok, "a nil slots channel must not silently act as always-at-capacity")
		assert.NotPanics(t, release)
	})
}

func TestSourceIP(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"nil address", nil, ""},
		{"tcp addr with port", &net.TCPAddr{IP: net.ParseIP("100.64.0.5"), Port: 51000}, "100.64.0.5"},
		{"ipv6 addr with port", &net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 51000}, "fd00::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sourceIP(tt.addr))
		})
	}
}

func TestServer_ResolveSourcePeerIdentity(t *testing.T) {
	t.Run("no resolver configured", func(t *testing.T) {
		s := &Server{}
		id, name := s.resolveSourcePeerIdentity("100.64.0.5")
		assert.Empty(t, id)
		assert.Empty(t, name)
	})

	t.Run("empty ip", func(t *testing.T) {
		s := &Server{resolveSourcePeer: func(ip string) (string, string, bool) {
			t.Fatal("resolver must not be called with an empty IP")
			return "", "", false
		}}
		id, name := s.resolveSourcePeerIdentity("")
		assert.Empty(t, id)
		assert.Empty(t, name)
	})

	t.Run("resolver finds no match", func(t *testing.T) {
		s := &Server{resolveSourcePeer: func(ip string) (string, string, bool) { return "", "", false }}
		id, name := s.resolveSourcePeerIdentity("100.64.0.5")
		assert.Empty(t, id)
		assert.Empty(t, name)
	})

	t.Run("resolver finds a match", func(t *testing.T) {
		s := &Server{resolveSourcePeer: func(ip string) (string, string, bool) {
			assert.Equal(t, "100.64.0.5", ip)
			return "pubkey-abc", "web-01.netbird.cloud", true
		}}
		id, name := s.resolveSourcePeerIdentity("100.64.0.5")
		assert.Equal(t, "pubkey-abc", id)
		assert.Equal(t, "web-01.netbird.cloud", name)
	})
}
