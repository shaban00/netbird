package ipcauth

import (
	"errors"
	"sync"
)

var errCallerTokenGone = errors.New("authenticated caller token is unavailable (the connection was closed)")

type callerToken struct {
	mu     sync.RWMutex
	h      uintptr
	closed bool
}

func newCallerToken(h uintptr) *callerToken {
	return &callerToken{h: h}
}

func (t *callerToken) use(fn func(h uintptr) error) error {
	if t == nil {
		return errCallerTokenGone
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed || t.h == 0 {
		return errCallerTokenGone
	}
	return fn(t.h)
}

// release closes the handle once, after any in-flight use has finished.
// Later calls do nothing, so a handle value is never closed twice.
func (t *callerToken) release(closeFn func(h uintptr) error) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	h := t.h
	t.h = 0
	t.mu.Unlock()
	if h == 0 {
		return nil
	}
	return closeFn(h)
}
