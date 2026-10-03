package grpc

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// cloudCredentialsRateBurst allows a short burst (e.g. first connect plus one  retry) before steady-state limiting kicks in.
	cloudCredentialsRateBurst = 3
	// cloudCredentialsLimiterCleanup is how often stale limiters are removed.
	cloudCredentialsLimiterCleanup = 5 * time.Minute
	// cloudCredentialsLimiterTTL is how long a limiter is kept after its last use.
	cloudCredentialsLimiterTTL = 20 * time.Minute
)

// cloudCredentialsRate caps how often one peer may request cloud credentials,
// regardless of outcome — it protects the upstream provider's own API quota
// (STS/IAM/Entra), not just NetBird's own auth.
var cloudCredentialsRate = rate.Every(15 * time.Second)

// cloudCredentialsLimiter tracks per-peer request rates for RequestCloudCredentials.
type cloudCredentialsLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	cancel   context.CancelFunc
}

func newCloudCredentialsLimiter() *cloudCredentialsLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	l := &cloudCredentialsLimiter{
		limiters: make(map[string]*limiterEntry),
		cancel:   cancel,
	}
	go l.cleanupLoop(ctx)
	return l
}

// allow reports whether peerKey may make another request now, consuming a
// token if so.
func (l *cloudCredentialsLimiter) allow(peerKey string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.limiters[peerKey]
	if !exists {
		entry = &limiterEntry{limiter: rate.NewLimiter(cloudCredentialsRate, cloudCredentialsRateBurst)}
		l.limiters[peerKey] = entry
	}
	entry.lastAccess = time.Now()
	return entry.limiter.Allow()
}

func (l *cloudCredentialsLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cloudCredentialsLimiterCleanup)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (l *cloudCredentialsLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for key, entry := range l.limiters {
		if now.Sub(entry.lastAccess) > cloudCredentialsLimiterTTL {
			delete(l.limiters, key)
		}
	}
}
