package fsa

import (
	"sync"
	"time"
)

// emailRateLimiter enforces a sliding-window per-email rate limit on login
// attempts. It complements the per-IP limiter on the bundled handlers and
// is meant to defend against inbox flooding and cross-IP enumeration.
type emailRateLimiter struct {
	max    int
	window time.Duration

	mu     sync.Mutex
	hits   map[string][]time.Time
	lastGC time.Time
}

func newEmailRateLimiter(max int, window time.Duration) *emailRateLimiter {
	return &emailRateLimiter{
		max:    max,
		window: window,
		hits:   make(map[string][]time.Time),
	}
}

// allow records an attempt for email and returns true if the call should be
// permitted under the current limit, false if it should be rejected.
func (l *emailRateLimiter) allow(email string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Opportunistic GC: once per window, drop entries with no recent hits.
	if now.Sub(l.lastGC) > l.window {
		for k, ts := range l.hits {
			pruned := pruneBefore(ts, cutoff)
			if len(pruned) == 0 {
				delete(l.hits, k)
			} else {
				l.hits[k] = pruned
			}
		}
		l.lastGC = now
	}

	ts := pruneBefore(l.hits[email], cutoff)
	if len(ts) >= l.max {
		l.hits[email] = ts
		return false
	}
	l.hits[email] = append(ts, now)
	return true
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for ; i < len(ts); i++ {
		if ts[i].After(cutoff) {
			break
		}
	}
	if i == 0 {
		return ts
	}
	return ts[i:]
}
