package fsa

import (
	"strings"
	"sync"
	"time"
)

// emailLimiterMaxEntries caps the in-memory map so an attacker cycling random
// emails can't grow it without bound between GC sweeps. When exceeded we
// force a full prune before inserting; if the map is still over the cap
// afterwards every recent entry counts, so the limiter degrades to rejecting
// the new email rather than evicting an established one.
const emailLimiterMaxEntries = 10_000

// emailRateLimiter enforces a sliding-window per-email rate limit on login
// attempts. It complements the per-IP limiter on the bundled handlers and
// is meant to defend against inbox flooding and cross-IP enumeration.
type emailRateLimiter struct {
	max        int
	window     time.Duration
	maxEntries int

	mu     sync.Mutex
	hits   map[string][]time.Time
	lastGC time.Time
}

func newEmailRateLimiter(max int, window time.Duration) *emailRateLimiter {
	return &emailRateLimiter{
		max:        max,
		window:     window,
		maxEntries: emailLimiterMaxEntries,
		hits:       make(map[string][]time.Time),
	}
}

// allow records an attempt for email and returns true if the call should be
// permitted under the current limit, false if it should be rejected. The
// email is normalized (trimmed + lower-cased) so casing variations share a
// bucket.
func (l *emailRateLimiter) allow(email string) bool {
	key := strings.ToLower(strings.TrimSpace(email))
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > l.window || len(l.hits) >= l.maxEntries {
		l.gcLocked(cutoff)
		l.lastGC = now
	}

	ts := pruneBefore(l.hits[key], cutoff)
	if len(ts) >= l.max {
		l.hits[key] = ts
		return false
	}
	// If the map is still at the cap after GC and this is a new key, reject
	// rather than letting the map grow unbounded.
	if _, exists := l.hits[key]; !exists && len(l.hits) >= l.maxEntries {
		return false
	}
	l.hits[key] = append(ts, now)
	return true
}

// gcLocked drops entries with no hits after cutoff. Caller must hold l.mu.
func (l *emailRateLimiter) gcLocked(cutoff time.Time) {
	for k, ts := range l.hits {
		pruned := pruneBefore(ts, cutoff)
		if len(pruned) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = pruned
		}
	}
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
