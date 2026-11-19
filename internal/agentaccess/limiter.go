package agentaccess

import (
	"sync"
	"time"
)

// limiterSweepThreshold bounds the tracked keys: beyond it expired windows are
// dropped, so one-shot source addresses cannot grow the map without bound.
const limiterSweepThreshold = 1024

// windowLimiter counts events per key in a fixed window that starts at the
// first event. It is in memory and per process, like the web sign-in limiter:
// the goal is to make guessing slow on a single machine, not to coordinate a
// distributed quota. A restart clears it.
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*limiterWindow
	now     func() time.Time
}

type limiterWindow struct {
	count     int
	expiresAt time.Time
}

func newWindowLimiter(limit int, window time.Duration, now func() time.Time) *windowLimiter {
	return &windowLimiter{limit: limit, window: window, entries: make(map[string]*limiterWindow), now: now}
}

// allow reports whether key is still under its limit, and how long it must
// wait when it is not.
func (limiter *windowLimiter) allow(key string) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	entry, ok := limiter.entries[key]
	if !ok || !now.Before(entry.expiresAt) || entry.count < limiter.limit {
		return true, 0
	}
	return false, entry.expiresAt.Sub(now)
}

// record counts one event for key.
func (limiter *windowLimiter) record(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.recordLocked(key, limiter.now())
}

func (limiter *windowLimiter) recordLocked(key string, now time.Time) {
	entry, ok := limiter.entries[key]
	if !ok || !now.Before(entry.expiresAt) {
		entry = &limiterWindow{expiresAt: now.Add(limiter.window)}
		limiter.entries[key] = entry
	}
	entry.count++
	if len(limiter.entries) > limiterSweepThreshold {
		for tracked, window := range limiter.entries {
			if !now.Before(window.expiresAt) {
				delete(limiter.entries, tracked)
			}
		}
	}
}

// take admits and counts one event in a single step; it is used where every
// attempt counts, not only failures.
func (limiter *windowLimiter) take(key string) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	entry, ok := limiter.entries[key]
	if ok && now.Before(entry.expiresAt) && entry.count >= limiter.limit {
		return false, entry.expiresAt.Sub(now)
	}
	limiter.recordLocked(key, now)
	return true, 0
}
