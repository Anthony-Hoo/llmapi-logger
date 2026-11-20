package agentaccess

import (
	"sync"
	"time"
)

// limiterSweepThreshold bounds the tracked keys: beyond it expired windows are
// dropped, so one-shot source addresses cannot grow the map without bound.
const limiterSweepThreshold = 1024

// pendingRetryAfter is the wait answered when a key is refused only because
// of attempts still in flight: they end within a request's time.
const pendingRetryAfter = time.Second

// windowLimiter counts events per key in a fixed window that starts at the
// first event. It is in memory and per process, like the web sign-in limiter:
// the goal is to make guessing slow on a single machine, not to coordinate a
// distributed quota. A restart clears it.
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*limiterWindow
	// pending counts the attempts of a key admitted by admit and not yet
	// ended by finish. It is kept apart from the windows: an attempt in
	// flight belongs to no window until it is known to have failed.
	pending map[string]int
	now     func() time.Time
}

type limiterWindow struct {
	count     int
	expiresAt time.Time
}

// limiterSlot identifies one event counted by take, so that refund gives it
// back to the same window and to no later one.
type limiterSlot struct {
	key       string
	expiresAt time.Time
}

func newWindowLimiter(limit int, window time.Duration, now func() time.Time) *windowLimiter {
	return &windowLimiter{limit: limit, window: window, entries: make(map[string]*limiterWindow), pending: make(map[string]int), now: now}
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

func (limiter *windowLimiter) recordLocked(key string, now time.Time) *limiterWindow {
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
	return entry
}

// liveCountLocked is the count of key's current window, 0 when it has none.
func (limiter *windowLimiter) liveCountLocked(key string, now time.Time) (int, time.Time) {
	entry, ok := limiter.entries[key]
	if !ok || !now.Before(entry.expiresAt) {
		return 0, time.Time{}
	}
	return entry.count, entry.expiresAt
}

// take admits and counts one event in a single step; it is used where every
// attempt counts, not only failures.
func (limiter *windowLimiter) take(key string) (bool, time.Duration) {
	_, allowed, wait := limiter.takeSlot(key)
	return allowed, wait
}

// takeSlot is take returning the slot it counted, for refund.
func (limiter *windowLimiter) takeSlot(key string) (limiterSlot, bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	if count, expiresAt := limiter.liveCountLocked(key, now); count >= limiter.limit {
		return limiterSlot{}, false, expiresAt.Sub(now)
	}
	entry := limiter.recordLocked(key, now)
	return limiterSlot{key: key, expiresAt: entry.expiresAt}, true, 0
}

// refund gives back an event counted by takeSlot. It only ever lowers the
// window the event was counted in: once that window has ended the event no
// longer counts anyway, and a later window never pays for it.
func (limiter *windowLimiter) refund(slot limiterSlot) {
	if slot.key == "" {
		return
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entry, ok := limiter.entries[slot.key]
	if !ok || !entry.expiresAt.Equal(slot.expiresAt) || entry.count == 0 {
		return
	}
	entry.count--
}

// admit starts one attempt whose outcome is not known yet. Two separate
// mechanisms decide, checked under one lock: the failure count (only finished
// attempts that failed add to it) refuses the key once it has reached the
// limit, with the window's remaining time; and a cap on the key's attempts in
// flight, independent of the failure count, refuses an attempt beyond
// inFlightCap with pendingRetryAfter. Legitimate concurrency is therefore
// limited only by the cap, never by the failure limit. Because attempts in
// flight are not failures yet, at most limit + inFlightCap attempts of one key
// can fail in one window. Every admitted attempt must be ended with finish.
func (limiter *windowLimiter) admit(key string, inFlightCap int) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	if count, expiresAt := limiter.liveCountLocked(key, now); count >= limiter.limit {
		return false, expiresAt.Sub(now)
	}
	if limiter.pending[key] >= inFlightCap {
		return false, pendingRetryAfter
	}
	limiter.pending[key]++
	return true, 0
}

// finish ends an attempt admit admitted; failed counts it as a failure.
func (limiter *windowLimiter) finish(key string, failed bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	switch pending := limiter.pending[key]; {
	case pending > 1:
		limiter.pending[key] = pending - 1
	default:
		delete(limiter.pending, key)
	}
	if failed {
		limiter.recordLocked(key, limiter.now())
	}
}
