package agentaccess

import (
	"sync"
	"time"
)

// limiterSweepThreshold bounds the tracked keys: beyond it expired windows are
// dropped, so one-shot source addresses cannot grow the map without bound.
const limiterSweepThreshold = 1024

// pendingRetryAfter is the wait answered when a key is full only because of
// attempts still in flight: they end within a request's time, and most of
// them are not failures.
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
	// pending counts the attempts of a key admitted by reserve and not yet
	// settled by confirm or release. It is kept apart from the windows: an
	// attempt in flight belongs to no window until it is known to count.
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

// reserve admits one attempt whose outcome is not known yet and holds a
// place for it, in one step: confirmed events and attempts in flight together
// stay below the limit, so concurrent attempts cannot all pass a check that
// each of them made before any was counted. Every admitted attempt must be
// settled with confirm (it counts) or release (it does not).
func (limiter *windowLimiter) reserve(key string) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	count, expiresAt := limiter.liveCountLocked(key, now)
	if count >= limiter.limit {
		return false, expiresAt.Sub(now)
	}
	if count+limiter.pending[key] >= limiter.limit {
		return false, pendingRetryAfter
	}
	limiter.pending[key]++
	return true, 0
}

// confirm settles a reserved attempt as an event that counts.
func (limiter *windowLimiter) confirm(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.settleLocked(key)
	limiter.recordLocked(key, limiter.now())
}

// release settles a reserved attempt that does not count.
func (limiter *windowLimiter) release(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.settleLocked(key)
}

func (limiter *windowLimiter) settleLocked(key string) {
	switch pending := limiter.pending[key]; {
	case pending > 1:
		limiter.pending[key] = pending - 1
	default:
		delete(limiter.pending, key)
	}
}
