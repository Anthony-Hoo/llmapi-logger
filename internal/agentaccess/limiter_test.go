package agentaccess

import (
	"fmt"
	"testing"
	"time"
)

// The in-flight cap and the failure count are separate: attempts in flight
// beyond the failure limit are admitted up to the cap, and only failed
// attempts fill the window.
func TestLimiterInFlightCapIsIndependentOfTheFailureLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newWindowLimiter(3, time.Minute, func() time.Time { return now })
	for index := 0; index < 5; index++ {
		if allowed, _ := limiter.admit("a", 5); !allowed {
			t.Fatalf("admit %d refused although only the cap limits attempts in flight", index)
		}
	}
	// Five attempts are in flight: a sixth is refused by the cap, with the
	// short wait of an in-flight refusal.
	if allowed, wait := limiter.admit("a", 5); allowed || wait != pendingRetryAfter {
		t.Fatalf("sixth admit = %v %s", allowed, wait)
	}
	if allowed, _ := limiter.admit("b", 5); !allowed {
		t.Fatal("another key is affected")
	}
	// A successful attempt frees its place and counts nothing.
	limiter.finish("a", false)
	if allowed, _ := limiter.admit("a", 5); !allowed {
		t.Fatal("finished place not reusable")
	}
	for index := 0; index < 3; index++ {
		limiter.finish("a", true)
	}
	if limiter.pending["a"] != 2 {
		t.Fatalf("pending = %v", limiter.pending)
	}
	// Three failures fill the window: the wait is the window's.
	if allowed, wait := limiter.admit("a", 5); allowed || wait != time.Minute {
		t.Fatalf("full window admit = %v %s", allowed, wait)
	}
	limiter.finish("a", false)
	limiter.finish("a", false)
	limiter.finish("b", false)
	if len(limiter.pending) != 0 {
		t.Fatalf("pending after every attempt finished = %v", limiter.pending)
	}
	now = now.Add(time.Minute)
	if allowed, _ := limiter.admit("a", 5); !allowed {
		t.Fatal("the window did not end")
	}
}

// Many live keys from distinct sources do not make every event sweep the
// whole map: sweeps are amortised, and expired windows still go once the map
// is swept.
func TestLimiterSweepIsAmortisedOverLiveKeys(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newWindowLimiter(3, time.Minute, func() time.Time { return now })
	const keys = 8000
	for index := 0; index < keys; index++ {
		limiter.record(fmt.Sprintf("192.0.2.%d", index))
	}
	if len(limiter.entries) != keys {
		t.Fatalf("live entries = %d, want %d: a live window was evicted", len(limiter.entries), keys)
	}
	// 1024 doubled up to 8000 is three sweeps; allow a little slack, far
	// below one sweep per event.
	if limiter.sweeps > 5 {
		t.Fatalf("sweeps = %d for %d live keys, want a logarithmic number", limiter.sweeps, keys)
	}
	now = now.Add(2 * time.Minute)
	before := limiter.sweeps
	for index := 0; limiter.sweeps == before; index++ {
		if index > 2*keys {
			t.Fatal("no sweep ran after the windows expired")
		}
		limiter.record(fmt.Sprintf("198.51.100.%d", index))
	}
	for key, window := range limiter.entries {
		if !now.Before(window.expiresAt) {
			t.Fatalf("expired window %s kept after a sweep", key)
		}
	}
	if len(limiter.entries) >= keys {
		t.Fatalf("entries after sweep = %d", len(limiter.entries))
	}
}

func TestLimiterRefundOnlyLowersTheWindowItCameFrom(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newWindowLimiter(1, time.Minute, func() time.Time { return now })
	slot, allowed, _ := limiter.takeSlot("k")
	if !allowed {
		t.Fatal("first take refused")
	}
	if _, allowed, _ := limiter.takeSlot("k"); allowed {
		t.Fatal("second take admitted")
	}
	limiter.refund(slot)
	next, allowed, _ := limiter.takeSlot("k")
	if !allowed {
		t.Fatal("refunded slot not reusable")
	}
	// A slot of an ended window is not given back to the next one.
	now = now.Add(2 * time.Minute)
	if _, allowed, _ := limiter.takeSlot("k"); !allowed {
		t.Fatal("new window refused")
	}
	limiter.refund(next)
	if _, allowed, _ := limiter.takeSlot("k"); allowed {
		t.Fatal("a stale refund opened the new window")
	}
	limiter.refund(limiterSlot{})
}
