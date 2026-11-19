package agentaccess

import (
	"testing"
	"time"
)

func TestLimiterReserveHoldsPlacesForAttemptsInFlight(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newWindowLimiter(3, time.Minute, func() time.Time { return now })
	for index := 0; index < 3; index++ {
		if allowed, _ := limiter.reserve("a"); !allowed {
			t.Fatalf("reserve %d refused", index)
		}
	}
	// Three attempts are in flight: a fourth is refused although none has
	// been counted yet, with the short wait of an in-flight refusal.
	if allowed, wait := limiter.reserve("a"); allowed || wait != pendingRetryAfter {
		t.Fatalf("fourth reserve = %v %s", allowed, wait)
	}
	if allowed, _ := limiter.reserve("b"); !allowed {
		t.Fatal("another key is affected")
	}
	// A released attempt frees its place and counts nothing.
	limiter.release("a")
	if allowed, _ := limiter.reserve("a"); !allowed {
		t.Fatal("released place not reusable")
	}
	for index := 0; index < 3; index++ {
		limiter.confirm("a")
	}
	if len(limiter.pending) != 1 {
		t.Fatalf("pending = %v", limiter.pending)
	}
	// Three confirmed failures fill the window: the wait is the window's.
	if allowed, wait := limiter.reserve("a"); allowed || wait != time.Minute {
		t.Fatalf("full window reserve = %v %s", allowed, wait)
	}
	now = now.Add(time.Minute)
	if allowed, _ := limiter.reserve("a"); !allowed {
		t.Fatal("the window did not end")
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
