package agentaccess

import (
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
