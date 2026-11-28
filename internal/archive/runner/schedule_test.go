package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// H.1: the next run is today's run_at in the configured zone, or
// tomorrow's once it has passed.
func TestUntilNextRunUsesTheConfiguredZone(t *testing.T) {
	h := newHarness(t)
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	h.options.Location = shanghai
	h.options.RunAt = "03:00"
	// 18:30 UTC is 02:30 in Shanghai: half an hour to go.
	h.clock.now = time.Date(2026, 11, 27, 18, 30, 0, 0, time.UTC)
	if wait := h.runner().untilNextRun(); wait != 30*time.Minute {
		t.Fatalf("wait %v", wait)
	}
	// 19:00 UTC is 03:00 there: the run time itself waits a whole day.
	h.clock.now = time.Date(2026, 11, 27, 19, 0, 0, 0, time.UTC)
	if wait := h.runner().untilNextRun(); wait != 24*time.Hour {
		t.Fatalf("wait %v", wait)
	}
}

// H.1, P item 2: a start runs at once when there was never a completed run
// or the last one started more than a day ago, not otherwise.
func TestCatchUp(t *testing.T) {
	h := newHarness(t)
	runner := h.runner()
	ctx := context.Background()
	if !runner.catchUpDue(ctx) {
		t.Fatal("no completed run: catch-up expected")
	}
	h.store.runs = append(h.store.runs, &storage.ArchiveRun{RunID: "r1", Status: storage.ArchiveRunCompleted, StartedAtNS: h.clock.Now().Add(-23 * time.Hour).UnixNano()})
	if runner.catchUpDue(ctx) {
		t.Fatal("a run 23 hours ago: no catch-up expected")
	}
	h.store.runs[0].StartedAtNS = h.clock.Now().Add(-25 * time.Hour).UnixNano()
	if !runner.catchUpDue(ctx) {
		t.Fatal("a run 25 hours ago: catch-up expected")
	}
	// A failed run does not count as the last completed one.
	h.store.runs = append(h.store.runs, &storage.ArchiveRun{RunID: "r2", Status: storage.ArchiveRunFailed, StartedAtNS: h.clock.Now().UnixNano()})
	if !runner.catchUpDue(ctx) {
		t.Fatal("only a failed run since: catch-up expected")
	}
}

// H.4: a failed run is tried again after the retry delay until one
// completes or the next try would start past the run deadline.
func TestFailedRunsAreRetriedWithinTheDeadline(t *testing.T) {
	h := newHarness(t)
	h.options.Now = time.Now
	h.options.RetryDelay = 20 * time.Millisecond
	h.options.RunDeadline = 70 * time.Millisecond
	h.addTurnless("only", protocolChat, baseTimeNS)
	h.store.fail["OpenSnapshot"] = errors.New("reader unavailable")
	runner := h.runner()
	started := time.Now()
	runner.runDay(context.Background())
	elapsed := time.Since(started)
	failed := 0
	for _, run := range h.store.runs {
		if run.Status == storage.ArchiveRunFailed {
			failed++
		}
	}
	if failed < 3 || failed > 4 || elapsed > time.Second {
		t.Fatalf("%d failed runs in %v", failed, elapsed)
	}

	// Once the failure clears, the next try completes and the day ends.
	h.store.runs = nil
	h.options.RunDeadline = time.Minute
	runner = h.runner()
	go func() {
		time.Sleep(30 * time.Millisecond)
		h.store.mu.Lock()
		delete(h.store.fail, "OpenSnapshot")
		h.store.mu.Unlock()
	}()
	runner.runDay(context.Background())
	last := h.store.runs[len(h.store.runs)-1]
	if last.Status != storage.ArchiveRunCompleted {
		t.Fatalf("last run %s", last.Status)
	}
}

// Start runs the catch-up at once and Close stops the schedule.
func TestStartRunsTheCatchUpAndCloseStops(t *testing.T) {
	h := newHarness(t)
	h.addTurnless("only", protocolChat, baseTimeNS)
	runner := h.runner()
	runner.Start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.store.mu.Lock()
		completed := len(h.store.runs) > 0 && h.store.runs[0].Status == storage.ArchiveRunCompleted
		h.store.mu.Unlock()
		if completed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no catch-up run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	runner.Close()
	runner.Close()
	h.requireEachOnce("only")
}
