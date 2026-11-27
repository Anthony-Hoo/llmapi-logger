package retention

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

type fakeStore struct {
	mu    sync.Mutex
	calls []deleteCall
	fn    func(context.Context, int64, int, int) (sqlite.RetentionResult, error)
}

type deleteCall struct {
	cutoffNS   int64
	auditLimit int
	gapLimit   int
}

func (store *fakeStore) DeleteExpired(ctx context.Context, cutoffNS int64, auditLimit, gapLimit int) (sqlite.RetentionResult, error) {
	store.mu.Lock()
	store.calls = append(store.calls, deleteCall{cutoffNS: cutoffNS, auditLimit: auditLimit, gapLimit: gapLimit})
	store.mu.Unlock()
	return store.fn(ctx, cutoffNS, auditLimit, gapLimit)
}

func (store *fakeStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.calls)
}

func TestRunOnceDrainsEachClassIndependentlyToLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		fn    func(int, int) sqlite.RetentionResult
		want  Result
		calls int
	}{
		{
			name: "audit backlog with no gaps",
			fn: func(auditLimit, _ int) sqlite.RetentionResult {
				return sqlite.RetentionResult{DeletedAudits: auditLimit}
			},
			want: Result{DeletedAudits: maxRowsPerKindPerRun},
			// The audit batch starts at one and doubles while the store is
			// fast: 1+2+...+128 = 255 in 8 calls, then 23 full batches and
			// the remaining 145.
			calls: 8 + 23 + 1,
		},
		{
			name: "gap backlog with no audits",
			fn: func(_, gapLimit int) sqlite.RetentionResult {
				return sqlite.RetentionResult{DeletedGaps: gapLimit}
			},
			want:  Result{DeletedGaps: maxRowsPerKindPerRun},
			calls: maxRowsPerKindPerRun / sqlite.RetentionBatchLimit,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{fn: func(_ context.Context, _ int64, auditLimit, gapLimit int) (sqlite.RetentionResult, error) {
				if auditLimit > sqlite.RetentionBatchLimit || gapLimit > sqlite.RetentionBatchLimit {
					t.Fatalf("limits audit=%d gap=%d exceed batch size", auditLimit, gapLimit)
				}
				return test.fn(auditLimit, gapLimit), nil
			}}
			runner, err := New(store, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			runner.now = func() time.Time { return time.Unix(1_000_000, 0) }
			result, err := runner.RunOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result != test.want {
				t.Fatalf("result = %+v, want %+v", result, test.want)
			}
			if store.callCount() != test.calls {
				t.Fatalf("calls = %d, want %d", store.callCount(), test.calls)
			}
		})
	}
}

func TestRunOnceStopsAfterFiniteGapBacklog(t *testing.T) {
	t.Parallel()

	remaining := 450
	store := &fakeStore{fn: func(_ context.Context, _ int64, _ int, gapLimit int) (sqlite.RetentionResult, error) {
		deleted := min(remaining, gapLimit)
		remaining -= deleted
		return sqlite.RetentionResult{DeletedGaps: deleted}, nil
	}}
	runner, err := New(store, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 0 || result.DeletedGaps != 450 || store.callCount() != 3 {
		t.Fatalf("result=%+v calls=%d, want 450 gaps in 3 calls", result, store.callCount())
	}
}

func TestDisabledRunnerNeverCallsStore(t *testing.T) {
	t.Parallel()

	store := &fakeStore{fn: func(context.Context, int64, int, int) (sqlite.RetentionResult, error) {
		t.Fatal("disabled runner called store")
		return sqlite.RetentionResult{}, nil
	}}
	runner, err := New(store, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner.Start(context.Background())
	runner.Close()
	if store.callCount() != 0 {
		t.Fatalf("disabled runner made %d calls", store.callCount())
	}
}

func TestRunnerStartsImmediatelyAndCloseCancelsCleanup(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	var once sync.Once
	store := &fakeStore{fn: func(ctx context.Context, _ int64, _, _ int) (sqlite.RetentionResult, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return sqlite.RetentionResult{}, ctx.Err()
	}}
	runner, err := New(store, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runner.Start(context.Background())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("initial cleanup did not start")
	}
	closed := make(chan struct{})
	go func() {
		runner.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("runner close did not cancel cleanup")
	}
}

func TestRunnerLogsStableFailureAndContinues(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	secondCall := make(chan struct{})
	var once sync.Once
	store := &fakeStore{}
	store.fn = func(context.Context, int64, int, int) (sqlite.RetentionResult, error) {
		calls := store.callCount()
		if calls == 1 {
			return sqlite.RetentionResult{}, errors.New("secret database path")
		}
		once.Do(func() { close(secondCall) })
		return sqlite.RetentionResult{}, nil
	}
	runner, err := New(store, 30, logger)
	if err != nil {
		t.Fatal(err)
	}
	runner.interval = time.Hour
	runner.retryInterval = 5 * time.Millisecond
	runner.Start(context.Background())
	select {
	case <-secondCall:
	case <-time.After(time.Second):
		t.Fatal("runner stopped after a cleanup failure")
	}
	runner.Close()
	logText := output.String()
	if !strings.Contains(logText, "retention_failed") {
		t.Fatalf("failure log missing stable category: %q", logText)
	}
	if strings.Contains(logText, "secret database path") {
		t.Fatalf("failure log leaked underlying error: %q", logText)
	}
}

func TestRunnerCatchesUpBeyondOneRunLimit(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	remaining := 8000
	drained := make(chan struct{})
	var once sync.Once
	store := &fakeStore{fn: func(_ context.Context, _ int64, auditLimit, _ int) (sqlite.RetentionResult, error) {
		mu.Lock()
		defer mu.Unlock()
		deleted := min(remaining, auditLimit)
		remaining -= deleted
		if remaining == 0 {
			once.Do(func() { close(drained) })
		}
		return sqlite.RetentionResult{DeletedAudits: deleted}, nil
	}}
	runner, err := New(store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runner.interval = time.Hour
	runner.retryInterval = 5 * time.Millisecond
	runner.Start(context.Background())
	defer runner.Close()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("retention waited for the idle interval after hitting its batch budget")
	}
	runner.Close()
	mu.Lock()
	defer mu.Unlock()
	if remaining != 0 || store.callCount() <= maxRowsPerKindPerRun/sqlite.RetentionBatchLimit {
		t.Fatal("retention did not continue through the bounded backlog")
	}
}

func TestCaughtUpRetentionReturnsToIdleSchedule(t *testing.T) {
	t.Parallel()
	store := &fakeStore{fn: func(context.Context, int64, int, int) (sqlite.RetentionResult, error) {
		return sqlite.RetentionResult{}, nil
	}}
	runner, err := New(store, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if delay := runner.cleanupAndLog(context.Background()); delay != cleanupInterval {
		t.Fatalf("idle delay=%s", delay)
	}
	if store.callCount() != 1 {
		t.Fatal("caught-up retention kept scanning")
	}
}

// costStore deletes audits on a fake clock. Each audit has its own cost, and
// a batch that would take longer than the statement timeout fails whole. It
// is a simplification of the PostgreSQL store, whose timeout applies to each
// statement of a batch and which has costs per batch and per checkpoint.
type costStore struct {
	clock   time.Time
	costs   []time.Duration // cost of each remaining audit, oldest first
	timeout time.Duration
	limits  []int
	failed  int
	held    time.Duration // total time batches held the store
	longest time.Duration
	pauses  []time.Duration
}

func (store *costStore) DeleteExpired(_ context.Context, _ int64, auditLimit, _ int) (sqlite.RetentionResult, error) {
	store.limits = append(store.limits, auditLimit)
	deleted := min(len(store.costs), auditLimit)
	var cost time.Duration
	for _, each := range store.costs[:deleted] {
		cost += each
	}
	if store.timeout > 0 && cost > store.timeout {
		store.failed++
		store.clock = store.clock.Add(store.timeout)
		store.held += store.timeout
		return sqlite.RetentionResult{}, errors.New("statement timeout")
	}
	store.clock = store.clock.Add(cost)
	store.held += cost
	store.longest = max(store.longest, cost)
	store.costs = store.costs[deleted:]
	return sqlite.RetentionResult{DeletedAudits: deleted}, nil
}

func uniformCosts(count int, each time.Duration) []time.Duration {
	costs := make([]time.Duration, count)
	for index := range costs {
		costs[index] = each
	}
	return costs
}

func newCostRunner(t *testing.T, store *costStore) *Runner {
	t.Helper()
	store.clock = time.Unix(1_000_000, 0)
	runner, err := New(store, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return store.clock }
	runner.pause = func(_ context.Context, duration time.Duration) { store.pauses = append(store.pauses, duration) }
	return runner
}

func TestAuditBatchGrowsWhileFullBatchesAreFast(t *testing.T) {
	t.Parallel()
	store := &costStore{costs: uniformCosts(100, 40*time.Millisecond)}
	runner := newCostRunner(t, store)
	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 1, 2, 4 and 8 audits take at most 320 ms, half the target or less, and
	// double the batch. 16 audits take 640 ms, which is within the target
	// but no longer fast, so the size stays. The last batch finds 5 left.
	if want := []int{1, 2, 4, 8, 16, 16, 16, 16, 16, 16}; !equalInts(store.limits, want) || len(store.costs) != 0 || runner.batchSize() != 16 {
		t.Fatalf("audit limits = %v, remaining %d, batch %d", store.limits, len(store.costs), runner.batchSize())
	}

	// The size is kept for the next run instead of starting over.
	store.costs, store.limits = uniformCosts(32, 40*time.Millisecond), nil
	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !equalInts(store.limits, []int{16, 16, 16}) {
		t.Fatalf("second run audit limits = %v", store.limits)
	}
}

func TestAuditBatchShrinksInProportionToASlowBatch(t *testing.T) {
	t.Parallel()
	store := &costStore{costs: uniformCosts(260, 20*time.Millisecond)}
	runner := newCostRunner(t, store)
	runner.setBatchSize(sqlite.RetentionBatchLimit)
	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 200 audits at 20 ms take 4 s, four times the target, so the next batch
	// asks for a quarter. 50 audits take exactly the target and stay.
	if want := []int{200, 50, 50}; !equalInts(store.limits, want) || runner.batchSize() != 50 {
		t.Fatalf("audit limits = %v, batch %d", store.limits, runner.batchSize())
	}
	// Each batch but the last is followed by a pause as long as it took.
	if len(store.pauses) != 2 || store.pauses[0] != 4*time.Second || store.pauses[1] != time.Second {
		t.Fatalf("pauses = %v", store.pauses)
	}
}

// On a disk where one audit takes seconds the batch stays at one audit: the
// smallest step, taken however long it is, with a capped pause after it.
func TestSingleAuditBatchKeepsGoingHoweverSlow(t *testing.T) {
	t.Parallel()
	store := &costStore{costs: uniformCosts(3, 8*time.Second), timeout: 30 * time.Second}
	runner := newCostRunner(t, store)
	result, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(store.limits, []int{1, 1, 1, 1}) || result.DeletedAudits != 3 || runner.batchSize() != 1 || store.failed != 0 {
		t.Fatalf("audit limits = %v, deleted %d, batch %d", store.limits, result.DeletedAudits, runner.batchSize())
	}
	for index, pause := range store.pauses[:3] {
		if pause != maxBatchPause {
			t.Fatalf("pause %d = %s, want the %s cap", index, pause, maxBatchPause)
		}
	}
}

// A batch sized on cheap audits can run into a stretch of expensive ones and
// fail at the statement timeout. A fixed batch size fails the same way on
// every retry; the runner retries with one audit and gets through.
func TestFailedBatchIsRetriedOneAuditAtATime(t *testing.T) {
	t.Parallel()
	store := &costStore{costs: uniformCosts(3, time.Millisecond), timeout: 30 * time.Second}
	var output bytes.Buffer
	runner := newCostRunner(t, store)
	runner.logger = slog.New(slog.NewTextHandler(&output, nil))
	// A run that completes comes first, as it usually does.
	if _, err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.setBatchSize(1)
	store.costs, store.limits = append(uniformCosts(400, time.Millisecond), uniformCosts(40, 3*time.Second)...), nil

	// The cheap audits grow the batch to 200. The batch after the first 255
	// holds the other 145 cheap audits and the 40 expensive ones, 120 s of
	// work, and fails.
	if _, err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("the oversized batch did not fail")
	}
	if store.failed != 1 || runner.batchSize() != 1 || len(store.costs) != 185 {
		t.Fatalf("failed %d, batch %d, remaining %d", store.failed, runner.batchSize(), len(store.costs))
	}
	if !strings.Contains(output.String(), "retention batch reduced to one audit") || !strings.Contains(output.String(), "failed_audit_batch=200") {
		t.Fatalf("the reduction was not logged: %q", output.String())
	}
	// The retry does not grow back on the cheap audits that are left, which
	// would run it into the expensive ones a second time.
	store.limits = nil
	result, err := runner.RunOnce(context.Background())
	if err != nil || result.DeletedAudits != 185 || store.failed != 1 || len(store.costs) != 0 {
		t.Fatalf("retry deleted %d, failures %d, err %v", result.DeletedAudits, store.failed, err)
	}
	for _, limit := range store.limits {
		if limit != 1 {
			t.Fatalf("retry audit limits = %v, want one audit at a time", store.limits)
		}
	}

	// Each run that completes lets the batch grow twice as far again.
	for _, ceiling := range []int{2, 4, 8} {
		store.costs, store.limits = uniformCosts(100, time.Millisecond), nil
		if _, err := runner.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if runner.batchSize() != ceiling {
			t.Fatalf("batch after a completed run = %d, want %d (%v)", runner.batchSize(), ceiling, store.limits)
		}
	}
}

// Mostly cheap audits with an expensive one now and then: no batch is given
// up, so the store is held for exactly the work there is, and no batch holds
// it for more than a full fixed-size batch would.
func TestUnevenAuditCostsWasteNoWork(t *testing.T) {
	t.Parallel()
	var costs []time.Duration
	var work time.Duration
	for index := range 5000 {
		cost := 5 * time.Millisecond
		if index%100 == 99 {
			cost = 2500 * time.Millisecond
		}
		costs = append(costs, cost)
		work += cost
	}
	store := &costStore{costs: costs, timeout: 30 * time.Second}
	runner := newCostRunner(t, store)
	result, err := runner.RunOnce(context.Background())
	if err != nil || result.DeletedAudits != 5000 {
		t.Fatalf("deleted %d, err %v", result.DeletedAudits, err)
	}
	if store.failed != 0 || store.held != work {
		t.Fatalf("failures %d, store held %s for %s of work", store.failed, store.held, work)
	}
	// A fixed batch of 200 holds two expensive audits and 198 cheap ones.
	if fixed := 2*2500*time.Millisecond + 198*5*time.Millisecond; store.longest > fixed {
		t.Fatalf("longest batch %s, a fixed batch takes %s", store.longest, fixed)
	}
}

func TestNextBatchSize(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		size, limit, deleted int
		elapsed              time.Duration
		want                 int
	}{
		"fast full batch doubles":                {size: 8, limit: 8, deleted: 8, elapsed: 500 * time.Millisecond, want: 16},
		"doubling stops at the batch limit":      {size: 128, limit: 128, deleted: 128, elapsed: time.Millisecond, want: 200},
		"within the target but not fast":         {size: 8, limit: 8, deleted: 8, elapsed: 501 * time.Millisecond, want: 8},
		"exactly the target":                     {size: 8, limit: 8, deleted: 8, elapsed: time.Second, want: 8},
		"slow batch shrinks in proportion":       {size: 200, limit: 200, deleted: 200, elapsed: 8 * time.Second, want: 25},
		"slow single audit stays at one":         {size: 1, limit: 1, deleted: 1, elapsed: 20 * time.Second, want: 1},
		"never below one":                        {size: 4, limit: 4, deleted: 4, elapsed: time.Minute, want: 1},
		"fast batch that ran out of audits":      {size: 8, limit: 8, deleted: 3, elapsed: time.Millisecond, want: 8},
		"fast batch cut by the run limit":        {size: 64, limit: 40, deleted: 40, elapsed: time.Millisecond, want: 64},
		"slow batch just over the target":        {size: 8, limit: 8, deleted: 8, elapsed: 1500 * time.Millisecond, want: 5},
		"slow batch cut by the run limit":        {size: 200, limit: 40, deleted: 40, elapsed: 4 * time.Second, want: 10},
		"slow batch that found fewer than asked": {size: 200, limit: 200, deleted: 60, elapsed: 6 * time.Second, want: 33},
	} {
		if got := nextBatchSize(test.size, test.limit, test.deleted, test.elapsed); got != test.want {
			t.Errorf("%s: next size = %d, want %d", name, got, test.want)
		}
	}
}

// Only a batch of several audits that failed slowly is taken as too large. A
// batch that failed at once did not fail for its size, and a single audit
// cannot be made smaller.
func TestOtherFailuresKeepTheBatchSize(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		size   int
		failed time.Duration
	}{
		"several audits failing at once": {size: 64, failed: 20 * time.Millisecond},
		"one audit failing slowly":       {size: 1, failed: 30 * time.Second},
	} {
		clock := time.Unix(1_000_000, 0)
		fail := true
		store := &fakeStore{fn: func(_ context.Context, _ int64, auditLimit, _ int) (sqlite.RetentionResult, error) {
			if fail {
				clock = clock.Add(test.failed)
				return sqlite.RetentionResult{}, errors.New("storage failure")
			}
			return sqlite.RetentionResult{DeletedAudits: min(auditLimit, 3)}, nil
		}}
		runner, err := New(store, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		runner.now = func() time.Time { return clock }
		runner.pause = func(context.Context, time.Duration) {}
		runner.setBatchSize(test.size)
		if _, err := runner.RunOnce(context.Background()); err == nil {
			t.Fatalf("%s: the failure was not returned", name)
		}
		// Had the failure set the ceiling, the size could not go above one.
		fail = false
		runner.setBatchSize(8)
		if _, err := runner.RunOnce(context.Background()); err != nil || runner.batchSize() != 8 {
			t.Fatalf("%s: batch after the failure = %d, err %v", name, runner.batchSize(), err)
		}
	}
}

func TestRunOnceKeepsTheBatchSizeWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	store := &fakeStore{fn: func(context.Context, int64, int, int) (sqlite.RetentionResult, error) {
		cancel()
		return sqlite.RetentionResult{}, context.Canceled
	}}
	runner, err := New(store, 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner.setBatchSize(64)
	if _, err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) || runner.batchSize() != 64 {
		t.Fatalf("error = %v, batch %d", err, runner.batchSize())
	}
}

func TestRunOnceStopsWhenCanceledDuringThePause(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	store := &fakeStore{fn: func(_ context.Context, _ int64, auditLimit, _ int) (sqlite.RetentionResult, error) {
		return sqlite.RetentionResult{DeletedAudits: auditLimit}, nil
	}}
	runner, err := New(store, 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner.pause = func(context.Context, time.Duration) { cancel() }
	if _, err := runner.RunOnce(ctx); !errors.Is(err, context.Canceled) || store.callCount() != 1 {
		t.Fatalf("error = %v after %d calls", err, store.callCount())
	}
}

func TestPauseForEndsWithTheDurationOrTheContext(t *testing.T) {
	t.Parallel()
	started := time.Now()
	pauseFor(context.Background(), 30*time.Millisecond)
	if waited := time.Since(started); waited < 30*time.Millisecond {
		t.Fatalf("pause returned after %s", waited)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started = time.Now()
	pauseFor(ctx, time.Minute)
	if waited := time.Since(started); waited > 10*time.Second {
		t.Fatalf("a canceled pause took %s", waited)
	}
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
