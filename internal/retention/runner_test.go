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
		name string
		fn   func(int, int) sqlite.RetentionResult
		want Result
	}{
		{
			name: "audit backlog with no gaps",
			fn: func(auditLimit, _ int) sqlite.RetentionResult {
				return sqlite.RetentionResult{DeletedAudits: auditLimit}
			},
			want: Result{DeletedAudits: maxRowsPerKindPerRun},
		},
		{
			name: "gap backlog with no audits",
			fn: func(_, gapLimit int) sqlite.RetentionResult {
				return sqlite.RetentionResult{DeletedGaps: gapLimit}
			},
			want: Result{DeletedGaps: maxRowsPerKindPerRun},
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
			if store.callCount() != maxRowsPerKindPerRun/sqlite.RetentionBatchLimit {
				t.Fatalf("calls = %d, want %d", store.callCount(), maxRowsPerKindPerRun/sqlite.RetentionBatchLimit)
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
	runner.interval = 5 * time.Millisecond
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
