// Package retention runs small, best-effort SQLite cleanup batches for the
// personal single-process deployment.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

const (
	cleanupInterval      = time.Hour
	cleanupRetryInterval = time.Minute
	maxRowsPerKindPerRun = 5000
)

// Store is the bounded maintenance operation required by Runner.
type Store interface {
	DeleteExpired(context.Context, int64, int, int) (sqlite.RetentionResult, error)
}

// Result reports the rows deleted during one cleanup run.
type Result struct {
	DeletedAudits int
	DeletedGaps   int
}

// Runner owns one optional daily retention loop.
type Runner struct {
	store         Store
	retentionDays int
	logger        *slog.Logger
	now           func() time.Time
	interval      time.Duration
	retryInterval time.Duration

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	close   sync.Once
}

// New constructs a runner. A zero retention period is a valid disabled
// configuration and does not require a store.
func New(store Store, retentionDays int, logger *slog.Logger) (*Runner, error) {
	if retentionDays < 0 {
		return nil, errors.New("retention: days cannot be negative")
	}
	if retentionDays > 0 && store == nil {
		return nil, errors.New("retention: nil store")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		store:         store,
		retentionDays: retentionDays,
		logger:        logger,
		now:           time.Now,
		interval:      cleanupInterval,
		retryInterval: cleanupRetryInterval,
		done:          make(chan struct{}),
	}, nil
}

// Start begins cleanup once. Enabled runners run immediately and then every
// hour when caught up, or after a short pause on backlog/failure.
func (runner *Runner) Start(parent context.Context) {
	if runner == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	runner.mu.Lock()
	if runner.started {
		runner.mu.Unlock()
		return
	}
	runner.started = true
	if runner.retentionDays == 0 {
		close(runner.done)
		runner.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	runner.cancel = cancel
	runner.mu.Unlock()

	go runner.loop(ctx)
}

// Close stops the loop and waits for an active cleanup call to return. It is
// safe before Start and safe to repeat.
func (runner *Runner) Close() {
	if runner == nil {
		return
	}
	runner.close.Do(func() {
		runner.mu.Lock()
		if !runner.started {
			runner.started = true
			close(runner.done)
			runner.mu.Unlock()
			return
		}
		cancel := runner.cancel
		done := runner.done
		runner.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		<-done
	})
}

// RunOnce deletes up to 5000 expired audits and 5000 expired gaps, with each
// class independently batched at no more than 200 rows per writer call. It is
// exported for explicit maintenance and deterministic tests; the background
// loop treats any returned error as non-fatal.
func (runner *Runner) RunOnce(ctx context.Context) (Result, error) {
	if runner == nil || runner.retentionDays == 0 {
		return Result{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cutoff := runner.now().Add(-time.Duration(runner.retentionDays) * 24 * time.Hour).UnixNano()
	var total Result
	auditsDone := false
	gapsDone := false
	for (!auditsDone && total.DeletedAudits < maxRowsPerKindPerRun) || (!gapsDone && total.DeletedGaps < maxRowsPerKindPerRun) {
		auditLimit := 0
		if !auditsDone && total.DeletedAudits < maxRowsPerKindPerRun {
			auditLimit = min(sqlite.RetentionBatchLimit, maxRowsPerKindPerRun-total.DeletedAudits)
		}
		gapLimit := 0
		if !gapsDone && total.DeletedGaps < maxRowsPerKindPerRun {
			gapLimit = min(sqlite.RetentionBatchLimit, maxRowsPerKindPerRun-total.DeletedGaps)
		}
		batch, err := runner.store.DeleteExpired(ctx, cutoff, auditLimit, gapLimit)
		if err != nil {
			return total, err
		}
		total.DeletedAudits += batch.DeletedAudits
		total.DeletedGaps += batch.DeletedGaps
		if auditLimit > 0 && batch.DeletedAudits < auditLimit {
			auditsDone = true
		}
		if gapLimit > 0 && batch.DeletedGaps < gapLimit {
			gapsDone = true
		}
		runtime.Gosched()
	}
	return total, nil
}

func (runner *Runner) loop(ctx context.Context) {
	defer close(runner.done)
	delay := runner.cleanupAndLog(ctx)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(runner.cleanupAndLog(ctx))
		}
	}
}

func (runner *Runner) cleanupAndLog(ctx context.Context) time.Duration {
	result, err := runner.RunOnce(ctx)
	if err != nil {
		if ctx.Err() == nil {
			runner.logger.Warn("retention cleanup failed", "error_category", "retention_failed", "storage_error", sqlite.ErrorClass(err))
		}
		return runner.retryInterval
	}
	if result.DeletedAudits > 0 || result.DeletedGaps > 0 {
		runner.logger.Info(
			"retention cleanup completed",
			"deleted_audits", result.DeletedAudits,
			"deleted_gaps", result.DeletedGaps,
		)
	}
	if result.DeletedAudits == maxRowsPerKindPerRun || result.DeletedGaps == maxRowsPerKindPerRun {
		return runner.retryInterval
	}
	return runner.interval
}
