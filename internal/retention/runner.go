// Package retention runs small, best-effort cleanup batches for the personal
// single-process deployment. The batches go through the store's single
// writer, which audit writes wait for, so the runner sizes each batch by how
// long the previous one took and then leaves the writer alone for as long.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"llmapi-logger/internal/storage"
)

const (
	cleanupInterval      = time.Hour
	cleanupRetryInterval = time.Minute
	maxRowsPerKindPerRun = 5000
)

// Store is the bounded maintenance operation required by Runner.
type Store interface {
	DeleteExpired(context.Context, int64, int, int) (storage.RetentionResult, error)
}

// Result reports the rows deleted during one cleanup run.
type Result struct {
	DeletedAudits int
	DeletedGaps   int
}

// Runner owns one optional retention loop.
type Runner struct {
	store         Store
	retentionDays int
	logger        *slog.Logger
	now           func() time.Time
	interval      time.Duration
	retryInterval time.Duration
	pause         func(context.Context, time.Duration)

	// batcher sizes the audit batches (batcher.go); kept across runs.
	batcher *Batcher

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
		pause:         pauseFor,
		batcher:       NewBatcher(),
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
// class independently batched at no more than 200 rows per writer call. The
// audit batch is sized by the time earlier batches took, and every batch is
// followed by a pause as long as the batch took. It is exported for explicit
// maintenance and deterministic tests; the background loop treats any
// returned error as non-fatal.
func (runner *Runner) RunOnce(ctx context.Context) (Result, error) {
	if runner == nil || runner.retentionDays == 0 {
		return Result{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cutoff := runner.now().Add(-time.Duration(runner.retentionDays) * 24 * time.Hour).UnixNano()
	runner.batcher.BeginRun()
	var total Result
	auditsDone := false
	gapsDone := false
	for (!auditsDone && total.DeletedAudits < maxRowsPerKindPerRun) || (!gapsDone && total.DeletedGaps < maxRowsPerKindPerRun) {
		size := runner.batchSize()
		auditLimit := 0
		if !auditsDone && total.DeletedAudits < maxRowsPerKindPerRun {
			auditLimit = min(size, maxRowsPerKindPerRun-total.DeletedAudits)
		}
		gapLimit := 0
		if !gapsDone && total.DeletedGaps < maxRowsPerKindPerRun {
			gapLimit = min(storage.RetentionBatchLimit, maxRowsPerKindPerRun-total.DeletedGaps)
		}
		started := runner.now()
		batch, err := runner.store.DeleteExpired(ctx, cutoff, auditLimit, gapLimit)
		elapsed := runner.now().Sub(started)
		if err != nil {
			// A batch of several audits that failed after more than the
			// target time may have failed for its size, by running into the
			// statement timeout. The retry asks for one audit, the smallest
			// step there is. A batch that failed at once did not.
			if runner.batcher.Failed(ctx, auditLimit, elapsed) {
				runner.logger.Info("retention batch reduced to one audit", "failed_audit_batch", auditLimit)
			}
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
		if auditLimit > 0 {
			runner.batcher.Done(size, auditLimit, batch.DeletedAudits, elapsed)
		}
		if (auditsDone || total.DeletedAudits >= maxRowsPerKindPerRun) && (gapsDone || total.DeletedGaps >= maxRowsPerKindPerRun) {
			break
		}
		runner.pause(ctx, PauseAfter(elapsed))
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
	runner.batcher.EndRun()
	return total, nil
}

func (runner *Runner) batchSize() int { return runner.batcher.Size() }

func (runner *Runner) setBatchSize(size int) { runner.batcher.SetSize(size) }
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
			runner.logger.Warn("retention cleanup failed", "error_category", "retention_failed", "storage_error", storage.ErrorClass(err))
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
