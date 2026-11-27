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

	// targetBatchTime is how long a batch of audits should hold the writer.
	// What an audit costs to delete depends on the disk and on how much the
	// audit holds, so the batch size is found by measuring: it starts at one
	// audit, doubles after a full batch that took at most half the target,
	// and shrinks in proportion after a batch that took longer than the
	// target.
	//
	// Measuring cannot foresee a run of expensive audits behind cheap ones: a
	// batch sized on the cheap ones can then fail at the store's statement
	// timeout. After a batch of several audits that failed slowly, the size
	// drops to one and stays there for the rest of that run and the next;
	// every later run that completes lets it grow twice as far as the one
	// before.
	targetBatchTime = time.Second
	// maxBatchPause caps the pause after a batch, which is otherwise as long
	// as the batch took. Cleanup then holds the writer at most half of the
	// time, unless single batches take longer than the cap.
	maxBatchPause = 5 * time.Second
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

	batchMu      sync.Mutex
	auditBatch   int  // audits asked for per batch; kept across runs
	auditCeiling int  // how far auditBatch may grow
	completedRun bool // the previous run ended without an error

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
		auditBatch:    1,
		auditCeiling:  storage.RetentionBatchLimit,
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
	runner.beginRun()
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
			if auditLimit > 1 && elapsed > targetBatchTime && ctx.Err() == nil {
				runner.failedAtSize()
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
			runner.setBatchSize(nextBatchSize(size, auditLimit, batch.DeletedAudits, elapsed))
		}
		if (auditsDone || total.DeletedAudits >= maxRowsPerKindPerRun) && (gapsDone || total.DeletedGaps >= maxRowsPerKindPerRun) {
			break
		}
		runner.pause(ctx, min(elapsed, maxBatchPause))
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
	runner.endRun()
	return total, nil
}

// nextBatchSize returns the batch size to use after a batch that asked for
// limit audits out of a batch size of size, deleted the given number and took
// elapsed. A slow batch shrinks the size in proportion to how far it missed
// the target. A fast one doubles it, but only when it was a full batch of the
// whole size: a batch cut short says little about what a larger one costs.
func nextBatchSize(size, limit, deleted int, elapsed time.Duration) int {
	switch {
	case elapsed > targetBatchTime:
		return max(int(int64(limit)*int64(targetBatchTime)/int64(elapsed)), 1)
	case limit == size && deleted == limit && elapsed <= targetBatchTime/2:
		return min(size*2, storage.RetentionBatchLimit)
	default:
		return size
	}
}

func (runner *Runner) batchSize() int {
	runner.batchMu.Lock()
	defer runner.batchMu.Unlock()
	return runner.auditBatch
}

func (runner *Runner) setBatchSize(size int) {
	runner.batchMu.Lock()
	defer runner.batchMu.Unlock()
	runner.auditBatch = min(max(size, 1), runner.auditCeiling)
}

// beginRun lets the batch grow twice as far as before when the previous run
// completed, which undoes the ceiling of a failed batch step by step.
func (runner *Runner) beginRun() {
	runner.batchMu.Lock()
	defer runner.batchMu.Unlock()
	if runner.completedRun {
		runner.auditCeiling = min(runner.auditCeiling*2, storage.RetentionBatchLimit)
	}
	runner.completedRun = false
}

func (runner *Runner) endRun() {
	runner.batchMu.Lock()
	defer runner.batchMu.Unlock()
	runner.completedRun = true
}

func (runner *Runner) failedAtSize() {
	runner.batchMu.Lock()
	defer runner.batchMu.Unlock()
	runner.auditBatch, runner.auditCeiling = 1, 1
}

// pauseFor waits for the duration or until the context ends.
func pauseFor(ctx context.Context, duration time.Duration) {
	if duration <= 0 {
		return
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
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
