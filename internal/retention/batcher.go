package retention

import (
	"context"
	"sync"
	"time"

	"llmapi-logger/internal/storage"
)

const (
	// TargetBatchTime is how long a batch of audits should hold the writer.
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
	TargetBatchTime = time.Second
	// MaxBatchPause caps the pause after a batch, which is otherwise as long
	// as the batch took. A caller then holds the writer at most half of the
	// time, unless single batches take longer than the cap.
	MaxBatchPause = 5 * time.Second

	targetBatchTime = TargetBatchTime
	maxBatchPause   = MaxBatchPause
)

// Batcher sizes the batches of audits a caller deletes through the store's
// single writer (PR #55): retention's direct delete and the cold archive's
// verified removal (doc/design/issue-59-stage4-cold-archive.md M.2) share it.
// It holds only the sizing policy; the caller measures how long each batch
// took and pauses for PauseAfter of it, so a fake clock or pause is the
// caller's. The size is kept across runs. A Batcher is safe for concurrent
// use, though a caller runs one batch at a time.
type Batcher struct {
	mu        sync.Mutex
	size      int  // audits asked for per batch
	ceiling   int  // how far size may grow
	completed bool // the previous run ended without an error
}

// NewBatcher returns a Batcher at one audit per batch with a ceiling of
// storage.RetentionBatchLimit.
func NewBatcher() *Batcher {
	return &Batcher{size: 1, ceiling: storage.RetentionBatchLimit}
}

// Size is the number of audits to ask for in the next batch.
func (batcher *Batcher) Size() int {
	batcher.mu.Lock()
	defer batcher.mu.Unlock()
	return batcher.size
}

// SetSize sets the batch size, at least one and at most the ceiling.
func (batcher *Batcher) SetSize(size int) {
	batcher.mu.Lock()
	defer batcher.mu.Unlock()
	batcher.size = min(max(size, 1), batcher.ceiling)
}

// BeginRun starts a run of batches. When the previous run completed, the
// ceiling a failed batch set doubles, which undoes it step by step.
func (batcher *Batcher) BeginRun() {
	batcher.mu.Lock()
	defer batcher.mu.Unlock()
	if batcher.completed {
		batcher.ceiling = min(batcher.ceiling*2, storage.RetentionBatchLimit)
	}
	batcher.completed = false
}

// EndRun records that the run completed without an error.
func (batcher *Batcher) EndRun() {
	batcher.mu.Lock()
	defer batcher.mu.Unlock()
	batcher.completed = true
}

// Done sizes the next batch after one that asked for limit audits out of a
// batch size of size, handled done of them and took elapsed.
func (batcher *Batcher) Done(size, limit, done int, elapsed time.Duration) {
	batcher.SetSize(nextBatchSize(size, limit, done, elapsed))
}

// Failed handles a batch of limit audits that failed after elapsed. A batch
// of several audits that failed after more than the target time may have
// failed for its size, by running into the statement timeout: the next
// batch asks for one audit, the smallest step there is, and so does every
// batch until a later run completes. Failed reports whether it reduced the
// size. A batch that failed at once did not fail for its size, a single
// audit cannot be made smaller, and a failure because ctx ended says nothing
// about the size.
func (batcher *Batcher) Failed(ctx context.Context, limit int, elapsed time.Duration) bool {
	if limit <= 1 || elapsed <= TargetBatchTime || ctx.Err() != nil {
		return false
	}
	batcher.mu.Lock()
	defer batcher.mu.Unlock()
	batcher.size, batcher.ceiling = 1, 1
	return true
}

// PauseAfter is how long to leave the writer alone after a batch that took
// elapsed: as long as the batch took, at most MaxBatchPause.
func PauseAfter(elapsed time.Duration) time.Duration { return min(elapsed, MaxBatchPause) }

// Wait waits for the duration or until ctx ends.
func Wait(ctx context.Context, duration time.Duration) { pauseFor(ctx, duration) }

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
