package audit

import (
	"errors"
	"sync/atomic"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/storage"
)

// memoryBudget is the process-wide plaintext budget of the unified write path
// (design F.2), counted in plaintext bytes.
type memoryBudget struct {
	limit int64
	used  atomic.Int64
}

// reserve takes size bytes from the budget, or nothing when they do not fit.
func (budget *memoryBudget) reserve(size int64) bool {
	if budget == nil || size <= 0 {
		return true
	}
	for {
		used := budget.used.Load()
		if used+size > budget.limit {
			return false
		}
		if budget.used.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

// fits reports whether size more bytes would fit now, without taking them.
func (budget *memoryBudget) fits(size int64) bool {
	if budget == nil || size <= 0 {
		return true
	}
	return budget.used.Load()+size <= budget.limit
}

func (budget *memoryBudget) release(size int64) {
	if budget == nil || size <= 0 {
		return
	}
	budget.used.Add(-size)
}

// Used returns the plaintext bytes currently held, for tests and metrics.
func (budget *memoryBudget) Used() int64 {
	if budget == nil {
		return 0
	}
	return budget.used.Load()
}

// queueBudget is the memory budget as the staging write queue sees it: the
// ciphertext waiting to be written counts, and is added without a limit
// check because it replaces plaintext that was just released (design F.2,
// F.5), so global_bytes is a soft limit.
type queueBudget struct{ budget *memoryBudget }

func (queue queueBudget) Add(size int64) {
	if queue.budget != nil && size > 0 {
		queue.budget.used.Add(size)
	}
}

func (queue queueBudget) Release(size int64) { queue.budget.release(size) }

// ErrStagingUnavailable is what a ChunkStager returns when it cannot take a
// chunk; the stage then stops retaining content (design F.6).
var ErrStagingUnavailable = errors.New("audit: body staging unavailable")

// ChunkStager is where local staging plugs into the unified write path
// (design F.3 to F.5); *staging.Stager implements it. The retainer hands it a
// sealed chunk whose plaintext the memory budget cannot hold and keeps only
// the returned index entry, through which a checkpoint or the commit reads
// the chunk again. After the commit the session calls Discard when it was
// acknowledged, or Keep when it was not, so that the next start imports what
// is staged. Without a stager every chunk is refused with
// ErrStagingUnavailable.
type ChunkStager interface {
	Stage(chunk storage.BodyChunk) (*staging.Ref, error)
	Discard(auditID string)
	Keep(auditID string)
}

type unavailableStager struct{}

func (unavailableStager) Stage(storage.BodyChunk) (*staging.Ref, error) {
	return nil, ErrStagingUnavailable
}
func (unavailableStager) Discard(string) {}
func (unavailableStager) Keep(string)    {}

// stagingFailureCode is the stable error code of a stage that stopped
// retaining because staging refused a chunk (F.6): a write error of the
// staging file is staging_write_failed; a full directory, a full disk or no
// staging at all is capture_budget_exhausted.
func stagingFailureCode(err error) string {
	if errors.Is(err, staging.ErrWriteFailed) {
		return "staging_write_failed"
	}
	return "capture_budget_exhausted"
}
