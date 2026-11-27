package audit

import (
	"errors"
	"sync/atomic"

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

// ErrStagingUnavailable is what a ChunkStager returns when it cannot take a
// chunk; the stage then stops retaining content (design F.6).
var ErrStagingUnavailable = errors.New("audit: body staging unavailable")

// ChunkStager is the seam where local staging plugs into the unified write
// path (design F.3 to F.5). The retainer hands it a sealed chunk whose
// plaintext the memory budget cannot hold; on success the stager owns the
// chunk and must yield it again through the commit's chunk source. Without a
// stager every such chunk is refused with ErrStagingUnavailable.
type ChunkStager interface {
	StageChunk(chunk storage.BodyChunk) error
}

type unavailableStager struct{}

func (unavailableStager) StageChunk(storage.BodyChunk) error { return ErrStagingUnavailable }
