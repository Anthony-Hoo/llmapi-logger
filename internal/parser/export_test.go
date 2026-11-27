package parser

import (
	"context"
	"time"
)

// ProcessForTest runs one synchronous parse of auditID for external tests
// that drive the worker against a real store.
func (worker *Worker) ProcessForTest(ctx context.Context, auditID string) {
	worker.process(ctx, auditID)
}

// BackfillForTest runs one insights backfill pass and returns how many audits
// it attempted.
func (worker *Worker) BackfillForTest(ctx context.Context) int {
	return worker.backfill(ctx)
}

// ResetBackfillForTest abandons the open insights pass and clears the rescan
// pause, keeping the watermark and the in-memory skip and retry sets: the
// next call starts a pass from the watermark (from the oldest audit with a
// store that has no horizon).
func (worker *Worker) ResetBackfillForTest() {
	worker.backfillMark.abandon()
	worker.backfillCursor = nil
	worker.backfillRetryQueue = nil
	worker.backfillNextScan = time.Time{}
}
