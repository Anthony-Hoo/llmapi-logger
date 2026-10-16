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

// ResetBackfillForTest restarts the backfill scan from the newest audit and
// clears the rescan pause, keeping the in-memory skip set.
func (worker *Worker) ResetBackfillForTest() {
	worker.backfillCursor = nil
	worker.backfillNextScan = time.Time{}
}
