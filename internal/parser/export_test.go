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

// ProjectBackfillForTest runs one project identity backfill pass and returns
// how many audits it attempted.
func (worker *Worker) ProjectBackfillForTest(ctx context.Context) int {
	return worker.projectBackfill(ctx)
}

// BackfillInputForTest loads the evidence backfill would analyse for one
// audit: the input, whether a rebuilt stream summary stands in for the
// response, and the skip reason or error.
func (worker *Worker) BackfillInputForTest(ctx context.Context, auditID string) (Input, bool, string, error) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if err != nil {
		return Input{}, false, "", err
	}
	input, _, reconstruction, reason, err := worker.backfillInput(ctx, audit)
	return input, reconstruction != nil, reason, err
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

// SetNowForTest replaces the worker clock; call it before Start.
func (worker *Worker) SetNowForTest(now func() time.Time) {
	worker.now = now
}
