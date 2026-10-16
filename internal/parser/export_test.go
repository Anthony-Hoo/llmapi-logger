package parser

import "context"

// ProcessForTest runs one synchronous parse of auditID for external tests
// that drive the worker against a real store.
func (worker *Worker) ProcessForTest(ctx context.Context, auditID string) {
	worker.process(ctx, auditID)
}
