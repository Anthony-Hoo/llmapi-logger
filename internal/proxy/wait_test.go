package proxy

import "time"

// The waits of this package's tests for the pipeline behind the handler. They
// are polling bounds: a passing run returns as soon as the condition holds, so
// a long bound costs nothing there. They are sized for a machine ten times
// slower than a developer's, which is what -race on a shared CI runner is.
const (
	// parseWait bounds the wait for one audit's parse. A parse is bounded by
	// the worker's job deadline (parser defaultJobDeadline, 2 minutes); past it
	// the worker gives the audit up, so waiting longer would prove nothing.
	parseWait = 2*time.Minute + 15*time.Second
	// recoveryWait bounds the waits for the writer: queued checkpoints to
	// land, and its capture recovery to finalize an audit whose commit
	// failed. Recovery runs every 5 seconds (captureRecoveryInterval in the
	// stores), so this is twelve rounds.
	recoveryWait = 12 * 5 * time.Second
)
