package sqlite

import "time"

// The waits of this package's tests for the writer. They poll or select, so
// a passing run does not wait for the bound; the bounds are sized for -race on
// a slow shared runner, ten times slower than a developer machine, with half
// as much again between runners.
const (
	// storeWait bounds a wait for one hand-off to or from the writer: a write
	// queued, started, finished, or blocked on a row lock. Each is a
	// goroutine switch or one statement, milliseconds here; ten times a
	// second, doubled for runner variance, is 20 seconds.
	storeWait = 30 * time.Second
	// recoveryWait bounds a wait for the capture recovery, which runs every
	// captureRecoveryInterval (5 seconds): twelve rounds.
	recoveryWait = 12 * captureRecoveryInterval
)
