package app

import "time"

// pipelineWait bounds the waits of this package's tests for the assembled
// pipeline: an audit committed, its caller resolved, parsed and analysed, a
// periodic refresh recovered, a failed commit finalized by the writer's
// recovery. Each takes well under a second here, or one 5-second recovery
// round (captureRecoveryInterval in the stores); under -race on a slow shared
// runner the work takes ten times longer and runners differ by half again:
// (10 s + 5 s) x 2 = 30 s, doubled for a commit retried before the recovery.
// The waits poll, so a passing run does not wait for the bound. The archive
// tests have their own bound (terminalWait), which also covers the parser's
// 30-second pending scan.
const pipelineWait = time.Minute
