package app

import "time"

// pipelineWait bounds the waits of this package's tests for the assembled
// pipeline: an audit committed, its caller resolved, parsed and analysed, a
// periodic refresh recovered, a failed commit finalized by the writer's
// recovery. The longest legitimate path is an audit the parser reaches only
// through its pending scan (every 30 seconds) after a writer recovery round
// (every 5 seconds); the work itself takes under a second here and some
// seconds under -race on a slow runner. Two minutes is above that sum with a
// margin, and above a parse released once (30 seconds of backoff plus the
// next scan). The waits poll, so a passing run does not wait for the bound.
// The archive tests have their own bound, terminalWait.
const pipelineWait = 2 * time.Minute
