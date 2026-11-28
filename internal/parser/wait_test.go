package parser

import "time"

// PipelineWait bounds every wait of this package's tests (internal and
// parser_test) for the worker or the capture path: a parse and its save, a
// hand-over after Finish, an audit becoming pending, a release. Each takes
// milliseconds to a second on a developer machine; under -race on a slow
// shared runner ten times that, and runners differ by half again, so 20
// seconds; a minute keeps a margin and stays below the worker's job deadline
// (defaultJobDeadline, 2 minutes), past which it gives an audit up anyway.
// The waits poll or select, so a passing run does not wait for the bound.
const PipelineWait = time.Minute
