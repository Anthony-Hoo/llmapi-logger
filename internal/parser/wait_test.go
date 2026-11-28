package parser

import "time"

// PipelineWait bounds every wait of this package's tests (internal and
// parser_test) for the worker or the capture path: a parse and its save, a
// hand-over after Finish, an audit becoming pending, a release. The longest
// legitimate path is a parse that is released once and retried by the
// worker: 30 seconds of backoff, up to 30 seconds until the next pending
// scan, and the parse itself, which takes under a second here and some
// seconds under -race on a slow runner. Two minutes is above that sum; it is
// also the worker's job deadline (defaultJobDeadline). A second release
// (60 seconds of backoff) is not legitimate in these tests and fails them.
// The waits poll or select, so a passing run does not wait for the bound.
const PipelineWait = 2 * time.Minute
