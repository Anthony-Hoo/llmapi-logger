package audit

import (
	"sync/atomic"
	"time"
)

// finishObserver, when set, receives how long each Session.Finish took. It
// exists for cmd/audit-bench, which runs the application in its own process
// and cannot otherwise separate the time the handler spends in Finish from
// the end of the stream. Production never sets it.
var finishObserver atomic.Pointer[func(time.Duration)]

// SetFinishObserver makes every later Session.Finish report its duration to
// observe, once per session (the first call does the work). nil removes it.
// The observer runs on the handler's goroutine after Finish's work, so it
// must be quick; it does not change what Finish does or returns.
func SetFinishObserver(observe func(time.Duration)) {
	if observe == nil {
		finishObserver.Store(nil)
		return
	}
	finishObserver.Store(&observe)
}

// timedFinish runs finish and reports its duration when an observer is set.
func (session *Session) timedFinish() error {
	observe := finishObserver.Load()
	if observe == nil {
		return session.finish()
	}
	started := time.Now()
	err := session.finish()
	(*observe)(time.Since(started))
	return err
}
