package parser

import "sync"

// backfillProgress records how far the insights backfill got, so other
// components can tell "not analysed yet" from "attempted and skipped or
// failed". The backfill lists candidates oldest first; one pass runs from an
// empty cursor until the list comes back empty. The parser goroutine writes,
// any goroutine reads.
type backfillProgress struct {
	mu sync.Mutex
	// open is true while a pass is running; startNS is when it began and
	// cursorNS the start time of the last candidate it attempted (0: none).
	open     bool
	startNS  int64
	cursorNS int64
	// completedNS is when the most recent completed pass began; 0 if none.
	completedNS int64
}

// begin opens a pass unless one is already running.
func (progress *backfillProgress) begin(nowNS int64) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if !progress.open {
		progress.open, progress.startNS, progress.cursorNS = true, nowNS, 0
	}
}

// advance records that every candidate up to startedAtNS was attempted.
func (progress *backfillProgress) advance(startedAtNS int64) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.open && startedAtNS > progress.cursorNS {
		progress.cursorNS = startedAtNS
	}
}

// complete closes the running pass: it attempted every candidate.
func (progress *backfillProgress) complete() {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.open {
		progress.open, progress.completedNS = false, progress.startNS
	}
}

// covered reports whether a pass that began at or after sinceNS has attempted
// every candidate that started before untilNS.
func (progress *backfillProgress) covered(untilNS, sinceNS int64) bool {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.completedNS != 0 && progress.completedNS >= sinceNS {
		return true
	}
	return progress.open && progress.startNS >= sinceNS && progress.cursorNS >= untilNS
}

// AnalysisBackfillCovered reports whether an insights backfill pass that
// began at or after sinceNS has attempted every parsed audit without a
// current analysis that started before untilNS. Audits still without an
// analysis after that were skipped or failed; waiting longer does not help.
// It is false while no analyzer is installed.
func (worker *Worker) AnalysisBackfillCovered(untilNS, sinceNS int64) bool {
	if worker == nil || worker.auditAnalyzer() == nil {
		return false
	}
	return worker.backfillProgress.covered(untilNS, sinceNS)
}
