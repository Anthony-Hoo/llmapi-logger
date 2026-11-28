package runner

import (
	"context"
	"errors"
	"sort"
	"time"

	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// failure is why a run failed: a stable reason code, and the cause, which
// may hold paths and is never logged.
type failure struct {
	reason string
	err    error
	// auditID names the one member a sample mismatch is attributed to.
	auditID string
	// hotUnreadable marks a sample_failed that says nothing about the
	// bundle: the hot side could not be read for the comparison (J.3).
	hotUnreadable bool
}

// isHotUnreadable reports whether err is a sample that could not compare
// because the hot side could not be read.
func isHotUnreadable(err error) bool {
	var target *failure
	return errors.As(err, &target) && target.hotUnreadable
}

func (failure *failure) Error() string { return "archive runner: " + failure.reason }
func (failure *failure) Unwrap() error { return failure.err }

func fail(reason string, err error) error {
	if code := bundle.ReasonOf(err); code != "" && reason == "" {
		reason = code
	}
	if reason == "" {
		reason = "archive_failed"
	}
	return &failure{reason: reason, err: err}
}

// reasonOf is the stable reason code of a run error.
func reasonOf(err error) string {
	var target *failure
	if errors.As(err, &target) {
		return target.reason
	}
	if code := bundle.ReasonOf(err); code != "" {
		return code
	}
	return "archive_failed"
}

// errCrash is what a Step hook turns into: the run stops where it is.
var errCrash = errors.New("archive runner: stopped at a step")

// run is one run's state.
type run struct {
	runner    *Runner
	ctx       context.Context
	id        string
	started   time.Time
	cutoffNS  int64
	deadline  time.Time
	watermark *storage.ArchivePosition
	result    Result

	// lookback holds the deferred audits still to look at again this run
	// (B.1: once per run, H.4); staleAfter and staleDone page the stale
	// members to re-include (archive_then_delete only, P item 8).
	lookback   []string
	staleAfter string
	staleDone  bool
	// segmentIndex numbers the segments of each bundle across passes.
	segmentIndex map[string]int
	// held are the members reconciliation found reading back differently
	// with an unchanged change stamp: no pass of this run selects them, and
	// the first pass records them deferred (export_failed). unrecorded lists
	// those the first pass has still to record.
	held       map[string]bool
	unrecorded []string
}

// holdMismatch defers a member of a publishing segment that reconciliation
// voided because it reads back differently (H.6 item 1, J.3), as the normal
// path does (pass.exclude): the other members are exported again by the
// passes of this run without it.
func (current *run) holdMismatch(auditID string) {
	if current.held == nil {
		current.held = map[string]bool{}
	}
	if current.held[auditID] {
		return
	}
	current.held[auditID] = true
	current.unrecorded = append(current.unrecorded, auditID)
	current.result.Excluded++
	current.result.SampleMismatched++
	current.options().Logger.Warn("archive sample mismatch", "error_category", "archive_sample_mismatch", "reason", "sample_mismatch")
}

func (current *run) options() Options { return current.runner.options }

func (current *run) now() time.Time { return current.runner.options.Now() }

func (current *run) step(name string) error {
	if hook := current.runner.options.Step; hook != nil {
		if err := hook(name); err != nil {
			return errCrash
		}
	}
	return nil
}

// execute is the body of a run (H.2): reconcile, passes, gaps, and the seam
// for the removal phase.
func (current *run) execute() error {
	if err := current.reconcile(); err != nil {
		return err
	}
	if err := current.loadLookback(); err != nil {
		return err
	}
	current.staleDone = current.options().Mode != storage.ArchiveModeArchiveThenDelete
	for pass := 0; ; pass++ {
		if err := current.ctx.Err(); err != nil {
			return err
		}
		if pass > 0 && !current.now().Before(current.deadline) {
			current.result.DeadlineReached = true
			break
		}
		more, err := current.pass()
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}
	if !current.result.DeadlineReached && !current.now().Before(current.deadline) {
		current.result.DeadlineReached = true
	}
	if !current.result.DeadlineReached {
		if err := current.gaps(); err != nil {
			return err
		}
	}
	// H.2: removal follows once the passes have ended or the deadline was
	// reached, over every segment sealed so far.
	return current.removalPhase()
}

// removalPhase is the removal of design M: in archive_then_delete, after
// every pass of the run has sealed its segments, remove the sealed members
// of the sealed segments of format version 1 or later in the order of M.2,
// then the exported gaps (P item 16). Members left sealed by an earlier run
// are among them, which continues what H.6 item 4 finds. export_only never
// removes anything.
func (current *run) removalPhase() error {
	if current.options().Mode != storage.ArchiveModeArchiveThenDelete {
		return nil
	}
	return current.remove()
}

// loadLookback reads the ids of every deferred audit.
func (current *run) loadLookback() error {
	after := ""
	for {
		page, err := current.options().Store.Deferred(current.ctx, after, listPage)
		if err != nil {
			return fail("catalog_failed", err)
		}
		for _, row := range page {
			current.lookback = append(current.lookback, row.AuditID)
		}
		if len(page) < listPage {
			return nil
		}
		after = page[len(page)-1].AuditID
	}
}

// exported is one audit read for a segment.
type exported struct {
	candidate storage.ArchiveCandidate
	export    *Export
}

// memberInfo is what the intent needs of a member besides the manifest.
type memberInfo struct {
	digest      [32]byte
	stamp       [32]byte
	turnCreated *int64
}

// pass is one pass: one snapshot, the audits selected in it and the
// segments written from them.
type pass struct {
	run      *run
	snapshot Snapshot
	buckets  map[string]*sink
	sinks    []*sink
	deferred map[string]string
	resolved map[string]bool
	exported []string
}

// pass runs one pass (H.2) and reports whether more may be due.
func (current *run) pass() (bool, error) {
	options := current.options()
	snapshot, err := options.Store.OpenSnapshot(current.ctx)
	if err != nil {
		return false, current.snapshotFailure(err)
	}
	defer snapshot.Close()
	work := &pass{run: current, snapshot: snapshot, buckets: map[string]*sink{}, deferred: map[string]string{}, resolved: map[string]bool{}}
	for _, id := range current.unrecorded {
		work.deferred[id] = storage.ArchiveDeferredExportFailed
	}
	current.unrecorded = nil

	budget := options.PassAudits
	var looked []storage.ArchiveCandidate
	if count := min(budget, len(current.lookback)); count > 0 {
		ids := current.lookback[:count]
		current.lookback = current.lookback[count:]
		candidates, err := snapshot.Candidates(ids, current.runner.formatVersion)
		if err != nil {
			return false, current.snapshotFailure(err)
		}
		present := map[string]bool{}
		for _, candidate := range candidates {
			present[candidate.AuditID] = true
		}
		for _, id := range ids {
			if !present[id] {
				work.resolved[id] = true // no longer in the hot store
			}
		}
		for _, candidate := range candidates {
			// Looked at by id, not through the cutoff-bounded page: an audit
			// that would be due but is younger than the current cutoff
			// (retention_days raised since it was deferred) is not exported,
			// and its deferred row stays as it is, since the watermark has
			// passed it.
			if candidate.Due() && candidate.StartedAtNS >= current.cutoffNS {
				continue
			}
			looked = append(looked, candidate)
		}
		budget -= count
	}
	if !current.staleDone && budget > 0 && len(current.lookback) == 0 {
		stale, err := snapshot.StaleCandidates(current.cutoffNS, current.runner.formatVersion, current.staleAfter, budget)
		if err != nil {
			return false, current.snapshotFailure(err)
		}
		if len(stale) < budget {
			current.staleDone = true
		}
		if len(stale) > 0 {
			current.staleAfter = stale[len(stale)-1].AuditID
		}
		looked = append(looked, stale...)
		budget -= len(stale)
	}
	var page storage.ArchiveDuePage
	queried := budget > 0
	if queried {
		if page, err = snapshot.Due(current.watermark, current.cutoffNS, current.runner.formatVersion, budget); err != nil {
			return false, current.snapshotFailure(err)
		}
		looked = append(looked, page.Candidates...)
	}
	more := len(current.lookback) > 0 || !current.staleDone || !queried || page.More

	selected := map[string]storage.ArchiveCandidate{}
	conversations := map[string]bool{}
	for _, candidate := range looked {
		if work.classify(candidate, selected) && candidate.ConversationID != nil {
			conversations[*candidate.ConversationID] = true
		}
	}
	// B.2: complete the conversations the pass touches.
	if len(conversations) > 0 {
		ids := make([]string, 0, len(conversations))
		for id := range conversations {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		completion, err := snapshot.ConversationCandidates(ids, current.cutoffNS, current.runner.formatVersion)
		if err != nil {
			return false, current.snapshotFailure(err)
		}
		for _, candidate := range completion {
			if _, done := selected[candidate.AuditID]; done {
				continue
			}
			if _, done := work.deferred[candidate.AuditID]; done {
				continue
			}
			work.classify(candidate, selected)
		}
	}

	if err := work.write(selected); err != nil {
		if !errors.Is(err, errCrash) {
			work.abort()
		}
		return false, err
	}
	if err := current.step(StepBeforeRecordPass); err != nil {
		return false, err
	}
	var watermark *storage.ArchivePosition
	if queried && page.Last != nil {
		watermark = page.Last
	}
	if err := work.record(watermark); err != nil {
		return false, err
	}
	if watermark != nil {
		current.watermark = watermark
	}
	return more, nil
}

// snapshotFailure is the run error of a failed snapshot query.
func (current *run) snapshotFailure(err error) error {
	if current.ctx.Err() != nil {
		return current.ctx.Err()
	}
	return fail("snapshot_failed", err)
}

// classify sorts one candidate: due ones into selected (true), deferred ones
// into the pass's deferrals, current ones (already archived) out. A member
// reconciliation held back is left out altogether: the first pass records
// its deferral.
func (work *pass) classify(candidate storage.ArchiveCandidate, selected map[string]storage.ArchiveCandidate) bool {
	switch {
	case work.run.held[candidate.AuditID]:
		return false
	case candidate.Current:
		work.resolved[candidate.AuditID] = true
		return false
	case candidate.Deferral != "":
		work.deferred[candidate.AuditID] = candidate.Deferral
		return false
	}
	selected[candidate.AuditID] = candidate
	return true
}

// export reads one audit; an exclusion is recorded and returns nil.
func (work *pass) export(candidate storage.ArchiveCandidate) (*exported, error) {
	current := work.run
	if err := current.ctx.Err(); err != nil {
		return nil, err
	}
	result, err := work.snapshot.Export(candidate.AuditID, candidate.NextRevision)
	if err == nil {
		return &exported{candidate: candidate, export: result}, nil
	}
	var exclusion *Exclusion
	if !errors.As(err, &exclusion) {
		return nil, current.snapshotFailure(err)
	}
	switch {
	case exclusion.Reason == postgres.ArchiveReasonNotFound:
		work.resolved[candidate.AuditID] = true
		return nil, nil
	case exclusion.Reason == postgres.ArchiveReasonOpen:
		work.deferred[candidate.AuditID] = storage.ArchiveDeferredOpen
	case exclusion.Integrity:
		// H.4: stays in the hot store, retried every run. The store has
		// already set its payload state to failed (P item 4).
		work.deferred[candidate.AuditID] = storage.ArchiveDeferredIntegrityFailed
		current.result.Counts.IntegrityFailedAudits++
		current.options().Logger.Error("archive integrity check failed",
			"error_category", "archive_integrity_failed", "reason", exclusion.Reason)
	default:
		work.deferred[candidate.AuditID] = storage.ArchiveDeferredExportFailed
	}
	current.result.Excluded++
	return nil, nil
}

// record ends a pass whose segments are all sealed (R.6 item 3): the
// watermark, the counters, the deferred audits and the resolved ones.
func (work *pass) record(watermark *storage.ArchivePosition) error {
	current := work.run
	nowNS := current.now().UnixNano()
	deferred := make([]storage.ArchiveDeferred, 0, len(work.deferred))
	for id, reason := range work.deferred {
		deferred = append(deferred, storage.ArchiveDeferred{AuditID: id, Reason: reason, FirstSeenAtNS: nowNS, LastCheckedAtNS: nowNS})
	}
	sort.Slice(deferred, func(left, right int) bool { return deferred[left].AuditID < deferred[right].AuditID })
	for _, id := range work.exported {
		work.resolved[id] = true
	}
	resolved := make([]string, 0, len(work.resolved))
	for id := range work.resolved {
		if _, again := work.deferred[id]; !again {
			resolved = append(resolved, id)
		}
	}
	sort.Strings(resolved)
	counts := current.result.Counts
	counts.DeferredAudits += int64(len(deferred))
	if err := current.options().Store.RecordPass(current.ctx, storage.ArchivePass{
		RunID: current.id, Watermark: watermark, Counts: &counts, Deferred: deferred, Resolved: resolved,
	}); err != nil {
		if current.ctx.Err() != nil {
			return current.ctx.Err()
		}
		return fail("catalog_failed", err)
	}
	current.result.Counts.DeferredAudits = counts.DeferredAudits
	for _, row := range deferred {
		current.result.Deferred[row.Reason]++
	}
	return nil
}
