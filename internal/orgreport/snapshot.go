package orgreport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// WeeklySnapshot is one materialized week (org_weekly_stats). It survives
// retention: the table has no foreign key to audits. ProjectNames keeps the
// names projects had when the snapshot was taken.
type WeeklySnapshot struct {
	Week          string
	FrozenAtNS    int64
	GeneratedAtNS int64
	Result        WeekResult
	ProjectNames  map[int64]string
}

// SnapshotStore persists weekly snapshots. Save replaces the whole week.
type SnapshotStore interface {
	SaveWeeklySnapshot(ctx context.Context, snapshot WeeklySnapshot) error
	LoadWeeklySnapshot(ctx context.Context, week string) (WeeklySnapshot, bool, error)
	// CountOrgPendingAudits counts the audits of [fromNS, toNS) a week still
	// waits for. A week is frozen only once nothing is pending.
	CountOrgPendingAudits(ctx context.Context, fromNS, toNS int64, identityVersion int) (PendingAudits, error)
}

// PendingAudits are the audits of one week that are not ready yet.
type PendingAudits struct {
	// Pending are still waiting for the parser, or analysed without a current
	// project identity.
	Pending int
	// Unanalysed are parsed and ended but have no analysis. The analysis
	// backfill picks them up, or skips them for good (no body left, no
	// parser); only its progress tells which.
	Unanalysed int
}

// AnalysisProgress reports the insights backfill's progress.
type AnalysisProgress interface {
	// AnalysisBackfillCovered reports whether a backfill pass that began at
	// or after sinceNS has attempted every unanalysed audit that started
	// before untilNS.
	AnalysisBackfillCovered(untilNS, sinceNS int64) bool
}

const (
	// freezeGrace waits after a week ends before freezing it, so late
	// parsing, caller resolution and billing lookups land first.
	freezeGrace = 2 * time.Hour
	// freezeLookbackWeeks is how many ended weeks the job checks; five
	// covers the default 30-day retention.
	freezeLookbackWeeks = 5
	// freezeCheckInterval rate-limits the idle-task check.
	freezeCheckInterval = 10 * time.Minute
	// freezeDeadline freezes a week even with pending audits, so a stuck
	// backfill can never let retention delete the evidence first.
	freezeDeadline = 72 * time.Hour
	// freezeTimeout bounds one background snapshot.
	freezeTimeout = 5 * time.Minute
	// liveCacheTTL bounds how long a computed live week is reused.
	liveCacheTTL = time.Minute
)

// snapshotJob guards the background freeze goroutine and the live cache.
type snapshotJob struct {
	running   atomic.Bool
	nextCheck atomic.Int64
	wait      sync.WaitGroup

	cacheMu sync.Mutex
	cache   map[string]cachedWeek

	// weekLocks serialise the snapshot writes of one week (the background
	// freeze, the web's Regenerate and the agent's RegenerateIfVersion), so a
	// check of the week's stored snapshot and the write that replaces it are
	// one step. Writes to different weeks do not wait for each other. Waiting
	// gives up when the caller's context ends.
	weekLocks weekLocks
	// stampMu guards lastStampNS, the last snapshot time written: a new
	// snapshot is stamped above it, so two writes never leave the same
	// generated_at even when the clock repeats a reading.
	stampMu     sync.Mutex
	lastStampNS int64
}

// weekLocks is a keyed lock: one lock per week label, created when the first
// writer of that week arrives and dropped when the last one leaves (it got
// the lock and released it, or gave up waiting). The zero value is ready.
type weekLocks struct {
	mu    sync.Mutex
	locks map[string]*weekLock
}

// weekLock is a mutex whose acquisition honours a context, and the count of
// writers holding or waiting for it.
type weekLock struct {
	slot  chan struct{}
	users int
}

// lock acquires the week's lock and returns its release, or returns ctx's
// error once ctx ends first; a caller that gives up leaves no entry behind.
func (locks *weekLocks) lock(ctx context.Context, week string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locks.mu.Lock()
	if locks.locks == nil {
		locks.locks = map[string]*weekLock{}
	}
	entry, ok := locks.locks[week]
	if !ok {
		entry = &weekLock{slot: make(chan struct{}, 1)}
		locks.locks[week] = entry
	}
	entry.users++
	locks.mu.Unlock()
	select {
	case entry.slot <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-entry.slot
				locks.leave(week, entry)
			})
		}, nil
	case <-ctx.Done():
		locks.leave(week, entry)
		return nil, ctx.Err()
	}
}

// leave drops one writer of week and the entry with the last one.
func (locks *weekLocks) leave(week string, entry *weekLock) {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	entry.users--
	if entry.users == 0 && locks.locks[week] == entry {
		delete(locks.locks, week)
	}
}

// size is the number of weeks with a writer holding or waiting (tests).
func (locks *weekLocks) size() int {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	return len(locks.locks)
}

// ErrNotStarted marks a regeneration that gave up before it began: it waited
// for its week's snapshot lock until its context ended, and nothing was computed or
// written. The error also matches the context's error.
var ErrNotStarted = errors.New("orgreport: regeneration did not start")

// notStarted wraps the context error of a lock wait that gave up.
func notStarted(err error) error { return fmt.Errorf("%w: %w", ErrNotStarted, err) }

type cachedWeek struct {
	compiled *Compiled
	// settings is the settings value the week was computed with; a saved
	// change replaces the pointer, so an older result is never reused.
	settings *Settings
	at       time.Time
	result   WeekResult
}

// SnapshotTick is the parser-worker idle task: at most every ten minutes it
// looks for ended weeks without a snapshot and freezes the oldest one in a
// background goroutine. It never blocks the parser goroutine.
func (service *Service) SnapshotTick(ctx context.Context) {
	if service == nil || service.snapshots == nil || service.data == nil {
		return
	}
	now := service.now()
	if now.UnixNano() < service.job.nextCheck.Load() {
		return
	}
	service.job.nextCheck.Store(now.Add(freezeCheckInterval).UnixNano())
	if !service.job.running.CompareAndSwap(false, true) {
		return
	}
	service.job.wait.Add(1)
	go func() {
		defer service.job.wait.Done()
		defer service.job.running.Store(false)
		jobContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), freezeTimeout)
		defer cancel()
		go func() {
			select {
			case <-ctx.Done():
				cancel()
			case <-jobContext.Done():
			}
		}()
		service.freezePending(jobContext, now)
	}()
}

// WaitSnapshots waits for a running freeze goroutine (tests and shutdown).
func (service *Service) WaitSnapshots() { service.job.wait.Wait() }

// freezePending freezes every ended week inside the lookback that has no
// snapshot yet and whose evidence is fully analysed, oldest first.
func (service *Service) freezePending(ctx context.Context, now time.Time) {
	current := service.settingsNow().WeekOf(now)
	weeks := make([]Week, 0, freezeLookbackWeeks)
	week := current.Previous()
	for index := 0; index < freezeLookbackWeeks; index++ {
		weeks = append([]Week{week}, weeks...)
		week = week.Previous()
	}
	for _, candidate := range weeks {
		if ctx.Err() != nil {
			return
		}
		if now.Before(candidate.End.Add(freezeGrace)) {
			continue
		}
		_, exists, err := service.snapshots.LoadWeeklySnapshot(ctx, candidate.Label())
		if err != nil {
			service.logger.Warn("org snapshot check failed", "error_code", "org_snapshot_failed", "reason", "load_failed")
			return
		}
		if exists {
			continue
		}
		counts, err := service.snapshots.CountOrgPendingAudits(ctx, candidate.Start.UnixNano(), candidate.End.UnixNano(), service.identityVersion)
		if err != nil {
			service.logger.Warn("org snapshot check failed", "error_code", "org_snapshot_failed", "reason", "pending_count_failed")
			return
		}
		pending := counts.Pending
		// Unanalysed audits wait for one backfill pass that began after the
		// week ended to reach past it; whatever is still unanalysed then was
		// skipped or failed and no longer holds the week.
		if counts.Unanalysed > 0 && (service.progress == nil ||
			!service.progress.AnalysisBackfillCovered(candidate.End.UnixNano(), candidate.End.Add(freezeGrace).UnixNano())) {
			pending += counts.Unanalysed
		}
		if pending > 0 && now.Before(candidate.End.Add(freezeDeadline)) {
			// Older weeks first: a later week must not freeze before an
			// earlier one is complete.
			return
		}
		if pending > 0 {
			service.logger.Warn("org snapshot frozen with pending audits", "error_code", "org_snapshot_incomplete", "week", candidate.Label(), "count", pending)
		}
		if err := service.freeze(ctx, candidate); err != nil {
			service.logger.Warn("org snapshot failed", "error_code", "org_snapshot_failed", "reason", "freeze_failed", "week", candidate.Label())
			return
		}
		service.logger.Info("org weekly snapshot frozen", "week", candidate.Label())
	}
}

// freeze computes and stores one week.
func (service *Service) freeze(ctx context.Context, week Week) error {
	unlock, err := service.job.weekLocks.lock(ctx, week.Label())
	if err != nil {
		return notStarted(err)
	}
	defer unlock()
	return service.freezeLocked(ctx, week)
}

// freezeLocked is freeze with the week's lock held.
func (service *Service) freezeLocked(ctx context.Context, week Week) error {
	result, compiled, err := service.compute(ctx, week, service.settings.Load())
	if err != nil {
		return err
	}
	now := service.nextStamp()
	snapshot := WeeklySnapshot{Week: week.Label(), FrozenAtNS: now, GeneratedAtNS: now, Result: result, ProjectNames: projectNames(result, compiled)}
	if err := service.snapshots.SaveWeeklySnapshot(ctx, snapshot); err != nil {
		return err
	}
	service.forget(week.Label())
	return nil
}

// nextStamp returns a snapshot time above every one handed out before. It
// is reserved before the save, so a failed save leaves a gap and never a
// repeat.
func (service *Service) nextStamp() int64 {
	service.job.stampMu.Lock()
	defer service.job.stampMu.Unlock()
	stamp := max(service.now().UnixNano(), service.job.lastStampNS+1)
	service.job.lastStampNS = stamp
	return stamp
}

// Regenerate recomputes an ended week from the evidence still retained and
// replaces its snapshot. The current week is never frozen.
func (service *Service) Regenerate(ctx context.Context, label string) error {
	if service.snapshots == nil {
		return ErrUnavailable
	}
	week, err := service.resolveWeek(label)
	if err != nil {
		return err
	}
	if !service.now().After(week.End) {
		return ErrInvalid
	}
	return service.freeze(ctx, week)
}

// compute loads a week with its margins, attributes it and runs the engine
// with one settings value.
func (service *Service) compute(ctx context.Context, week Week, settings *Settings) (WeekResult, *Compiled, error) {
	attributed, err := service.load(ctx, week.Start.Add(-loadMargin).UnixNano(), week.End.Add(loadMargin).UnixNano())
	if err != nil {
		return WeekResult{}, nil, err
	}
	result := ComputeWeek(WeekInput{Week: week, Settings: *settings, Requests: attributed.Requests, Principals: attributed.Compiled.Principals()})
	return result, attributed.Compiled, nil
}

// live returns a computed (unfrozen) week, reusing a result computed less
// than a minute ago with the same catalog snapshot and the same settings.
func (service *Service) live(ctx context.Context, week Week) (WeekResult, *Compiled, error) {
	compiled := service.current.Load()
	settings := service.settings.Load()
	label := week.Label()
	service.job.cacheMu.Lock()
	if cached, ok := service.job.cache[label]; ok && cached.compiled == compiled && cached.settings == settings && service.now().Sub(cached.at) < liveCacheTTL {
		service.job.cacheMu.Unlock()
		return cached.result, compiled, nil
	}
	service.job.cacheMu.Unlock()
	result, used, err := service.compute(ctx, week, settings)
	if err != nil {
		return WeekResult{}, nil, err
	}
	service.job.cacheMu.Lock()
	if service.job.cache == nil {
		service.job.cache = map[string]cachedWeek{}
	}
	if len(service.job.cache) > 16 {
		service.job.cache = map[string]cachedWeek{}
	}
	service.job.cache[label] = cachedWeek{compiled: used, settings: settings, at: service.now(), result: result}
	service.job.cacheMu.Unlock()
	return result, used, nil
}

func (service *Service) forget(label string) {
	service.job.cacheMu.Lock()
	delete(service.job.cache, label)
	service.job.cacheMu.Unlock()
}

func projectNames(result WeekResult, compiled *Compiled) map[int64]string {
	names := map[int64]string{}
	for _, row := range result.Users {
		for _, cell := range row.Projects {
			if cell.Project > 0 {
				names[int64(cell.Project)] = compiled.ProjectName(int64(cell.Project))
			}
		}
	}
	return names
}
