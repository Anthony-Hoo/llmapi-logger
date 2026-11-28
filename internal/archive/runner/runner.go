// Package runner is the scheduled cold archive pass
// (doc/design/issue-59-stage4-cold-archive.md, sections B, H and J.3): once a
// day it reconciles the archive directory with the catalog, then exports the
// audits retention would delete, in passes of one export snapshot each, into
// conversation and bucket bundles, re-reads and samples every bundle before
// it is sealed in the catalog, and exports the expired gaps.
//
// This build step only exports. In archive_then_delete the run does exactly
// what export_only does; removal (design M, the P4 package) is a phase after
// the passes, see Runner.removalPhase.
package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	mathrand "math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/retention"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Defaults of the options that the configuration does not carry.
const (
	// DefaultRetryDelay is the wait before a failed run is tried again,
	// within the run deadline (H.4, P item 3).
	DefaultRetryDelay = 10 * time.Minute
	// catchUpAge is how old the last completed run may be before a start
	// schedules one at once (H.1).
	catchUpAge = 24 * time.Hour
	// gapBundleLimit bounds the gaps of one gap bundle; a gap row is small.
	gapBundleLimit = 10000
)

// ErrRunInProgress is returned when a run overlaps another.
var ErrRunInProgress = errors.New("archive runner: a run is already in progress")

// Options assemble a Runner. Mode is storage.ArchiveModeExportOnly or
// storage.ArchiveModeArchiveThenDelete.
type Options struct {
	Mode                 string
	Dir                  string
	Encrypt              bool
	RunAt                string
	Location             *time.Location
	RetentionDays        int
	SegmentMaxBytes      int64
	ConversationMinTurns int
	ConversationMinBytes int64
	PassAudits           int
	RunDeadline          time.Duration
	VerifySample         float64
	// RetryDelay is the wait after a failed run; zero is DefaultRetryDelay.
	RetryDelay time.Duration

	Store Store
	// Keys sign and encrypt the bundles and fingerprint credentials.
	Keys *security.ArchiveKeys
	// Events, when set, checks the copied integrity events' MACs when a
	// bundle is re-read (J.2 item 7).
	Events bundle.EventVerifier
	// Sampler compares sampled members with the hot store (J.3).
	Sampler Sampler
	// SourceSchemaVersion is the hot database's migration version.
	SourceSchemaVersion string
	Logger              *slog.Logger
	Now                 func() time.Time

	// Fault is passed to the bundle writer (bundle.Options.Fault).
	Fault func(operation, path string) error
	// Step, when set, is called at the named points of a segment's
	// publication (StepAfterIntent and the others); a non-nil result stops
	// the run there as a crash would: nothing is cleaned up and the run is
	// not finished. Tests use it to drive reconciliation.
	Step func(step string) error
	// Random returns a number in [0, 1) for the sample; nil uses math/rand.
	Random func() float64
	// FormatVersionOverride, when positive, replaces archive.FormatVersion
	// as the format version the run selects by and registers its segments
	// with. It exists for tests that drive the removal of format version 1
	// before the format is frozen; the bundles themselves still carry
	// archive.FormatVersion. Production never sets it.
	FormatVersionOverride int64
}

// Points of Options.Step.
const (
	StepAfterIntent      = "after_intent"
	StepAfterPublish     = "after_publish"
	StepBeforeSeal       = "before_seal"
	StepBeforeRecordPass = "before_record_pass"
	// StepBetweenRemovalBatches is reached after each committed removal
	// batch that is not the last, StepAfterRemoval after the last batch of
	// audits and gaps, before the run record is finished (M.3).
	StepBetweenRemovalBatches = "between_removal_batches"
	StepAfterRemoval          = "after_removal"
)

// Runner runs the archive once a day. It never runs twice at the same time.
type Runner struct {
	options       Options
	hour, minute  int
	formatVersion int64
	running       atomic.Bool
	// batcher sizes the removal batches (retention.Batcher); kept across
	// runs. pause leaves the writer alone after a batch.
	batcher  *retention.Batcher
	pause    func(context.Context, time.Duration)
	stop     context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

// New validates the options.
func New(options Options) (*Runner, error) {
	switch {
	case options.Mode != storage.ArchiveModeExportOnly && options.Mode != storage.ArchiveModeArchiveThenDelete:
		return nil, errors.New("archive runner: unknown mode")
	case options.Store == nil || options.Keys == nil || options.Sampler == nil:
		return nil, errors.New("archive runner: needs a store, the archive keys and a sampler")
	case options.Dir == "":
		return nil, errors.New("archive runner: needs the archive directory")
	case options.RetentionDays <= 0:
		return nil, errors.New("archive runner: needs retention_days")
	case options.PassAudits < 1 || options.PassAudits > config.MaxArchivePassAudits:
		return nil, errors.New("archive runner: invalid pass size")
	case options.ConversationMinTurns < 1 || options.ConversationMinBytes < 1 || options.SegmentMaxBytes < 1:
		return nil, errors.New("archive runner: invalid bundle thresholds")
	case options.RunDeadline <= 0 || !(options.VerifySample >= 0 && options.VerifySample <= 1):
		return nil, errors.New("archive runner: invalid deadline or sample rate")
	}
	hour, minute, err := config.ParseRunAt(options.RunAt)
	if err != nil {
		return nil, err
	}
	formatVersion, err := strconv.ParseInt(archive.FormatVersion, 10, 64)
	if err != nil {
		return nil, err
	}
	if options.FormatVersionOverride < 0 {
		return nil, errors.New("archive runner: invalid format version override")
	}
	if options.FormatVersionOverride > 0 {
		formatVersion = options.FormatVersionOverride
	}
	if options.Location == nil {
		options.Location = time.Local
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RetryDelay <= 0 {
		options.RetryDelay = DefaultRetryDelay
	}
	if options.Random == nil {
		options.Random = mathrand.Float64
	}
	if options.SourceSchemaVersion == "" {
		return nil, errors.New("archive runner: needs the source schema version")
	}
	return &Runner{options: options, hour: hour, minute: minute, formatVersion: formatVersion,
		batcher: retention.NewBatcher(), pause: retention.Wait}, nil
}

// Start runs the schedule until ctx ends or Close is called: a catch-up run
// at once when the last completed run is older than a day or there is none
// (H.1), then one run a day at run_at in the configured zone. A failed run is
// retried after RetryDelay while the run deadline of the day allows.
func (runner *Runner) Start(ctx context.Context) {
	if runner == nil {
		return
	}
	loop, cancel := context.WithCancel(ctx)
	runner.stop = cancel
	runner.done = make(chan struct{})
	go func() {
		defer close(runner.done)
		if runner.catchUpDue(loop) {
			runner.runDay(loop)
		}
		for {
			timer := time.NewTimer(runner.untilNextRun())
			select {
			case <-loop.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			runner.runDay(loop)
		}
	}()
}

// Close stops the schedule, cancelling a run in progress, and waits for it.
func (runner *Runner) Close() {
	if runner == nil || runner.stop == nil {
		return
	}
	runner.stopOnce.Do(func() {
		runner.stop()
		<-runner.done
	})
}

// catchUpDue reports whether the last completed run started more than a day
// ago or never happened. A catalog that cannot be read schedules the run:
// the run itself then reports the failure.
func (runner *Runner) catchUpDue(ctx context.Context) bool {
	last, err := runner.options.Store.LastCompletedRun(ctx)
	if err != nil {
		return ctx.Err() == nil
	}
	return last == nil || runner.options.Now().Sub(time.Unix(0, last.StartedAtNS)) > catchUpAge
}

// untilNextRun is sessionanalysis.Runner's algorithm: today's run_at in the
// zone, or tomorrow's once it has passed.
func (runner *Runner) untilNextRun() time.Duration {
	location := runner.options.Location
	now := runner.options.Now().In(location)
	next := time.Date(now.Year(), now.Month(), now.Day(), runner.hour, runner.minute, 0, 0, location)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next.Sub(now)
}

// runDay runs once and, after a failure, again every RetryDelay until a run
// completes or the next attempt would start past the run deadline counted
// from the first attempt (H.4).
func (runner *Runner) runDay(ctx context.Context) {
	first := runner.options.Now()
	deadline := first.Add(runner.options.RunDeadline)
	for {
		// A retry keeps the day's deadline, not a new one of its own.
		result, err := runner.runOnce(ctx, deadline)
		if err == nil && result.Status == storage.ArchiveRunCompleted || ctx.Err() != nil || errors.Is(err, errCrash) {
			return
		}
		if runner.options.Now().Add(runner.options.RetryDelay).Sub(first) >= runner.options.RunDeadline {
			return
		}
		timer := time.NewTimer(runner.options.RetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Result is what one run did.
type Result struct {
	RunID  string
	Status string
	// Reason is the stable reason code of a failed run.
	Reason       string
	Counts       storage.ArchiveRunCounts
	Excluded     int64
	ExportedGaps int64
	// Refused counts the members the bundle writer refused, SampleMismatched
	// those that read back differently from the hot store; both are deferred
	// export_failed and also in Excluded.
	Refused          int64
	SampleMismatched int64
	// Deferred counts the deferred audits by reason.
	Deferred         map[string]int64
	DeadlineReached  bool
	ReconciledSealed int64
	// Removal is what the removal phase did (archive_then_delete). The
	// removed audits and gaps are also in Counts, and the members it found
	// changed in Counts.StaleAudits.
	Removal  RemovalResult
	Duration time.Duration
}

// FormatVersion is the format version the runner selects by and registers
// segments with.
func (runner *Runner) FormatVersion() int64 { return runner.formatVersion }

// RunOnce runs the archive once (H.2): reconciliation, passes until nothing
// is due or the deadline passes, then the gaps. It returns the result of a
// finished run; a run stopped by ctx is left running in the catalog (the
// next run marks it interrupted and reconciles what it left) and returns
// ctx's error.
func (runner *Runner) RunOnce(ctx context.Context) (Result, error) {
	return runner.runOnce(ctx, time.Time{})
}

// runOnce is RunOnce with the run's deadline; zero is RunDeadline from now.
func (runner *Runner) runOnce(ctx context.Context, deadline time.Time) (Result, error) {
	if !runner.running.CompareAndSwap(false, true) {
		return Result{}, ErrRunInProgress
	}
	defer runner.running.Store(false)
	options := runner.options
	started := options.Now()
	runID, err := newID()
	if err != nil {
		return Result{}, err
	}
	if deadline.IsZero() {
		deadline = started.Add(options.RunDeadline)
	}
	current := &run{
		runner: runner, ctx: ctx, id: runID, started: started,
		cutoffNS:     started.Add(-time.Duration(options.RetentionDays) * 24 * time.Hour).UnixNano(),
		deadline:     deadline,
		result:       Result{RunID: runID, Deferred: map[string]int64{}},
		segmentIndex: map[string]int{},
	}
	watermark, err := options.Store.Watermark(ctx, runner.formatVersion)
	if err != nil {
		return runner.failedToStart(ctx, err)
	}
	current.watermark = watermark
	if _, err := options.Store.BeginRun(ctx, storage.ArchiveRun{
		RunID: runID, Mode: options.Mode, CutoffNS: current.cutoffNS, StartedAtNS: started.UnixNano(),
		Status: storage.ArchiveRunRunning, FormatVersion: runner.formatVersion, Watermark: watermark,
	}); err != nil {
		return runner.failedToStart(ctx, err)
	}
	runErr := current.execute()
	if errors.Is(runErr, errCrash) {
		return current.result, runErr
	}
	if ctx.Err() != nil {
		options.Logger.Warn("archive run interrupted", "error_category", "archive_interrupted",
			"exported_audits", current.result.Counts.ExportedAudits, "duration_ms", options.Now().Sub(started).Milliseconds())
		return current.result, ctx.Err()
	}
	current.result.Status = storage.ArchiveRunCompleted
	if runErr != nil {
		current.result.Status = storage.ArchiveRunFailed
		current.result.Reason = reasonOf(runErr)
	}
	current.result.Duration = options.Now().Sub(started)
	if err := options.Store.FinishRun(ctx, storage.ArchiveRunFinish{
		RunID: runID, FinishedAtNS: options.Now().UnixNano(), Status: current.result.Status, Counts: current.result.Counts,
	}); err != nil && runErr == nil {
		current.result.Status, current.result.Reason = storage.ArchiveRunFailed, "catalog_failed"
		runErr = err
	}
	current.logCompletion(runErr)
	return current.result, runErr
}

func (runner *Runner) failedToStart(ctx context.Context, err error) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	runner.options.Logger.Warn("archive run failed", "error_category", "archive_failed", "reason", "catalog_failed",
		"storage_error", storage.ErrorClass(err))
	return Result{Status: storage.ArchiveRunFailed, Reason: "catalog_failed"}, err
}

// logCompletion writes the completion line of a finished run (H.5): stable
// codes and counts only, no path, file name or audit content.
func (current *run) logCompletion(runErr error) {
	result := current.result
	attributes := []any{
		"status", result.Status,
		"exported_audits", result.Counts.ExportedAudits,
		"deferred_audits", result.Counts.DeferredAudits,
		"integrity_failed_audits", result.Counts.IntegrityFailedAudits,
		"excluded_audits", result.Excluded,
		"stale_audits", result.Counts.StaleAudits,
		"exported_gaps", result.ExportedGaps,
		"refused_audits", result.Refused,
		"sample_mismatch_audits", result.SampleMismatched,
		"segments", result.Counts.Segments,
		"disk_bytes", result.Counts.DiskBytes,
		"removed_audits", result.Counts.RemovedAudits,
		"removed_gaps", result.Counts.RemovedGaps,
		"duration_ms", result.Duration.Milliseconds(),
	}
	for _, reason := range deferralReasons {
		if count := result.Deferred[reason]; count > 0 {
			attributes = append(attributes, "deferred_"+reason, count)
		}
	}
	if removal := result.Removal; removal.BundleCheckFailedSegments > 0 {
		attributes = append(attributes, "bundle_check_failed_segments", removal.BundleCheckFailedSegments,
			"held_back_members", removal.HeldBackMembers, "held_back_gaps", removal.HeldBackGaps)
	}
	if result.ReconciledSealed > 0 {
		attributes = append(attributes, "reconciled_segments", result.ReconciledSealed)
	}
	if result.DeadlineReached {
		attributes = append(attributes, "deadline_reached", true)
	}
	logger := current.runner.options.Logger
	if runErr != nil {
		attributes = append(attributes, "error_category", "archive_failed", "reason", result.Reason)
		if class := storage.ErrorClass(runErr); class != "" && bundle.ReasonOf(runErr) == "" {
			attributes = append(attributes, "storage_error", class)
		}
		logger.Warn("archive run failed", attributes...)
		return
	}
	logger.Info("archive run completed", attributes...)
}

var deferralReasons = []string{
	storage.ArchiveDeferredOpen, storage.ArchiveDeferredParsePending, storage.ArchiveDeferredCallerPending,
	storage.ArchiveDeferredIntegrityFailed, storage.ArchiveDeferredExportFailed,
}

func newID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// sampleSize is the number of members to compare in a bundle of n: the
// rate's share rounded up, at least one (J.3).
func sampleSize(rate float64, n int) int {
	if n == 0 {
		return 0
	}
	size := int(math.Ceil(rate * float64(n)))
	return min(max(size, 1), n)
}
