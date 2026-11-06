package sessionanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

// Store is the storage surface of the batch runner.
type Store interface {
	ListSessionCandidates(ctx context.Context, sinceNS, quietBeforeNS, signalVersion int64, limit int) ([]storage.SessionCandidate, error)
	LoadSessionAudits(ctx context.Context, sessionKey []byte) ([]storage.SessionAuditRow, bool, error)
	SaveSessionSignals(ctx context.Context, signals storage.SessionSignals, fprs []storage.SessionTextFPR) error
	PruneSessionAnalysis(ctx context.Context, fingerprintCutoffNS int64) (int64, error)
	RecordSessionAnalysisRun(ctx context.Context, run storage.SessionAnalysisRun) error
}

// Run triggers.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
)

// ErrRunInProgress is returned when a manual run overlaps another run.
var ErrRunInProgress = errors.New("sessionanalysis: a run is already in progress")

const (
	maxLookback         = 14 * 24 * time.Hour
	maxCandidatesPerRun = 5000
	sessionTimeout      = 2 * time.Minute
	fingerprintKeep     = 180 * 24 * time.Hour
)

// Options assemble a Runner.
type Options struct {
	Config        config.SessionAnalysisConfig
	RetentionDays int
	Store         Store
	Loader        ConversationLoader
	Vocabulary    *Vocabulary
	Insights      *insights.Vocabulary
	Fingerprints  Fingerprinter
	Location      *time.Location
	Logger        *slog.Logger
	Now           func() time.Time
}

// Runner is the daily batch (doc 24 sections 5 and 7).
type Runner struct {
	options  Options
	hour     int
	minute   int
	running  atomic.Bool
	trigger  chan struct{}
	stop     context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

// NewRunner validates the options.
func NewRunner(options Options) (*Runner, error) {
	if options.Store == nil || options.Loader == nil || options.Vocabulary == nil || options.Insights == nil || options.Fingerprints == nil {
		return nil, errors.New("sessionanalysis: runner needs store, loader, vocabularies and fingerprinter")
	}
	hour, minute, err := config.ParseRunAt(options.Config.RunAt)
	if err != nil {
		return nil, err
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
	return &Runner{options: options, hour: hour, minute: minute, trigger: make(chan struct{}, 1)}, nil
}

// Start runs the schedule loop until ctx ends or Close is called.
func (runner *Runner) Start(ctx context.Context) {
	if runner == nil {
		return
	}
	loopContext, cancel := context.WithCancel(ctx)
	runner.stop = cancel
	runner.done = make(chan struct{})
	go func() {
		defer close(runner.done)
		for {
			wait := runner.untilNextRun()
			timer := time.NewTimer(wait)
			trigger := TriggerSchedule
			select {
			case <-loopContext.Done():
				timer.Stop()
				return
			case <-runner.trigger:
				timer.Stop()
				trigger = TriggerManual
			case <-timer.C:
			}
			if _, err := runner.RunOnce(loopContext, trigger); err != nil && !errors.Is(err, ErrRunInProgress) && loopContext.Err() == nil {
				runner.options.Logger.Warn("session analysis run failed", "error_category", "session_analysis_failed")
			}
		}
	}()
}

// Close stops the loop and waits for it.
func (runner *Runner) Close() {
	if runner == nil || runner.stop == nil {
		return
	}
	runner.stopOnce.Do(func() {
		runner.stop()
		<-runner.done
	})
}

// TriggerNow asks the loop to run as soon as possible.
func (runner *Runner) TriggerNow() error {
	if runner == nil {
		return errors.New("sessionanalysis: runner unavailable")
	}
	if runner.running.Load() {
		return ErrRunInProgress
	}
	select {
	case runner.trigger <- struct{}{}:
	default:
	}
	return nil
}

// Running reports whether a run is in progress.
func (runner *Runner) Running() bool {
	return runner != nil && runner.running.Load()
}

func (runner *Runner) untilNextRun() time.Duration {
	now := runner.options.Now().In(runner.options.Location)
	next := time.Date(now.Year(), now.Month(), now.Day(), runner.hour, runner.minute, 0, 0, runner.options.Location)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next.Sub(now)
}

func (runner *Runner) lookback() time.Duration {
	lookback := maxLookback
	if days := runner.options.RetentionDays; days > 0 && time.Duration(days)*24*time.Hour < lookback {
		lookback = time.Duration(days) * 24 * time.Hour
	}
	return lookback
}

// RunOnce analyses every due session once. It never overlaps itself.
func (runner *Runner) RunOnce(ctx context.Context, trigger string) (storage.SessionAnalysisRun, error) {
	if !runner.running.CompareAndSwap(false, true) {
		return storage.SessionAnalysisRun{}, ErrRunInProgress
	}
	defer runner.running.Store(false)
	options := runner.options
	started := options.Now()
	run := storage.SessionAnalysisRun{StartedAtNS: started.UnixNano(), Trigger: trigger}
	reasons := map[string]int64{}
	finish := func(category string) (storage.SessionAnalysisRun, error) {
		run.FinishedAtNS = options.Now().UnixNano()
		run.ErrorCategory = category
		encoded, _ := json.Marshal(reasons)
		run.SkipReasons = string(encoded)
		recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := options.Store.RecordSessionAnalysisRun(recordContext, run); err != nil {
			options.Logger.Warn("session analysis run summary not saved", "error_category", "session_analysis_record_failed")
		}
		return run, nil
	}

	pruned, err := options.Store.PruneSessionAnalysis(ctx, started.Add(-fingerprintKeep).UnixNano())
	if err != nil {
		finish("prune_failed")
		return run, err
	}
	run.Pruned = pruned
	idle := time.Duration(options.Config.SessionIdleMinutes) * time.Minute
	candidates, err := options.Store.ListSessionCandidates(ctx, started.Add(-runner.lookback()).UnixNano(), started.Add(-idle).UnixNano(), SignalVersion, maxCandidatesPerRun)
	if err != nil {
		finish("candidates_failed")
		return run, err
	}
	run.Candidates = int64(len(candidates))
	thresholds := Thresholds{MinUserTurns: options.Config.MinUserTurns, MinActiveSeconds: options.Config.MinActiveSeconds}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			finish("canceled")
			return run, err
		}
		reason, err := runner.analyzeOne(ctx, candidate.SessionKey, thresholds)
		if err != nil {
			run.Skipped++
			reasons["error"]++
			continue
		}
		run.Analyzed++
		if reason != "" {
			reasons[reason]++
		}
	}
	options.Logger.Info("session analysis run completed",
		"candidates", run.Candidates, "analyzed", run.Analyzed, "skipped", run.Skipped,
		"duration_ms", options.Now().Sub(started).Milliseconds())
	return finish("")
}

func (runner *Runner) analyzeOne(ctx context.Context, key []byte, thresholds Thresholds) (string, error) {
	options := runner.options
	sessionContext, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	rows, truncated, err := options.Store.LoadSessionAudits(sessionContext, key)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", errors.New("sessionanalysis: session vanished")
	}
	session, err := BuildSession(sessionContext, key, rows, truncated, options.Loader, options.Vocabulary, options.Insights)
	if err != nil {
		return "", err
	}
	signals, fprs := ComputeSignals(session, options.Vocabulary, options.Fingerprints, thresholds, options.Now())
	if err := options.Store.SaveSessionSignals(sessionContext, signals, fprs); err != nil {
		return "", err
	}
	return signals.SkipReason, nil
}
