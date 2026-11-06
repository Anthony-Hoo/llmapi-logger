package sessionanalysis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Store is the storage surface of the batch runner.
type Store interface {
	ListSessionCandidates(ctx context.Context, sinceNS, quietBeforeNS, signalVersion int64, limit int) ([]storage.SessionCandidate, error)
	LoadSessionAudits(ctx context.Context, sessionKey []byte) ([]storage.SessionAuditRow, bool, error)
	SaveSessionSignals(ctx context.Context, signals storage.SessionSignals, fprs []storage.SessionTextFPR) error
	PruneSessionAnalysis(ctx context.Context, fingerprintCutoffNS int64) (int64, error)
	RecordSessionAnalysisRun(ctx context.Context, run storage.SessionAnalysisRun) error
	SaveSessionPack(ctx context.Context, pack storage.SessionPack, members [][]byte) error
	ListChatDigestMembers(ctx context.Context, apiKeyFPR []byte, client string, fromNS, toNS int64, limit int) ([]storage.SessionSignals, error)
	ListFacetCandidates(ctx context.Context, settledBeforeNS int64, promptVersion, model string, limit int) ([]storage.SessionPack, error)
	SaveSessionFacet(ctx context.Context, facet storage.SessionFacet, fprs []storage.SessionTextFPR) error
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
	Cipher        security.Cipher
	// LLM is nil unless session_analysis.llm.enabled.
	LLM          Completer
	ClientLabels map[string]string
	Location     *time.Location
	Logger       *slog.Logger
	Now          func() time.Time
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
	if options.Store == nil || options.Loader == nil || options.Vocabulary == nil || options.Insights == nil || options.Fingerprints == nil || options.Cipher == nil {
		return nil, errors.New("sessionanalysis: runner needs store, loader, vocabularies, fingerprinter and cipher")
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
	digests := map[string]digestBucket{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			finish("canceled")
			return run, err
		}
		signals, err := runner.analyzeOne(ctx, candidate.SessionKey, thresholds)
		if err != nil {
			run.Skipped++
			reasons["error"]++
			continue
		}
		run.Analyzed++
		if signals.SkipReason != "" {
			reasons[signals.SkipReason]++
		}
		if signals.SkipReason == SkipSingleTurnChat {
			bucket := runner.bucketOf(signals)
			digests[bucket.id()] = bucket
		}
	}
	for _, bucket := range digests {
		if err := ctx.Err(); err != nil {
			finish("canceled")
			return run, err
		}
		if err := runner.rebuildDigest(ctx, bucket); err != nil {
			reasons["digest_error"]++
		}
	}
	if err := runner.runFacets(ctx, &run); err != nil {
		finish("facets_failed")
		return run, err
	}
	options.Logger.Info("session analysis run completed",
		"candidates", run.Candidates, "analyzed", run.Analyzed, "skipped", run.Skipped,
		"duration_ms", options.Now().Sub(started).Milliseconds())
	return finish("")
}

func (runner *Runner) packOptions() PackOptions {
	return PackOptions{MaxTokens: runner.options.Config.Pack.MaxTokens, Location: runner.options.Location, ClientLabels: runner.options.ClientLabels}
}

func (runner *Runner) analyzeOne(ctx context.Context, key []byte, thresholds Thresholds) (storage.SessionSignals, error) {
	options := runner.options
	sessionContext, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	rows, truncated, err := options.Store.LoadSessionAudits(sessionContext, key)
	if err != nil {
		return storage.SessionSignals{}, err
	}
	if len(rows) == 0 {
		return storage.SessionSignals{}, errors.New("sessionanalysis: session vanished")
	}
	session, err := BuildSession(sessionContext, key, rows, truncated, options.Loader, options.Vocabulary, options.Insights)
	if err != nil {
		return storage.SessionSignals{}, err
	}
	signals, fprs := ComputeSignals(session, options.Vocabulary, options.Fingerprints, thresholds, options.Now())
	if err := options.Store.SaveSessionSignals(sessionContext, signals, fprs); err != nil {
		return storage.SessionSignals{}, err
	}
	if !signals.Eligible {
		return signals, nil
	}
	pack := BuildSessionPack(session, signals, options.Vocabulary, runner.packOptions())
	if pack.Text == "" {
		return signals, nil
	}
	stored, err := runner.sealPack(key, storage.PackKindSession, pack, signals.APIKeyFPR, signals.NewAPITokenID, signals.Client, signals.FirstNS, signals.LastNS, signals.LastAuditID, 1)
	if err != nil {
		return storage.SessionSignals{}, err
	}
	if err := options.Store.SaveSessionPack(sessionContext, stored, nil); err != nil {
		return storage.SessionSignals{}, err
	}
	return signals, nil
}

// PackAAD is the additional data binding a pack ciphertext to its key.
func PackAAD(key []byte) ([]byte, error) {
	return security.AAD("session_pack", hex.EncodeToString(key))
}

func (runner *Runner) sealPack(key []byte, kind string, pack Pack, apiKey []byte, tokenID *int64, client string, firstNS, lastNS int64, lastAuditID string, members int64) (storage.SessionPack, error) {
	aad, err := PackAAD(key)
	if err != nil {
		return storage.SessionPack{}, err
	}
	sealed, err := runner.options.Cipher.Encrypt(aad, []byte(pack.Text))
	if err != nil {
		return storage.SessionPack{}, err
	}
	return storage.SessionPack{
		SessionKey: key, Kind: kind, APIKeyFPR: apiKey, NewAPITokenID: tokenID, Client: client,
		PackHash: pack.Hash(), PackEnc: sealed, RefMap: EncodeRefMap(pack.RefMap),
		TokenEstimate: int64(pack.Tokens), Truncated: pack.Truncated, Members: members,
		FirstNS: firstNS, LastNS: lastNS, LastAuditID: lastAuditID, BuiltAtNS: runner.options.Now().UnixNano(),
	}, nil
}

// digestBucket is one key, client and local day of single-turn chats.
type digestBucket struct {
	apiKey  []byte
	tokenID *int64
	client  string
	day     time.Time
}

func (bucket digestBucket) id() string {
	return hex.EncodeToString(bucket.apiKey) + "\x00" + bucket.client + "\x00" + bucket.day.Format("2006-01-02")
}

func (runner *Runner) bucketOf(signals storage.SessionSignals) digestBucket {
	local := time.Unix(0, signals.LastNS).In(runner.options.Location)
	client := signals.Client
	if client == "" {
		client = "unknown"
	}
	return digestBucket{
		apiKey: signals.APIKeyFPR, tokenID: signals.NewAPITokenID, client: client,
		day: time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, runner.options.Location),
	}
}

// maxDigestMembersPerDay bounds the single-turn chats of one key, client and
// day that a digest rebuild reads.
const maxDigestMembersPerDay = 200

// rebuildDigest rebuilds the chat digest packs of one bucket from all of its
// current members, so chats closed in later runs join the same day's digest.
func (runner *Runner) rebuildDigest(ctx context.Context, bucket digestBucket) error {
	options := runner.options
	digestContext, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	members, err := options.Store.ListChatDigestMembers(digestContext, bucket.apiKey, bucket.client,
		bucket.day.UnixNano(), bucket.day.AddDate(0, 0, 1).UnixNano(), maxDigestMembersPerDay)
	if err != nil {
		return err
	}
	items := make([]DigestItem, 0, len(members))
	for _, member := range members {
		rows, truncated, err := options.Store.LoadSessionAudits(digestContext, member.SessionKey)
		if err != nil || len(rows) == 0 {
			continue
		}
		session, err := BuildSession(digestContext, member.SessionKey, rows, truncated, options.Loader, options.Vocabulary, options.Insights)
		if err != nil {
			continue
		}
		main := session.MainNode()
		if main == nil || len(main.Turns) == 0 {
			continue
		}
		turn := main.Turns[0]
		items = append(items, DigestItem{SessionKey: member.SessionKey, AuditID: turn.AuditID, StartedNS: turn.StartedNS, Text: turn.Text, Model: member.MainModel})
	}
	for chunk := 0; chunk*maxDigestItems < len(items); chunk++ {
		end := (chunk + 1) * maxDigestItems
		if end > len(items) {
			end = len(items)
		}
		part := items[chunk*maxDigestItems : end]
		pack := BuildDigestPack(bucket.client, part, options.Vocabulary, runner.packOptions())
		key := options.Fingerprints.Fingerprint(domainDigest, []byte(bucket.id()+"\x00"+strconv.Itoa(chunk)))
		keys := make([][]byte, 0, len(part))
		lastAudit, firstNS, lastNS := part[0].AuditID, part[0].StartedNS, part[0].StartedNS
		for _, item := range part {
			keys = append(keys, item.SessionKey)
			if item.StartedNS >= lastNS {
				lastNS, lastAudit = item.StartedNS, item.AuditID
			}
			if item.StartedNS < firstNS {
				firstNS = item.StartedNS
			}
		}
		stored, err := runner.sealPack(key, storage.PackKindChatDigest, pack, bucket.apiKey, bucket.tokenID, bucket.client, firstNS, lastNS, lastAudit, int64(len(part)))
		if err != nil {
			return err
		}
		if err := options.Store.SaveSessionPack(digestContext, stored, keys); err != nil {
			return err
		}
	}
	return nil
}
