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
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Store is the storage surface of the batch runner.
type Store interface {
	ListSessionCandidates(ctx context.Context, sinceNS, quietBeforeNS, signalVersion int64, limit int) ([]storage.SessionCandidate, error)
	LoadSessionAudits(ctx context.Context, agentRootFPR, apiKeyFPR []byte) ([]storage.SessionAuditRow, bool, error)
	// SaveSessionSignals writes signals, fingerprints and the session pack
	// (nil: none) atomically, so a failed write leaves the session due.
	SaveSessionSignals(ctx context.Context, signals storage.SessionSignals, fprs []storage.SessionTextFPR, pack *storage.SessionPack) error
	// PruneSessionAnalysis drops the derived rows of sessions whose audits
	// retention deleted; only sessions older than expiredBeforeNS are checked
	// (zero: none), in bounded batches.
	PruneSessionAnalysis(ctx context.Context, expiredBeforeNS, fingerprintCutoffNS int64) (int64, error)
	RecordSessionAnalysisRun(ctx context.Context, run storage.SessionAnalysisRun) error
	ListChatDigestMembers(ctx context.Context, apiKeyFPR []byte, client string, fromNS, toNS int64, limit int) ([]storage.SessionSignals, error)
	// ListPendingDigestMembers lists single-turn chats whose digest bucket
	// has not been rebuilt with them yet.
	ListPendingDigestMembers(ctx context.Context, limit int) ([]storage.SessionSignals, error)
	// SaveChatDigests replaces one bucket's digests and clears its pending
	// members atomically.
	SaveChatDigests(ctx context.Context, bucket storage.ChatDigestBucket, chunks []storage.ChatDigestChunk, staleKeys [][]byte) error
	ListFacetCandidates(ctx context.Context, settledBeforeNS int64, promptVersion, model string, limit int) ([]storage.SessionPack, error)
	SaveSessionFacet(ctx context.Context, facet storage.SessionFacet, fprs []storage.SessionTextFPR) error
	// ListSessionProjects and UpdateSessionProjects keep the stored booking of
	// recent sessions in step with the project rules (ProjectResolver only).
	ListSessionProjects(ctx context.Context, sinceNS, computedBeforeNS int64, limit int) ([]storage.SessionProjectRef, error)
	UpdateSessionProjects(ctx context.Context, refs []storage.SessionProjectRef) error
}

// ProjectResolver books an analysis session to a project of the organisation
// reports (doc 23). It is nil when org reports are disabled: sessions then
// carry no project and no bucket, and nothing is treated as a service.
type ProjectResolver interface {
	ResolveSession(ctx context.Context, agentRootFPR, apiKeyFPR []byte) (orgreport.SessionProject, error)
	ProjectName(id int64) string
	// ReportGroups lists the enabled project groups with their members.
	ReportGroups() []orgreport.ReportGroup
}

// projectField renders a booking as the pack's project field (doc 24 section
// 6.7): the project name with the signal level it matched at, or one of the
// two unmatched buckets. An unknown booking has no field.
func projectField(project orgreport.SessionProject) string {
	switch {
	case !project.Known:
		return ""
	case project.Project > 0:
		name := project.Name
		if name == "" {
			name = "#" + strconv.FormatInt(int64(project.Project), 10)
		}
		if project.Level != "" {
			name += "(" + project.Level + ")"
		}
		return name
	case project.Project == orgreport.ProjectUnattributed:
		return "未归属"
	}
	return "无项目上下文"
}

// projectColumns maps a booking to the stored project id and bucket. An
// unknown booking stores neither and is filled in by a later refresh.
func projectColumns(project orgreport.SessionProject) (*int64, string) {
	var id *int64
	if project.Known && project.Project > 0 {
		value := int64(project.Project)
		id = &value
	}
	switch {
	case project.Service:
		return id, storage.BucketService
	case !project.Known:
		return nil, ""
	case project.Project > 0:
		return id, storage.BucketAttributed
	case project.Project == orgreport.ProjectUnattributed:
		return nil, storage.BucketUnattributed
	}
	return nil, storage.BucketNoContext
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
	// Projects is nil unless organisation reports are enabled.
	Projects ProjectResolver
	// WeekStartsSunday cuts report weeks on Sunday instead of Monday
	// (org_reports.week_start).
	WeekStartsSunday bool
	// LLM is nil unless session_analysis.llm.enabled.
	LLM          Completer
	ClientLabels map[string]string
	Location     *time.Location
	Logger       *slog.Logger
	Now          func() time.Time
}

// Runner is the daily batch (doc 24 sections 5 and 7).
type Runner struct {
	// options is read all through a run, also by the goroutines a run starts.
	// Its Config and LLM change only at the start of RunOnce, while no run is
	// in progress (see Apply).
	options Options
	// runAt is the daily run time as minutes after midnight.
	runAt   atomic.Int32
	pending atomic.Pointer[runtimeSettings]
	running atomic.Bool
	trigger chan struct{}
	// reschedule wakes the loop after the run time changed.
	reschedule chan struct{}
	stop       context.CancelFunc
	done       chan struct{}
	stopOnce   sync.Once
}

// runtimeSettings is what Apply hands to the next run.
type runtimeSettings struct {
	config config.SessionAnalysisConfig
	llm    Completer
}

// Apply replaces the configuration and the model client of the runner. The
// new values take effect at the start of the next run, never inside a running
// one; a new daily run time reschedules the loop at once. llm is nil when the
// model stage is disabled. The caller validates configuration first.
func (runner *Runner) Apply(configuration config.SessionAnalysisConfig, llm Completer) error {
	if runner == nil {
		return errors.New("sessionanalysis: runner unavailable")
	}
	hour, minute, err := config.ParseRunAt(configuration.RunAt)
	if err != nil {
		return err
	}
	runner.pending.Store(&runtimeSettings{config: configuration, llm: llm})
	runner.runAt.Store(int32(hour*60 + minute))
	select {
	case runner.reschedule <- struct{}{}:
	default:
	}
	return nil
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
	runner := &Runner{options: options, trigger: make(chan struct{}, 1), reschedule: make(chan struct{}, 1)}
	runner.runAt.Store(int32(hour*60 + minute))
	return runner, nil
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
			case <-runner.reschedule:
				timer.Stop()
				continue // the run time changed: wait for the new one
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
	runAt := int(runner.runAt.Load())
	next := time.Date(now.Year(), now.Month(), now.Day(), runAt/60, runAt%60, 0, 0, runner.options.Location)
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
	if next := runner.pending.Swap(nil); next != nil {
		// Settings saved since the last run. Nothing else reads Config or LLM
		// while no run is in progress.
		runner.options.Config, runner.options.LLM = next.config, next.llm
	}
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

	// Retention deletes audits by start time, so only sessions older than the
	// retention period can have lost theirs. Without retention none can.
	expiredBefore := int64(0)
	if days := options.RetentionDays; days > 0 {
		expiredBefore = started.Add(-time.Duration(days) * 24 * time.Hour).UnixNano()
	}
	pruned, err := options.Store.PruneSessionAnalysis(ctx, expiredBefore, started.Add(-fingerprintKeep).UnixNano())
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
		signals, err := runner.analyzeOne(ctx, candidate.AgentRootFPR, candidate.APIKeyFPR, thresholds)
		if err != nil {
			run.Skipped++
			reasons["error"]++
			continue
		}
		run.Analyzed++
		if signals.SkipReason != "" {
			reasons[signals.SkipReason]++
		}
	}
	if rebooked, err := runner.refreshProjects(ctx, started, thresholds); err != nil {
		reasons["project_refresh_error"]++
	} else if rebooked > 0 {
		reasons["rebooked"] += rebooked
	}
	// Every bucket with a pending member is rebuilt: new single-turn chats,
	// and the remaining members of digests dropped because a member left the
	// single-turn category or expired. A failed rebuild stays pending.
	pending, err := options.Store.ListPendingDigestMembers(ctx, maxCandidatesPerRun)
	if err != nil {
		finish("digests_failed")
		return run, err
	}
	digests := map[string]digestBucket{}
	order := make([]string, 0)
	for _, member := range pending {
		bucket := runner.bucketOf(member)
		if _, seen := digests[bucket.id()]; !seen {
			digests[bucket.id()] = bucket
			order = append(order, bucket.id())
		}
	}
	for _, id := range order {
		bucket := digests[id]
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
	if err := runner.runReports(ctx); err != nil {
		finish("reports_failed")
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

// SessionKey is the analysis session key of the requests of one agent-tree
// root sent with one API key (nil: no key fingerprint). Keys never share a
// session, so pack and facet ownership checks see one key's content only.
func SessionKey(fp Fingerprinter, agentRootFPR, apiKeyFPR []byte) []byte {
	value := make([]byte, 0, len(agentRootFPR)+len(apiKeyFPR))
	value = append(append(value, agentRootFPR...), apiKeyFPR...)
	return fp.Fingerprint(domainSession, value)
}

func (runner *Runner) analyzeOne(ctx context.Context, root, apiKey []byte, thresholds Thresholds) (storage.SessionSignals, error) {
	options := runner.options
	sessionContext, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	rows, truncated, err := options.Store.LoadSessionAudits(sessionContext, root, apiKey)
	if err != nil {
		return storage.SessionSignals{}, err
	}
	if len(rows) == 0 {
		return storage.SessionSignals{}, errors.New("sessionanalysis: session vanished")
	}
	key := SessionKey(options.Fingerprints, root, apiKey)
	session, err := BuildSession(sessionContext, key, rows, truncated, options.Loader, options.Vocabulary, options.Insights)
	if err != nil {
		return storage.SessionSignals{}, err
	}
	signals, fprs := ComputeSignals(session, options.Vocabulary, options.Fingerprints, thresholds, options.Now())
	// The stored pair must equal the candidate's, or it would be due again.
	signals.AgentRootFPR = append([]byte(nil), root...)
	signals.APIKeyFPR = append([]byte(nil), apiKey...)
	if len(apiKey) == 0 {
		signals.APIKeyFPR = nil
	}
	packOptions := runner.packOptions()
	if options.Projects != nil {
		project, err := options.Projects.ResolveSession(sessionContext, root, apiKey)
		if err != nil {
			return storage.SessionSignals{}, err // stays due and is retried
		}
		signals.ProjectID, signals.Bucket = projectColumns(project)
		packOptions.Project = projectField(project)
		if project.Service {
			// A service principal's sessions keep signals only: no pack, no
			// chat digest and no sentence fingerprints.
			signals.Eligible, signals.SkipReason, fprs = false, SkipService, nil
		}
	}
	if signals.SkipReason == SkipSingleTurnChat {
		// Saving queues the bucket for a digest rebuild; leaving a bucket
		// drops the digests that still hold this chat.
		signals.DigestBucket = runner.bucketOf(signals).key(options.Fingerprints)
	}
	// The pack is built and sealed before anything is written: signals mark
	// the session analysed, so they are stored only together with its pack.
	var stored *storage.SessionPack
	if signals.Eligible {
		if pack := BuildSessionPack(session, signals, options.Vocabulary, packOptions); pack.Text != "" {
			sealed, err := runner.sealPack(key, storage.PackKindSession, pack, signals.APIKeyFPR, signals.NewAPITokenID, signals.Client, signals.FirstNS, signals.LastNS, signals.LastAuditID, 1)
			if err != nil {
				return storage.SessionSignals{}, err
			}
			stored = &sealed
		}
	}
	if err := options.Store.SaveSessionSignals(sessionContext, signals, fprs, stored); err != nil {
		return storage.SessionSignals{}, err
	}
	return signals, nil
}

const projectRefreshBatch = 200

// refreshProjects re-books the sessions of the two reported weeks that this
// run did not analyse: project rules and principal classes change after a
// session was analysed, and the project identity backfill may finish later.
// A changed project or bucket is a column update; a session that became or
// stopped being a service is analysed again, which adds or removes its pack,
// digest membership and fingerprints. It returns the number of changed rows.
func (runner *Runner) refreshProjects(ctx context.Context, started time.Time, thresholds Thresholds) (int64, error) {
	options := runner.options
	if options.Projects == nil {
		return 0, nil
	}
	since := runner.weekStart(started).AddDate(0, 0, -7)
	refs, err := options.Store.ListSessionProjects(ctx, since.UnixNano(), started.UnixNano(), maxCandidatesPerRun)
	if err != nil {
		return 0, err
	}
	changed := int64(0)
	updates := make([]storage.SessionProjectRef, 0, projectRefreshBatch)
	flush := func() error {
		if len(updates) == 0 {
			return nil
		}
		err := options.Store.UpdateSessionProjects(ctx, updates)
		if err == nil {
			changed += int64(len(updates))
		}
		updates = updates[:0]
		return err
	}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		project, err := options.Projects.ResolveSession(ctx, ref.AgentRootFPR, ref.APIKeyFPR)
		if err != nil {
			return changed, err
		}
		id, bucket := projectColumns(project)
		wasService := ref.Bucket == storage.BucketService
		if project.Service != wasService {
			// Decided before the "no verdict" skip: a caller stops being a
			// service whether or not its project is known yet.
			if _, err := runner.analyzeOne(ctx, ref.AgentRootFPR, ref.APIKeyFPR, thresholds); err == nil {
				changed++
			}
			continue
		}
		if wasService || bucket == "" || (bucket == ref.Bucket && sameID(id, ref.ProjectID)) {
			continue // still a service, no verdict yet, or unchanged
		}
		updates = append(updates, storage.SessionProjectRef{SessionKey: ref.SessionKey, ProjectID: id, Bucket: bucket})
		if len(updates) == projectRefreshBatch {
			if err := flush(); err != nil {
				return changed, err
			}
		}
	}
	return changed, flush()
}

func sameID(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// weekStart is the start of the report week containing t.
func (runner *Runner) weekStart(t time.Time) time.Time {
	return weekStartOn(t, runner.options.Location, runner.options.WeekStartsSunday)
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

// key is the bucket's keyed fingerprint, stored with its member chats.
func (bucket digestBucket) key(fp Fingerprinter) []byte {
	return fp.Fingerprint(domainDigest, []byte(bucket.id()))
}

// chunkKey is the session key of the bucket's chunk-th digest pack.
func (bucket digestBucket) chunkKey(fp Fingerprinter, chunk int) []byte {
	return fp.Fingerprint(domainDigest, []byte(bucket.id()+"\x00"+strconv.Itoa(chunk)))
}

// maxDigestChunks is the most digest packs one bucket can fill.
const maxDigestChunks = (maxDigestMembersPerDay + maxDigestItems - 1) / maxDigestItems

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
		rows, truncated, err := options.Store.LoadSessionAudits(digestContext, member.AgentRootFPR, member.APIKeyFPR)
		if err != nil {
			return err // the bucket stays pending and is retried
		}
		if len(rows) == 0 {
			continue // expired; the next prune removes its signals
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
	chunks := make([]storage.ChatDigestChunk, 0, maxDigestChunks)
	for chunk := 0; chunk*maxDigestItems < len(items) && chunk < maxDigestChunks; chunk++ {
		end := (chunk + 1) * maxDigestItems
		if end > len(items) {
			end = len(items)
		}
		part := items[chunk*maxDigestItems : end]
		pack := BuildDigestPack(bucket.client, part, options.Vocabulary, runner.packOptions())
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
		stored, err := runner.sealPack(bucket.chunkKey(options.Fingerprints, chunk), storage.PackKindChatDigest, pack, bucket.apiKey, bucket.tokenID, bucket.client, firstNS, lastNS, lastAudit, int64(len(part)))
		if err != nil {
			return err
		}
		chunks = append(chunks, storage.ChatDigestChunk{Pack: stored, Members: keys})
	}
	// Chunks the bucket no longer fills, all of them when no member is left.
	stale := make([][]byte, 0, maxDigestChunks)
	for chunk := len(chunks); chunk < maxDigestChunks; chunk++ {
		stale = append(stale, bucket.chunkKey(options.Fingerprints, chunk))
	}
	return options.Store.SaveChatDigests(digestContext, storage.ChatDigestBucket{
		APIKeyFPR: bucket.apiKey, Client: bucket.client, FromNS: bucket.day.UnixNano(), ToNS: bucket.day.AddDate(0, 0, 1).UnixNano(),
	}, chunks, stale)
}
