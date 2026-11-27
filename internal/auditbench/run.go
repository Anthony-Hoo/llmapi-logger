package auditbench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"llmapi-logger/internal/app"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/protofixture"
)

// DatabaseEnv names the environment variable that holds the PostgreSQL
// connection string. It is never accepted on the command line, so it cannot
// appear in process listings or shell history, and it is never printed.
const DatabaseEnv = "AUDIT_BENCH_DATABASE_URL"

type runOptions struct {
	workload     Workload
	output       string
	freshSchema  bool
	dropSchema   bool
	settle       time.Duration
	drainTimeout time.Duration
	pollInterval time.Duration
	commit       string
}

var phaseNames = []string{"load", "drain", "reads", "idle"}

// safeError keeps error text that cannot carry a connection string: the
// SQLSTATE of a server error, or a fixed description.
func safeError(what string, err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return fmt.Errorf("%s: SQLSTATE %s", what, pgError.Code)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s failed (%T)", what, err)
}

func buildInfo(override string) BuildInfo {
	info := BuildInfo{GoVersion: runtime.Version(), Commit: "unknown", Source: "none"}
	if override != "" {
		info.Commit, info.Source = override, "flag"
		return info
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				info.Commit, info.Source = setting.Value, "vcs"
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			}
		}
	}
	return info
}

func randomToken(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}

// withSearchPath points a connection string at one schema, the way the
// integration tests isolate themselves.
func withSearchPath(dsn, schema string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid connection URL")
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	return dsn + " search_path=" + schema, nil
}

func reserveAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	return address, listener.Close()
}

func waitListening(ctx context.Context, address string, done <-chan error) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case runErr := <-done:
			return fmt.Errorf("application exited before listening: %v", runErr)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for the application to listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func benchConfig(workload Workload, appDSN, keyPath, adminToken, upstreamURL string) (config.Config, error) {
	configuration := config.Default()
	listen, err := reserveAddress()
	if err != nil {
		return configuration, err
	}
	admin, err := reserveAddress()
	if err != nil {
		return configuration, err
	}
	configuration.Listen = listen
	configuration.AdminListen = admin
	configuration.NewAPI.URL = upstreamURL
	configuration.Mode = "available"
	configuration.DatabaseURL = appDSN
	configuration.KeyPath = keyPath
	configuration.AdminToken = adminToken
	configuration.RetentionDays = 0
	configuration.Insights.Enabled = workload.Insights
	configuration.OrgReports.Enabled = workload.OrgReports
	configuration.SessionAnalysis.Enabled = false
	if workload.CallerLookups {
		// Local placeholder credential for the fake NewAPI management API.
		configuration.NewAPI.AccessToken = "bench-newapi-access-token"
		configuration.NewAPI.UserID = 1
	}
	configuration.Interceptors = map[string]config.InterceptorConfig{"require-client-credential": {Type: "require_credential"}}
	credential := []string{"require-client-credential"}
	configuration.Routes = []config.RouteConfig{
		{ID: "openai-chat-completions", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions", Interceptors: credential},
		{ID: "openai-completions", Method: http.MethodPost, Path: "/v1/completions", Match: "exact", Parser: "openai.completions", Interceptors: credential},
		{ID: "openai-responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses", Interceptors: credential},
		{ID: "openai-responses-compact", Method: http.MethodPost, Path: "/v1/responses/compact", Match: "exact", Parser: "openai.responses_compact", Interceptors: credential},
		{ID: "anthropic-messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages", Interceptors: credential},
		{ID: "gemini-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content", Interceptors: credential},
		{ID: "gemini-stream-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content", Interceptors: credential},
	}
	return configuration, config.Validate(configuration)
}

type bench struct {
	options   runOptions
	stats     *statsConn
	writerPID int32
	sampler   *memorySampler
	tracker   *queryTracker
	result    Result

	activityMu  sync.Mutex
	maxActivity []Activity
}

func (bench *bench) warn(format string, arguments ...any) {
	bench.result.Warnings = append(bench.result.Warnings, fmt.Sprintf(format, arguments...))
}

func (bench *bench) noteActivity(phase int, activity Activity) {
	bench.activityMu.Lock()
	defer bench.activityMu.Unlock()
	if phase < 0 || phase >= len(bench.maxActivity) {
		return
	}
	current := &bench.maxActivity[phase]
	current.SameDatabase = max(current.SameDatabase, activity.SameDatabase)
	current.OtherDatabase = max(current.OtherDatabase, activity.OtherDatabase)
}

func (bench *bench) snapshot(ctx context.Context) (snapshot, error) {
	value, err := bench.stats.takeSnapshot(ctx, bench.writerPID)
	if err != nil {
		return value, safeError("statistics snapshot", err)
	}
	return value, nil
}

// runBench executes the run subcommand.
func runBench(ctx context.Context, options runOptions, getenv func(string) string, stdout io.Writer) error {
	dsn := getenv(DatabaseEnv)
	if dsn == "" {
		return fmt.Errorf("set %s to the PostgreSQL connection string", DatabaseEnv)
	}
	connectionConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid PostgreSQL connection configuration")
	}
	connectionConfig.RuntimeParams["application_name"] = "audit-bench"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return safeError("connect to PostgreSQL", err)
	}
	bench := &bench{
		options:     options,
		stats:       &statsConn{conn: connection},
		sampler:     newMemorySampler(len(phaseNames) + 1),
		maxActivity: make([]Activity, len(phaseNames)+1),
	}
	defer bench.stats.close()
	bench.tracker = newQueryTracker(bench.stats)
	bench.result = Result{Tool: "audit-bench", FormatVersion: FormatVersion, Build: buildInfo(options.commit),
		StartedAt: time.Now().UTC(), Workload: options.workload, Logs: map[string]int64{}}
	if bench.result.Build.Commit == "unknown" {
		bench.warn("git commit unknown: build with VCS stamping or pass --commit")
	}
	if bench.result.Build.Modified {
		bench.warn("binary was built from a modified working tree")
	}

	// Refuse a database that already holds audit tables.
	var exists bool
	var schema string
	if err := bench.stats.inTx(ctx, true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_regclass('audit_records') IS NOT NULL, COALESCE(current_schema(), '')`).Scan(&exists, &schema)
	}); err != nil {
		return safeError("inspect target schema", err)
	}
	appDSN := dsn
	createdSchema := ""
	if options.freshSchema {
		schema = fmt.Sprintf("audit_bench_%s_%s", time.Now().UTC().Format("20060102150405"), randomToken(3))
		if err := bench.stats.inTx(ctx, false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
			return err
		}); err != nil {
			return safeError("create schema", err)
		}
		createdSchema = schema
		if err := bench.stats.inTx(ctx, false, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT set_config('search_path', $1, false)", pgx.Identifier{schema}.Sanitize())
			return err
		}); err != nil {
			return safeError("select schema", err)
		}
		if appDSN, err = withSearchPath(dsn, schema); err != nil {
			return err
		}
	} else if exists {
		return errors.New("the target schema already holds audit tables; point the tool at an empty database or pass --fresh-schema")
	} else if schema == "" {
		return errors.New("the connection has no current schema to create audit tables in")
	}
	defer func() {
		if createdSchema != "" && options.dropSchema {
			dropContext, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := bench.stats.inTx(dropContext, false, func(tx pgx.Tx) error {
				_, err := tx.Exec(dropContext, "DROP SCHEMA "+pgx.Identifier{createdSchema}.Sanitize()+" CASCADE")
				return err
			}); err != nil {
				fmt.Fprintf(stdout, "warning: could not drop schema %s: %v\n", createdSchema, safeError("drop schema", err))
			}
		}
	}()
	bench.result.Postgres.FreshSchema = options.freshSchema
	bench.result.Postgres.Schema = schema
	bench.result.Postgres.SettleSeconds = int(options.settle / time.Second)
	settings, versionNumber, err := bench.stats.settings(ctx)
	if err != nil {
		return safeError("read server settings", err)
	}
	bench.result.Postgres.Settings, bench.result.Postgres.VersionNumber = settings, versionNumber
	bench.result.Postgres.ForceFlush = versionNumber >= 150000
	if versionNumber < 180000 {
		bench.warn("PostgreSQL before 18 has no per-backend WAL statistics; only cluster-wide WAL is reported")
	}

	keyDirectory, err := os.MkdirTemp("", "audit-bench-")
	if err != nil {
		return errors.New("create key directory failed")
	}
	defer os.RemoveAll(keyDirectory)

	// Fake upstream and fake NewAPI management on one local listener.
	upstream := protofixture.NewUpstream("bench-" + randomToken(4) + "-")
	upstream.FirstByteDelay = time.Duration(options.workload.FirstByteMS) * time.Millisecond
	upstream.ChunkDelay = time.Duration(options.workload.ChunkDelayMS) * time.Millisecond
	newAPI := newFakeNewAPI()
	mux := http.NewServeMux()
	mux.Handle("/api/", newAPI)
	mux.Handle("/", upstream)
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("listen for the fake upstream failed")
	}
	upstreamServer := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: nil}
	go func() { _ = upstreamServer.Serve(upstreamListener) }()
	defer upstreamServer.Close()

	adminToken := randomToken(24)
	configuration, err := benchConfig(options.workload, appDSN, filepath.Join(keyDirectory, "audit.key"), adminToken, "http://"+upstreamListener.Addr().String())
	if err != nil {
		return fmt.Errorf("build application configuration: %w", err)
	}
	logs := newCountingHandler()
	application, err := app.NewContext(ctx, configuration, slog.New(logs))
	if err != nil {
		return errors.New("assemble the application failed; check that the database is reachable and empty")
	}
	appContext, cancelApp := context.WithCancel(context.Background())
	appDone := make(chan error, 1)
	go func() { appDone <- application.Run(appContext) }()
	stopApp := func() {
		cancelApp()
		select {
		case <-appDone:
		case <-time.After(2 * time.Minute):
			bench.warn("application did not stop within 2 minutes")
		}
	}
	appStopped := false
	defer func() {
		if !appStopped {
			stopApp()
		}
	}()
	for _, address := range []string{configuration.Listen, configuration.AdminListen} {
		if err := waitListening(ctx, address, appDone); err != nil {
			return err
		}
	}
	adminURL := "http://" + configuration.AdminListen
	admin := &http.Client{Timeout: 5 * time.Minute}
	if err := waitReady(ctx, admin, adminURL, adminToken); err != nil {
		return err
	}
	for attempt := 0; attempt < 50 && bench.writerPID == 0; attempt++ {
		pid, err := bench.stats.writerPID(ctx)
		if err == nil {
			bench.writerPID = pid
			break
		}
		_ = sleepContext(ctx, 100*time.Millisecond)
	}
	if bench.writerPID == 0 {
		bench.warn("application writer session not found; per-backend statistics unavailable")
	}

	fmt.Fprintf(stdout, "audit-bench: schema %s, settling %s before the first snapshot\n", schema, options.settle)
	if err := sleepContext(ctx, options.settle); err != nil {
		return err
	}
	snapshots := make([]snapshot, 0, len(phaseNames)+1)
	start, err := bench.snapshot(ctx)
	if err != nil {
		return err
	}
	snapshots = append(snapshots, start)

	// The samplers stop through samplerContext, but their queries run on a
	// detached context: cancelling a pgx query mid-flight closes the session.
	samplerContext, cancelSamplers := context.WithCancel(ctx)
	var samplers sync.WaitGroup
	stopSamplers := func() {
		cancelSamplers()
		samplers.Wait()
	}
	defer stopSamplers()
	samplers.Add(2)
	go func() { defer samplers.Done(); bench.sampler.loop(samplerContext) }()
	// The latency poll runs only until the drain is over, so the reads and
	// idle phases see no tool queries on audit_records.
	trackerContext, cancelTracker := context.WithCancel(ctx)
	var trackerDone sync.WaitGroup
	trackerDone.Add(1)
	go func() { defer trackerDone.Done(); bench.tracker.loop(trackerContext, options.pollInterval) }()
	stopTracker := func() {
		cancelTracker()
		trackerDone.Wait()
	}
	defer stopTracker()
	go func() {
		defer samplers.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-samplerContext.Done():
				return
			case <-ticker.C:
				queryContext, cancel := context.WithTimeout(context.WithoutCancel(samplerContext), 30*time.Second)
				if activity, err := bench.stats.sampleActivity(queryContext); err == nil {
					bench.noteActivity(int(bench.sampler.phase.Load()), activity)
				}
				cancel()
			}
		}
	}()
	var pollCounts [][2]int64
	notePolls := func() {
		bench.stats.mu.Lock()
		pollCounts = append(pollCounts, [2]int64{bench.stats.latencyPolls, bench.stats.drainPolls})
		bench.stats.mu.Unlock()
	}
	notePolls()

	// Load.
	bench.sampler.phase.Store(0)
	fmt.Fprintln(stdout, "audit-bench: load phase")
	traffic := newDriver(options.workload, "http://"+configuration.Listen, upstream, newAPI, bench.tracker)
	traffic.run(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	loadEnd, err := bench.snapshot(ctx)
	if err != nil {
		return err
	}
	snapshots = append(snapshots, loadEnd)
	notePolls()

	// Drain.
	bench.sampler.phase.Store(1)
	fmt.Fprintln(stdout, "audit-bench: drain phase")
	served := upstream.Stats().Served
	drain := bench.drain(ctx, served, options)
	bench.result.Audits.AnalysisPending, bench.result.Audits.IdentityPending = drain.analysis, drain.identity
	bench.result.Audits.DrainTimedOut = drain.timedOut
	stopTracker()
	bench.tracker.poll(context.WithoutCancel(ctx))
	if drain.timedOut {
		bench.warn("drain timed out after %s: %d audits not terminal", options.drainTimeout, drain.open)
	}
	readIDs := bench.readSample(ctx, traffic.snapshotRecords())
	if err := sleepContext(ctx, options.settle); err != nil {
		return err
	}
	drainEnd, err := bench.snapshot(ctx)
	if err != nil {
		return err
	}
	snapshots = append(snapshots, drainEnd)
	notePolls()

	// Reads through the management API.
	bench.sampler.phase.Store(2)
	fmt.Fprintf(stdout, "audit-bench: reads phase (%d audits)\n", len(readIDs))
	bench.result.Reads = sampleReads(ctx, admin, adminURL, adminToken, readIDs)
	if err := sleepContext(ctx, options.settle); err != nil {
		return err
	}
	readsEnd, err := bench.snapshot(ctx)
	if err != nil {
		return err
	}
	snapshots = append(snapshots, readsEnd)
	notePolls()

	// Idle.
	bench.sampler.phase.Store(3)
	idle := time.Duration(options.workload.IdleSeconds) * time.Second
	fmt.Fprintf(stdout, "audit-bench: idle phase (%s)\n", idle)
	if err := sleepContext(ctx, idle); err != nil {
		return err
	}
	if err := sleepContext(ctx, options.settle); err != nil {
		return err
	}
	idleEnd, err := bench.snapshot(ctx)
	if err != nil {
		return err
	}
	snapshots = append(snapshots, idleEnd)
	notePolls()
	stopSamplers()
	bench.sampler.phase.Store(4)

	// Everything below reads the database after the last snapshot, so it
	// cannot disturb the measured counters.
	for index, name := range phaseNames {
		phase := difference(name, snapshots[index], snapshots[index+1])
		phase.MemoryPeakBytes, phase.HeapPeakBytes = bench.sampler.peaks(index)
		phase.Activity = bench.maxActivity[index]
		phase.LatencyPolls = pollCounts[index+1][0] - pollCounts[index][0]
		phase.DrainPolls = pollCounts[index+1][1] - pollCounts[index][1]
		bench.result.Phases = append(bench.result.Phases, phase)
	}
	bench.result.Write = difference("load+drain", snapshots[0], snapshots[2])
	for index := range 2 {
		peakTotal, peakHeap := bench.sampler.peaks(index)
		bench.result.Write.MemoryPeakBytes = max(bench.result.Write.MemoryPeakBytes, peakTotal)
		bench.result.Write.HeapPeakBytes = max(bench.result.Write.HeapPeakBytes, peakHeap)
	}
	bench.result.Write.LatencyPolls = pollCounts[2][0] - pollCounts[0][0]
	bench.result.Write.DrainPolls = pollCounts[2][1] - pollCounts[0][1]
	total := difference("total", snapshots[0], snapshots[len(snapshots)-1])
	for index := range phaseNames {
		peakTotal, peakHeap := bench.sampler.peaks(index)
		total.MemoryPeakBytes = max(total.MemoryPeakBytes, peakTotal)
		total.HeapPeakBytes = max(total.HeapPeakBytes, peakHeap)
		total.Activity.SameDatabase = max(total.Activity.SameDatabase, bench.maxActivity[index].SameDatabase)
		total.Activity.OtherDatabase = max(total.Activity.OtherDatabase, bench.maxActivity[index].OtherDatabase)
	}
	total.LatencyPolls = pollCounts[len(pollCounts)-1][0] - pollCounts[0][0]
	total.DrainPolls = pollCounts[len(pollCounts)-1][1] - pollCounts[0][1]
	bench.result.Total = total
	bench.result.Memory = MemorySummary{PeakTotalBytes: total.MemoryPeakBytes, PeakHeapBytes: total.HeapPeakBytes, PeakRSSBytes: peakRSS()}
	if snapshots[0].walReset != snapshots[len(snapshots)-1].walReset || snapshots[0].database.StatsReset != snapshots[len(snapshots)-1].database.StatsReset {
		bench.result.Postgres.StatsWereReset = true
		bench.warn("statistics were reset during the run; counter differences are invalid")
	}
	bench.result.Postgres.BackendStats = snapshots[0].writer.Available
	bench.result.Contamination = ContaminationInfo{MaxSameDatabase: total.Activity.SameDatabase, MaxOtherDatabase: total.Activity.OtherDatabase}
	// The application holds at most five sessions: the writer and four readers.
	if total.Activity.SameDatabase > 5 || total.Activity.OtherDatabase > 0 {
		bench.result.Contamination.Contaminated = true
		bench.warn("other sessions were active (up to %d in this database, %d in others): cluster-wide WAL and database-wide commits include their work; use the per-table and writer-backend figures",
			total.Activity.SameDatabase, total.Activity.OtherDatabase)
	}

	if total.Writer.Available && total.WALOutsideWriter > 1_000_000 && total.WALOutsideWriter*2 > total.WAL.Bytes {
		bench.result.Contamination.Contaminated = true
		bench.warn("%.1f MB of the %.1f MB cluster WAL was not written by the application writer; other sessions were probably active",
			float64(total.WALOutsideWriter)/1e6, float64(total.WAL.Bytes)/1e6)
	}

	records := traffic.snapshotRecords()
	bench.summarizeClient(records)
	if err := bench.summarizeDatabase(ctx, snapshots[len(snapshots)-1], records); err != nil {
		return err
	}
	stats := upstream.Stats()
	bench.result.Upstream = UpstreamSummary{Served: stats.Served, Unknown: stats.Unknown, Mismatched: stats.Mismatched,
		Aborted: stats.Aborted, Cancelled: stats.Cancelled, NewAPILookups: newAPI.lookups.Load()}
	if stats.Mismatched > 0 {
		bench.warn("%d requests reached the upstream with bytes different from what the client sent", stats.Mismatched)
	}
	stopApp()
	appStopped = true
	for key, value := range logs.snapshot() {
		bench.result.Logs[key] = value
	}
	bench.result.FinishedAt = time.Now().UTC()

	if err := writeJSON(options.output+".json", bench.result); err != nil {
		return errors.New("write result JSON failed")
	}
	if err := os.WriteFile(options.output+".md", []byte(renderMarkdown(bench.result)), 0o644); err != nil {
		return errors.New("write result Markdown failed")
	}
	fmt.Fprintf(stdout, "audit-bench: wrote %s.json and %s.md\n", options.output, options.output)
	return nil
}

func waitReady(ctx context.Context, client *http.Client, adminURL, token string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, adminURL+"/readyz", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if err := sleepContext(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("the application did not become ready; is the database reachable?")
}

type drainState struct {
	open, analysis, identity int64
	timedOut                 bool
}

// drain waits until every audit is terminal, caller lookups are done and
// analysis has caught up. Candidates that stay unchanged for five polls are
// treated as permanently skipped and reported.
func (bench *bench) drain(ctx context.Context, served int64, options runOptions) drainState {
	deadline := time.Now().Add(options.drainTimeout)
	var state drainState
	stable := 0
	var previous [3]int64
	for {
		var total, open, callerPending int64
		err := bench.stats.inTx(ctx, true, func(tx pgx.Tx) error {
			bench.stats.drainPolls++
			return tx.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE ended_at_ns IS NULL OR parse_status IN ('pending', 'processing')),
       count(*) FILTER (WHERE caller_status = 'pending'),
       (SELECT count(*) FROM audit_records AS ar LEFT JOIN audit_analysis AS aa ON aa.audit_id = ar.audit_id
         WHERE ar.ended_at_ns IS NOT NULL AND ar.parse_status IN ('ok', 'partial')
           AND (aa.audit_id IS NULL OR aa.analysis_version < $1)),
       (SELECT count(*) FROM audit_analysis AS aa LEFT JOIN audit_project_identity AS pi ON pi.audit_id = aa.audit_id
         WHERE pi.audit_id IS NULL OR pi.identity_version < $2)
FROM audit_records`, insights.AnalysisVersion, insights.ProjectIdentityVersion).Scan(&total, &open, &callerPending, &state.analysis, &state.identity)
		})
		if err == nil {
			state.open = open
			if !options.workload.CallerLookups {
				callerPending = 0
			}
			if !options.workload.Insights {
				state.analysis = 0
			}
			if !options.workload.OrgReports {
				state.identity = 0
			}
			settled := total >= served && open == 0 && callerPending == 0
			current := [3]int64{total, state.analysis, state.identity}
			if settled && current == previous {
				stable++
			} else {
				stable = 0
			}
			previous = current
			if settled && (state.analysis == 0 && state.identity == 0 || stable >= 5) {
				return state
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			state.timedOut = true
			return state
		}
		_ = sleepContext(ctx, time.Second)
	}
}

// sampleOrder returns the request ids that may be sampled, sorted by each
// request's place in the workload. Request ids are random per run, so sorting
// by them would make the seeded shuffle pick a different mix of audits each
// time and the read percentiles of two runs would not be comparable.
func sampleOrder(records []requestRecord) []string {
	usable := make([]requestRecord, 0, len(records))
	for _, record := range records {
		if record.requestID != "" && record.err != "transport" {
			usable = append(usable, record)
		}
	}
	sort.SliceStable(usable, func(left, right int) bool { return usable[left].order < usable[right].order })
	ids := make([]string, 0, len(usable))
	for _, record := range usable {
		ids = append(ids, record.requestID)
	}
	return ids
}

// readSample picks the audits whose detail and export are read. It runs at
// the end of the drain phase so the lookup does not touch the reads phase.
func (bench *bench) readSample(ctx context.Context, records []requestRecord) []string {
	_, known, _ := bench.tracker.results()
	ids := sampleOrder(records)
	rng := mathrand.New(mathrand.NewPCG(bench.options.workload.Seed, 0x7eed))
	rng.Shuffle(len(ids), func(left, right int) { ids[left], ids[right] = ids[right], ids[left] })
	if len(ids) > bench.options.workload.ReadSamples {
		ids = ids[:bench.options.workload.ReadSamples]
	}
	missing := make([]string, 0)
	audits := make([]string, 0, len(ids))
	for _, id := range ids {
		if audit, ok := known[id]; ok {
			audits = append(audits, audit)
		} else {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		_ = bench.stats.inTx(ctx, true, func(tx pgx.Tx) error {
			bench.stats.drainPolls++
			rows, err := tx.Query(ctx, `SELECT audit_id FROM audit_records WHERE newapi_request_id = ANY($1)`, missing)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var audit string
				if err := rows.Scan(&audit); err == nil {
					audits = append(audits, audit)
				}
			}
			return rows.Err()
		})
	}
	return audits
}

func adminGet(ctx context.Context, client *http.Client, target, token string) (int, time.Duration) {
	started := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, 0
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return 0, time.Since(started)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode, time.Since(started)
}

// sampleReads reads the detail and both exports of each sampled audit, one
// request at a time. An export falls back to the raw body when no verified
// reconstruction exists, which is how the UI offers the download.
func sampleReads(ctx context.Context, client *http.Client, adminURL, token string, audits []string) ReadSummary {
	summary := ReadSummary{Sampled: len(audits), Statuses: make(map[string]int64)}
	var detail, request, response []float64
	for _, audit := range audits {
		base := adminURL + "/api/v1/audits/" + url.PathEscape(audit)
		status, elapsed := adminGet(ctx, client, base, token)
		summary.Statuses[fmt.Sprintf("detail %d", status)]++
		if status == http.StatusOK {
			detail = append(detail, milliseconds(elapsed))
		}
		for _, side := range []string{"request", "response"} {
			status, elapsed := adminGet(ctx, client, base+"/reconstructed/"+side, token)
			kind := "reconstructed"
			if status != http.StatusOK {
				summary.Statuses[fmt.Sprintf("export_%s reconstructed %d", side, status)]++
				summary.RawFallbacks++
				status, elapsed = adminGet(ctx, client, base+"/raw/"+side, token)
				kind = "raw"
			}
			summary.Statuses[fmt.Sprintf("export_%s %s %d", side, kind, status)]++
			if status == http.StatusOK {
				if side == "request" {
					request = append(request, milliseconds(elapsed))
				} else {
					response = append(response, milliseconds(elapsed))
				}
			}
		}
	}
	summary.Detail, summary.ExportRequest, summary.ExportResponse = summarize(detail), summarize(request), summarize(response)
	return summary
}

func (bench *bench) summarizeClient(records []requestRecord) {
	latency, _, open := bench.tracker.results()
	client := ClientSummary{ByCase: make(map[string]int64), Errors: make(map[string]int64), ByGroup: make(map[string]GroupLatencies), QueryableMissed: int64(open)}
	var ttfb, end, queryable []float64
	groups := make(map[string][3][]float64)
	for _, record := range records {
		client.Requests++
		client.ByCase[record.caseName]++
		bench.result.Audits.RequestBodyBytes += int64(record.sentBytes)
		if record.err != "" {
			client.Errors[record.err]++
		}
		values := groups[record.group]
		if record.ttfb > 0 {
			ttfb = append(ttfb, milliseconds(record.ttfb))
			values[0] = append(values[0], milliseconds(record.ttfb))
		}
		end = append(end, milliseconds(record.end))
		values[1] = append(values[1], milliseconds(record.end))
		if value, ok := latency[record.requestID]; ok {
			queryable = append(queryable, milliseconds(value))
			values[2] = append(values[2], milliseconds(value))
		}
		groups[record.group] = values
	}
	client.TTFB, client.EndOfStream, client.Queryable = summarize(ttfb), summarize(end), summarize(queryable)
	for group, values := range groups {
		client.ByGroup[group] = GroupLatencies{TTFB: summarize(values[0]), EndOfStream: summarize(values[1]), Queryable: summarize(values[2])}
	}
	if open > 0 {
		bench.warn("%d tracked requests never became queryable with a terminal parse status", open)
	}
	bench.result.Client = client
}

// summarizeDatabase reads exact row counts and status breakdowns after the
// last snapshot, and checks every request's parse status against the
// fixture's expectation.
func (bench *bench) summarizeDatabase(ctx context.Context, final snapshot, records []requestRecord) error {
	names := make([]string, 0, len(final.tables))
	for name := range final.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	audits := &bench.result.Audits
	audits.ByForwardStatus, audits.ByCaptureStatus, audits.ByParseStatus = map[string]int64{}, map[string]int64{}, map[string]int64{}
	audits.ByRetention, audits.ByCallerStatus, audits.Mismatches = map[string]int64{}, map[string]int64{}, map[string]int64{}
	statuses := make(map[string]string)
	err := bench.stats.inTx(ctx, true, func(tx pgx.Tx) error {
		for _, name := range names {
			var rows int64
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{name}.Sanitize()).Scan(&rows); err != nil {
				return err
			}
			table := final.tables[name]
			bench.result.Tables = append(bench.result.Tables, TableFinal{Name: name, Rows: rows, HeapBytes: table.HeapBytes,
				ToastBytes: table.ToastBytes, IndexBytes: table.IndexBytes, TotalBytes: table.HeapBytes + table.ToastBytes + table.IndexBytes})
		}
		rows, err := tx.Query(ctx, `SELECT forward_status, capture_status, parse_status, caller_status, count(*) FROM audit_records GROUP BY 1, 2, 3, 4`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var forward, capture, parse, caller string
			var count int64
			if err := rows.Scan(&forward, &capture, &parse, &caller, &count); err != nil {
				rows.Close()
				return err
			}
			audits.Count += count
			audits.ByForwardStatus[forward] += count
			audits.ByCaptureStatus[capture] += count
			audits.ByParseStatus[parse] += count
			audits.ByCallerStatus[caller] += count
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT retention_state, count(*) FROM body_streams GROUP BY 1`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var state string
			var count int64
			if err := rows.Scan(&state, &count); err != nil {
				rows.Close()
				return err
			}
			audits.ByRetention[state] = count
		}
		rows.Close()
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM turns), (SELECT count(*) FROM conversations)`).Scan(&audits.Turns, &audits.Conversations); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT newapi_request_id, parse_status FROM audit_records WHERE newapi_request_id IS NOT NULL`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, status string
			if err := rows.Scan(&id, &status); err != nil {
				rows.Close()
				return err
			}
			statuses[id] = status
		}
		rows.Close()
		return rows.Err()
	})
	if err != nil {
		return safeError("read final summary", err)
	}
	for _, record := range records {
		status, ok := statuses[record.requestID]
		switch {
		case !record.forwarded:
			audits.NotForwarded++
		case !ok:
			audits.ExpectationLost++
			audits.Mismatches[record.caseName+" -> no audit"]++
		case status == record.expect:
			audits.ExpectationOK++
		default:
			audits.ExpectationMiss++
			audits.Mismatches[fmt.Sprintf("%s -> %s (want %s)", record.caseName, status, record.expect)]++
		}
	}
	if audits.NotForwarded > 0 {
		bench.warn("%d requests never reached the upstream (rejected by an interceptor or failed in transport)", audits.NotForwarded)
	}
	if audits.ExpectationMiss > 0 || audits.ExpectationLost > 0 {
		bench.warn("%d audits had an unexpected parse status and %d requests had no audit", audits.ExpectationMiss, audits.ExpectationLost)
	}
	return nil
}
