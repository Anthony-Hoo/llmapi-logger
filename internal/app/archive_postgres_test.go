package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/archive/runner"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The archive runner end to end on PostgreSQL (design N.2 and the stage 4
// brief): real traffic of the four protocols through the proxy, the parser
// worker and the unified write path, then archive runs with a clock that
// makes the audits due.

type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (buffer *lockedBuffer) Write(p []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.Write(p)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.String()
}

type archiveEnv struct {
	t        *testing.T
	ctx      context.Context
	cfg      config.Config
	db       *sql.DB
	upstream *protofixture.Upstream
	app      *App
	data     *httptest.Server
	logs     *lockedBuffer
	offset   atomic.Int64
	fault    atomic.Pointer[func(operation, path string) error]
	step     atomic.Pointer[func(step string) error]
	sent     int
}

func archiveDSN(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL application integration")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := fmt.Sprintf("app_archive_%d", time.Now().UnixNano())
	if _, err := db.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA " + schema + " CASCADE") })
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	scoped, err := sql.Open("pgx", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scoped.Close() })
	return parsed.String(), scoped
}

func newArchiveEnv(t *testing.T, mode string) *archiveEnv {
	t.Helper()
	dsn, db := archiveDSN(t)
	base := t.TempDir()
	upstream := protofixture.NewUpstream("ar")
	upstream.SetRequestID = false
	upstream.CancelWait = 30 * time.Second
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	cfg := testConfig(t)
	cfg.DatabaseURL = dsn
	cfg.KeyPath = filepath.Join(base, "key", "audit.key")
	cfg.AdminToken = "synthetic-test-admin"
	cfg.NewAPI.URL = server.URL
	cfg.RetentionDays = 1
	cfg.Archive.Mode = mode
	cfg.Archive.Dir = filepath.Join(base, "archive")
	cfg.Archive.VerifySample = 1
	// The streamed conversations of traffic (five turns and more) are
	// conversation bundles, the two-turn ones go to the buckets.
	cfg.Archive.ConversationMinTurns = 4
	cfg.Routes = []config.RouteConfig{
		{ID: "openai-chat-completions", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "openai-responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "anthropic-messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages"},
		{ID: "gemini-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		{ID: "gemini-stream-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
	}
	env := &archiveEnv{t: t, ctx: context.Background(), cfg: cfg, db: db, upstream: upstream, logs: &lockedBuffer{}}
	env.start()
	return env
}

// start assembles the application with the archive seams.
func (env *archiveEnv) start() {
	t := env.t
	t.Helper()
	seams := archiveSeams{
		now: func() time.Time { return time.Now().Add(time.Duration(env.offset.Load())) },
		fault: func(operation, path string) error {
			if hook := env.fault.Load(); hook != nil {
				return (*hook)(operation, path)
			}
			return nil
		},
		step: func(step string) error {
			if hook := env.step.Load(); hook != nil {
				return (*hook)(step)
			}
			return nil
		},
	}
	application, err := NewContext(env.ctx, env.cfg, slog.New(slog.NewJSONHandler(env.logs, nil)), withArchiveSeams(seams))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	if application.auditStore == nil || !application.auditStore.Healthy() {
		t.Fatalf("PostgreSQL did not initialize: %s", env.logs.String())
	}
	if err := application.parserWorker.Start(env.ctx); err != nil {
		t.Fatal(err)
	}
	env.app = application
	if env.data != nil {
		env.data.Close()
	}
	env.data = httptest.NewServer(application.server.Handler)
	t.Cleanup(env.data.Close)
}

// send sends one exchange through the proxy.
func (env *archiveEnv) send(exchange protofixture.Exchange) {
	t := env.t
	t.Helper()
	id := env.upstream.Register(&exchange)
	request, err := http.NewRequest(exchange.Method, env.data.URL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(protofixture.ExchangeHeader, id)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	env.sent++
}

// traffic sends, for every protocol, a streamed conversation of turns
// normal turns with a 429 in the middle and an unterminated stream at the
// end (a request-only turn), and a non-streamed conversation of two turns.
func (env *archiveEnv) traffic(protocols []protofixture.Protocol, turns int) []*protofixture.Conversation {
	t := env.t
	t.Helper()
	options := protofixture.Options{Seed: 59, ItemBytes: 200, SystemBytes: 400, ToolDefinitions: 2}
	var conversations []*protofixture.Conversation
	for index, protocol := range protocols {
		streamed := protofixture.NewConversation(protocol, true, options, 2*index)
		for turn := 0; turn < turns; turn++ {
			features := protofixture.Features{}
			if turn == 1 {
				features.Tools = true
			}
			env.send(streamed.Next(protofixture.ScenarioBasic, features))
			if turn == 0 {
				exchange, err := streamed.Abnormal(protofixture.ScenarioError429)
				if err != nil {
					t.Fatal(err)
				}
				env.send(exchange)
			}
		}
		exchange, err := streamed.Abnormal(protofixture.ScenarioNoTerminal)
		if err != nil {
			t.Fatal(err)
		}
		env.send(exchange)
		plain := protofixture.NewConversation(protocol, false, options, 2*index+1)
		env.send(plain.Next(protofixture.ScenarioBasic, protofixture.Features{Image: true}))
		env.send(plain.Next(protofixture.ScenarioBasic, protofixture.Features{}))
		conversations = append(conversations, streamed, plain)
	}
	if stats := env.upstream.Stats(); stats.Mismatched != 0 || stats.Unknown != 0 {
		t.Fatalf("upstream stats %+v", stats)
	}
	env.waitTerminal()
	return conversations
}

// waitTerminal waits until every sent request is an ended audit whose parse
// is final.
func (env *archiveEnv) waitTerminal() {
	t := env.t
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var total, final int
		err := env.db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE ended_at_ns IS NOT NULL AND parse_status NOT IN ('pending', 'processing')
			AND caller_status <> 'pending') FROM audit_records`).Scan(&total, &final)
		if err == nil && total == env.sent && final == total {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audits %d, final %d, sent %d (%v)", total, final, env.sent, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// due makes every audit so far due: the clock runs retention_days + 1 ahead.
func (env *archiveEnv) due() { env.offset.Store(int64(2 * 24 * time.Hour)) }

func (env *archiveEnv) run() (runner.Result, error) {
	env.t.Helper()
	if env.app.archive == nil {
		env.t.Fatalf("archive runner not assembled: %s", env.logs.String())
	}
	return env.app.archive.RunOnce(env.ctx)
}

func (env *archiveEnv) mustRun() runner.Result {
	env.t.Helper()
	result, err := env.run()
	if err != nil || result.Status != storage.ArchiveRunCompleted {
		env.t.Fatalf("archive run %+v: %v (%v)", result, err, errors.Unwrap(err))
	}
	return result
}

func (env *archiveEnv) auditIDs() []string {
	env.t.Helper()
	rows, err := env.db.Query(`SELECT audit_id FROM audit_records ORDER BY audit_id`)
	if err != nil {
		env.t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			env.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// requireOneSealedMember checks that every audit has exactly one current
// member, sealed, in a sealed segment, and that no other member is current.
func (env *archiveEnv) requireOneSealedMember(ids []string) {
	t := env.t
	t.Helper()
	for _, id := range ids {
		var sealed, current int
		if err := env.db.QueryRow(`
SELECT COUNT(*) FILTER (WHERE m.state = 'sealed' AND s.state = 'sealed'), COUNT(*) FILTER (WHERE m.state <> 'stale')
FROM archive_members AS m JOIN archive_segments AS s ON s.segment_id = m.segment_id WHERE m.audit_id = $1`, id).Scan(&sealed, &current); err != nil {
			t.Fatal(err)
		}
		if sealed != 1 || current != 1 {
			t.Fatalf("audit %s: %d sealed members, %d current", id, sealed, current)
		}
	}
	var publishing int
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM archive_segments WHERE state <> 'sealed'`).Scan(&publishing); err != nil || publishing != 0 {
		t.Fatalf("%d segments not sealed (%v)", publishing, err)
	}
}

// readArchive opens the archive with audit-archive's Go API and verifies
// every bundle fully (J.2, with the events' MACs); it returns the reader.
func (env *archiveEnv) readArchive() (*archivecli.Reader, int) {
	t := env.t
	t.Helper()
	keys, err := archivecli.LoadKeys(env.cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := archivecli.OpenReader(env.ctx, env.cfg.Archive.Dir, archivecli.ReaderOptions{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if problems := reader.Index().Problems(); len(problems) > 0 {
		t.Fatalf("index problems %+v", problems)
	}
	bundles := reader.Index().Bundles()
	for _, entry := range bundles {
		if _, err := reader.Bundle(env.ctx, entry); err != nil {
			t.Fatalf("bundle %s: %v", filepath.Base(entry.ManifestPath), err)
		}
	}
	return reader, len(bundles)
}

// tableCounts counts the rows of every table of the schema but the catalog.
func (env *archiveEnv) tableCounts() map[string]int64 {
	t := env.t
	t.Helper()
	rows, err := env.db.Query(`SELECT table_name FROM information_schema.tables
WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' AND table_name NOT LIKE 'archive\_%' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	counts := map[string]int64{}
	for _, table := range tables {
		var count int64
		if err := env.db.QueryRow(`SELECT COUNT(*) FROM "` + table + `"`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts[table] = count
	}
	return counts
}

// fileDigests is the SHA-256 of every file under the archive directory.
func (env *archiveEnv) fileDigests() map[string][32]byte {
	t := env.t
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.Walk(env.cfg.Archive.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, _ := filepath.Rel(env.cfg.Archive.Dir, path)
			out[filepath.ToSlash(relative)] = sha256.Sum256(data)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return out
}

func manifestCount(files map[string][32]byte) int {
	count := 0
	for name := range files {
		if strings.HasSuffix(name, bundle.ManifestSuffix) {
			count++
		}
	}
	return count
}

// Every due audit of the four protocols lands in exactly one sealed member;
// the bundles verify with audit-archive's Go API and every member reads the
// same from the bundle as from the hot store (the run samples them all, and
// the test compares them again); export_only deletes nothing and direct
// retention is not running; a second run exports nothing; turns a
// conversation gets after it was archived go to a new bundle in a later run
// and the old bundle stays as it was; expired gaps are exported once.
func TestPostgresArchiveExportsEveryDueAudit(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeExportOnly)
	if env.app.retention != nil {
		t.Fatal("direct retention assembled with the archive on")
	}
	if !strings.Contains(env.logs.String(), `"error_category":"archive_export_only"`) {
		t.Fatalf("start-up logs %s", env.logs.String())
	}
	conversations := env.traffic(protofixture.Protocols(), 3)
	if _, err := env.db.Exec(`INSERT INTO audit_gaps (started_at_ns, ended_at_ns, reason, request_count, detail, created_at_ns)
VALUES (1000, 2000, 'queue_full', 3, '', 2001), (3000, 4000, 'db_unavailable', 1, '', 4001)`); err != nil {
		t.Fatal(err)
	}
	before := env.tableCounts()
	ids := env.auditIDs()
	env.due()

	first := env.mustRun()
	if first.Counts.ExportedAudits != int64(len(ids)) || first.Counts.DeferredAudits != 0 || first.Counts.IntegrityFailedAudits != 0 ||
		first.Excluded != 0 || first.ExportedGaps != 2 || first.Counts.Segments < 2 {
		t.Fatalf("first run %+v for %d audits", first, len(ids))
	}
	env.requireOneSealedMember(ids)
	if after := env.tableCounts(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("export_only changed hot rows:\nbefore %v\nafter  %v", before, after)
	}
	reader, bundles := env.readArchive()
	if int64(bundles) != first.Counts.Segments {
		t.Fatalf("%d bundles, %d segments", bundles, first.Counts.Segments)
	}
	kinds := map[string]int{}
	for _, entry := range reader.Index().Bundles() {
		kinds[entry.Manifest.BundleKind]++
	}
	if kinds["conversation"] != 4 || kinds["bucket"] < 1 || kinds["gaps"] != 1 {
		t.Fatalf("bundle kinds %v", kinds)
	}
	keys, err := archivecli.LoadKeys(env.cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	hot, err := query.New(env.app.auditStore, env.app.cipher)
	if err != nil {
		t.Fatal(err)
	}
	sampler := runner.QuerySampler{Hot: hot, Fingerprinter: keys.Archive}
	// The comparison must have had something to compare: count what the hot
	// side serves.
	var details, turns, timelines, raws int
	for _, id := range ids {
		audit, err := reader.Audit(env.ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		equal, err := sampler.Compare(env.ctx, audit)
		if err != nil || !equal {
			t.Fatalf("%s reads differently from the archive (%v)", id, err)
		}
		if _, err := hot.Get(env.ctx, id, nil); err == nil {
			details++
		}
		if _, err := hot.ReconstructTurn(env.ctx, id); err == nil {
			turns++
		}
		if _, err := hot.Timeline(env.ctx, id, query.SideResponse); err == nil {
			timelines++
		}
		for _, side := range []query.Side{query.SideRequest, query.SideResponse} {
			if err := hot.StreamRaw(env.ctx, id, side, io.Discard); err == nil {
				raws++
			}
		}
	}
	t.Logf("%d audits, %d bundles, %d segments: %d details, %d turns, %d timelines, %d raw requests compared",
		len(ids), bundles, first.Counts.Segments, details, turns, timelines, raws)
	if details != len(ids) || turns < len(ids)/2 || timelines == 0 || raws == 0 {
		t.Fatalf("too little compared: %d details, %d turns, %d timelines, %d raw", details, turns, timelines, raws)
	}
	logs := env.logs.String()
	if !strings.Contains(logs, `"msg":"archive run completed"`) || strings.Contains(logs, env.cfg.Archive.Dir) {
		t.Fatalf("logs %s", logs)
	}

	second := env.mustRun()
	if second.Counts.ExportedAudits != 0 || second.Counts.Segments != 0 || second.ExportedGaps != 0 {
		t.Fatalf("second run %+v", second)
	}

	// New turns on archived conversations: the next run puts them in new
	// bundles and leaves every existing file as it was.
	old := env.fileDigests()
	env.send(conversations[0].Next(protofixture.ScenarioBasic, protofixture.Features{}))
	env.send(conversations[3].Next(protofixture.ScenarioBasic, protofixture.Features{}))
	env.waitTerminal()
	third := env.mustRun()
	if third.Counts.ExportedAudits != 2 || third.Counts.Segments < 1 {
		t.Fatalf("third run %+v", third)
	}
	now := env.fileDigests()
	for name, digest := range old {
		if now[name] != digest {
			t.Fatalf("archived file %s changed", name)
		}
	}
	if manifestCount(now) <= manifestCount(old) {
		t.Fatal("no new bundle")
	}
	env.requireOneSealedMember(env.auditIDs())
	env.readArchive()
}

// An audit whose integrity event was tampered stays in the hot store, is
// deferred integrity_failed and reported, and the rest of the pass is
// archived; the store's payload state is failed as after the background
// verification finds damage (P item 4).
func TestPostgresArchiveKeepsATamperedAuditHot(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeExportOnly)
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat}, 2)
	ids := env.auditIDs()
	tampered := ids[len(ids)/2]
	if _, err := env.db.Exec(`UPDATE integrity_events SET event_mac = set_byte(event_mac, 0, get_byte(event_mac, 0) # 1)
WHERE audit_id = $1 AND event_type = 'capture_finalized'`, tampered); err != nil {
		t.Fatal(err)
	}
	env.due()
	result := env.mustRun()
	if result.Counts.IntegrityFailedAudits != 1 || result.Counts.ExportedAudits != int64(len(ids)-1) || result.Deferred[storage.ArchiveDeferredIntegrityFailed] != 1 {
		t.Fatalf("result %+v", result)
	}
	var reason string
	if err := env.db.QueryRow(`SELECT reason FROM archive_deferred WHERE audit_id = $1`, tampered).Scan(&reason); err != nil || reason != storage.ArchiveDeferredIntegrityFailed {
		t.Fatalf("deferral %q, %v", reason, err)
	}
	var members int
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM archive_members WHERE audit_id = $1`, tampered).Scan(&members); err != nil || members != 0 {
		t.Fatalf("tampered audit has %d members", members)
	}
	var others []string
	for _, id := range ids {
		if id != tampered {
			others = append(others, id)
		}
	}
	env.requireOneSealedMember(others)
	if env.app.auditStore.IntegrityPayloadState() != "failed" {
		t.Fatalf("payload state %s", env.app.auditStore.IntegrityPayloadState())
	}
	if !strings.Contains(env.logs.String(), `"error_category":"archive_integrity_failed"`) {
		t.Fatalf("logs %s", env.logs.String())
	}
	// Retried every run, still refused.
	if again := env.mustRun(); again.Counts.IntegrityFailedAudits != 1 || again.Counts.ExportedAudits != 0 {
		t.Fatalf("second run %+v", again)
	}
}

// A run interrupted after the intent, after publication, before the seal
// and before the pass is recorded is completed by the next run's
// reconciliation: every audit in exactly one sealed member, no duplicate
// line in the archive, no temporary file left.
func TestPostgresArchiveReconcilesAnInterruptedRun(t *testing.T) {
	for _, stop := range []string{runner.StepAfterIntent, runner.StepAfterPublish, runner.StepBeforeSeal, runner.StepBeforeRecordPass} {
		t.Run(stop, func(t *testing.T) {
			env := newArchiveEnv(t, config.ArchiveModeExportOnly)
			env.traffic([]protofixture.Protocol{protofixture.AnthropicMessages}, 2)
			ids := env.auditIDs()
			env.due()
			crash := func(step string) error {
				if step == stop {
					return errors.New("crash")
				}
				return nil
			}
			env.step.Store(&crash)
			if _, err := env.run(); err == nil {
				t.Fatal("the run did not stop")
			}
			env.step.Store(nil)
			result := env.mustRun()
			env.requireOneSealedMember(ids)
			reader, _ := env.readArchive()
			lines := map[string]int{}
			for _, entry := range reader.Index().Bundles() {
				for _, member := range entry.Manifest.Members {
					lines[member.AuditID]++
				}
			}
			for _, id := range ids {
				if lines[id] != 1 {
					t.Fatalf("audit %s is in %d bundles (result %+v)", id, lines[id], result)
				}
			}
			for name := range env.fileDigests() {
				if bundle.IsTempName(filepath.Base(name)) {
					t.Fatalf("temporary file %s left", name)
				}
			}
			var interrupted int
			if err := env.db.QueryRow(`SELECT COUNT(*) FROM archive_runs WHERE status = 'interrupted'`).Scan(&interrupted); err != nil || interrupted != 1 {
				t.Fatalf("interrupted runs %d (%v)", interrupted, err)
			}
		})
	}
}

// A full disk while writing leaves no published manifest, registers nothing
// as sealed, and the audits remain due for the next run.
func TestPostgresArchiveDiskFullPublishesNothing(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeExportOnly)
	env.traffic([]protofixture.Protocol{protofixture.Gemini}, 2)
	ids := env.auditIDs()
	env.due()
	full := func(operation, path string) error {
		if operation == bundle.FaultWrite {
			return errors.New("no space left on device")
		}
		return nil
	}
	env.fault.Store(&full)
	result, err := env.run()
	if err == nil || result.Status != storage.ArchiveRunFailed {
		t.Fatalf("result %+v, %v", result, err)
	}
	if files := env.fileDigests(); manifestCount(files) != 0 {
		t.Fatalf("files %v", files)
	}
	var segments int
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM archive_segments`).Scan(&segments); err != nil || segments != 0 {
		t.Fatalf("segments %d (%v)", segments, err)
	}
	var status string
	if err := env.db.QueryRow(`SELECT status FROM archive_runs`).Scan(&status); err != nil || status != storage.ArchiveRunFailed {
		t.Fatalf("run status %q (%v)", status, err)
	}
	if !strings.Contains(env.logs.String(), `"error_category":"archive_failed"`) {
		t.Fatalf("logs %s", env.logs.String())
	}
	env.fault.Store(nil)
	env.mustRun()
	env.requireOneSealedMember(ids)
}

// Guards on PostgreSQL: archive_then_delete exports as export_only and says
// removal is not active; turning the archive off with retention on after
// runs warns that direct deletion resumed and assembles retention again; an
// archive path that is not a directory leaves the runner off and the audit
// working.
func TestPostgresArchiveStartupGuards(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeArchiveThenDelete)
	if !strings.Contains(env.logs.String(), `"error_category":"archive_removal_inactive"`) || env.app.retention != nil {
		t.Fatalf("logs %s", env.logs.String())
	}
	env.traffic([]protofixture.Protocol{protofixture.OpenAIResponses}, 1)
	before := env.tableCounts()
	env.due()
	result := env.mustRun()
	if result.Counts.ExportedAudits != int64(env.sent) {
		t.Fatalf("result %+v", result)
	}
	if after := env.tableCounts(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("archive_then_delete removed hot rows in this build step")
	}
	if err := env.app.Close(); err != nil {
		t.Fatal(err)
	}

	env.cfg.Archive.Mode = config.ArchiveModeOff
	env.cfg.RetentionDays = 30
	env.logs = &lockedBuffer{}
	env.start()
	if env.app.retention == nil || env.app.archive != nil ||
		!strings.Contains(env.logs.String(), `"error_category":"archive_direct_delete_resumed"`) {
		t.Fatalf("retention %v archive %v logs %s", env.app.retention, env.app.archive, env.logs.String())
	}
	if err := env.app.Close(); err != nil {
		t.Fatal(err)
	}

	env.cfg.Archive.Mode = config.ArchiveModeExportOnly
	env.cfg.Archive.Dir = filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(env.cfg.Archive.Dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.logs = &lockedBuffer{}
	env.start()
	if env.app.archive != nil || !strings.Contains(env.logs.String(), `"error_category":"archive_unavailable"`) ||
		!env.app.auditSink.Healthy() || env.app.retention != nil {
		t.Fatalf("archive %v logs %s", env.app.archive, env.logs.String())
	}
}
