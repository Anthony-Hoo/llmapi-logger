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
	// formatVersion, when positive, overrides the runner's format version
	// (archive_remove_postgres_test.go).
	formatVersion int64
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
	return newArchiveEnvWith(t, mode, nil)
}

// newArchiveEnvWith is newArchiveEnv with a hook that adjusts the
// environment before the application starts.
func newArchiveEnvWith(t *testing.T, mode string, configure func(*archiveEnv)) *archiveEnv {
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
	if configure != nil {
		configure(env)
	}
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
		formatVersion: env.formatVersion,
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

// blockedRequest sends a request a content policy rule rejects before
// NewAPI: an audit without a turn.
func (env *archiveEnv) blockedRequest() {
	t := env.t
	t.Helper()
	admin := httptest.NewServer(env.app.adminServer.Handler())
	defer admin.Close()
	post := func(base, path, body string) int {
		request, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+env.cfg.AdminToken)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode
	}
	if status := post(admin.URL, "/api/v1/content-policy-rules", `{"name":"archive-test","enabled":true,"action":"block","scan_scopes":["latest_user"],"keywords":["ARCHIVE_BLOCK"]}`); status != http.StatusCreated {
		t.Fatalf("rule status %d", status)
	}
	if status := post(env.data.URL, "/v1/chat/completions", `{"model":"lab-model","messages":[{"role":"user","content":"ARCHIVE_BLOCK"}]}`); status != http.StatusBadRequest {
		t.Fatalf("block status %d", status)
	}
	env.sent++
	env.waitTerminal()
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
	env.blockedRequest()
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
	// The blocked request has no turn: it is the last line of its bucket.
	turnless := 0
	for _, entry := range reader.Index().Bundles() {
		members := entry.Manifest.Members
		for index, member := range members {
			if member.ConversationID == nil {
				turnless++
				if entry.Manifest.BundleKind != "bucket" || index != len(members)-1 {
					t.Fatalf("turnless audit at line %d of %d in a %s bundle", index, len(members), entry.Manifest.BundleKind)
				}
			}
		}
	}
	if turnless != 1 {
		t.Fatalf("%d turnless members", turnless)
	}
	var protocols []string
	if rows, err := env.db.Query(`SELECT DISTINCT protocol FROM audit_records ORDER BY protocol`); err == nil {
		for rows.Next() {
			var protocol string
			_ = rows.Scan(&protocol)
			protocols = append(protocols, protocol)
		}
		rows.Close()
	}
	t.Logf("bundle kinds %v, audit protocols %v", kinds, protocols)
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

// J.3: a member that changes between the export and the sample reads
// differently from the hot store, but its change stamp (ArchiveChangeStamp)
// shows the change, so it counts as stale and the bundle stands.
func TestPostgresArchiveSampleTreatsAChangedRecordAsStale(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeExportOnly)
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat}, 1)
	ids := env.auditIDs()
	env.due()
	changed := false
	late := func(step string) error {
		if step == runner.StepAfterPublish && !changed {
			changed = true
			if _, err := env.db.Exec(`UPDATE audit_records SET ttft_ns = COALESCE(ttft_ns, 0) + 1 WHERE audit_id = $1`, ids[0]); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	env.step.Store(&late)
	result := env.mustRun()
	if !changed || result.Counts.StaleAudits < 1 || result.Counts.Segments < 1 {
		t.Fatalf("result %+v", result)
	}
	for name := range env.fileDigests() {
		if strings.HasSuffix(name, bundle.RejectedSuffix) {
			t.Fatalf("bundle rejected: %s", name)
		}
	}
	env.requireOneSealedMember(ids)
}

// One member in the middle of a pass that cannot be archived must not stop
// the archive. The member's own response object is damaged in the hot store
// after the export snapshot was taken: the snapshot still exports and
// writes it, but the hot store no longer serves it the same, and its change
// stamp (which does not cover shared content objects) is unchanged, so the
// read-equivalence sample attributes the difference to that member. Its
// bundle is rejected, the member deferred export_failed and left hot, and
// every other due audit ends in a sealed bundle that verifies; the
// watermark advances and the next run completes.
//
// A writer refusal cannot be produced from real rows: Export runs the same
// checks first and excludes such a record itself. The refusal path is
// covered by the runner's host tests.
func TestPostgresArchiveDefersOneUnarchivableMember(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeExportOnly)
	env.traffic([]protofixture.Protocol{protofixture.OpenAIChat, protofixture.AnthropicMessages}, 2)
	ids := env.auditIDs()
	// A turn no other turn builds on, and its own answer object.
	var bad string
	var object []byte
	if err := env.db.QueryRow(`
SELECT t.audit_id, i.object_hash FROM turns AS t JOIN turn_response_items AS i ON i.turn_id = t.turn_id
JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE NOT EXISTS (SELECT 1 FROM turns AS c WHERE c.parent_turn_id = t.turn_id)
  AND (SELECT COUNT(*) FROM turn_response_items AS o WHERE o.object_hash = i.object_hash) = 1
  AND NOT EXISTS (SELECT 1 FROM turn_context_ops AS p WHERE p.object_hash = i.object_hash)
ORDER BY a.started_at_ns LIMIT 1 OFFSET 1`).Scan(&bad, &object); err != nil {
		t.Fatal(err)
	}
	env.due()
	damaged := false
	damage := func(step string) error {
		if step == runner.StepAfterPublish && !damaged {
			damaged = true
			if _, err := env.db.Exec(`UPDATE content_objects SET data_enc = set_byte(data_enc, 20, get_byte(data_enc, 20) # 1) WHERE object_hash = $1`, object); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	env.step.Store(&damage)
	result := env.mustRun()
	env.step.Store(nil)
	if !damaged || result.SampleMismatched != 1 || result.Counts.ExportedAudits != int64(len(ids)-1) {
		t.Fatalf("result %+v for %d audits", result, len(ids))
	}
	var reason string
	if err := env.db.QueryRow(`SELECT reason FROM archive_deferred WHERE audit_id = $1`, bad).Scan(&reason); err != nil || reason != storage.ArchiveDeferredExportFailed {
		t.Fatalf("deferral %q (%v)", reason, err)
	}
	var current, hot int
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM archive_members WHERE audit_id = $1 AND state <> 'stale'`, bad).Scan(&current); err != nil || current != 0 {
		t.Fatalf("the bad member has %d current members", current)
	}
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE audit_id = $1`, bad).Scan(&hot); err != nil || hot != 1 {
		t.Fatal("the bad member left the hot store")
	}
	var others []string
	for _, id := range ids {
		if id != bad {
			others = append(others, id)
		}
	}
	env.requireOneSealedMember(others)
	reader, _ := env.readArchive()
	for _, entry := range reader.Index().Bundles() {
		for _, member := range entry.Manifest.Members {
			if member.AuditID == bad {
				t.Fatal("a live bundle holds the bad member")
			}
		}
	}
	rejected := 0
	for name := range env.fileDigests() {
		if strings.HasSuffix(name, bundle.ManifestSuffix+bundle.RejectedSuffix) {
			rejected++
		}
	}
	if rejected != 1 {
		t.Fatalf("%d rejected bundles", rejected)
	}
	var watermark sql.NullString
	if err := env.db.QueryRow(`SELECT watermark_audit_id FROM archive_runs WHERE run_id = $1`, result.RunID).Scan(&watermark); err != nil ||
		!watermark.Valid || !env.isLastStarted(watermark.String) {
		t.Fatalf("watermark %v (%v)", watermark, err)
	}
	if !strings.Contains(env.logs.String(), `"sample_mismatch_audits":1`) {
		t.Fatalf("logs %s", env.logs.String())
	}
	// The next run looks at the deferred member again (its object no
	// longer opens, so the export now refuses it as damaged) and completes.
	again := env.mustRun()
	if again.Counts.ExportedAudits != 0 || again.Counts.IntegrityFailedAudits != 1 {
		t.Fatalf("second run %+v", again)
	}
}

// isLastStarted reports whether id is the audit that started last.
func (env *archiveEnv) isLastStarted(id string) bool {
	var last string
	if err := env.db.QueryRow(`SELECT audit_id FROM audit_records ORDER BY started_at_ns DESC, audit_id DESC LIMIT 1`).Scan(&last); err != nil {
		env.t.Fatal(err)
	}
	return last == id
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

// Guards on PostgreSQL: archive_then_delete at the built-in trial format
// version 0 says so, exports and removes nothing; turning the archive off
// with retention on after
// runs warns that direct deletion resumed and assembles retention again; an
// archive path that is not a directory leaves the runner off and the audit
// working.
func TestPostgresArchiveStartupGuards(t *testing.T) {
	env := newArchiveEnv(t, config.ArchiveModeArchiveThenDelete)
	if !strings.Contains(env.logs.String(), `"error_category":"archive_removal_active"`) ||
		!strings.Contains(env.logs.String(), `"error_category":"archive_removal_trial_format"`) || env.app.retention != nil {
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
		t.Fatal("archive_then_delete removed hot rows at format version 0")
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
