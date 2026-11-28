package integration_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/archive/runner"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// The archive acceptance harness (doc/design/issue-59-stage4-cold-archive.md
// J, N): one PostgreSQL schema with the real proxy handler, the audit
// manager with staging, the parser worker and the query service wired as
// internal/app wires them, and the archive runner assembled as
// internal/app/archive.go assembles it, with the runner's clock, fault and
// step seams that the application keeps unexported. Traffic is sent through
// an HTTP server in front of the proxy handler, one request at a time.

// archiveLogBuffer is a goroutine-safe log sink.
type archiveLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (buffer *archiveLogBuffer) Write(p []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.Write(p)
}

func (buffer *archiveLogBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return bytes.Clone(buffer.data.Bytes())
}

var archiveRoutes = []config.RouteConfig{
	{ID: "openai-chat-completions", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions", Interceptors: []string{"credential"}},
	{ID: "openai-responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses", Interceptors: []string{"credential"}},
	{ID: "anthropic-messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages", Interceptors: []string{"credential"}},
	{ID: "gemini-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content", Interceptors: []string{"credential"}},
	{ID: "gemini-stream-generate-content", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content", Interceptors: []string{"credential"}},
}

type archiveRigOptions struct {
	// dsn and keyPath reuse an existing schema and key (an application ran
	// on them before); empty creates new ones.
	dsn, keyPath string
	encrypt      bool
	// deferWorker leaves the parser worker stopped until startWorker.
	deferWorker bool
	// wrapUpstream wraps the fake provider (to add response headers).
	wrapUpstream func(http.Handler) http.Handler
	// segmentMaxBytes and minTurns are the runner's bundle thresholds; zero
	// is 16 MiB and 4.
	segmentMaxBytes int64
	minTurns        int
}

type archiveRig struct {
	t       *testing.T
	ctx     context.Context
	options archiveRigOptions
	dsn     string
	// db is query-only; rw writes, for the tests that change rows after the
	// fact as an attacker or a bug would.
	db, rw   *sql.DB
	keyPath  string
	key      []byte
	cipher   *security.AESGCM
	store    *postgres.Store
	worker   *parser.Worker
	stopWork context.CancelFunc
	upstream *protofixture.Upstream
	server   *httptest.Server
	client   *http.Client
	hot      *query.Service
	keys     *security.ArchiveKeys
	events   *security.IntegritySigner
	dir      string
	logs     *archiveLogBuffer
	runner   *runner.Runner
	// offset is added to the runner's clock.
	offset atomic.Int64
	fault  atomic.Pointer[func(operation, path string) error]
	step   atomic.Pointer[func(step string) error]
	// readerRoots is the directory of every reader rig.reader opened.
	readerRoots map[*archivecli.Reader]string
	// seen lists the audit ids found so far, in sending order.
	seen []string
}

func newArchiveRig(t *testing.T, options archiveRigOptions) *archiveRig {
	t.Helper()
	ctx := context.Background()
	rig := &archiveRig{t: t, ctx: ctx, options: options, logs: &archiveLogBuffer{}, client: &http.Client{Timeout: archiveClientTimeout}}
	rig.dsn = options.dsn
	if rig.dsn == "" {
		rig.dsn = newIntegrationDatabaseURL(t)
	}
	rig.keyPath = options.keyPath
	if rig.keyPath == "" {
		rig.keyPath = filepath.Join(t.TempDir(), "key", "audit.key")
		if err := os.MkdirAll(filepath.Dir(rig.keyPath), 0o700); err != nil {
			t.Fatal(err)
		}
		key := make([]byte, security.KeySize)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rig.keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key, err := security.LoadOrCreateKey(rig.keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	rig.key = key
	rig.db = openAuditDatabase(t, rig.dsn)
	t.Cleanup(func() { _ = rig.db.Close() })
	if rig.rw, err = sql.Open("pgx", rig.dsn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rig.rw.Close() })
	store, err := postgres.Open(ctx, rig.dsn)
	if err != nil {
		t.Fatal(err)
	}
	rig.store = store
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatalf("integrity chain: %v", err)
	}
	if rig.cipher, err = security.NewAESGCM(key); err != nil {
		t.Fatal(err)
	}
	fingerprints, err := security.NewCredentialFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	if rig.keys, err = security.DeriveArchiveKeys(key); err != nil {
		t.Fatal(err)
	}
	if rig.events, err = security.NewIntegritySigner(key); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(rig.logs, nil))
	stager, err := staging.Open(filepath.Join(t.TempDir(), "staging"), rig.cipher, staging.Options{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	if _, err := store.RecoverInterruptedAudits(ctx, time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	manager, err := audit.NewManagerWithOptions(store, rig.cipher, fingerprints, audit.ModeAvailable, logger, audit.Options{Stager: stager})
	if err != nil {
		t.Fatal(err)
	}
	if rig.worker, err = parser.NewWorker(store, rig.cipher, builtin.All(), logger); err != nil {
		t.Fatal(err)
	}
	manager.SetCompletionNotifier(rig.worker.Notify)
	manager.SetHandover(rig.worker.Submit)
	t.Cleanup(func() {
		if rig.stopWork != nil {
			rig.stopWork()
		}
		rig.worker.Close()
	})
	if !options.deferWorker {
		rig.startWorker()
	}
	matcher, err := routing.Compile(archiveRoutes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := interceptor.NewEngine(map[string]config.InterceptorConfig{"credential": {Type: "require_credential"}}, archiveRoutes)
	if err != nil {
		t.Fatal(err)
	}
	rig.upstream = protofixture.NewUpstream("ar")
	rig.upstream.SetRequestID = false
	// A client-cancel answer waits at its cut for the client to go away;
	// the client closes at once, so this only bounds a slow machine.
	rig.upstream.CancelWait = 2 * time.Minute
	var provider http.Handler = rig.upstream
	if options.wrapUpstream != nil {
		provider = options.wrapUpstream(provider)
	}
	upstreamServer := httptest.NewServer(provider)
	t.Cleanup(upstreamServer.Close)
	target, _ := url.Parse(upstreamServer.URL)
	rig.server = httptest.NewServer(proxy.NewWithAudit(target, matcher, engine, manager, logger))
	t.Cleanup(rig.server.Close)
	if rig.hot, err = query.New(store, rig.cipher); err != nil {
		t.Fatal(err)
	}
	rig.dir = filepath.Join(t.TempDir(), "archive")
	if err := staging.PrepareDirectory(rig.dir); err != nil {
		t.Fatal(err)
	}
	rig.buildRunner()
	return rig
}

func (rig *archiveRig) startWorker() {
	rig.t.Helper()
	ctx, cancel := context.WithCancel(rig.ctx)
	rig.stopWork = cancel
	if err := rig.worker.Start(ctx); err != nil {
		rig.t.Fatal(err)
	}
}

// buildRunner assembles the runner as internal/app assembleArchive does,
// with the seams of the internal/app tests.
func (rig *archiveRig) buildRunner() {
	t := rig.t
	t.Helper()
	segmentMax := rig.options.segmentMaxBytes
	if segmentMax == 0 {
		segmentMax = config.MinArchiveSegmentMaxBytes
	}
	minTurns := rig.options.minTurns
	if minTurns == 0 {
		minTurns = 4
	}
	created, err := runner.New(runner.Options{
		Mode: storage.ArchiveModeExportOnly, Dir: filepath.Clean(rig.dir), Encrypt: rig.options.encrypt, RunAt: config.DefaultArchiveRunAt,
		Location: time.UTC, RetentionDays: 1, SegmentMaxBytes: segmentMax, ConversationMinTurns: minTurns,
		ConversationMinBytes: config.DefaultArchiveConversationMinBytes, PassAudits: config.DefaultArchivePassAudits,
		RunDeadline: time.Duration(config.DefaultArchiveRunDeadlineMinutes) * time.Minute,
		// The default sample (at least one member per bundle): the tests
		// compare every member themselves (compare), and a full sample
		// would repeat that pass inside every run.
		VerifySample: config.DefaultArchiveVerifySample,
		Store:        runner.FromPostgres(rig.store, postgres.ArchiveSnapshotOptions{Cipher: rig.cipher, Fingerprinter: rig.keys}),
		Keys:         rig.keys, Events: rig.events,
		Sampler:             runner.QuerySampler{Hot: rig.hot, Fingerprinter: rig.keys},
		SourceSchemaVersion: strconv.Itoa(postgres.LatestSchemaVersion),
		Logger:              slog.New(slog.NewJSONHandler(rig.logs, nil)),
		Now:                 func() time.Time { return time.Now().Add(time.Duration(rig.offset.Load())) },
		Fault: func(operation, path string) error {
			if hook := rig.fault.Load(); hook != nil {
				return (*hook)(operation, path)
			}
			return nil
		},
		Step: func(step string) error {
			if hook := rig.step.Load(); hook != nil {
				return (*hook)(step)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.runner = created
}

// due puts the runner's clock exactly retention_days ahead: the cutoff of
// a run is then the wall time it starts, so everything sent before is due
// and nothing sent during the run is.
func (rig *archiveRig) due() { rig.offset.Store(int64(24 * time.Hour)) }

func (rig *archiveRig) run() (runner.Result, error) {
	rig.t.Helper()
	return rig.runner.RunOnce(rig.ctx)
}

func (rig *archiveRig) mustRun() runner.Result {
	rig.t.Helper()
	result, err := rig.run()
	if err != nil || result.Status != storage.ArchiveRunCompleted {
		rig.t.Fatalf("archive run %+v: %v", result, err)
	}
	return result
}

// requireCleanRun requires that a run archived exactly want audits and left
// nothing out: no exclusion, refusal, sample mismatch, deferral, integrity
// failure or rejected bundle (R.5 item 8 on real traffic).
func (rig *archiveRig) requireCleanRun(result runner.Result, want int) {
	rig.t.Helper()
	rig.requireCleanCounts(result, want)
	for name := range rig.files() {
		if strings.HasSuffix(name, bundle.RejectedSuffix) {
			rig.t.Fatalf("rejected bundle %s", name)
		}
	}
}

// requireCleanCounts is requireCleanRun without the look for rejected
// bundles on disk, for a run after one whose bundle was rejected.
func (rig *archiveRig) requireCleanCounts(result runner.Result, want int) {
	rig.t.Helper()
	deferred := int64(0)
	for _, count := range result.Deferred {
		deferred += count
	}
	if result.Counts.ExportedAudits != int64(want) || result.Excluded != 0 || result.Refused != 0 || result.SampleMismatched != 0 ||
		deferred != 0 || result.Counts.IntegrityFailedAudits != 0 || result.Counts.StaleAudits != 0 || result.Counts.DeferredAudits != 0 {
		rig.t.Fatalf("run for %d audits: %+v", want, result)
	}
}

// send sends one exchange through the proxy and returns its audit id once
// the audit ended (and, with the worker running, its parse is final).
func (rig *archiveRig) send(exchange protofixture.Exchange) string {
	rig.t.Helper()
	id := rig.upstream.Register(&exchange)
	header := exchange.RequestHeader.Clone()
	header.Set(protofixture.ExchangeHeader, id)
	return rig.sendRequest(exchange.Method, exchange.Path, header, exchange.RequestBody, exchange.Response.ClientCancel, exchange.Response.CutAt)
}

// sendRequest sends one request through the proxy; cancel stops reading
// after cutAt bytes and closes the connection, as a client that gives up.
func (rig *archiveRig) sendRequest(method, path string, header http.Header, body []byte, cancel bool, cutAt int) string {
	t := rig.t
	t.Helper()
	request, err := http.NewRequest(method, rig.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = header
	response, err := rig.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if cancel {
		if _, err := io.ReadFull(response.Body, make([]byte, cutAt)); err != nil {
			t.Fatal(err)
		}
	} else {
		_, _ = io.Copy(io.Discard, response.Body)
	}
	response.Body.Close()
	return rig.newestAudit()
}

// newestAudit waits for the audit of the request just sent (the newest one
// not seen yet), until it ended and, with the worker running, its parse and
// caller lookup are final.
func (rig *archiveRig) newestAudit() string {
	t := rig.t
	t.Helper()
	deadline := time.Now().Add(archiveSettleTimeout)
	seen := append([]string{}, rig.seen...)
	var id string
	for {
		if id == "" {
			_ = rig.db.QueryRow(`SELECT audit_id FROM audit_records WHERE NOT (audit_id = ANY($1)) ORDER BY started_at_ns DESC LIMIT 1`, seen).Scan(&id)
		}
		if id != "" {
			var ended sql.NullInt64
			var parse, caller string
			if err := rig.db.QueryRow(`SELECT ended_at_ns, parse_status, caller_status FROM audit_records WHERE audit_id = $1`, id).Scan(&ended, &parse, &caller); err == nil &&
				ended.Valid && (rig.stopWork == nil || parse != storage.ParsePending && parse != storage.ParseProcessing) {
				if caller == storage.CallerPending {
					t.Fatalf("audit %s waits for a caller lookup", id)
				}
				rig.seen = append(rig.seen, id)
				return id
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no final audit for the request just sent (found %q)", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitParsed waits until every audit's parse is final.
func (rig *archiveRig) waitParsed() {
	t := rig.t
	t.Helper()
	deadline := time.Now().Add(archiveSettleTimeout)
	for {
		var open int
		if err := rig.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE ended_at_ns IS NULL OR parse_status IN ('pending', 'processing')`).Scan(&open); err == nil && open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d audits not final", open)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (rig *archiveRig) auditIDs() []string {
	rig.t.Helper()
	rows, err := rig.db.Query(`SELECT audit_id FROM audit_records ORDER BY started_at_ns, audit_id`)
	if err != nil {
		rig.t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rig.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// archiveKeysOf loads the reader tool's keys from a master key file.
func archiveKeysOf(t *testing.T, keyPath string) *archivecli.Keys {
	t.Helper()
	keys, err := archivecli.LoadKeys(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// reader opens dir with the reader tool's Go API and fully verifies every
// bundle (J.2, with the copied events' MACs).
func (rig *archiveRig) reader(dir string) *archivecli.Reader {
	t := rig.t
	t.Helper()
	reader, err := archivecli.OpenReader(rig.ctx, dir, archivecli.ReaderOptions{Keys: archiveKeysOf(t, rig.keyPath)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if rig.readerRoots == nil {
		rig.readerRoots = map[*archivecli.Reader]string{}
	}
	rig.readerRoots[reader] = dir
	if problems := reader.Index().Problems(); len(problems) > 0 {
		t.Fatalf("index problems %+v", problems)
	}
	for _, entry := range reader.Index().Bundles() {
		if _, err := reader.Bundle(rig.ctx, entry); err != nil {
			t.Fatalf("bundle %s: %v", filepath.Base(entry.ManifestPath), err)
		}
	}
	return reader
}

// cli runs audit-archive with its arguments and returns the exit code,
// standard output and standard error.
func archiveCLI(ctx context.Context, args ...string) (int, []byte, []byte) {
	var stdout, stderr bytes.Buffer
	code := archivecli.Run(ctx, args, &archivecli.Env{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.Bytes(), stderr.Bytes()
}

// files is the SHA-256 of every file under the archive directory, by path
// relative to it.
func (rig *archiveRig) files() map[string][32]byte {
	return archiveFileDigests(rig.t, rig.dir)
}

func archiveFileDigests(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, _ := filepath.Rel(dir, path)
			out[filepath.ToSlash(relative)] = sha256.Sum256(data)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return out
}

func manifestPaths(dir string, files map[string][32]byte) []string {
	var out []string
	for name := range files {
		if strings.HasSuffix(name, bundle.ManifestSuffix) {
			out = append(out, filepath.Join(dir, filepath.FromSlash(name)))
		}
	}
	sort.Strings(out)
	return out
}

// tableHashes is, for every archived table (archive.ManifestTables) and the
// other tables of the schema but the catalog, the SHA-256 of all its rows in
// a fixed order: COPY-like text of every column, rows sorted by that text.
func (rig *archiveRig) tableHashes() map[string]string {
	t := rig.t
	t.Helper()
	rows, err := rig.db.Query(`SELECT table_name FROM information_schema.tables
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
	for table := range archive.ManifestTables() {
		found := false
		for _, name := range tables {
			found = found || name == table
		}
		if !found {
			t.Fatalf("archived table %s is not in the schema", table)
		}
	}
	out := map[string]string{}
	for _, table := range tables {
		var digest string
		var count int64
		// The row's text form covers every column, BYTEA included (as hex).
		if err := rig.db.QueryRow(`SELECT COUNT(*), encode(sha256(convert_to(COALESCE(string_agg(r::text, E'\n' ORDER BY r::text), ''), 'UTF8')), 'hex') FROM "`+table+`" AS r`).Scan(&count, &digest); err != nil {
			t.Fatal(err)
		}
		out[table] = fmt.Sprintf("%d:%s", count, digest)
	}
	return out
}

// catalogRows is the text of every row of the archive catalog tables but
// archive_runs, which gains a row per run.
func (rig *archiveRig) catalogRows() string {
	t := rig.t
	t.Helper()
	var out []string
	for _, table := range []string{"archive_segments", "archive_members", "archive_gap_members", "archive_deferred"} {
		var text string
		if err := rig.db.QueryRow(`SELECT COALESCE(string_agg(r::text, E'\n' ORDER BY r::text), '') FROM "` + table + `" AS r`).Scan(&text); err != nil {
			t.Fatal(err)
		}
		out = append(out, table+":\n"+text)
	}
	return strings.Join(out, "\n")
}

// scanTarget is one place a scan looks: its name and bytes, and whether it
// is a file of the archive.
type scanTarget struct {
	name string
	data []byte
}

// archiveScanTargets reads every file under dir, and with each file that is
// a gzip stream (in full or cut off, as a temporary file can be) also its
// decompressed bytes. File names are targets of their own.
func archiveScanTargets(t *testing.T, dir string) []scanTarget {
	t.Helper()
	var out []scanTarget
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		relative, _ := filepath.Rel(dir, path)
		out = append(out, scanTarget{name: "name of " + relative, data: []byte(relative)})
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // a temporary file removed meanwhile
			}
			return err
		}
		out = append(out, scanTarget{name: relative, data: data})
		if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
			reader, err := gzip.NewReader(bytes.NewReader(data))
			if err == nil {
				plain, _ := io.ReadAll(reader) // a cut-off stream yields what it has
				out = append(out, scanTarget{name: relative + " (gunzipped)", data: plain})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// markerForms are the forms a marker can take in the archive's files: as
// is, JSON-escaped is the same for these ASCII markers, percent-encoded,
// hex, and base64 at all three alignments (the middle part that does not
// depend on the neighbouring bytes).
func markerForms(marker string) [][]byte {
	forms := [][]byte{[]byte(marker), []byte(url.QueryEscape(marker)), []byte(hex.EncodeToString([]byte(marker)))}
	for shift := 0; shift < 3; shift++ {
		padded := append(bytes.Repeat([]byte{'#'}, shift), marker...)
		encoded := base64Std(padded)
		// Drop the characters that mix padding or neighbouring bytes in.
		start := (shift*4 + 2) / 3
		end := len(encoded) - 4
		if end-start >= 8 {
			forms = append(forms, []byte(encoded[start+1:end]))
		}
	}
	return forms
}

func base64Std(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// findMarkers returns "target: marker" for every marker found in any form.
func findMarkers(targets []scanTarget, markers []string) []string {
	var found []string
	for _, target := range targets {
		for _, marker := range markers {
			for _, form := range markerForms(marker) {
				if bytes.Contains(target.data, form) {
					found = append(found, target.name+": "+marker)
					break
				}
			}
		}
	}
	return found
}

// postgresTargets dumps every column of every table of the schema as raw
// bytes, one target per table.
func (rig *archiveRig) postgresTargets(tables ...string) []scanTarget {
	t := rig.t
	t.Helper()
	if len(tables) == 0 {
		rows, err := rig.db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			tables = append(tables, name)
		}
		rows.Close()
	}
	var out []scanTarget
	for _, table := range tables {
		rows, err := rig.db.Query(`SELECT * FROM "` + table + `"`)
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := rows.Columns()
		var data bytes.Buffer
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				switch typed := value.(type) {
				case []byte:
					data.Write(typed)
				case string:
					data.WriteString(typed)
				default:
					fmt.Fprint(&data, typed)
				}
				data.WriteByte(0)
			}
		}
		rows.Close()
		out = append(out, scanTarget{name: "table " + table, data: data.Bytes()})
	}
	return out
}

// describeAudit is what the hot store holds for one audit and the log lines
// that name it, for a failure message that explains itself: the outcome
// columns, each stage and body, the parse result, the turn, and the log.
func (rig *archiveRig) describeAudit(id string) string {
	var out strings.Builder
	var forward, capture, parse string
	var status, ended sql.NullInt64
	var errorCode sql.NullString
	var started int64
	if err := rig.db.QueryRow(`SELECT forward_status, capture_status, parse_status, error_code, status_code, started_at_ns, ended_at_ns FROM audit_records WHERE audit_id = $1`, id).
		Scan(&forward, &capture, &parse, &errorCode, &status, &started, &ended); err != nil {
		return fmt.Sprintf("audit %s not readable: %v", id, err)
	}
	fmt.Fprintf(&out, "audit %s: forward_status=%s capture_status=%s parse_status=%s error_code=%v status_code=%v duration_ms=%d\n",
		id, forward, capture, parse, errorCode.String, status.Int64, (ended.Int64-started)/1e6)
	if rows, err := rig.db.Query(`SELECT s.stage, s.state, COALESCE(s.error_code, ''), COALESCE(b.observed_length, -1), COALESCE(b.stored_length, -1),
  COALESCE(b.state, ''), COALESCE(b.retention_state, ''), COALESCE(b.error_code, ''), COALESCE(b.chunk_count, -1), COALESCE(b.eof_seen, 0), COALESCE(b.source_stage, '')
FROM http_stages AS s LEFT JOIN body_streams AS b ON b.audit_id = s.audit_id AND b.stage = s.stage WHERE s.audit_id = $1 ORDER BY s.started_at_ns`, id); err == nil {
		for rows.Next() {
			var stage, state, stageError, bodyState, retention, bodyError, source string
			var observed, stored, chunks, eof int64
			if rows.Scan(&stage, &state, &stageError, &observed, &stored, &bodyState, &retention, &bodyError, &chunks, &eof, &source) == nil {
				fmt.Fprintf(&out, "  stage %s state=%s error=%s body observed=%d stored=%d state=%s retention=%s error=%s chunks=%d eof=%d source=%s\n",
					stage, state, stageError, observed, stored, bodyState, retention, bodyError, chunks, eof, source)
			}
		}
		rows.Close()
	}
	var parsedStatus, parsedError, parsedClass sql.NullString
	if err := rig.db.QueryRow(`SELECT status, error_code, upstream_error_class FROM parsed_results WHERE audit_id = $1`, id).Scan(&parsedStatus, &parsedError, &parsedClass); err == nil {
		fmt.Fprintf(&out, "  parsed status=%s error_code=%s upstream_error_class=%s\n", parsedStatus.String, parsedError.String, parsedClass.String)
	}
	var turns int
	_ = rig.db.QueryRow(`SELECT COUNT(*) FROM turns WHERE audit_id = $1`, id).Scan(&turns)
	fmt.Fprintf(&out, "  turns=%d\n", turns)
	for _, line := range strings.Split(string(rig.logs.Bytes()), "\n") {
		if strings.Contains(line, id) {
			out.WriteString("  log " + line + "\n")
		}
	}
	return out.String()
}

// Waits of the harness, derived from what they wait for, so that a machine
// many times slower than a workstation (the race detector on a shared CI
// runner) does not turn a slow audit into a failure:
//
//   - archiveSettleTimeout: an audit ends and its parse becomes final. A
//     handover the parser misses is picked up by its pending scan (every
//     30 s, parser.defaultScanInterval) and one parse may take up to the
//     parser's job deadline (2 min); a minute of margin on top.
//   - archiveClientTimeout: one request through the proxy, bounded by the
//     proxy's own response header timeout (5 min by default).
const (
	archiveSettleTimeout = 30*time.Second + 2*time.Minute + time.Minute
	archiveClientTimeout = 5*time.Minute + time.Minute
)

// archiveSendWorkers is how many conversations sendConversations sends at
// once.
const archiveSendWorkers = 4

// sendConversations sends independent conversations through the proxy, up
// to archiveSendWorkers at a time, each conversation's exchanges in order
// (one exchange's audit is final before the next is sent). Each audit is
// found by the SHA-256 of its request body (body_streams.sha256 of the
// inbound stage), which every exchange of the set must have to itself. It
// returns the audit id of every exchange.
func (rig *archiveRig) sendConversations(conversations [][]protofixture.Exchange) map[string]protofixture.Exchange {
	t := rig.t
	t.Helper()
	owner := map[[32]byte]bool{}
	for _, conversation := range conversations {
		for _, exchange := range conversation {
			sum := sha256.Sum256(exchange.RequestBody)
			if owner[sum] {
				t.Fatalf("two exchanges send the same request body (%s/%s)", exchange.Protocol, exchange.Scenario)
			}
			owner[sum] = true
		}
	}
	database, err := sql.Open("pgx", rig.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	type sent struct {
		id       string
		exchange protofixture.Exchange
		err      error
	}
	work := make(chan []protofixture.Exchange)
	results := make(chan sent)
	var workers sync.WaitGroup
	for range archiveSendWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for conversation := range work {
				for _, exchange := range conversation {
					id, err := rig.sendOne(database, exchange)
					results <- sent{id: id, exchange: exchange, err: err}
					if err != nil {
						break
					}
				}
			}
		}()
	}
	go func() {
		for _, conversation := range conversations {
			work <- conversation
		}
		close(work)
		workers.Wait()
		close(results)
	}()
	out := map[string]protofixture.Exchange{}
	var failures []string
	for result := range results {
		if result.err != nil {
			failures = append(failures, result.err.Error())
			continue
		}
		out[result.id] = result.exchange
		rig.seen = append(rig.seen, result.id)
	}
	if len(failures) > 0 {
		t.Fatalf("%d sends failed:\n%s", len(failures), strings.Join(failures, "\n"))
	}
	return out
}

// sendOne sends one exchange and waits, on its own connection, for its
// audit to be final; it may run on any goroutine.
func (rig *archiveRig) sendOne(database *sql.DB, exchange protofixture.Exchange) (string, error) {
	label := fmt.Sprintf("%s/%s stream=%v turn %d", exchange.Protocol, exchange.Scenario, exchange.Stream, exchange.Turn)
	registered := rig.upstream.Register(&exchange)
	request, err := http.NewRequest(exchange.Method, rig.server.URL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	if err != nil {
		return "", err
	}
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(protofixture.ExchangeHeader, registered)
	response, err := rig.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	if exchange.Response.ClientCancel {
		_, err = io.ReadFull(response.Body, make([]byte, exchange.Response.CutAt))
	} else {
		// An upstream abort ends the answer early: the error is the scenario.
		_, _ = io.Copy(io.Discard, response.Body)
	}
	response.Body.Close()
	if err != nil {
		return "", fmt.Errorf("%s: read the answer: %w", label, err)
	}
	sum := sha256.Sum256(exchange.RequestBody)
	deadline := time.Now().Add(archiveSettleTimeout)
	var id string
	for {
		if id == "" {
			_ = database.QueryRow(`SELECT audit_id FROM body_streams WHERE stage = $1 AND sha256 = $2`, storage.StageRequestReceived, sum[:]).Scan(&id)
		}
		if id != "" {
			var ended sql.NullInt64
			var parse, caller string
			if err := database.QueryRow(`SELECT ended_at_ns, parse_status, caller_status FROM audit_records WHERE audit_id = $1`, id).Scan(&ended, &parse, &caller); err == nil &&
				ended.Valid && parse != storage.ParsePending && parse != storage.ParseProcessing {
				if caller == storage.CallerPending {
					return "", fmt.Errorf("%s: audit %s waits for a caller lookup", label, id)
				}
				return id, nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s: no final audit after %v (found %q)", label, archiveSettleTimeout, id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// archiveWaitFinal waits up to archiveSettleTimeout until one audit ended
// and its parse is final.
func archiveWaitFinal(t *testing.T, database *sql.DB, auditID string) {
	t.Helper()
	deadline := time.Now().Add(archiveSettleTimeout)
	for time.Now().Before(deadline) {
		var parse string
		var ended sql.NullInt64
		if err := database.QueryRow(`SELECT parse_status, ended_at_ns FROM audit_records WHERE audit_id = $1`, auditID).Scan(&parse, &ended); err == nil &&
			ended.Valid && parse != storage.ParsePending && parse != storage.ParseProcessing {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit %s not final after %v", auditID, archiveSettleTimeout)
}
