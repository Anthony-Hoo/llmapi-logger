package proxy

// Design I.1 on SQLite: the same traffic goes through the real proxy handler
// once per write path, with the same deterministic clock, audit ids and
// upstream, and everything observable is compared: the bytes and headers the
// client received, the completion log line, every stored row (ciphertext
// opened under the AAD of its own row), the detail view, the raw, timeline
// and reconstruction exports, and the parse results.
//
// Determinism needs every read and write to happen in the same pieces in
// both runs, so nothing crosses a socket: the client request is a recorder
// call and the upstream is a scripted RoundTripper on the handler's
// ReverseProxy. The capture clock is a counter; the parser worker's clock
// cannot be injected from this package, so the columns it stamps are masked.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const eqClockOrigin = 1_750_000_000_000_000_000

var eqKey = bytes.Repeat([]byte{0x4d}, security.KeySize)

// eqExchange is one scripted request and the upstream's answer.
type eqExchange struct {
	name     string
	method   string
	path     string
	header   http.Header
	body     []byte
	trailer  http.Header // request trailers
	readSize int         // the size of every read of the inbound body

	unreachable bool
	// earlyAnswer, when positive, makes the upstream answer after reading
	// this many request bytes; the rest is read while the response streams.
	earlyAnswer int
	status      int
	respHeader  http.Header
	respChunks  [][]byte
	respTrailer http.Header
	cutAt       int
	abort       bool
	cancel      bool
}

// eqUpstream is the scripted upstream of one run.
type eqUpstream struct {
	current *eqExchange
	cancel  context.CancelFunc
	// hook, when set, is called at "roundtrip" (before the request body is
	// read), "request-read" (after each read, with the bytes so far),
	// "request-done" and "response-read" (before each response read, with
	// the response bytes so far).
	hook func(event string, count int)
}

func (upstream *eqUpstream) event(name string, count int) {
	if upstream.hook != nil {
		upstream.hook(name, count)
	}
}

type eqRoundTrip func(*http.Request) (*http.Response, error)

func (function eqRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (upstream *eqUpstream) roundTrip(request *http.Request) (*http.Response, error) {
	exchange := upstream.current
	if exchange.unreachable {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}
	upstream.event("roundtrip", 0)
	var rest io.ReadCloser
	if request.Body != nil {
		buffer := make([]byte, 32<<10)
		read := 0
		for exchange.earlyAnswer <= 0 || read < exchange.earlyAnswer {
			limit := len(buffer)
			if exchange.earlyAnswer > 0 {
				limit = min(limit, exchange.earlyAnswer-read)
			}
			count, err := request.Body.Read(buffer[:limit])
			read += count
			upstream.event("request-read", read)
			if err != nil {
				break
			}
		}
		upstream.event("request-done", read)
		if exchange.earlyAnswer > 0 {
			rest = request.Body
		} else {
			_ = request.Body.Close()
		}
	}
	header := exchange.respHeader.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set("X-Oneapi-Request-Id", "request-"+exchange.name)
	status := exchange.status
	if status == 0 {
		status = http.StatusOK
	}
	body := &eqResponseBody{exchange: exchange, rest: rest, cancel: upstream.cancel, upstream: upstream}
	for _, chunk := range exchange.respChunks {
		body.data = append(body.data, chunk)
	}
	contentLength := int64(-1)
	if raw := header.Get("Content-Length"); raw != "" {
		contentLength, _ = strconv.ParseInt(raw, 10, 64)
	}
	response := &http.Response{
		StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: body, ContentLength: contentLength, Request: request,
	}
	if exchange.respTrailer != nil {
		response.Trailer = http.Header{}
		body.trailer = response.Trailer
	}
	return response, nil
}

// eqResponseBody yields one response chunk per Read, after draining what is
// left of the request body, and breaks at the cut as the scenario says.
type eqResponseBody struct {
	exchange *eqExchange
	rest     io.ReadCloser
	data     [][]byte
	written  int
	cancel   context.CancelFunc
	trailer  http.Header
	upstream *eqUpstream
}

func (body *eqResponseBody) Read(buffer []byte) (int, error) {
	if body.rest != nil {
		count, err := body.rest.Read(buffer[:min(len(buffer), body.exchange.readSize)])
		if err != nil {
			_ = body.rest.Close()
			body.rest = nil
		}
		if count > 0 {
			// The request bytes are not response bytes; report nothing yet.
			return 0, nil
		}
	}
	for len(body.data) > 0 && len(body.data[0]) == 0 {
		body.data = body.data[1:]
	}
	if len(body.data) == 0 {
		for name, values := range body.exchange.respTrailer {
			body.trailer[name] = values
		}
		return 0, io.EOF
	}
	body.upstream.event("response-read", body.written)
	cut := body.exchange.cutAt
	if cut > 0 && body.written >= cut {
		if body.exchange.cancel {
			body.cancel()
			return 0, context.Canceled
		}
		return 0, io.ErrUnexpectedEOF
	}
	piece := body.data[0]
	if cut > 0 && body.written+len(piece) > cut {
		piece = piece[:cut-body.written]
	}
	count := copy(buffer, piece)
	body.data[0] = body.data[0][count:]
	body.written += count
	return count, nil
}

func (body *eqResponseBody) Close() error {
	if body.rest != nil {
		_ = body.rest.Close()
	}
	return nil
}

// fixedReader returns at most size bytes per Read.
type fixedReader struct {
	data []byte
	size int
}

func (reader *fixedReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer[:min(len(buffer), reader.size)], reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

func (reader *fixedReader) Close() error { return nil }

// eqRun is one write path's process: store, manager, handler, parser.
type eqRun struct {
	t        *testing.T
	path     string
	dbPath   string
	store    *sqlite.Store
	cipher   security.Cipher
	manager  *audit.Manager
	handler  http.Handler
	upstream *eqUpstream
	worker   *parser.Worker
	query    *query.Service
	logs     *lockedBuffer
	clock    atomic.Int64
	reads    atomic.Int64
	noParse  bool
}

func eqRoutes() []config.RouteConfig {
	return []config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions", Interceptors: []string{"credential"}},
		{ID: "responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses", Interceptors: []string{"credential", "body-limit"}},
		{ID: "messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages", Interceptors: []string{"credential"}},
		{ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		{ID: "gemini-stream", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
		{ID: "probe", Method: http.MethodGet, Path: "/v1/probe", Match: "exact", Parser: "openai.chat_completions"},
	}
}

func newEqRun(t *testing.T, writePath string, options audit.Options, wrap func(*sqlite.Store) audit.Store) *eqRun {
	t.Helper()
	ctx := context.Background()
	run := &eqRun{t: t, path: writePath, dbPath: filepath.Join(t.TempDir(), "audit.db"), logs: &lockedBuffer{}}
	store, err := sqlite.Open(ctx, run.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, eqKey); err != nil {
		t.Fatal(err)
	}
	run.store = store
	if run.cipher, err = security.NewAESGCM(eqKey); err != nil {
		t.Fatal(err)
	}
	credentials, err := security.NewCredentialFingerprinter(eqKey)
	if err != nil {
		t.Fatal(err)
	}
	run.clock.Store(eqClockOrigin)
	options.WritePath = writePath
	options.Now = func() time.Time {
		run.reads.Add(1)
		return time.Unix(0, run.clock.Add(1))
	}
	options.Random = rand.NewChaCha8([32]byte{7})
	logger := slog.New(slog.NewJSONHandler(run.logs, nil))
	var sessionStore audit.Store = store
	if wrap != nil {
		sessionStore = wrap(store)
	}
	if run.manager, err = audit.NewManagerWithOptions(sessionStore, run.cipher, credentials, audit.ModeAvailable, logger, options); err != nil {
		t.Fatal(err)
	}
	if run.worker, err = parser.NewWorker(store, run.cipher, builtin.All(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	run.manager.SetCompletionNotifier(run.worker.Notify)
	workerCtx, stop := context.WithCancel(ctx)
	if err := run.worker.Start(workerCtx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(); run.worker.Close() })
	if run.query, err = query.New(store, run.cipher); err != nil {
		t.Fatal(err)
	}
	routes := eqRoutes()
	interceptors := map[string]config.InterceptorConfig{
		"credential": {Type: "require_credential"},
		"body-limit": {Type: "max_body_bytes", Config: map[string]any{"max_bytes": 3 << 20}},
	}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := interceptor.NewEngine(interceptors, routes)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("http://newapi.example.com")
	handler := NewWithAudit(target, matcher, engine, run.manager, logger).(*handler)
	run.upstream = &eqUpstream{}
	handler.reverseProxy.Transport = eqRoundTrip(run.upstream.roundTrip)
	run.handler = handler
	return run
}

type eqClientView struct {
	status  int
	header  http.Header
	body    []byte
	trailer http.Header
}

// send runs one exchange through the handler and waits until its parse has
// ended, so the parse order (and parent inference) is the same in both runs.
func (run *eqRun) send(exchange *eqExchange) (eqClientView, string) {
	run.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run.upstream.current = exchange
	run.upstream.cancel = cancel
	var body io.Reader = http.NoBody
	if exchange.body != nil {
		body = &fixedReader{data: exchange.body, size: exchange.readSize}
	}
	request := httptest.NewRequestWithContext(ctx, exchange.method, "http://proxy.example.com"+exchange.path, body)
	request.Header = exchange.header.Clone()
	if exchange.body != nil {
		request.ContentLength = int64(len(exchange.body))
	}
	if exchange.trailer != nil {
		request.Trailer = exchange.trailer.Clone()
	}
	recorder := httptest.NewRecorder()
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				panic(recovered)
			}
		}()
		run.handler.ServeHTTP(recorder, request)
	}()
	result := recorder.Result()
	view := eqClientView{status: result.StatusCode, header: result.Header, body: recorder.Body.Bytes(), trailer: result.Trailer}
	id := run.lastAuditID()
	if !run.noParse {
		run.waitParsed(id)
	}
	return view, id
}

func (run *eqRun) lastAuditID() string {
	run.t.Helper()
	records := completionLogRecords(run.t, run.logs.Bytes())
	if len(records) == 0 {
		run.t.Fatal("no completion log")
	}
	id, _ := records[len(records)-1]["audit_id"].(string)
	return id
}

func (run *eqRun) waitParsed(id string) {
	run.t.Helper()
	if id == "" {
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := run.store.Snapshot(context.Background(), id)
		if err != nil {
			run.t.Fatal(err)
		}
		if status := snapshot.Audit.ParseStatus; status != "pending" && status != "processing" {
			return
		}
		run.worker.Notify(id)
		time.Sleep(2 * time.Millisecond)
	}
	run.t.Fatalf("audit %s was not parsed", id)
}

// eqExchanges is the traffic of I.1: the protofixture catalogue on all four
// protocols in both modes, plus the shapes the catalogue does not cover.
func eqExchanges(t *testing.T) []*eqExchange {
	t.Helper()
	var exchanges []*eqExchange
	for index, value := range protofixture.Catalog() {
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(index + 1)})
		if err != nil {
			t.Fatal(err)
		}
		for turn, exchange := range built {
			exchanges = append(exchanges, fromFixture(fmt.Sprintf("%02d-%d", index, turn), exchange, 4096))
		}
	}
	big, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 91, HistoryItems: 600, ItemBytes: 4000, DeltaBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	large := fromFixture("large", big[0], 256<<10)
	if len(large.body) <= 1<<20 {
		t.Fatalf("large request is only %d bytes", len(large.body))
	}
	exchanges = append(exchanges, large)

	plain := exchanges[0]
	early := cloneExchange(large, "early-answer")
	early.earlyAnswer = 600 << 10
	exchanges = append(exchanges, early)

	trailers := cloneExchange(plain, "trailers")
	trailers.trailer = http.Header{"X-Request-Checksum": {"sum-1"}, "X-Request-Note": {"a", "b"}}
	trailers.respHeader = trailers.respHeader.Clone()
	trailers.respHeader.Set("Trailer", "X-Response-Usage")
	trailers.respHeader.Del("Content-Length")
	trailers.respTrailer = http.Header{"X-Response-Usage": {"tokens=42"}}
	exchanges = append(exchanges, trailers)

	noCredential := cloneExchange(plain, "rejected")
	noCredential.header = http.Header{"Content-Type": {"application/json"}, "User-Agent": {"client-example/1.0"}}
	exchanges = append(exchanges, noCredential)

	tooLarge := cloneExchange(plain, "body-limit")
	tooLarge.path = "/v1/responses"
	tooLarge.body = bytes.Repeat([]byte("x"), 4<<20)
	exchanges = append(exchanges, tooLarge)

	unreachable := cloneExchange(plain, "unreachable")
	unreachable.unreachable = true
	exchanges = append(exchanges, unreachable)

	probe := cloneExchange(plain, "no-body")
	probe.method, probe.path, probe.body = http.MethodGet, "/v1/probe", nil
	exchanges = append(exchanges, probe)
	return exchanges
}

func fromFixture(name string, exchange protofixture.Exchange, readSize int) *eqExchange {
	header := exchange.RequestHeader.Clone()
	header.Set("User-Agent", "client-example/1.0")
	return &eqExchange{
		name: name, method: exchange.Method, path: exchange.Path, header: header,
		body: append([]byte(nil), exchange.RequestBody...), readSize: readSize,
		status: exchange.Response.Status, respHeader: exchange.Response.Header.Clone(),
		respChunks: exchange.Response.Chunks, cutAt: exchange.Response.CutAt,
		abort: exchange.Response.Abort, cancel: exchange.Response.ClientCancel,
	}
}

func cloneExchange(source *eqExchange, name string) *eqExchange {
	clone := *source
	clone.name = name
	clone.header = source.header.Clone()
	clone.respHeader = source.respHeader.Clone()
	return &clone
}

// copyChunks gives each run its own response chunks; the body reader
// consumes them.
func copyChunks(exchange *eqExchange) *eqExchange {
	clone := *exchange
	clone.respChunks = make([][]byte, len(exchange.respChunks))
	for index, chunk := range exchange.respChunks {
		clone.respChunks[index] = append([]byte(nil), chunk...)
	}
	return &clone
}

func TestUnifiedWritePathMatchesLegacyEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("the whole fixture catalogue through both write paths")
	}
	legacy := newEqRun(t, audit.WritePathLegacy, audit.Options{}, nil)
	var counting *countingStore
	unified := newEqRun(t, audit.WritePathUnified, audit.Options{}, func(store *sqlite.Store) audit.Store {
		counting = &countingStore{Store: store}
		return counting
	})
	var ids []string
	for _, exchange := range eqExchanges(t) {
		var legacyView, unifiedView eqClientView
		var legacyID, unifiedID string
		var wait sync.WaitGroup
		wait.Go(func() { legacyView, legacyID = legacy.send(copyChunks(exchange)) })
		unifiedView, unifiedID = unified.send(copyChunks(exchange))
		wait.Wait()
		if legacyID != unifiedID {
			t.Fatalf("%s: audit ids %s and %s", exchange.name, legacyID, unifiedID)
		}
		if legacyView.status != unifiedView.status || !bytes.Equal(legacyView.body, unifiedView.body) ||
			fmt.Sprint(legacyView.header) != fmt.Sprint(unifiedView.header) || fmt.Sprint(legacyView.trailer) != fmt.Sprint(unifiedView.trailer) {
			t.Fatalf("%s: client saw %d %v %q, unified %d %v %q", exchange.name, legacyView.status, legacyView.header, legacyView.body,
				unifiedView.status, unifiedView.header, unifiedView.body)
		}
		if legacy.reads.Load() != unified.reads.Load() {
			t.Fatalf("%s: clock reads %d (legacy) and %d (unified)", exchange.name, legacy.reads.Load(), unified.reads.Load())
		}
		ids = append(ids, legacyID)
	}
	compareCompletionLogs(t, legacy.logs.Bytes(), unified.logs.Bytes())
	for _, id := range ids {
		compareQueryViews(t, id, legacy, unified)
	}
	legacy.worker.Close()
	unified.worker.Close()
	legacyDump := dumpEqDatabase(t, legacy.dbPath, legacy.cipher)
	unifiedDump := dumpEqDatabase(t, unified.dbPath, unified.cipher)
	if diffs := diffEqDumps(legacyDump, unifiedDump); len(diffs) != 0 {
		t.Fatalf("stored rows differ:\n%s", strings.Join(diffs[:min(len(diffs), 40)], "\n"))
	}
	if len(legacyDump["audit_records"]) != len(ids) || len(legacyDump["parsed_results"]) == 0 || len(legacyDump["body_chunks"]) == 0 {
		t.Fatalf("dump has %d audits, %d parse results, %d chunks", len(legacyDump["audit_records"]), len(legacyDump["parsed_results"]), len(legacyDump["body_chunks"]))
	}
	for _, run := range []*eqRun{legacy, unified} {
		if err := run.store.VerifyIntegrityPayloads(context.Background()); err != nil {
			t.Fatalf("%s: integrity: %v", run.path, err)
		}
	}
	if counting.legacyOps.Load() != 0 || counting.commits.Load() != int64(len(ids)) || counting.checkpoints.Load() == 0 {
		t.Fatalf("unified store saw %d legacy operations, %d commits for %d audits, %d checkpoints",
			counting.legacyOps.Load(), counting.commits.Load(), len(ids), counting.checkpoints.Load())
	}
	t.Logf("%d exchanges, %d clock reads per run, %d checkpoints", len(ids), legacy.reads.Load(), counting.checkpoints.Load())
}

// The completion log line is identical except for the measured durations.
func compareCompletionLogs(t *testing.T, legacy, unified []byte) {
	t.Helper()
	strip := func(records []map[string]any) []string {
		out := make([]string, len(records))
		for index, record := range records {
			delete(record, "time")
			delete(record, "duration_ms")
			delete(record, "ttft_ms")
			encoded, _ := json.Marshal(record)
			out[index] = string(encoded)
		}
		return out
	}
	left, right := strip(completionLogRecords(t, legacy)), strip(completionLogRecords(t, unified))
	if len(left) != len(right) {
		t.Fatalf("completion logs: %d and %d records", len(left), len(right))
	}
	for index := range left {
		if left[index] != right[index] {
			t.Fatalf("completion log %d:\n legacy  %s\n unified %s", index, left[index], right[index])
		}
	}
}

// compareQueryViews compares the detail view and every export the query
// service offers, which are what the web views and the agent exports render.
func compareQueryViews(t *testing.T, id string, legacy, unified *eqRun) {
	t.Helper()
	ctx := context.Background()
	render := func(run *eqRun) []string {
		var views []string
		add := func(name string, value any, err error) {
			encoded, _ := json.Marshal(value)
			views = append(views, fmt.Sprintf("%s err=%v %s", name, err, maskParseTimes(string(encoded))))
		}
		detail, err := run.query.Get(ctx, id, nil)
		add("detail", detail, err)
		for _, side := range []query.Side{query.SideRequest, query.SideResponse} {
			var raw bytes.Buffer
			err := run.query.StreamRaw(ctx, id, side, &raw)
			sum := sha256.Sum256(raw.Bytes())
			add("raw-"+string(side), hex.EncodeToString(sum[:]), err)
			timeline, err := run.query.Timeline(ctx, id, side)
			add("timeline-"+string(side), timeline, err)
		}
		turn, err := run.query.ReconstructTurn(ctx, id)
		add("turn", turn, err)
		bodies, err := run.query.ReconstructBodies(ctx, id)
		add("bodies", bodies, err)
		return views
	}
	left, right := render(legacy), render(unified)
	for index := range left {
		if left[index] != right[index] {
			at := 0
			for at < min(len(left[index]), len(right[index])) && left[index][at] == right[index][at] {
				at++
			}
			from := max(at-200, 0)
			t.Fatalf("audit %s view %d differs at %d:\n legacy  %.500s\n unified %.500s", id, index, at, left[index][from:], right[index][from:])
		}
	}
}

// maskParseTimes blanks the timestamps the parser worker stamps with its own
// clock, which this package cannot replace.
func maskParseTimes(text string) string {
	for _, key := range []string{`"ParsedAtNS":`, `"CreatedAtNS":`, `"parsed_at_ns":`, `"created_at_ns":`} {
		for start := 0; ; {
			index := strings.Index(text[start:], key)
			if index < 0 {
				break
			}
			index += start + len(key)
			end := index
			if end < len(text) && text[end] == '"' {
				end++
			}
			for end < len(text) && (text[end] >= '0' && text[end] <= '9' || text[end] == '-') {
				end++
			}
			if end < len(text) && text[end] == '"' {
				end++
			}
			text = text[:index] + "0" + text[end:]
			start = index
		}
	}
	return text
}

type eqRow map[string]string

// parserClockColumns are stamped with the parser worker's wall clock.
func parserClockColumn(table, column string) bool {
	if !strings.HasSuffix(column, "_at_ns") {
		return false
	}
	switch table {
	case "audit_records", "http_stages", "body_streams", "body_chunks", "audit_gaps", "integrity_events":
		return table == "audit_records" && (column == "parse_next_at_ns" || column == "parsed_at_ns")
	default:
		return true
	}
}

func dumpEqDatabase(t *testing.T, path string, cipher security.Cipher) map[string][]eqRow {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	names, err := database.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for names.Next() {
		var name string
		if err := names.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = names.Close()
	dump := map[string][]eqRow{}
	for _, table := range tables {
		rows, err := database.Query(`SELECT * FROM "` + table + `"`)
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			raw := map[string]any{}
			for index, column := range columns {
				raw[column] = values[index]
			}
			row := eqRow{}
			for _, column := range columns {
				row[column] = renderEqColumn(t, cipher, table, column, raw)
			}
			dump[table] = append(dump[table], row)
		}
		_ = rows.Close()
	}
	return dump
}

func eqText(value any) string {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case string:
		return typed
	default:
		return fmt.Sprint(value)
	}
}

func renderEqColumn(t *testing.T, cipher security.Cipher, table, column string, row map[string]any) string {
	key := table + "." + column
	switch key {
	case "schema_migrations.applied_at_ns", "user_agent_rules.created_at_ns", "user_agent_rules.updated_at_ns":
		return "<volatile>"
	case "integrity_events.previous_mac", "integrity_events.payload_digest", "integrity_events.event_mac":
		return fmt.Sprintf("<mac:%v>", row[column] != nil)
	}
	if parserClockColumn(table, column) || key == "integrity_events.created_at_ns" && eqText(row["event_type"]) != "capture_finalized" {
		return fmt.Sprintf("<parser-clock:%v>", row[column] != nil)
	}
	var aad []string
	switch key {
	case "audit_records.request_uri_enc":
		aad = []string{eqText(row["audit_id"]), "request_uri"}
	case "http_headers.value_enc":
		aad = []string{eqText(row["audit_id"]), "header", eqText(row["stage"]), eqText(row["kind"]), eqText(row["name"]), eqText(row["value_index"])}
	case "body_chunks.data_enc":
		aad = []string{eqText(row["audit_id"]), "body_chunk_v2", eqText(row["stage"]), eqText(row["seq"]), eqText(row["compression"])}
	case "stream_timelines.timeline_enc":
		aad = []string{eqText(row["audit_id"]), "stream_timeline_v1", eqText(row["stage"]), eqText(row["compression"])}
	}
	value := row[column]
	if aad != nil {
		additional, err := security.AAD(aad...)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := cipher.Decrypt(additional, value.([]byte))
		if err != nil {
			return "DECRYPT-FAILED"
		}
		sum := sha256.Sum256(plaintext)
		return fmt.Sprintf("dec(len=%d):%x", len(plaintext), sum)
	}
	switch typed := value.(type) {
	case nil:
		return "NULL"
	case []byte:
		// Other ciphertext (parse results, objects) is compared by length:
		// the nonces differ, and a different plaintext length shows.
		return fmt.Sprintf("blob(len=%d)", len(typed))
	case string:
		return strconv.Quote(typed)
	default:
		return fmt.Sprintf("%T:%v", value, value)
	}
}

func (row eqRow) key() string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key + "=" + row[key] + " ")
	}
	return builder.String()
}

var eqDumpMu sync.Mutex

func diffEqDumps(legacy, unified map[string][]eqRow) []string {
	eqDumpMu.Lock()
	defer eqDumpMu.Unlock()
	tables := map[string]bool{}
	for table := range legacy {
		tables[table] = true
	}
	for table := range unified {
		tables[table] = true
	}
	var names []string
	for table := range tables {
		names = append(names, table)
	}
	sort.Strings(names)
	var diffs []string
	for _, table := range names {
		count := map[string]int{}
		for _, row := range legacy[table] {
			count[row.key()]++
		}
		for _, row := range unified[table] {
			count[row.key()]--
		}
		var keys []string
		for key, value := range count {
			if value != 0 {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			side := "only legacy"
			if count[key] < 0 {
				side = "only unified"
			}
			diffs = append(diffs, fmt.Sprintf("%s: %s: %.400s", table, side, key))
		}
	}
	return diffs
}

// countingStore counts the write operations a session issues.
type countingStore struct {
	*sqlite.Store
	legacyOps, checkpoints, commits atomic.Int64
	checkpoint                      func(sqlite.AuditCheckpoint) error
	commit                          func(sqlite.AuditCommit) (sqlite.AuditFinish, error, bool)
}

func (store *countingStore) StartStage(ctx context.Context, stage sqlite.HTTPStage) error {
	store.legacyOps.Add(1)
	return store.Store.StartStage(ctx, stage)
}
func (store *countingStore) AddChunk(ctx context.Context, chunk sqlite.BodyChunk) error {
	store.legacyOps.Add(1)
	return store.Store.AddChunk(ctx, chunk)
}
func (store *countingStore) FinishAuditWithResult(ctx context.Context, finish sqlite.AuditFinish) (sqlite.AuditFinish, error) {
	store.legacyOps.Add(1)
	return store.Store.FinishAuditWithResult(ctx, finish)
}
func (store *countingStore) Checkpoint(ctx context.Context, checkpoint sqlite.AuditCheckpoint) error {
	store.checkpoints.Add(1)
	if store.checkpoint != nil {
		if err := store.checkpoint(checkpoint); err != nil {
			return err
		}
	}
	return store.Store.Checkpoint(ctx, checkpoint)
}
func (store *countingStore) CommitAudit(ctx context.Context, commit sqlite.AuditCommit) (sqlite.AuditFinish, error) {
	store.commits.Add(1)
	if store.commit != nil {
		if finish, err, handled := store.commit(commit); handled {
			return finish, err
		}
	}
	return store.Store.CommitAudit(ctx, commit)
}
