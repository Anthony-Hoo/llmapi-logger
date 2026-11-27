package parser_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// These tests measure what one insights backfill pass costs per audit with
// the real parsers, the real insights runner and real captured evidence
// (doc/design/issue-59-unified-write-cold-archive.md appendix A.6). The SQLite
// store lists candidates with the same anti-join as PostgreSQL: every ended
// ok/partial audit without a current audit_analysis row, on every pass.

// countingStore counts the evidence reads the backfill makes per audit. A
// body load is the first page of a body's chunks (afterSeq -1): every load of
// a body starts there, however many pages it then reads.
type countingStore struct {
	*sqlite.Store
	mu        sync.Mutex
	bodyLoads map[string]int
	// missing makes LoadParserAudit report sql.ErrNoRows, as when retention
	// deletes an audit between the candidate list and the load.
	missing map[string]bool
}

func (store *countingStore) ReadParserChunks(ctx context.Context, auditID, stage string, afterSeq int64, limit int) ([]storage.BodyChunk, error) {
	if afterSeq < 0 {
		store.mu.Lock()
		store.bodyLoads[auditID]++
		store.mu.Unlock()
	}
	return store.Store.ReadParserChunks(ctx, auditID, stage, afterSeq, limit)
}

func (store *countingStore) LoadParserAudit(ctx context.Context, auditID string) (storage.ParserAudit, error) {
	store.mu.Lock()
	gone := store.missing[auditID]
	store.mu.Unlock()
	if gone {
		return storage.ParserAudit{}, sql.ErrNoRows
	}
	return store.Store.LoadParserAudit(ctx, auditID)
}

// takeLoads returns and resets the body loads per audit.
func (store *countingStore) takeLoads() map[string]int {
	store.mu.Lock()
	defer store.mu.Unlock()
	loads := store.bodyLoads
	store.bodyLoads = map[string]int{}
	return loads
}

// countingWorker replaces the harness worker with one reading through a
// countingStore; parsers lists the parsers it knows (nil: all built-in ones).
func (harness *insightsHarness) countingWorker(parsers []parser.Parser) *countingStore {
	harness.t.Helper()
	counting := &countingStore{Store: harness.store, bodyLoads: map[string]int{}, missing: map[string]bool{}}
	if parsers == nil {
		parsers = builtin.All()
	}
	worker, err := parser.NewWorker(counting, harnessCipher(harness.t), parsers, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.t.Cleanup(worker.Close)
	harness.worker = worker
	return counting
}

func harnessCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// runPass drives one complete insights backfill pass: from an empty cursor
// until the candidate list comes back empty. It returns the audits attempted.
func runPass(t *testing.T, worker *parser.Worker) int {
	t.Helper()
	ctx := context.Background()
	worker.ResetBackfillForTest()
	began := time.Now().UnixNano()
	attempted := 0
	for range 100000 {
		attempted += worker.BackfillForTest(ctx)
		if worker.AnalysisBackfillCovered(math.MaxInt64, began) {
			return attempted
		}
	}
	t.Fatal("backfill pass did not complete")
	return 0
}

func gzipText(t *testing.T, text string) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := io.WriteString(writer, text); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

// doomedAnalyzer wraps the real runner and fails the named audits every
// time, as a deterministic analysis error or a long storage outage would.
type doomedAnalyzer struct {
	parser.AuditAnalyzer
	fail map[string]bool
}

func (analyzer doomedAnalyzer) AnalyzeAudit(ctx context.Context, input insights.Input) error {
	if analyzer.fail[input.AuditID] {
		return &insights.RunError{Code: insights.ErrorCodeAnalysisSaveFailed, Err: errors.New("synthetic save failure")}
	}
	return analyzer.AuditAnalyzer.AnalyzeAudit(ctx, input)
}

// noGraphReconstructor reports that the named audits have no turn graph and
// counts every reconstruction it is asked for.
type noGraphReconstructor struct {
	parser.Reconstructor
	mu     sync.Mutex
	none   map[string]bool
	called map[string]int
}

func (reconstructor *noGraphReconstructor) ReconstructBodies(ctx context.Context, auditID string) (parser.Reconstruction, error) {
	reconstructor.mu.Lock()
	reconstructor.called[auditID]++
	none := reconstructor.none[auditID]
	reconstructor.mu.Unlock()
	if none {
		return parser.Reconstruction{}, parser.ErrReconstructionUnavailable
	}
	return reconstructor.Reconstructor.ReconstructBodies(ctx, auditID)
}

func (reconstructor *noGraphReconstructor) take() map[string]int {
	reconstructor.mu.Lock()
	defer reconstructor.mu.Unlock()
	called := reconstructor.called
	reconstructor.called = map[string]int{}
	return called
}

// costCase is one kind of audit and the body loads each backfill pass spends
// on it: request and response bodies count separately.
type costCase struct {
	id         string
	wantStatus string
	perPass    []int
	analysed   bool
}

func TestBackfillCostPerKindOfAudit(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	store := harness.countingWorker(nil)
	ctx := context.Background()
	anthropic := func(extra ...string) map[string][]string {
		return headers(append([]string{"User-Agent", "example-agent/1.0", "X-Api-Key", "sk-costkey", "anthropic-version", "2023-06-01"}, extra...)...)
	}
	ok := messagesResponse("model-example", `{"type":"text","text":"ok"}`)
	cases := map[string]*costCase{}
	add := func(name, id, status string, analysed bool, perPass ...int) {
		cases[name] = &costCase{id: id, wantStatus: status, perPass: perPass, analysed: analysed}
	}

	// Analysed by the first pass, then done.
	add("analysable", harness.send("/v1/messages", anthropic(), messagesBody("model-example", "You are an agent.", userMessage("task")), ok),
		storage.ParseOK, true, 2, 0, 0)
	// A request whose gzip expansion passes MaxGzipRatio. decodeContent stops
	// at the ratio limit (gzip_ratio_exceeded) and hands on a truncated
	// prefix, as it truncates an identity body over MaxDecodedBodyBytes
	// (body_too_large): the parser still reads the response, so the audit is
	// partial, but the request is no longer JSON and the real runner fails on
	// it every time. backfillFail keeps it for the next pass.
	overLimit := messagesBody("model-example", "You are an agent.", userMessage("pad"+strings.Repeat(" ", 4<<20)))
	add("over_decode_limit", harness.send("/v1/messages", anthropic("Content-Encoding", "gzip"), gzipText(t, overLimit), ok),
		storage.ParsePartial, false, 2, 2, 2)
	// A request in an encoding the parser cannot decode: partial, the request
	// decodes to nothing, skipped as no_request_body after one load.
	add("unsupported_request_encoding", harness.send("/v1/messages", anthropic("Content-Encoding", "br"), "not-brotli", ok),
		storage.ParsePartial, false, 2, 0, 0)
	// No request body at all: skipped as no_body before any body is read.
	add("no_request_body_stream", harness.send("/v1/messages", anthropic(), "", ok),
		storage.ParseOK, false, 0, 0, 0)
	// The analysis fails every time (a deterministic save failure): reloaded
	// on every pass.
	failing := harness.send("/v1/messages", anthropic(), messagesBody("model-example", "You are an agent.", userMessage("doomed")), ok)
	add("analysis_always_fails", failing, storage.ParseOK, false, 2, 2, 2)
	// Raw released, no reconstructor: skipped as raw_unavailable unread.
	add("raw_unavailable", harness.sendChat("released task", chatResponse("model-example", "ok")),
		storage.ParseOK, false, 0, 0, 0)

	for name, test := range cases {
		audit, err := harness.store.LoadParserAudit(ctx, test.id)
		if err != nil || audit.ParseStatus != test.wantStatus {
			t.Fatalf("%s: parse status %q, want %q (%v)", name, audit.ParseStatus, test.wantStatus, err)
		}
	}

	harness.enableInsights(false)
	runner, err := insights.NewRunner(harness.store, harnessCipher(t), nil, harness.fp)
	if err != nil {
		t.Fatal(err)
	}
	harness.worker.SetAnalyzer(doomedAnalyzer{AuditAnalyzer: runner, fail: map[string]bool{failing: true}})
	store.takeLoads() // drop the live parse reads
	for pass := range 3 {
		attempted := runPass(t, harness.worker)
		loads := store.takeLoads()
		t.Logf("pass %d: attempted %d audits, body loads %v", pass+1, attempted, loads)
		for name, test := range cases {
			if loads[test.id] != test.perPass[pass] {
				t.Errorf("pass %d %s: %d body loads, want %d", pass+1, name, loads[test.id], test.perPass[pass])
			}
		}
	}
	for name, test := range cases {
		if harness.hasAnalysis(test.id) != test.analysed {
			t.Errorf("%s: analysed=%v, want %v", name, !test.analysed, test.analysed)
		}
	}
}

// The remaining skip reasons: the parser set or the evidence changed between
// the live parse and the backfill, or retention won a race. Each is skipped
// once and then remembered.
func TestBackfillCostOfTheOtherSkipReasons(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	harness.countingWorker(nil)
	anthropic := headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-costkey", "anthropic-version", "2023-06-01")
	ok := messagesResponse("model-example", `{"type":"text","text":"ok"}`)
	missing := harness.send("/v1/messages", anthropic, messagesBody("model-example", "You are an agent.", userMessage("gone")), ok)
	harness.send("/v1/messages", anthropic, messagesBody("model-example", "You are an agent.", userMessage("orphaned")), ok)
	noGraph := harness.sendChat("graphless task", chatResponse("model-example", "ok"))
	harness.sendChat("unusable task", chatResponse("model-example", "ok"))

	// A worker that no longer knows the Anthropic parser, and whose chat
	// parser now reports an error.
	var parsers []parser.Parser
	for _, implementation := range builtin.All() {
		switch implementation.Name() {
		case "anthropic.messages":
		case "openai.chat_completions":
			parsers = append(parsers, erroringParser{implementation})
		default:
			parsers = append(parsers, implementation)
		}
	}
	store := harness.countingWorker(parsers)
	harness.enableInsights(true)
	service, err := query.New(harness.store, harnessCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	reconstructor := &noGraphReconstructor{Reconstructor: service, none: map[string]bool{noGraph: true}, called: map[string]int{}}
	harness.worker.SetReconstructor(reconstructor)
	store.missing[missing] = true
	for pass := range 3 {
		attempted := runPass(t, harness.worker)
		loads := store.takeLoads()
		rebuilt := reconstructor.take()
		t.Logf("pass %d: attempted %d, body loads %v, reconstructions %v", pass+1, attempted, loads, rebuilt)
		// The first pass tries all four (audit_missing, parser_not_registered,
		// no_turn_graph, parse_not_usable); none reads a raw body, and the two
		// OpenAI audits are rebuilt from the turn graph once.
		want, wantRebuilt := 0, 0
		if pass == 0 {
			want, wantRebuilt = 4, 2
		}
		if attempted != want || len(loads) != 0 || len(rebuilt) != wantRebuilt {
			t.Errorf("pass %d: attempted %d (want %d), body loads %v, reconstructions %v", pass+1, attempted, want, loads, rebuilt)
		}
	}
}

// erroringParser stands for a parser that no longer yields a usable result
// for evidence it once parsed.
type erroringParser struct{ parser.Parser }

func (erroringParser) Parse(context.Context, parser.Input) parser.Result {
	return parser.Result{Status: parser.StatusError, ErrorCode: "parse_error"}
}
