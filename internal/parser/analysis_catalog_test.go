package parser_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

var updateAnalysisGolden = flag.Bool("update-analysis", false, "rewrite testdata/analysis_catalog.golden")

// analysisCatalogGolden pins the insights analysis of the whole protocol
// fixture catalogue as the live path computes it: proxy, capture, parse,
// turn, then the analyzer with the real linker over SQLite.
//
// insights.AnalysisVersion must change whenever the same captured evidence
// would produce a different audit_analysis row, so that the backfill
// recomputes old rows. A diff in this file is that question being asked: if
// it changes a row field (rather than only the analyzer input), either bump
// AnalysisVersion and record why in module 20 section 9, or say in the commit
// why old rows may keep their value.
const analysisCatalogGolden = "testdata/analysis_catalog.golden"

// analysisCatalogSeed matches the parser fixture tests.
const analysisCatalogSeed = 42

// TestAnalysisOfFixtureCatalog runs every exchange of the protofixture
// catalogue, stream and non-stream, normal and abnormal, through the live
// path and compares the analyzer input and the stored analysis row, detail
// included, with the golden file. Values that differ between runs (audit ids,
// timestamps, nonces) are replaced by stable labels or by their presence.
// LLMAPI_ANALYSIS_CATALOG_OUT writes the dump to that path instead.
func TestAnalysisOfFixtureCatalog(t *testing.T) {
	type namedCase struct {
		name  string
		build func() ([]protofixture.Exchange, error)
	}
	var cases []namedCase
	for _, value := range protofixture.Catalog() {
		cases = append(cases, namedCase{value.String(), func() ([]protofixture.Exchange, error) {
			return protofixture.Build(value, protofixture.Options{Seed: analysisCatalogSeed})
		}})
	}
	for _, hand := range analysisHandCases() {
		cases = append(cases, namedCase{hand.name, func() ([]protofixture.Exchange, error) { return []protofixture.Exchange{hand.exchange()}, nil }})
	}
	dumps := make([][]string, len(cases))
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	for index, value := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			for attempt := 1; ; attempt++ {
				exchanges, err := value.build()
				if err != nil {
					t.Errorf("%s: %v", value.name, err)
					return
				}
				lines, err := analyzeExchanges(value.name, exchanges)
				var fault *loopbackFault
				if errors.As(err, &fault) && attempt < 5 {
					t.Logf("%s: retrying after %v", value.name, err)
					continue
				}
				if err != nil {
					t.Errorf("%s (attempt %d): %v", value.name, attempt, err)
				}
				dumps[index] = lines
				return
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "# insights.AnalysisVersion %d; seed %d; regenerate with: go test ./internal/parser -run TestAnalysisOfFixtureCatalog -update-analysis\n",
		insights.AnalysisVersion, analysisCatalogSeed)
	for _, lines := range dumps {
		for _, line := range lines {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	if path := os.Getenv("LLMAPI_ANALYSIS_CATALOG_OUT"); path != "" {
		if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if *updateAnalysisGolden {
		if err := os.WriteFile(analysisCatalogGolden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(analysisCatalogGolden)
	if err != nil {
		t.Fatalf("read %s (run with -update-analysis to create it): %v", analysisCatalogGolden, err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("the analysis of the fixture catalogue changed:\n%s\n"+
			"If a row field changed for the same evidence, insights.AnalysisVersion needs a bump (module 20 section 9); "+
			"rerun with -update-analysis once that is settled.", lineDiff(string(want), out.String()))
	}
}

// lineDiff lists the lines only one side has, each with the exchange it
// belongs to, at most 60 of them.
func lineDiff(want, got string) string {
	qualify := func(text string) []string {
		var lines []string
		section := ""
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "== ") {
				section = strings.TrimPrefix(line, "== ")
				continue
			}
			lines = append(lines, section+" "+strings.TrimSpace(line))
		}
		return lines
	}
	wantList, gotList := qualify(want), qualify(got)
	wantLines, gotLines := map[string]bool{}, map[string]bool{}
	for _, line := range wantList {
		wantLines[line] = true
	}
	for _, line := range gotList {
		gotLines[line] = true
	}
	var report []string
	for _, line := range wantList {
		if !gotLines[line] {
			report = append(report, "- "+line)
		}
	}
	for _, line := range gotList {
		if !wantLines[line] {
			report = append(report, "+ "+line)
		}
	}
	if len(report) > 60 {
		report = append(report[:60], fmt.Sprintf("... %d more", len(report)-60))
	}
	return strings.Join(report, "\n")
}

// loopbackFault is a broken connection on the test's own loopback hops. It
// shows up as an upstream connection closed mid-answer ("use of closed
// network connection") when the upstream answers at once. The likely cause,
// inferred and not proven: the upstream answers before the proxy's transport
// has made its final read of the request body, the HTTP/1 server in front of
// the proxy refuses that read once the response has started, and the
// transport closes the connection. A plain net/http reverse proxy with
// nothing from this repository shows the same failures, so it is not what
// this test is about; the fake upstream's first-byte delay makes it rare, and a
// case that still hits it is run again on a fresh store.
type loopbackFault struct{ err error }

func (fault *loopbackFault) Error() string { return "loopback fault: " + fault.err.Error() }

// capturingAnalyzer records the input of each analysis before the runner
// derives and saves the row.
type capturingAnalyzer struct {
	next   parser.AuditAnalyzer
	mu     sync.Mutex
	inputs map[string]insights.Input
}

func (analyzer *capturingAnalyzer) AnalyzeAudit(ctx context.Context, input insights.Input) error {
	analyzer.mu.Lock()
	analyzer.inputs[input.AuditID] = input
	analyzer.mu.Unlock()
	return analyzer.next.AnalyzeAudit(ctx, input)
}

// analysisHandCase is a stream shape the catalogue does not generate whose
// analysis changed when stream reading moved to the folded body (stage 2 of
// issue #59): the old stream aggregation counted an Anthropic server tool
// call as a tool call and dropped a Gemini function call repeated in a later
// chunk, where the non-stream reading of the same answer did neither. Each
// stream is pinned next to the non-stream body of the same answer.
type analysisHandCase struct {
	name     string
	exchange func() protofixture.Exchange
}

func analysisHandCases() []analysisHandCase {
	exchange := func(path, parserName string, header http.Header, request, contentType string, chunks ...string) protofixture.Exchange {
		header.Set("Content-Type", "application/json")
		response := protofixture.Response{Status: http.StatusOK, Header: http.Header{"Content-Type": {contentType}}}
		for _, chunk := range chunks {
			response.Chunks = append(response.Chunks, []byte(chunk))
		}
		return protofixture.Exchange{Method: http.MethodPost, Path: path, ParserName: parserName, RequestHeader: header,
			RequestBody: []byte(request), Response: response}
	}
	anthropic := func(contentType string, chunks ...string) protofixture.Exchange {
		return exchange("/v1/messages", "anthropic.messages", http.Header{"X-Api-Key": {"sk-handanthropic"}, "Anthropic-Version": {"2023-06-01"}},
			`{"model":"model-example","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"look it up"}]}`, contentType, chunks...)
	}
	event := func(name, data string) string { return "event: " + name + "\ndata: " + data + "\n\n" }
	gemini := func(path, contentType string, chunks ...string) protofixture.Exchange {
		return exchange(path, "gemini.stream_generate_content", http.Header{"X-Goog-Api-Key": {"sk-handgemini"}},
			`{"contents":[{"role":"user","parts":[{"text":"read a.go"}]}]}`, contentType, chunks...)
	}
	const readCall = `{"functionCall":{"name":"read_file","args":{"path":"a.go"}}}`
	const usage = `"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}`
	return []analysisHandCase{
		{"hand/anthropic_server_tool/sse", func() protofixture.Exchange {
			return anthropic("text/event-stream",
				event("message_start", `{"type":"message_start","message":{"id":"msg_hand","type":"message","role":"assistant","model":"model-example","content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":1}}}`),
				event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"srvtoolu_hand","name":"web_search","input":{}}}`),
				event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"go\"}"}}`),
				event("content_block_stop", `{"type":"content_block_stop","index":0}`),
				event("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"web_search_tool_result","tool_use_id":"srvtoolu_hand","content":[]}}`),
				event("content_block_stop", `{"type":"content_block_stop","index":1}`),
				event("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`),
				event("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"found"}}`),
				event("content_block_stop", `{"type":"content_block_stop","index":2}`),
				event("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`),
				event("message_stop", `{"type":"message_stop"}`))
		}},
		{"hand/anthropic_server_tool/json", func() protofixture.Exchange {
			return anthropic("application/json",
				`{"id":"msg_hand","type":"message","role":"assistant","model":"model-example","content":[`+
					`{"type":"server_tool_use","id":"srvtoolu_hand","name":"web_search","input":{"query":"go"}},`+
					`{"type":"web_search_tool_result","tool_use_id":"srvtoolu_hand","content":[]},{"type":"text","text":"found"}],`+
					`"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":7}}`)
		}},
		{"hand/gemini_repeated_call/sse", func() protofixture.Exchange {
			return gemini("/v1beta/models/model-example:streamGenerateContent?alt=sse", "text/event-stream",
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Reading"}]},"index":0}]}`+"\r\n\r\n",
				`data: {"candidates":[{"content":{"role":"model","parts":[`+readCall+`]},"index":0}]}`+"\r\n\r\n",
				`data: {"candidates":[{"content":{"role":"model","parts":[`+readCall+`]},"finishReason":"STOP","index":0}],`+usage+`}`+"\r\n\r\n")
		}},
		{"hand/gemini_repeated_call/json", func() protofixture.Exchange {
			value := gemini("/v1beta/models/model-example:generateContent", "application/json",
				`{"candidates":[{"content":{"role":"model","parts":[{"text":"Reading"},`+readCall+`,`+readCall+`]},"finishReason":"STOP","index":0}],`+usage+`}`)
			value.ParserName = "gemini.generate_content"
			return value
		}},
	}
}

// analyzeExchanges sends exchanges in order through the live path of a fresh
// store and returns the flattened dump, each line prefixed by name#index.
func analyzeExchanges(name string, exchanges []protofixture.Exchange) ([]string, error) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
	fail := func(err error) ([]string, error) { return nil, err }
	dir, err := os.MkdirTemp("", "analysis-catalog-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	store, err := sqlite.Open(ctx, filepath.Join(dir, "audit.db"))
	if err != nil {
		return fail(err)
	}
	defer store.Close()
	if err := store.EnableIntegrity(ctx, key); err != nil {
		return fail(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		return fail(err)
	}
	credentials, err := security.NewCredentialFingerprinter(key)
	if err != nil {
		return fail(err)
	}
	fp, err := security.NewAnalysisFingerprinter(key)
	if err != nil {
		return fail(err)
	}
	manager, closeManager, err := newTestManager(dir, store, cipher, credentials, logger, audit.Options{})
	if err != nil {
		return fail(err)
	}
	defer closeManager()
	fake := protofixture.NewUpstream("fx-")
	fake.CancelWait = 10 * time.Second
	// Answering only after the proxy's transport has finished sending the
	// request body avoids most loopbackFault retries (see there).
	fake.FirstByteDelay = 20 * time.Millisecond
	upstream := httptest.NewServer(fake)
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		return fail(err)
	}
	routes := []config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages"},
		{ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		{ID: "gemini-stream", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
	}
	matcher, err := routing.Compile(routes)
	if err != nil {
		return fail(err)
	}
	engine, err := interceptor.NewEngine(nil, routes)
	if err != nil {
		return fail(err)
	}
	front := httptest.NewServer(proxy.NewWithAudit(target, matcher, engine, manager, logger))
	defer front.Close()
	worker, err := parser.NewWorker(store, cipher, builtin.All(), logger)
	if err != nil {
		return fail(err)
	}
	defer worker.Close()
	runner, err := insights.NewRunner(store, cipher, nil, fp)
	if err != nil {
		return fail(err)
	}
	capture := &capturingAnalyzer{next: runner, inputs: map[string]insights.Input{}}
	worker.SetHeaderAllowlist(insights.DefaultVocabulary().HeaderAllowlist())
	worker.SetAnalyzer(capture)
	compactStore, _ := any(store).(insights.CompactDetailStore)
	codec := insights.CipherDetailCodec{Cipher: cipher, Store: compactStore, Fingerprinter: fp}

	seen := map[string]bool{}
	labels := map[string]string{}
	var ids []string
	for index := range exchanges {
		exchange := &exchanges[index]
		label := fmt.Sprintf("%s#%d", name, index)
		sendErr := sendFixtureExchange(ctx, front.URL, fake, exchange)
		auditID, err := nextParsedAudit(ctx, store, worker, seen)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if sendErr != nil {
			return nil, &loopbackFault{fmt.Errorf("%s: %w", label, sendErr)}
		}
		// The race can also cut an answer that was meant to break anyway, or
		// fail only the request side's capture while the client sees the
		// whole answer: the proxy must have seen exactly the bytes the
		// fixture sends, and an unbroken exchange must be captured complete.
		if input, ok := capture.inputs[auditID]; ok && !bytes.Equal(input.Response, exchange.Response.Seen()) {
			return nil, &loopbackFault{fmt.Errorf("%s: captured %d response bytes, the fixture sends %d", label, len(input.Response), len(exchange.Response.Seen()))}
		}
		if exchange.Response.CutAt == 0 {
			if parsed, err := store.LoadParserAudit(ctx, auditID); err == nil && parsed.CaptureStatus != storage.CaptureComplete {
				return nil, &loopbackFault{fmt.Errorf("%s: capture %s", label, parsed.CaptureStatus)}
			}
		}
		labels[auditID] = label
		ids = append(ids, auditID)
	}

	var lines []string
	for index, auditID := range ids {
		label := labels[auditID]
		exchange := exchanges[index]
		record := map[string]any{
			"evidence": map[string]any{
				"request":  digestOf(exchange.RequestBody),
				"response": digestOf(exchange.Response.Seen()),
				"status":   exchange.Response.Status,
				"cut_at":   exchange.Response.CutAt,
			},
		}
		parsed, err := store.LoadParserAudit(ctx, auditID)
		if err != nil {
			return fail(fmt.Errorf("%s: load audit: %w", label, err))
		}
		parsed.AuditID = ""
		record["audit"] = parsed
		if input, ok := capture.inputs[auditID]; ok {
			record["input"] = input
		} else {
			record["input"] = "none"
		}
		row, err := store.LoadAnalysis(ctx, auditID)
		if err != nil {
			record["row"] = "none"
		} else {
			if detail, err := codec.OpenDetailContext(ctx, row.AuditID, row.AnalysisVersion, row.DetailEnc); err != nil {
				record["detail"] = "unreadable: " + err.Error()
			} else {
				record["detail"] = detail
			}
			row.AuditID, row.AnalyzedAtNS, row.StartedAtNS, row.DetailEnc = "", 0, 0, nil
			for objectIndex := range row.DetailObjects {
				row.DetailObjects[objectIndex].PayloadEnc = nil
			}
			record["row"] = row
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return fail(err)
		}
		// Audit ids are random; conversation ids and links may embed them.
		text := string(encoded)
		for id, name := range labels {
			text = strings.ReplaceAll(text, id, "<"+name+">")
		}
		var tree any
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		if err := decoder.Decode(&tree); err != nil {
			return fail(err)
		}
		compactAnalysisDump(tree)
		var leaves []string
		flattenAnalysis(&leaves, "", tree)
		sort.Strings(leaves)
		lines = append(lines, "== "+label)
		for _, leaf := range leaves {
			lines = append(lines, "  "+leaf)
		}
	}
	return lines, nil
}

// sendFixtureExchange sends one exchange through the proxy and reads the
// answer the way a client would, abandoning a client-cancel answer at its cut.
func sendFixtureExchange(ctx context.Context, proxyURL string, fake *protofixture.Upstream, exchange *protofixture.Exchange) error {
	id := fake.Register(exchange)
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, exchange.Method, proxyURL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	if err != nil {
		return err
	}
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(protofixture.ExchangeHeader, id)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if exchange.Response.ClientCancel && exchange.Response.CutAt > 0 {
		prefix := make([]byte, exchange.Response.CutAt)
		if _, err := io.ReadFull(response.Body, prefix); err != nil {
			return fmt.Errorf("read before cancel: %w", err)
		}
		cancel()
		return nil
	}
	read, err := io.Copy(io.Discard, response.Body)
	if err != nil && !exchange.Response.Abort {
		return fmt.Errorf("status %d, read %d of %d bytes: %w", response.StatusCode, read, len(exchange.Response.Body()), err)
	}
	return nil
}

// nextParsedAudit waits for the audit of the exchange just sent to become
// parseable and parses it, analysis included.
func nextParsedAudit(ctx context.Context, store *sqlite.Store, worker *parser.Worker, seen map[string]bool) (string, error) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ids, err := store.ListPendingParseIDs(ctx, 100)
		if err != nil {
			return "", err
		}
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				worker.ProcessForTest(ctx, id)
				return id, nil
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return "", fmt.Errorf("audit did not become parseable")
}

// compactAnalysisDump keeps the dump small enough to review: the per-item
// request lists of the detail become a count and a digest, and each message
// of the analyzer's conversation one line of its role, phase and part types
// plus a digest of its content. A change still shows on the line it touches.
func compactAnalysisDump(tree any) {
	root, _ := tree.(map[string]any)
	if audit, ok := root["audit"].(map[string]any); ok {
		delete(audit, "AuditID")
	}
	if row, ok := root["row"].(map[string]any); ok {
		for _, key := range []string{"AuditID", "AnalyzedAtNS", "StartedAtNS", "DetailEnc"} {
			delete(row, key)
		}
	}
	summarize := func(value any) dumpSummary {
		encoded, _ := json.Marshal(value)
		count := 0
		if list, ok := value.([]any); ok {
			count = len(list)
		}
		return dumpSummary(fmt.Sprintf("n=%d %s", count, digestOf(encoded)))
	}
	if detail, ok := root["detail"].(map[string]any); ok {
		for _, key := range []string{"items", "tools", "item_fprs"} {
			if value, exists := detail[key]; exists {
				detail[key] = summarize(value)
			}
		}
	}
	input, ok := root["input"].(map[string]any)
	if !ok {
		return
	}
	delete(input, "AuditID")
	conv, _ := input["Conversation"].(map[string]any)
	messages, _ := conv["messages"].([]any)
	for index, value := range messages {
		message, _ := value.(map[string]any)
		parts, _ := message["content"].([]any)
		types := make([]string, 0, len(parts))
		for _, part := range parts {
			kind, _ := part.(map[string]any)["type"].(string)
			types = append(types, kind)
		}
		role, _ := message["role"].(string)
		phase, _ := message["phase"].(string)
		encoded, _ := json.Marshal(message)
		messages[index] = dumpSummary(fmt.Sprintf("%s/%s [%s] %s", role, phase, strings.Join(types, ","), digestOf(encoded)))
	}
}

// dumpSummary is written as it is, never digested again.
type dumpSummary string

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%s len=%d", hex.EncodeToString(sum[:8]), len(data))
}

// flattenAnalysis emits one "path = value" leaf per scalar. Timestamps and
// durations become their presence; long strings and byte fields their digest.
func flattenAnalysis(leaves *[]string, path string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			flattenAnalysis(leaves, path+"."+name, child)
		}
		if len(typed) == 0 {
			*leaves = append(*leaves, path+" = {}")
		}
	case []any:
		for index, child := range typed {
			flattenAnalysis(leaves, fmt.Sprintf("%s[%02d]", path, index), child)
		}
		if len(typed) == 0 {
			*leaves = append(*leaves, path+" = []")
		}
	case dumpSummary:
		*leaves = append(*leaves, path+" = "+string(typed))
	default:
		name := path[strings.LastIndex(path, ".")+1:]
		if typed != nil && (strings.HasSuffix(name, "NS") || strings.HasSuffix(name, "AtNS")) {
			*leaves = append(*leaves, path+" = <set>")
			return
		}
		if text, ok := typed.(string); ok && len(text) > 48 {
			*leaves = append(*leaves, path+" = "+digestOf([]byte(text)))
			return
		}
		encoded, _ := json.Marshal(typed)
		*leaves = append(*leaves, path+" = "+string(encoded))
	}
}
