package parser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// relayWriter is a ResponseWriter the test can watch while the proxy is
// still streaming into it.
type relayWriter struct {
	mu     sync.Mutex
	header http.Header
	code   int
	body   bytes.Buffer
}

func (writer *relayWriter) Header() http.Header { return writer.header }
func (writer *relayWriter) WriteHeader(code int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.code == 0 {
		writer.code = code
	}
}
func (writer *relayWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.code == 0 {
		writer.code = http.StatusOK
	}
	return writer.body.Write(data)
}
func (writer *relayWriter) Flush() {}
func (writer *relayWriter) received() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.body.Len()
}

// sendCancelled proxies one request whose upstream streams partial and then
// holds the stream open; once the client has received partial it goes away,
// as a client that cancels mid-stream does. It returns the parsed audit id.
func (harness *insightsHarness) sendCancelled(path string, headers http.Header, body, partial string) string {
	harness.t.Helper()
	sent := make(chan struct{})
	harness.mu.Lock()
	harness.response = upstreamResponse{contentType: "text/event-stream", body: partial, sent: sent}
	harness.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy"+path, strings.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	writer := &relayWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		harness.handler.ServeHTTP(writer, request)
	}()
	deadline := time.Now().Add(5 * time.Second)
	<-sent
	for writer.received() < len(partial) {
		if time.Now().After(deadline) {
			harness.t.Fatalf("the client received %d of %d bytes", writer.received(), len(partial))
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	return harness.parseNext()
}

// parseNext parses the next audit that became pending and returns its id.
func (harness *insightsHarness) parseNext() string {
	harness.t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ids, err := harness.store.ListPendingParseIDs(ctx, 100)
		if err != nil {
			harness.t.Fatal(err)
		}
		for _, id := range ids {
			if !harness.seen[id] {
				harness.seen[id] = true
				harness.worker.ProcessForTest(ctx, id)
				return id
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	harness.t.Fatal("audit did not become parseable")
	return ""
}

// recordingProjectStore keeps the project identity rows the runner saves.
type recordingProjectStore struct {
	mu   sync.Mutex
	rows map[string]storage.ProjectIdentityRow
}

func (store *recordingProjectStore) SaveProjectIdentity(_ context.Context, row storage.ProjectIdentityRow) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.rows[row.AuditID] = row
	return nil
}

const requestOnlySession = `"metadata":{"user_id":"{\"device_id\":\"device-example\",\"session_id\":\"session-request-only\"}"},`

// The first user message carries a working directory, which the project
// identity extractor reads from the request body.
const requestOnlyHistory = `{"role":"user","content":"# Environment\nYou have been invoked in the following environment:\n - Primary working directory: /home/dev/example-project\n - Is a git repository: true"},` +
	`{"role":"user","content":"explain the build"}`

func requestOnlyRequest(messages string) string {
	return `{"model":"model-example","max_tokens":64,"stream":true,` + requestOnlySession + `"system":"You are an agent.","messages":[` + messages + `]}`
}

const halfAnswerStream = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_half\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"model-example\",\"content\":[],\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"half an ans\"}}\n\n"

// noStopStream is complete as bytes but ends without message_stop.
const noStopStream = halfAnswerStream +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n"

type sideRetention struct{ request, response string }

func (harness *insightsHarness) retention(auditID string) sideRetention {
	harness.t.Helper()
	ctx := context.Background()
	var states [4]string
	for index, stage := range []string{sqlite.StageRequestReceived, sqlite.StageRequestSent, sqlite.StageResponseReceived, sqlite.StageResponseSent} {
		loaded, err := harness.store.LoadParserStage(ctx, auditID, stage)
		if err != nil || loaded.Body == nil {
			harness.t.Fatalf("%s %s: %+v %v", auditID, stage, loaded.Body, err)
		}
		if loaded.Body.RetentionState == sqlite.RetentionMetadata && loaded.Body.StoredLength != 0 {
			harness.t.Fatalf("%s %s: released stage keeps stored_length %d", auditID, stage, loaded.Body.StoredLength)
		}
		states[index] = loaded.Body.RetentionState
	}
	if states[0] != states[1] || states[2] != states[3] {
		harness.t.Fatalf("%s: the stages of one side differ: %v", auditID, states)
	}
	return sideRetention{request: states[0], response: states[2]}
}

func (harness *insightsHarness) service() *query.Service {
	harness.t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		harness.t.Fatal(err)
	}
	service, err := query.New(harness.store, cipher)
	if err != nil {
		harness.t.Fatal(err)
	}
	return service
}

func (harness *insightsHarness) parsedPlaintext(auditID string) (storage.ParsedResultSummary, []byte) {
	harness.t.Helper()
	detail, err := harness.store.QueryAuditDetail(context.Background(), auditID, nil)
	if err != nil || detail.ParsedResult == nil {
		harness.t.Fatalf("%s: parsed result %+v, %v", auditID, detail.ParsedResult, err)
	}
	cipher, _ := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	plaintext, err := auditmodel.OpenParsedResult(cipher, auditID, detail.ParsedResult.ParserName, detail.ParsedResult.ParsedJSONEnc)
	if err != nil {
		harness.t.Fatal(err)
	}
	return *detail.ParsedResult, plaintext
}

// TestRequestOnlyTurnsOfIncompleteResponses runs Anthropic audits whose
// response cannot be carried by a turn through the proxy, the store and the
// worker: a stream the client cancelled mid-way and a stream without its
// terminal event. Each gets a request-only turn: its request raw is released,
// its response raw stays and downloads byte for byte, the parse keeps the
// status and error code it had, the parsed result keeps the assistant message
// on its own instead of a second copy of the conversation, and the detail
// shows what the fallback conversation showed. The next turn links to the
// request-only one. Insights and project identity, live and by backfill,
// equal what they were with everything retained.
func TestRequestOnlyTurnsOfIncompleteResponses(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	ctx := context.Background()
	projects := &recordingProjectStore{rows: map[string]storage.ProjectIdentityRow{}}
	cipher, _ := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	project, err := insights.NewProjectRunner(projects, cipher, insights.DefaultVocabulary(), harness.fp)
	if err != nil {
		t.Fatal(err)
	}
	harness.worker.SetProjectAnalyzer(project)
	h := headers("User-Agent", "claude-cli/2.1.300 (external, cli)", "X-Api-Key", "sk-requestonlykey", "anthropic-version", "2023-06-01")
	request := requestOnlyRequest(requestOnlyHistory)

	noStop := harness.send("/v1/messages", h, request, upstreamResponse{contentType: "text/event-stream", body: noStopStream})
	cancelled := harness.sendCancelled("/v1/messages", h, request, halfAnswerStream)
	// The client sends the half answer back and asks to go on. Both earlier
	// turns qualify as its parent; the newer one, the cancelled turn, wins.
	next := harness.send("/v1/messages", h,
		requestOnlyRequest(requestOnlyHistory+`,{"role":"assistant","content":[{"type":"text","text":"half an ans"}]},{"role":"user","content":"please finish"}`),
		upstreamResponse{contentType: "text/event-stream", body: messagesStream("")})

	service := harness.service()
	cases := []struct {
		name, id, response, status, code string
		complete                         bool
	}{
		{"cancelled mid-stream", cancelled, halfAnswerStream, sqlite.ParsePartial, "", false},
		{"terminal event missing", noStop, noStopStream, sqlite.ParsePartial, "missing_message_stop", true},
	}
	for _, test := range cases {
		if got := harness.retention(test.id); got.request != sqlite.RetentionMetadata || got.response != sqlite.RetentionFull {
			t.Fatalf("%s: retention %+v, want request metadata and response full", test.name, got)
		}
		parsed, plaintext := harness.parsedPlaintext(test.id)
		code := ""
		if parsed.ErrorCode != nil {
			code = *parsed.ErrorCode
		}
		if parsed.Status != test.status || (test.code != "" && code != test.code) || code == "" ||
			code == "normalization_failed" || code == "reconstruction_failed" {
			t.Fatalf("%s: parse %s / %q", test.name, parsed.Status, code)
		}
		t.Logf("%s: saved as %s / %s", test.name, parsed.Status, code)
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(plaintext, &envelope); err != nil {
			t.Fatal(err)
		}
		if _, exists := envelope["conversation"]; exists || bytes.Contains(plaintext, []byte("explain the build")) {
			t.Fatalf("%s: the conversation is stored again: %s", test.name, plaintext)
		}
		if !bytes.Contains(envelope[parser.PartialResponseMessagesKey], []byte("half an ans")) {
			t.Fatalf("%s: the partial answer is not kept: %s", test.name, plaintext)
		}
		if events := integrityEventTypes(t, harness.dbPath, test.id); !reflect.DeepEqual(events, []string{"capture_finalized", "semantic_compacted"}) {
			t.Fatalf("%s: integrity events %v", test.name, events)
		}

		detail, err := service.Get(ctx, test.id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if detail.Turn == nil || detail.Turn.ResponseLayout != auditmodel.LayoutNone || detail.Turn.RequestLayout == auditmodel.LayoutNone {
			t.Fatalf("%s: turn %+v", test.name, detail.Turn)
		}
		var raw bytes.Buffer
		if err := service.StreamRaw(ctx, test.id, query.SideResponse, &raw); err != nil || raw.String() != test.response {
			t.Fatalf("%s: response raw = %q, %v", test.name, raw.String(), err)
		}
		if err := service.StreamRaw(ctx, test.id, query.SideRequest, &raw); !errors.Is(err, query.ErrNotRetained) {
			t.Fatalf("%s: request raw = %v, want ErrNotRetained", test.name, err)
		}
		rebuilt, err := service.ReconstructTurn(ctx, test.id)
		if err != nil {
			t.Fatal(err)
		}
		if encoded, _ := json.Marshal(rebuilt.Request); canonicalText(t, encoded) != canonicalText(t, []byte(request)) || rebuilt.Response != nil {
			t.Fatalf("%s: rebuilt %s / %v", test.name, encoded, rebuilt.Response)
		}

		// What the old code stored as the fallback conversation and showed:
		// the parse of the request and the response as they were captured.
		fallback := anthropic.New().Parse(ctx, parser.Input{
			Request:  parser.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(request)},
			Response: parser.BodySource{Present: true, Complete: test.complete, ContentType: "text/event-stream", Data: []byte(test.response)},
		}).Conversation
		if !reflect.DeepEqual(detail.Conversation, fallback) {
			got, _ := json.Marshal(detail.Conversation)
			want, _ := json.Marshal(fallback)
			t.Fatalf("%s: detail conversation differs from the fallback\n got: %s\nwant: %s", test.name, got, want)
		}
		messages := detail.Conversation.Messages
		last := messages[len(messages)-1]
		if last.Phase != "response" || last.Content[0].Text != "half an ans" || last.Index != len(messages)-1 {
			t.Fatalf("%s: conversation %+v", test.name, messages)
		}
		for _, same := range []func() (any, error){
			func() (any, error) { return service.SessionConversation(ctx, test.id) },
			func() (any, error) { turn, err := service.ReconstructTurn(ctx, test.id); return turn.Conversation, err },
		} {
			if value, err := same(); err != nil || !reflect.DeepEqual(value, detail.Conversation) {
				t.Fatalf("%s: another reader sees %+v, %v", test.name, value, err)
			}
		}
	}

	// The next turn of the session continues the cancelled one.
	nextDetail, err := service.Get(ctx, next, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelledDetail, err := service.Get(ctx, cancelled, nil)
	if err != nil {
		t.Fatal(err)
	}
	if nextDetail.Turn == nil || nextDetail.Turn.ParentTurnID == nil || *nextDetail.Turn.ParentTurnID != cancelledDetail.Turn.TurnID ||
		nextDetail.Turn.ConversationID != cancelledDetail.Turn.ConversationID {
		t.Fatalf("next turn %+v, parent %+v", nextDetail.Turn, cancelledDetail.Turn)
	}
	if _, err := service.ReconstructTurn(ctx, next); err != nil {
		t.Fatalf("next turn does not rebuild: %v", err)
	}
	if err := harness.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity payloads: %v", err)
	}

	// Insights: the live analysis ran on the captured bodies; the backfill
	// rebuilds the request from the turn and reads the response raw.
	live := make(map[string]sqlite.AnalysisRow)
	for _, test := range cases {
		row := harness.analysis(test.id)
		live[test.id] = row
		row.AnalysisVersion--
		if err := harness.store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	harness.enableInsights(true)
	for _, test := range cases {
		input, summary, reason, err := harness.worker.BackfillInputForTest(ctx, test.id)
		if err != nil || reason != "" || summary || string(input.Response.Data) != test.response || input.Response.Complete != test.complete {
			t.Fatalf("%s: backfill input %q summary=%v complete=%v: %q %v", test.name, input.Response.Data, summary, input.Response.Complete, reason, err)
		}
		// Project identity: the identity backfill reads the rebuilt request.
		body, ok := harness.worker.ProjectRequestBodyForTest(ctx, test.id)
		if !ok || canonicalText(t, body) != canonicalText(t, []byte(request)) {
			t.Fatalf("%s: project body %s %v", test.name, body, ok)
		}
		liveIdentity := projects.rows[test.id]
		if liveIdentity.Source == "" || liveIdentity.Source == "none" {
			t.Fatalf("%s: live identity %+v", test.name, liveIdentity)
		}
		backfilled, err := project.Row(insights.Input{AuditID: test.id, Protocol: "anthropic", Endpoint: "messages", Request: body, Headers: input.Headers}, true)
		if err != nil {
			t.Fatal(err)
		}
		// The extraction time and the encryption nonce differ by nature.
		backfilled.ExtractedAtNS = liveIdentity.ExtractedAtNS
		backfilled.IdentityEnc, liveIdentity.IdentityEnc = nil, nil
		if !reflect.DeepEqual(backfilled, liveIdentity) {
			t.Fatalf("%s: backfilled identity differs\n got: %+v\nwant: %+v", test.name, backfilled, liveIdentity)
		}
	}
	harness.worker.ResetBackfillForTest()
	harness.worker.BackfillForTest(ctx)
	for _, test := range cases {
		want, got := live[test.id], harness.analysis(test.id)
		want.DetailEnc, got.DetailEnc = nil, nil
		got.AnalyzedAtNS = want.AnalyzedAtNS
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: backfilled analysis differs\n got: %+v\nwant: %+v", test.name, got, want)
		}
	}
}

func canonicalText(t *testing.T, value []byte) string {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		t.Fatalf("decode %s: %v", value, err)
	}
	canonical, err := auditmodel.CanonicalJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

// Audits whose request cannot stand for itself get no request-only turn and
// keep all four stages, with the parse saved exactly as before: a request
// that is not JSON, one over the parser's decode limit (here the gzip
// expansion ratio) and one the normalizer refuses (it holds a reserved
// marker key).
func TestNoRequestOnlyTurnWithoutAUsableRequest(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	ctx := context.Background()
	h := headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-requestonlykey", "anthropic-version", "2023-06-01")
	stream := upstreamResponse{contentType: "text/event-stream", body: noStopStream}
	chat := headers("Authorization", "Bearer sk-requestonlykey")
	chatStream := upstreamResponse{contentType: "text/event-stream", body: openAIHalfStream}
	cases := []struct {
		name     string
		path     string
		headers  http.Header
		body     string
		response upstreamResponse
		// code is the saved error code; empty means any code but the
		// normalization and reconstruction ones.
		code string
	}{
		{"not JSON", "/v1/messages", h, `{"model":"model-example","messages":[`, stream, "missing_message_stop"},
		{"over the decode limit", "/v1/messages", headers("User-Agent", "example-agent/1.0", "X-Api-Key", "sk-requestonlykey", "Content-Encoding", "gzip"),
			gzipText(t, requestOnlyRequest(`{"role":"user","content":"`+strings.Repeat("a", 256<<10)+`"}`)), stream, "gzip_ratio_exceeded"},
		// The normalizer refuses it.
		{"reserved marker", "/v1/messages", h, requestOnlyRequest(`{"role":"user","content":[{"type":"text","text":"x","` + auditmodel.ItemMarkerKey + `":0}]}`), stream, "missing_message_stop"},
		// It normalizes, and preparing its objects fails: a data URL that is
		// not base64.
		{"does not verify", "/v1/chat/completions", chat,
			`{"model":"model-example","stream":true,"messages":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,%%%invalid%%%"}]}]}`, chatStream, ""},
	}
	for _, test := range cases {
		id := harness.send(test.path, test.headers, test.body, test.response)
		if got := harness.retention(id); got.request != sqlite.RetentionFull || got.response != sqlite.RetentionFull {
			t.Fatalf("%s: retention %+v, want full", test.name, got)
		}
		detail, err := harness.store.QueryAuditDetail(ctx, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if detail.TurnGraph != nil || detail.ParsedResult == nil || detail.ParsedResult.Status != sqlite.ParsePartial ||
			detail.ParsedResult.ErrorCode == nil || (test.code != "" && *detail.ParsedResult.ErrorCode != test.code) ||
			*detail.ParsedResult.ErrorCode == "normalization_failed" || *detail.ParsedResult.ErrorCode == "reconstruction_failed" {
			t.Fatalf("%s: turn %v, parsed %+v", test.name, detail.TurnGraph != nil, detail.ParsedResult)
		}
		t.Logf("%s: saved as %s / %s", test.name, detail.ParsedResult.Status, *detail.ParsedResult.ErrorCode)
		if events := integrityEventTypes(t, harness.dbPath, id); !reflect.DeepEqual(events, []string{"capture_finalized"}) {
			t.Fatalf("%s: integrity events %v", test.name, events)
		}
	}
	if err := harness.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity payloads: %v", err)
	}
}

// openAIFallback is what the old worker stored as the fallback conversation
// of a Chat Completions audit whose stream was cut: the parse of the
// captured bodies.
func openAIFallback(t *testing.T, request, response string) any {
	t.Helper()
	implementation, err := openai.New(openai.ChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	return implementation.Parse(context.Background(), parser.Input{
		Request:  parser.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(request)},
		Response: parser.BodySource{Present: true, ContentType: "text/event-stream", Data: []byte(response)},
	}).Conversation
}

// openAIHalfStream is a Chat Completions stream cut before its end.
const openAIHalfStream = `data: {"id":"chatcmpl-half","object":"chat.completion.chunk","model":"model-example","choices":[{"index":0,"delta":{"role":"assistant","content":"half an ans"}}]}` + "\n\n"

// The same for OpenAI Chat Completions, whose rebuilt conversation comes
// from another adapter. Insights take an OpenAI audit's session from its turn
// conversation (insights.Link), so a cancelled audit, which had no turn
// before, now has session link "conversation"; live and backfilled analyses
// are equal.
func TestRequestOnlyTurnOfAnOpenAICancel(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	ctx := context.Background()
	h := headers("Authorization", "Bearer sk-requestonlykey", "User-Agent", "example-agent/1.0")
	request := `{"model":"model-example","stream":true,"prompt_cache_key":"cache-request-only","messages":[{"role":"system","content":"You are an agent."},{"role":"user","content":"explain the build"}]}`
	id := harness.sendCancelled("/v1/chat/completions", h, request, openAIHalfStream)
	if got := harness.retention(id); got.request != sqlite.RetentionMetadata || got.response != sqlite.RetentionFull {
		t.Fatalf("retention %+v", got)
	}
	parsed, plaintext := harness.parsedPlaintext(id)
	if parsed.Status != sqlite.ParsePartial || parsed.ErrorCode == nil || bytes.Contains(plaintext, []byte(`"conversation"`)) ||
		!bytes.Contains(plaintext, []byte(parser.PartialResponseMessagesKey)) {
		t.Fatalf("parsed %+v: %s", parsed, plaintext)
	}
	t.Logf("saved as %s / %s", parsed.Status, *parsed.ErrorCode)
	service := harness.service()
	detail, err := service.Get(ctx, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	fallback := openAIFallback(t, request, openAIHalfStream)
	if !reflect.DeepEqual(detail.Conversation, fallback) {
		got, _ := json.Marshal(detail.Conversation)
		want, _ := json.Marshal(fallback)
		t.Fatalf("detail conversation differs from the fallback\n got: %s\nwant: %s", got, want)
	}
	live := harness.analysis(id)
	if live.SessionLink == nil || *live.SessionLink != insights.SessionLinkConversation || live.AnalysisSessionID == nil || *live.AnalysisSessionID != detail.Turn.ConversationID {
		t.Fatalf("live analysis session %v / %v, turn conversation %s", live.SessionLink, live.AnalysisSessionID, detail.Turn.ConversationID)
	}
	row := live
	row.AnalysisVersion--
	if err := harness.store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	harness.enableInsights(true)
	harness.worker.ResetBackfillForTest()
	harness.worker.BackfillForTest(ctx)
	got := harness.analysis(id)
	live.DetailEnc, got.DetailEnc = nil, nil
	got.AnalyzedAtNS = live.AnalyzedAtNS
	if !reflect.DeepEqual(got, live) {
		t.Fatalf("backfilled analysis differs\n got: %+v\nwant: %+v", got, live)
	}
	if err := harness.store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("integrity payloads: %v", err)
	}
}
