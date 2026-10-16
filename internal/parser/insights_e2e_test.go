package parser_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	"llmapi-logger/internal/proxy"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// insightsHarness drives real requests through the audit proxy into SQLite,
// then parses and analyses each audit synchronously with the real worker.
type insightsHarness struct {
	t       *testing.T
	dbPath  string
	store   *sqlite.Store
	fp      *security.AnalysisFingerprinter
	handler http.Handler
	worker  *parser.Worker

	mu       sync.Mutex
	response upstreamResponse
	seen     map[string]bool
}

type upstreamResponse struct {
	contentType string
	body        string
}

func newInsightsHarness(t *testing.T, analyzer func(store *sqlite.Store, cipher security.Cipher, fp *security.AnalysisFingerprinter) parser.AuditAnalyzer) *insightsHarness {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := bytes.Repeat([]byte{0x5a}, security.KeySize)
	harness := &insightsHarness{t: t, dbPath: filepath.Join(t.TempDir(), "audit.db"), seen: map[string]bool{}}

	store, err := sqlite.Open(ctx, harness.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(ctx, key); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := security.NewCredentialFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	harness.fp, err = security.NewAnalysisFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	harness.store = store
	manager, err := audit.NewManager(store, cipher, credentials, audit.ModeAvailable, logger)
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		harness.mu.Lock()
		next := harness.response
		harness.mu.Unlock()
		response.Header().Set("Content-Type", next.contentType)
		_, _ = io.WriteString(response, next.body)
	}))
	t.Cleanup(upstream.Close)
	routes := []config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages"},
	}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := interceptor.NewEngine(nil, routes)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	harness.handler = proxy.NewWithAudit(target, matcher, engine, manager, logger)

	harness.worker, err = parser.NewWorker(store, cipher, builtin.All(), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(harness.worker.Close)
	if analyzer != nil {
		harness.worker.SetHeaderAllowlist(insights.DefaultVocabulary().HeaderAllowlist())
		harness.worker.SetAnalyzer(analyzer(store, cipher, harness.fp))
	}
	return harness
}

func runnerAnalyzer(t *testing.T) func(*sqlite.Store, security.Cipher, *security.AnalysisFingerprinter) parser.AuditAnalyzer {
	return func(store *sqlite.Store, cipher security.Cipher, fp *security.AnalysisFingerprinter) parser.AuditAnalyzer {
		runner, err := insights.NewRunner(store, cipher, nil, fp)
		if err != nil {
			t.Fatal(err)
		}
		return runner
	}
}

// send proxies one request, waits for its audit to end, parses it and
// returns the audit id.
func (harness *insightsHarness) send(path string, headers http.Header, body string, response upstreamResponse) string {
	harness.t.Helper()
	harness.mu.Lock()
	harness.response = response
	harness.mu.Unlock()
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		harness.t.Fatalf("proxy status = %d body=%q", recorder.Code, recorder.Body.String())
	}
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

func (harness *insightsHarness) analysis(auditID string) sqlite.AnalysisRow {
	harness.t.Helper()
	row, err := harness.store.LoadAnalysis(context.Background(), auditID)
	if err != nil {
		harness.t.Fatalf("load analysis %s: %v", auditID, err)
	}
	return row
}

func (harness *insightsHarness) agent(client, rawID string) []byte {
	return insights.AgentFPR(harness.fp, client, rawID)
}

func headers(pairs ...string) http.Header {
	result := http.Header{}
	for index := 0; index+1 < len(pairs); index += 2 {
		result.Add(pairs[index], pairs[index+1])
	}
	return result
}

func chatResponse(model, content string) upstreamResponse {
	return upstreamResponse{contentType: "application/json", body: `{"id":"chatcmpl-test","object":"chat.completion","model":"` + model +
		`","choices":[{"index":0,"message":{"role":"assistant","content":"` + content + `"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":20,"completion_tokens":3,"total_tokens":23}}`}
}

func responsesResponse(model string) upstreamResponse {
	return upstreamResponse{contentType: "application/json", body: `{"id":"resp_test","object":"response","model":"` + model +
		`","status":"completed","output":[{"type":"message","id":"msg_test","role":"assistant","content":[{"type":"output_text","text":"done"}]}],` +
		`"usage":{"input_tokens":20,"output_tokens":3,"total_tokens":23}}`}
}

func messagesResponse(model string, content string) upstreamResponse {
	return upstreamResponse{contentType: "application/json", body: `{"id":"msg_test","type":"message","role":"assistant","model":"` + model +
		`","content":[` + content + `],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":3}}`}
}

func chatBody(model, system, user string) string {
	return `{"model":"` + model + `","messages":[{"role":"system","content":"` + system + `"},{"role":"user","content":"` + user + `"}]}`
}

type wantAgent struct {
	client, role       string
	node, parent, root []byte
	source             string
}

func assertAgent(t *testing.T, label string, row sqlite.AnalysisRow, want wantAgent) {
	t.Helper()
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	if text(row.AgentClient) != want.client || text(row.AgentRole) != want.role || text(row.AgentLinkSource) != want.source {
		t.Fatalf("%s: client=%q role=%q source=%q, want %q %q %q", label,
			text(row.AgentClient), text(row.AgentRole), text(row.AgentLinkSource), want.client, want.role, want.source)
	}
	for _, field := range []struct {
		name      string
		got, want []byte
	}{{"node", row.AgentNodeFPR, want.node}, {"parent", row.AgentParentFPR, want.parent}, {"root", row.AgentRootFPR, want.root}} {
		if !bytes.Equal(field.got, field.want) {
			t.Fatalf("%s: %s fingerprint = %x, want %x", label, field.name, field.got, field.want)
		}
	}
	if want.node != nil {
		wantSession := "agt_" + hex.EncodeToString(want.node)[:24]
		if row.AnalysisSessionID == nil || *row.AnalysisSessionID != wantSession || text(row.SessionLink) != insights.SessionLinkAgent {
			t.Fatalf("%s: session = %v link=%v, want %s", label, row.AnalysisSessionID, row.SessionLink, wantSession)
		}
	}
}

func TestInsightsAgentTreesFromClientHeaders(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	auth := "Bearer sk-test-tree-key"
	chat := func(h http.Header, user string) string {
		h.Set("Authorization", auth)
		return harness.send("/v1/chat/completions", h, chatBody("model-example", "You are an agent.", user), chatResponse("model-example", "ok"))
	}

	// Codex on the Responses API: session-id is the tree, thread-id the node.
	codexBody := `{"model":"model-example","input":[{"role":"user","content":[{"type":"input_text","text":"codex task"}]}]}`
	codex := func(extra ...string) sqlite.AnalysisRow {
		h := headers(append([]string{"User-Agent", "codex_cli_rs/0.50.0", "originator", "codex_cli_rs",
			"Authorization", auth, "session-id", "raw-codex-session"}, extra...)...)
		return harness.analysis(harness.send("/v1/responses", h, codexBody, responsesResponse("model-example")))
	}
	codexRoot := harness.agent("codex", "raw-codex-session")
	codexMain := harness.agent("codex", "raw-codex-main")
	codexChild := harness.agent("codex", "raw-codex-child")
	assertAgent(t, "codex main", codex("thread-id", "raw-codex-main"),
		wantAgent{client: "codex", role: "main", node: codexMain, root: codexRoot, source: "header"})
	assertAgent(t, "codex child", codex("thread-id", "raw-codex-child", "x-codex-parent-thread-id", "raw-codex-main", "x-openai-subagent", "collab_spawn"),
		wantAgent{client: "codex", role: "subagent", node: codexChild, parent: codexMain, root: codexRoot, source: "header"})
	assertAgent(t, "codex compact", codex("thread-id", "raw-codex-main", "x-openai-subagent", "compact"),
		wantAgent{client: "codex", role: "compaction", node: codexMain, root: codexRoot, source: "header"})

	// Claude Code on Messages: the session id is the main agent's node.
	claude := func(extra ...string) sqlite.AnalysisRow {
		h := headers(append([]string{"User-Agent", "claude-cli/2.1.90 (external, cli)", "X-Api-Key", "sk-test-tree-key",
			"anthropic-version", "2023-06-01", "X-Claude-Code-Session-Id", "raw-claude-session"}, extra...)...)
		body := `{"model":"model-example","max_tokens":64,"system":"You are Claude Code.","messages":[{"role":"user","content":"claude task"}]}`
		return harness.analysis(harness.send("/v1/messages", h, body, messagesResponse("model-example", `{"type":"text","text":"ok"}`)))
	}
	ccRoot := harness.agent("claude_code", "raw-claude-session")
	ccAgent := harness.agent("claude_code", "raw-claude-agent")
	ccGrand := harness.agent("claude_code", "raw-claude-grand")
	assertAgent(t, "claude main", claude(), wantAgent{client: "claude_code", role: "main", node: ccRoot, root: ccRoot, source: "header"})
	assertAgent(t, "claude agent", claude("X-Claude-Code-Agent-Id", "raw-claude-agent"),
		wantAgent{client: "claude_code", role: "subagent", node: ccAgent, parent: ccRoot, root: ccRoot, source: "header"})
	assertAgent(t, "claude grandchild", claude("X-Claude-Code-Agent-Id", "raw-claude-grand", "X-Claude-Code-Parent-Agent-Id", "raw-claude-agent"),
		wantAgent{client: "claude_code", role: "subagent", node: ccGrand, parent: ccAgent, root: ccRoot, source: "header"})
	assertAgent(t, "claude compaction", claude("X-Claude-Code-Agent-Id", "raw-claude-agent", "X-Claude-Code-Request-Class", "compaction"),
		wantAgent{client: "claude_code", role: "compaction", node: ccAgent, parent: ccRoot, root: ccRoot, source: "header"})

	// OpenCode has no root header: the root comes from the parent's row.
	// Under ChatGPT auth it also sends originator, which must not win.
	ocRoot := harness.agent("opencode", "raw-oc-root")
	ocChild := harness.agent("opencode", "raw-oc-child")
	ocGrand := harness.agent("opencode", "raw-oc-grand")
	opencode := func(extra ...string) sqlite.AnalysisRow {
		return harness.analysis(chat(headers(append([]string{"User-Agent", "opencode/1.19.2", "originator", "opencode"}, extra...)...), "opencode task"))
	}
	assertAgent(t, "opencode root", opencode("x-opencode-session-id", "raw-oc-root"),
		wantAgent{client: "opencode", role: "main", node: ocRoot, root: ocRoot, source: "header"})
	assertAgent(t, "opencode child", opencode("x-opencode-session-id", "raw-oc-child", "x-opencode-parent-session-id", "raw-oc-root"),
		wantAgent{client: "opencode", role: "subagent", node: ocChild, parent: ocRoot, root: ocRoot, source: "header"})
	assertAgent(t, "opencode grandchild", opencode("x-opencode-session-id", "raw-oc-grand", "x-parent-session-id", "raw-oc-child"),
		wantAgent{client: "opencode", role: "subagent", node: ocGrand, parent: ocChild, root: ocRoot, source: "header"})

	// dsh names its parent in the body session log.
	dshRoot := harness.agent("dsh", "raw-dsh-root")
	dshChild := harness.agent("dsh", "raw-dsh-child")
	dshMain := chat(headers("User-Agent", "deepseek-harness/0.3", "x-deepseek-harness-session-id", "raw-dsh-root"), "dsh task")
	assertAgent(t, "dsh main", harness.analysis(dshMain), wantAgent{client: "dsh", role: "main", node: dshRoot, root: dshRoot, source: "header"})
	dshBody := `{"model":"model-example","messages":[{"role":"user","content":"dsh child task"}],` +
		`"dsh_session_log":{"header":{"parentSession":"raw-dsh-root","origin":"subagent","delegationDepth":1}}}`
	dshChildID := harness.send("/v1/chat/completions", headers("User-Agent", "deepseek-harness/0.3", "Authorization", auth,
		"x-deepseek-harness-session-id", "raw-dsh-child"), dshBody, chatResponse("model-example", "ok"))
	assertAgent(t, "dsh child", harness.analysis(dshChildID),
		wantAgent{client: "dsh", role: "subagent", node: dshChild, parent: dshRoot, root: dshRoot, source: "body"})
	dshCompact := chat(headers("User-Agent", "deepseek-harness/0.3", "x-deepseek-harness-session-id", "raw-dsh-root", "x-deepseek-harness-compact", "1"), "dsh compact")
	assertAgent(t, "dsh compaction", harness.analysis(dshCompact), wantAgent{client: "dsh", role: "compaction", node: dshRoot, root: dshRoot, source: "header"})

	// Custom X-Agent-* headers: main, child, grandchild and a compaction of
	// the child that stays attached to the child.
	tree := harness.agent("custom", "raw-custom-tree")
	child := harness.agent("custom", "raw-custom-child")
	grand := harness.agent("custom", "raw-custom-grand")
	custom := func(extra ...string) sqlite.AnalysisRow {
		return harness.analysis(chat(headers(append([]string{"User-Agent", "example-framework/1.0", "X-Agent-Session-Id", "raw-custom-tree"}, extra...)...), "custom task"))
	}
	assertAgent(t, "custom main", custom("X-Agent-Id", "raw-custom-tree", "X-Agent-Name", "planner"),
		wantAgent{client: "custom", role: "main", node: tree, root: tree, source: "header"})
	assertAgent(t, "custom child", custom("X-Agent-Id", "raw-custom-child", "X-Agent-Parent-Id", "raw-custom-tree"),
		wantAgent{client: "custom", role: "subagent", node: child, parent: tree, root: tree, source: "header"})
	assertAgent(t, "custom grandchild", custom("X-Agent-Id", "raw-custom-grand", "X-Agent-Parent-Id", "raw-custom-child"),
		wantAgent{client: "custom", role: "subagent", node: grand, parent: child, root: tree, source: "header"})
	assertAgent(t, "custom compaction", custom("X-Agent-Id", "raw-custom-child", "X-Agent-Parent-Id", "raw-custom-tree", "X-Agent-Role", "compaction"),
		wantAgent{client: "custom", role: "compaction", node: child, parent: tree, root: tree, source: "header"})

	// Raw agent ids appear only inside encrypted headers and detail blobs.
	harness.store.Close()
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(harness.dbPath + suffix)
		if err != nil {
			continue
		}
		for _, raw := range []string{"raw-codex-main", "raw-claude-agent", "raw-oc-child", "raw-dsh-root", "raw-custom-grand", "planner"} {
			if bytes.Contains(data, []byte(raw)) {
				t.Fatalf("raw agent identifier %q stored in plaintext", raw)
			}
		}
	}
}

func messagesBody(model, system string, messages ...string) string {
	return `{"model":"` + model + `","max_tokens":64,"system":"` + system + `","messages":[` + strings.Join(messages, ",") + `]}`
}

func userMessage(text string) string { return `{"role":"user","content":"` + text + `"}` }

func assistantMessage(text string) string { return `{"role":"assistant","content":"` + text + `"}` }

const spawnPrompt = "Investigate the parser module and report the entry points"

func spawnResponse(prompt string) upstreamResponse {
	return messagesResponse("model-example", `{"type":"tool_use","id":"toolu_test","name":"Task","input":{"prompt":"`+prompt+`"}}`)
}

// messages sends an Anthropic request from an unrecognised client. Test keys
// avoid dashes: NewAPI normalization keeps only the segment before the first
// dash, so "sk-a-1" and "sk-a-2" would share one api_key_fpr.
func (harness *insightsHarness) messages(apiKey, body string, response upstreamResponse) sqlite.AnalysisRow {
	harness.t.Helper()
	h := headers("User-Agent", "example-agent/1.0", "X-Api-Key", apiKey, "anthropic-version", "2023-06-01")
	return harness.analysis(harness.send("/v1/messages", h, body, response))
}

func TestInsightsContentMatchLinksOnlyAUniqueParent(t *testing.T) {
	t.Parallel()
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	ok := messagesResponse("model-example", `{"type":"text","text":"ok"}`)

	t.Run("unique parent links", func(t *testing.T) {
		t.Parallel()
		harness := newInsightsHarness(t, runnerAnalyzer(t))
		parent := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the work")), spawnResponse(spawnPrompt))
		if len(parent.SpawnHints) != 1 || text(parent.AgentClient) != insights.ClientUnknown || text(parent.AgentRole) != "main" {
			t.Fatalf("parent row: hints=%d client=%s role=%s", len(parent.SpawnHints), text(parent.AgentClient), text(parent.AgentRole))
		}
		childBody := messagesBody("model-example", "You are a research helper.", userMessage(spawnPrompt))
		child := harness.messages("sk-testkeyalpha", childBody, ok)
		if text(child.AgentLinkSource) != "content" || child.AgentLinkConfidence == nil || *child.AgentLinkConfidence != 70 ||
			text(child.AgentRole) != "subagent" || !bytes.Equal(child.AgentParentFPR, parent.AgentNodeFPR) ||
			!bytes.Equal(child.AgentRootFPR, parent.AgentRootFPR) || bytes.Equal(child.AgentNodeFPR, parent.AgentNodeFPR) {
			t.Fatalf("content link: source=%s confidence=%v role=%s parent=%x root=%x", text(child.AgentLinkSource),
				child.AgentLinkConfidence, text(child.AgentRole), child.AgentParentFPR, child.AgentRootFPR)
		}
		// Later steps of the child inherit the link from their previous step.
		next := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are a research helper.",
			userMessage(spawnPrompt), assistantMessage("looking"), userMessage("continue")), ok)
		if text(next.PrevAuditID) != child.AuditID || text(next.AgentLinkSource) != "content" ||
			!bytes.Equal(next.AgentParentFPR, parent.AgentNodeFPR) || !bytes.Equal(next.AgentNodeFPR, child.AgentNodeFPR) {
			t.Fatalf("second child step: prev=%s source=%s parent=%x", text(next.PrevAuditID), text(next.AgentLinkSource), next.AgentParentFPR)
		}
	})

	t.Run("prefix stripped opener links with lower confidence", func(t *testing.T) {
		t.Parallel()
		harness := newInsightsHarness(t, runnerAnalyzer(t))
		parent := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the work")), spawnResponse(spawnPrompt))
		child := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are a research helper.",
			userMessage(`You are a subagent spawned by another session.\n`+spawnPrompt)), ok)
		if text(child.AgentLinkSource) != "content" || child.AgentLinkConfidence == nil || *child.AgentLinkConfidence != 60 ||
			!bytes.Equal(child.AgentParentFPR, parent.AgentNodeFPR) {
			t.Fatalf("stripped link: source=%s confidence=%v", text(child.AgentLinkSource), child.AgentLinkConfidence)
		}
	})

	t.Run("two candidate parents do not link", func(t *testing.T) {
		t.Parallel()
		harness := newInsightsHarness(t, runnerAnalyzer(t))
		harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the first")), spawnResponse(spawnPrompt))
		harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the second")), spawnResponse(spawnPrompt))
		child := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are a research helper.", userMessage(spawnPrompt)), ok)
		if child.AgentLinkSource != nil || child.AgentParentFPR != nil || text(child.AgentRole) != "main" {
			t.Fatalf("ambiguous parents linked: source=%s parent=%x", text(child.AgentLinkSource), child.AgentParentFPR)
		}
	})

	t.Run("different api key does not link", func(t *testing.T) {
		t.Parallel()
		harness := newInsightsHarness(t, runnerAnalyzer(t))
		harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the work")), spawnResponse(spawnPrompt))
		child := harness.messages("sk-testkeybeta", messagesBody("model-example", "You are a research helper.", userMessage(spawnPrompt)), ok)
		if child.AgentLinkSource != nil || child.AgentParentFPR != nil {
			t.Fatalf("cross-key content link: source=%s", text(child.AgentLinkSource))
		}
	})

	t.Run("auxiliary requests are never content children", func(t *testing.T) {
		t.Parallel()
		harness := newInsightsHarness(t, runnerAnalyzer(t))
		harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are the planner.", userMessage("plan the work")), spawnResponse(spawnPrompt))
		title := harness.messages("sk-testkeyalpha", messagesBody("model-example", "You are a title generator.", userMessage(spawnPrompt)), ok)
		if text(title.AgentRole) != "title" || title.AgentLinkSource != nil || title.AgentParentFPR != nil {
			t.Fatalf("title request: role=%s source=%s", text(title.AgentRole), text(title.AgentLinkSource))
		}
	})
}

func TestInsightsPreviousStepDiffAndEvents(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	ok := messagesResponse("model-example", `{"type":"text","text":"ok"}`)
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	intValue := func(value *int) int {
		if value == nil {
			return -1
		}
		return *value
	}
	const system = "You are a coding agent."
	step := func(model string, messages ...string) sqlite.AnalysisRow {
		return harness.messages("sk-testkeyalpha", messagesBody(model, system, messages...), ok)
	}
	// A parallel conversation with another opener must not be chosen.
	other := step("model-example", userMessage("an unrelated task"))

	first := step("model-example", userMessage("fix the bug"))
	if first.PrevAuditID != nil || first.AppendedItems != nil || text(first.SessionLink) != "inferred" ||
		text(first.AnalysisSessionID) == text(other.AnalysisSessionID) {
		t.Fatalf("first step: prev=%v link=%s", first.PrevAuditID, text(first.SessionLink))
	}
	extended := step("model-example", userMessage("fix the bug"), assistantMessage("looking"), userMessage("go on"))
	if text(extended.PrevAuditID) != first.AuditID || intValue(extended.AppendedItems) != 2 || intValue(extended.RemovedItems) != 0 ||
		extended.EventFlags != 0 || text(extended.AnalysisSessionID) != text(first.AnalysisSessionID) {
		t.Fatalf("prefix extension: prev=%s appended=%d removed=%d events=%d", text(extended.PrevAuditID),
			intValue(extended.AppendedItems), intValue(extended.RemovedItems), extended.EventFlags)
	}
	switched := step("model-other", userMessage("fix the bug"), assistantMessage("looking"), userMessage("go on"), assistantMessage("done"), userMessage("next"))
	if text(switched.PrevAuditID) != extended.AuditID || switched.EventFlags != insights.EventModelSwitch {
		t.Fatalf("model switch: prev=%s events=%d", text(switched.PrevAuditID), switched.EventFlags)
	}
	injected := step("model-other", userMessage("fix the bug"), assistantMessage("looking"), userMessage("go on"), assistantMessage("done"),
		userMessage("next"), assistantMessage("sure"), userMessage("<system-reminder>context refreshed</system-reminder>"))
	if injected.EventFlags&insights.EventInjected == 0 || intValue(injected.AppendedItems) != 2 {
		t.Fatalf("injected: events=%d appended=%d", injected.EventFlags, intValue(injected.AppendedItems))
	}

	// Grow the context past 8k estimated tokens, then compact it.
	large := strings.Repeat("log line with details ", 2000)
	big := step("model-other", userMessage("fix the bug"), assistantMessage("looking"), userMessage(large), assistantMessage("read it"))
	total := big.EstSystem + big.EstTools + big.EstUser + big.EstInjected + big.EstAssistant + big.EstReasoning + big.EstToolResult + big.EstMedia
	if total < 8000 || text(big.PrevAuditID) != injected.AuditID {
		t.Fatalf("large step: estimate=%d prev=%s", total, text(big.PrevAuditID))
	}
	compacted := step("model-other", userMessage("fix the bug"), assistantMessage("summary of earlier work"), userMessage("continue"))
	if text(compacted.PrevAuditID) != big.AuditID || compacted.EventFlags&insights.EventCompaction == 0 || intValue(compacted.RemovedItems) <= 0 {
		t.Fatalf("compaction: prev=%s events=%d removed=%d", text(compacted.PrevAuditID), compacted.EventFlags, intValue(compacted.RemovedItems))
	}
}

func TestInsightsDisabledWorkerWritesNoAnalysis(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, nil)
	auditID := harness.send("/v1/chat/completions", headers("Authorization", "Bearer sk-test-tree-key", "X-Agent-Id", "raw-disabled"),
		chatBody("model-example", "You are an agent.", "task"), chatResponse("model-example", "ok"))
	if _, err := harness.store.LoadAnalysis(context.Background(), auditID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("LoadAnalysis without analyzer = %v, want no rows", err)
	}
	audit, err := harness.store.LoadParserAudit(context.Background(), auditID)
	if err != nil || audit.ParseStatus != sqlite.ParseOK {
		t.Fatalf("parse status = %q err=%v", audit.ParseStatus, err)
	}
}

// failingAnalyzer fails or panics; either way the committed parse must stand.
type failingAnalyzer struct {
	panic bool
	calls int
}

func (analyzer *failingAnalyzer) AnalyzeAudit(context.Context, insights.Input) error {
	analyzer.calls++
	if analyzer.panic {
		panic("analysis test panic")
	}
	return &insights.RunError{Code: insights.ErrorCodeAnalysisSaveFailed, Err: errors.New("analysis test failure")}
}

func TestInsightsAnalysisFailureKeepsParseResult(t *testing.T) {
	t.Parallel()
	for _, panics := range []bool{false, true} {
		analyzer := &failingAnalyzer{panic: panics}
		harness := newInsightsHarness(t, func(*sqlite.Store, security.Cipher, *security.AnalysisFingerprinter) parser.AuditAnalyzer {
			return analyzer
		})
		auditID := harness.send("/v1/chat/completions", headers("Authorization", "Bearer sk-test-tree-key"),
			chatBody("model-example", "You are an agent.", "task"), chatResponse("model-example", "ok"))
		audit, err := harness.store.LoadParserAudit(context.Background(), auditID)
		if err != nil || audit.ParseStatus != sqlite.ParseOK || analyzer.calls != 1 {
			t.Fatalf("panic=%v: parse status = %q calls=%d err=%v", panics, audit.ParseStatus, analyzer.calls, err)
		}
		if _, err := harness.store.LoadAnalysis(context.Background(), auditID); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("panic=%v: LoadAnalysis = %v, want no rows", panics, err)
		}
		// The worker keeps serving after a failed analysis.
		next := harness.send("/v1/chat/completions", headers("Authorization", "Bearer sk-test-tree-key"),
			chatBody("model-example", "You are an agent.", "again"), chatResponse("model-example", "ok"))
		if audit, err := harness.store.LoadParserAudit(context.Background(), next); err != nil || audit.ParseStatus != sqlite.ParseOK || analyzer.calls != 2 {
			t.Fatalf("panic=%v: follow-up parse status = %q calls=%d", panics, audit.ParseStatus, analyzer.calls)
		}
	}
}

func TestInsightsStreamTimingIsRelativeToAuditStart(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	stream := upstreamResponse{contentType: "text/event-stream", body: "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"model\":\"model-example\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"model\":\"model-example\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1,\"total_tokens\":6}}\n\n" +
		"data: [DONE]\n\n"}
	body := `{"model":"model-example","stream":true,"messages":[{"role":"user","content":"stream it"}]}`
	row := harness.analysis(harness.send("/v1/chat/completions", headers("Authorization", "Bearer sk-test-tree-key"), body, stream))
	if row.FirstEventNS == nil || *row.FirstEventNS < 0 || *row.FirstEventNS > int64(time.Minute) ||
		row.GenerationNS == nil || *row.GenerationNS < 0 {
		t.Fatalf("timing first=%v generation=%v", row.FirstEventNS, row.GenerationNS)
	}
	if row.Output == nil || *row.Output != 1 {
		t.Fatalf("stream usage output = %v", row.Output)
	}
}
