package contentpolicy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/routing"
)

func TestEmptySnapshotAllowsEverything(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	result, replayed := evaluate(t, engine, matcher, `{"model":"gpt-test","messages":[{"role":"user","content":"reverse shell"}]}`)
	if !result.Allowed {
		t.Fatalf("empty snapshot rejected: %+v", result)
	}
	if replayed != `{"model":"gpt-test","messages":[{"role":"user","content":"reverse shell"}]}` {
		t.Fatalf("replayed body changed: %q", replayed)
	}
	if rules := service.List(); len(rules) != 0 {
		t.Fatalf("initial rules = %+v", rules)
	}
}

func TestBlockRuleRejectsKeywordBeforeForwarding(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	rule, err := service.Create(context.Background(), RuleInput{
		Name:     "cyber words",
		Enabled:  true,
		Keywords: []string{"reverse shell"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rule.ScanScopes) != len(AllScanScopes) {
		t.Fatalf("default scopes = %v", rule.ScanScopes)
	}

	body := `{"model":"gpt-test","messages":[{"role":"user","content":"please build a REVERSE SHELL"}]}`
	result, replayed := evaluate(t, engine, matcher, body)
	if result.Allowed || result.StatusCode != http.StatusBadRequest || result.BlockedBy != InterceptorID ||
		result.BlockCode != BlockCode || result.Internal != nil {
		t.Fatalf("unexpected result = %+v", result)
	}
	if replayed != body {
		t.Fatalf("replayed body changed: %q", replayed)
	}
}

func TestModelScopeSkipsUnmatchedAndMissingModels(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	if _, err := service.Create(context.Background(), RuleInput{
		Name:         "gpt only",
		Enabled:      true,
		Action:       ActionBlock,
		ModelPattern: "^gpt",
		Keywords:     []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		body    string
		allowed bool
	}{
		{`{"model":"gpt-test","messages":[{"role":"user","content":"forbidden"}]}`, false},
		{`{"model":"deepseek-test","messages":[{"role":"user","content":"forbidden"}]}`, true},
		{`{"messages":[{"role":"user","content":"forbidden"}]}`, true},
	}
	for _, test := range cases {
		result, _ := evaluate(t, engine, matcher, test.body)
		if result.Allowed != test.allowed {
			t.Fatalf("body %q result = %+v", test.body, result)
		}
	}
}

func TestEmptyModelPatternAppliesWithoutModel(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	if _, err := service.Create(context.Background(), RuleInput{
		Name:     "all models",
		Enabled:  true,
		Keywords: []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}
	result, _ := evaluate(t, engine, matcher, `{"messages":[{"role":"user","content":"forbidden"}]}`)
	if result.Allowed {
		t.Fatalf("all-model rule did not apply: %+v", result)
	}
}

func TestScanScopeSelection(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	latestOnly, err := service.Create(context.Background(), RuleInput{
		Name:       "latest only",
		Enabled:    true,
		ScanScopes: []string{ScopeLatestUser},
		Keywords:   []string{"secretword"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = latestOnly

	systemBody := `{"model":"gpt-test","messages":[{"role":"system","content":"secretword"},{"role":"user","content":"hello"}]}`
	if result, _ := evaluate(t, engine, matcher, systemBody); !result.Allowed {
		t.Fatalf("latest-only rule blocked a system keyword: %+v", result)
	}
	latestBody := `{"model":"gpt-test","messages":[{"role":"system","content":"hello"},{"role":"user","content":"secretword"}]}`
	if result, _ := evaluate(t, engine, matcher, latestBody); result.Allowed {
		t.Fatalf("latest-only rule missed the latest user keyword: %+v", result)
	}

	// A freshly created rule defaults to every scope.
	service, engine, matcher, _ = newTestEngine(t)
	allScopes, err := service.Create(context.Background(), RuleInput{
		Name:     "all scopes",
		Enabled:  true,
		Keywords: []string{"secretword"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = allScopes
	if result, _ := evaluate(t, engine, matcher, systemBody); result.Allowed {
		t.Fatalf("default all-scope rule missed a system keyword: %+v", result)
	}
}

func TestDryRunAllowsAndLogsRuleID(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	service, engine, matcher, _ := newTestEngineWithLogger(t, &logs)
	if _, err := service.Create(context.Background(), RuleInput{
		Name:     "dry run",
		Enabled:  true,
		Action:   ActionDryRun,
		Keywords: []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}
	result, _ := evaluate(t, engine, matcher, `{"model":"gpt-test","messages":[{"role":"user","content":"forbidden"}]}`)
	if !result.Allowed {
		t.Fatalf("dry run rejected: %+v", result)
	}
	if !strings.Contains(logs.String(), "content policy dry run match") || !strings.Contains(logs.String(), "policy_rule_id") {
		t.Fatalf("dry run log = %q", logs.String())
	}
}

func TestInvalidUpdateKeepsActiveSnapshot(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	created, err := service.Create(context.Background(), RuleInput{
		Name:     "valid",
		Enabled:  true,
		Keywords: []string{"forbidden"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), created.ID, RuleInput{
		Name:         "invalid regex",
		Enabled:      true,
		ModelPattern: "[",
		Keywords:     []string{"forbidden"},
	}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("invalid update error = %v", err)
	}
	if result, _ := evaluate(t, engine, matcher, `{"model":"gpt-test","messages":[{"role":"user","content":"forbidden"}]}`); result.Allowed {
		t.Fatalf("invalid update replaced the snapshot: %+v", result)
	}
	if _, err := service.Update(context.Background(), 9999, RuleInput{Name: "missing", Enabled: true, Keywords: []string{"x"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update error = %v", err)
	}
	if err := service.Delete(context.Background(), 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete error = %v", err)
	}
}

func TestCreateUpdateDeleteAreImmediate(t *testing.T) {
	t.Parallel()

	service, engine, matcher, _ := newTestEngine(t)
	created, err := service.Create(context.Background(), RuleInput{
		Name:         "temporary",
		Enabled:      true,
		ModelPattern: "^gpt",
		Keywords:     []string{"forbidden"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"model":"gpt-test","messages":[{"role":"user","content":"forbidden"}]}`
	if result, _ := evaluate(t, engine, matcher, body); result.Allowed {
		t.Fatalf("created rule did not apply: %+v", result)
	}
	if _, err := service.Update(context.Background(), created.ID, RuleInput{
		Name:         "disabled",
		Enabled:      false,
		ModelPattern: "^gpt",
		Keywords:     []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}
	if result, _ := evaluate(t, engine, matcher, body); !result.Allowed {
		t.Fatalf("disabled rule still applied: %+v", result)
	}
	if err := service.Delete(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if result, _ := evaluate(t, engine, matcher, body); !result.Allowed {
		t.Fatalf("deleted rule still applied: %+v", result)
	}
	next, err := service.Create(context.Background(), RuleInput{Name: "next", Enabled: true, Keywords: []string{"forbidden"}})
	if err != nil {
		t.Fatal(err)
	}
	if next.ID <= created.ID {
		t.Fatalf("rule ids were reused: created=%d next=%d", created.ID, next.ID)
	}
}

func TestEmptyScanScopesAreRejected(t *testing.T) {
	t.Parallel()

	service, _, _, _ := newTestEngine(t)
	_, err := service.Create(context.Background(), RuleInput{
		Name:       "no scopes",
		Enabled:    true,
		ScanScopes: []string{},
		Keywords:   []string{"forbidden"},
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("empty scan scopes error = %v", err)
	}
}

func TestEncodedMalformedAndUnsupportedParserFailOpen(t *testing.T) {
	t.Parallel()

	service, engine, matcher, logs := newTestEngineWithLogger(t, nil)
	if _, err := service.Create(context.Background(), RuleInput{
		Name:     "guard",
		Enabled:  true,
		Keywords: []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}

	encoded := requestFor(`{"model":"gpt-test","messages":[{"role":"user","content":"forbidden"}]}`, matcher)
	encoded.Header.Set("Content-Encoding", "gzip")
	result := engine.Evaluate(encoded.Context(), encoded, mustMatch(t, matcher, encoded))
	if !result.Allowed {
		t.Fatalf("encoded body was scanned: %+v", result)
	}

	result, _ = evaluate(t, engine, matcher, `not json at all`)
	if !result.Allowed {
		t.Fatalf("malformed JSON was rejected: %+v", result)
	}
	_ = logs
}

func TestGeminiTemplateModelScope(t *testing.T) {
	t.Parallel()

	routes := []config.RouteConfig{{
		ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent",
		Match: "template", Parser: "gemini.generate_content",
	}}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	service, err := New(context.Background(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	base, err := interceptor.NewEngine(nil, routes)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := base.WithGlobal(InterceptorID, service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(context.Background(), RuleInput{
		Name:         "gpt gemini",
		Enabled:      true,
		ModelPattern: "^gpt",
		Keywords:     []string{"forbidden"},
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"contents":[{"role":"user","parts":[{"text":"forbidden"}]}]}`
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1beta/models/gpt-5:generateContent", strings.NewReader(body))
	match, ok := matcher.Match(request.Method, request.URL.EscapedPath())
	if !ok {
		t.Fatal("gemini route did not match")
	}
	result := engine.Evaluate(request.Context(), request, match)
	if result.Allowed || result.StatusCode != http.StatusBadRequest {
		t.Fatalf("gemini path model scope result = %+v", result)
	}
}

func TestRequirementsMatchEngineBodyLimit(t *testing.T) {
	t.Parallel()

	service, _, _, _ := newTestEngine(t)
	requirements := service.Requirements()
	if !requirements.NeedsBody || requirements.MaxBodyBytes != interceptor.MaxBodyBytes {
		t.Fatalf("requirements = %+v", requirements)
	}
}

func newTestEngine(t *testing.T) (*Service, *interceptor.Engine, *routing.Matcher, *bytes.Buffer) {
	t.Helper()
	return newTestEngineWithLogger(t, nil)
}

func newTestEngineWithLogger(t *testing.T, logs *bytes.Buffer) (*Service, *interceptor.Engine, *routing.Matcher, *bytes.Buffer) {
	t.Helper()
	if logs == nil {
		logs = &bytes.Buffer{}
	}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	routes := []config.RouteConfig{{
		ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions",
	}}
	matcher, err := routing.Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	base, err := interceptor.NewEngine(nil, routes)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := base.WithGlobal(InterceptorID, service)
	if err != nil {
		t.Fatal(err)
	}
	return service, engine, matcher, logs
}

func evaluate(t *testing.T, engine *interceptor.Engine, matcher *routing.Matcher, body string) (interceptor.Result, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1/chat/completions", strings.NewReader(body))
	match, ok := matcher.Match(request.Method, request.URL.EscapedPath())
	if !ok {
		t.Fatal("route did not match")
	}
	result := engine.Evaluate(request.Context(), request, match)
	replayed, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return result, string(replayed)
}

func requestFor(body string, matcher *routing.Matcher) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1/chat/completions", strings.NewReader(body))
	return request
}

func mustMatch(t *testing.T, matcher *routing.Matcher, request *http.Request) routing.Match {
	t.Helper()
	match, ok := matcher.Match(request.Method, request.URL.EscapedPath())
	if !ok {
		t.Fatal("route did not match")
	}
	return match
}
