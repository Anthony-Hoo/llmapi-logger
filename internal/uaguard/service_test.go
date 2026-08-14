package uaguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/routing"
)

func TestDefaultRuleBlocksGPTWithoutMatchingUserAgent(t *testing.T) {
	t.Parallel()

	service, engine, matcher := newTestEngine(t)
	if rules := service.List(); len(rules) != 1 || rules[0].ModelPattern != "^gpt" || rules[0].UserAgentPattern != "^(codex-tui|Codex Desktop)" || !rules[0].Enabled {
		t.Fatalf("default rules = %+v", rules)
	}

	tests := []struct {
		name      string
		body      string
		userAgent string
		allowed   bool
	}{
		{name: "matching desktop UA", body: `{"model":"gpt-5"}`, userAgent: "Codex Desktop/1.0", allowed: true},
		{name: "matching terminal UA", body: `{"model":"gpt-5"}`, userAgent: "codex-tui/1.0", allowed: true},
		{name: "desktop text not at prefix", body: `{"model":"gpt-5"}`, userAgent: "client Codex Desktop/1.0", allowed: false},
		{name: "missing UA", body: `{"model":"gpt-5"}`, allowed: false},
		{name: "wrong UA", body: `{"model":"gpt-5"}`, userAgent: "codex desktop", allowed: false},
		{name: "non GPT model", body: `{"model":"deepseek-test"}`, allowed: true},
		{name: "missing model", body: `{"stream":true}`, allowed: true},
		{name: "malformed JSON", body: `{"model":`, allowed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, replayed := evaluate(t, engine, matcher, test.body, test.userAgent)
			if result.Allowed != test.allowed {
				t.Fatalf("result = %+v", result)
			}
			if !test.allowed && (result.StatusCode != http.StatusUnauthorized || result.BlockedBy != InterceptorID || result.BlockCode != BlockCode || result.Internal != nil) {
				t.Fatalf("unexpected rejection = %+v", result)
			}
			if replayed != test.body {
				t.Fatalf("replayed body = %q, want %q", replayed, test.body)
			}
		})
	}
}

func TestRequirementsUse512MiBBodyLimit(t *testing.T) {
	t.Parallel()

	const wantMaxBodyBytes int64 = 512 << 20
	if interceptor.MaxBodyBytes != wantMaxBodyBytes {
		t.Fatalf("interceptor.MaxBodyBytes = %d, want %d", interceptor.MaxBodyBytes, wantMaxBodyBytes)
	}
	requirements := (&Service{}).Requirements()
	if !requirements.NeedsBody || requirements.MaxBodyBytes != wantMaxBodyBytes {
		t.Fatalf("requirements = %+v", requirements)
	}
}

func TestBodyLargerThanLegacy16MiBLimitIsAllowed(t *testing.T) {
	_, engine, matcher := newTestEngine(t)

	const legacyLimit int64 = 16 << 20
	prefix := `{"model":"gpt-large"}`
	bodySize := legacyLimit + 1
	body := io.MultiReader(
		strings.NewReader(prefix),
		io.LimitReader(fillReader(' '), bodySize-int64(len(prefix))),
	)
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1/chat/completions", body)
	request.ContentLength = bodySize
	request.Header.Set("User-Agent", "Codex Desktop test")
	match, ok := matcher.Match(request.Method, request.URL.EscapedPath())
	if !ok {
		t.Fatal("route did not match")
	}

	result := engine.Evaluate(request.Context(), request, match)
	if !result.Allowed {
		t.Fatalf("result = %+v", result)
	}
	if replayed, err := io.Copy(io.Discard, request.Body); err != nil || replayed != bodySize {
		t.Fatalf("replayed body bytes = %d, err = %v, want %d", replayed, err, bodySize)
	}
}

func TestRuleUpdatesAreImmediateAndInvalidRegexKeepsLastSnapshot(t *testing.T) {
	t.Parallel()

	service, engine, matcher := newTestEngine(t)
	updated, err := service.Update(context.Background(), 1, RuleInput{
		Name:             "case insensitive desktop",
		Enabled:          true,
		ModelPattern:     `(?i)^gpt`,
		UserAgentPattern: `(?i)codex desktop`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != 1 {
		t.Fatalf("updated ID = %d", updated.ID)
	}
	if result, _ := evaluate(t, engine, matcher, `{"model":"GPT-test"}`, "codex desktop"); !result.Allowed {
		t.Fatalf("updated rule did not take effect: %+v", result)
	}

	_, err = service.Update(context.Background(), 1, RuleInput{
		Name:             "invalid",
		Enabled:          true,
		ModelPattern:     `[`,
		UserAgentPattern: `anything`,
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("invalid regex error = %v", err)
	}
	if result, _ := evaluate(t, engine, matcher, `{"model":"GPT-test"}`, "codex desktop"); !result.Allowed {
		t.Fatalf("invalid update replaced active snapshot: %+v", result)
	}

	created, err := service.Create(context.Background(), RuleInput{
		Name:             "deepseek client",
		Enabled:          true,
		ModelPattern:     `^deepseek`,
		UserAgentPattern: `Approved Client`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, _ := evaluate(t, engine, matcher, `{"model":"deepseek-test"}`, "wrong"); result.Allowed || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("created rule did not take effect: %+v", result)
	}
	if err := service.Delete(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if result, _ := evaluate(t, engine, matcher, `{"model":"deepseek-test"}`, "wrong"); !result.Allowed {
		t.Fatalf("deleted rule still active: %+v", result)
	}
}

func newTestEngine(t *testing.T) (*Service, *interceptor.Engine, *routing.Matcher) {
	t.Helper()
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
	service, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := base.WithGlobal(InterceptorID, service)
	if err != nil {
		t.Fatal(err)
	}
	return service, engine, matcher
}

func evaluate(t *testing.T, engine *interceptor.Engine, matcher *routing.Matcher, body, userAgent string) (interceptor.Result, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://proxy/v1/chat/completions", strings.NewReader(body))
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	}
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

type fillReader byte

func (reader fillReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(reader)
	}
	return len(buffer), nil
}
