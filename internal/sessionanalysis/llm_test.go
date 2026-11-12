package sessionanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/config"
)

type recordedRequest struct {
	body   map[string]any
	header http.Header
}

func modelServer(t *testing.T, respond func(body map[string]any) (int, string)) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	requests := make([]recordedRequest, 0)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, _ := io.ReadAll(request.Body)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		mu.Lock()
		requests = append(requests, recordedRequest{body: body, header: request.Header.Clone()})
		mu.Unlock()
		if request.URL.Path != "/v1/chat/completions" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		status, content := respond(body)
		writer.WriteHeader(status)
		if status == http.StatusOK {
			encoded, _ := json.Marshal(map[string]any{
				"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}},
				"usage":   map[string]any{"prompt_tokens": 1500, "completion_tokens": 200},
			})
			_, _ = writer.Write(encoded)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func llmConfig(baseURL string) config.SessionAnalysisLLM {
	return config.SessionAnalysisLLM{
		Enabled: true, BaseURL: baseURL, Model: "local-small", APIKey: "local-test-key", StructuredOutput: "json_schema",
		ContextTokens: 16384, DisableThinking: true, MaxOutputTokens: 600, MaxConcurrency: 2, TimeoutSeconds: 10, MaxSessionsRun: 10,
	}
}

func TestLLMClientRequestShapeAndPrefixStability(t *testing.T) {
	server, requests := modelServer(t, func(map[string]any) (int, string) {
		return http.StatusOK, "<think>\nlet me think\n</think>\n```json\n{\"goal\":\"x\"}\n```"
	})
	client, err := NewLLMClient(llmConfig(server.URL+"/v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Complete(context.Background(), FacetMessages("[会话] 第一个包", false), FacetSchema(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(context.Background(), FacetMessages("[会话] 第二个包", false), FacetSchema(false)); err != nil {
		t.Fatal(err)
	}
	if cleanModelOutput(first.Content) != `{"goal":"x"}` || first.InputTokens != 1500 || first.OutputTokens != 200 {
		t.Fatalf("completion = %+v / %q", first, cleanModelOutput(first.Content))
	}
	body := (*requests)[0].body
	if body["model"] != "local-small" || body["temperature"] != float64(0) || body["max_tokens"] != float64(600) || body["think"] != false {
		t.Fatalf("body = %v", body)
	}
	if kwargs, _ := body["chat_template_kwargs"].(map[string]any); kwargs["enable_thinking"] != false {
		t.Fatalf("thinking switch missing: %v", body["chat_template_kwargs"])
	}
	if thinking, _ := body["thinking"].(map[string]any); thinking["type"] != "disabled" {
		t.Fatalf("thinking object missing: %v", body["thinking"])
	}
	format, _ := body["response_format"].(map[string]any)
	if format["type"] != "json_schema" {
		t.Fatalf("response_format = %v", format)
	}
	if got := (*requests)[0].header.Get("Authorization"); got != "Bearer local-test-key" {
		t.Fatalf("authorization = %q", got)
	}
	// The fixed prefix is byte-identical across calls; only the pack differs
	// and it comes last.
	messages := func(index int) []any { return (*requests)[index].body["messages"].([]any) }
	firstSystem := messages(0)[0].(map[string]any)["content"]
	secondSystem := messages(1)[0].(map[string]any)["content"]
	if firstSystem != secondSystem || firstSystem != FacetSystemPrompt(false) {
		t.Fatal("system prefix differs between calls")
	}
	if last := messages(0)[len(messages(0))-1].(map[string]any)["content"].(string); !strings.HasSuffix(last, "第一个包") {
		t.Fatalf("pack is not the last message: %q", last)
	}
	for _, variable := range []string{"2026", "agt_", "ses_"} {
		if strings.Contains(FacetSystemPrompt(false), variable) || strings.Contains(FacetSystemPrompt(true), variable) {
			t.Errorf("fixed prefix contains variable text %q", variable)
		}
	}
}

func TestLLMClientDropsThinkingSwitchesWhenRejected(t *testing.T) {
	server, requests := modelServer(t, func(body map[string]any) (int, string) {
		if _, ok := body["think"]; ok {
			return http.StatusBadRequest, ""
		}
		return http.StatusOK, "{}"
	})
	client, err := NewLLMClient(llmConfig(server.URL+"/v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if _, err := client.Complete(context.Background(), FacetMessages("p", false), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(*requests) != 3 {
		t.Fatalf("requests = %d (one rejected, then two without switches)", len(*requests))
	}
}

func TestLLMClientRefusesNonLocalPeers(t *testing.T) {
	publicResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	// A host name that resolves to a public address is refused at dial time,
	// before any connection attempt.
	client, err := NewLLMClient(llmConfig("http://model.example.internal:8000/v1"), publicResolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(context.Background(), FacetMessages("p", false), nil); !errors.Is(err, ErrNonLocalPeer) {
		t.Fatalf("err = %v", err)
	}
	literal, err := NewLLMClient(llmConfig("http://203.0.113.9:8000/v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := literal.Complete(context.Background(), FacetMessages("p", false), nil); !errors.Is(err, ErrNonLocalPeer) {
		t.Fatalf("literal err = %v", err)
	}
	// A host name that resolves to loopback is allowed.
	server, _ := modelServer(t, func(map[string]any) (int, string) { return http.StatusOK, "{}" })
	port := server.URL[strings.LastIndex(server.URL, ":")+1:]
	loopbackResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	named, err := NewLLMClient(llmConfig("http://model.example.internal:"+port+"/v1"), loopbackResolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := named.Complete(context.Background(), FacetMessages("p", false), nil); err != nil {
		t.Fatalf("loopback name refused: %v", err)
	}
}

func TestCleanModelOutput(t *testing.T) {
	for input, want := range map[string]string{
		`{"a":1}`:                              `{"a":1}`,
		"<think>x</think>{\"a\":1}":            `{"a":1}`,
		"reasoning…</think>\n{\"a\":1}":        `{"a":1}`,
		"```json\n{\"a\":1}\n```":              `{"a":1}`,
		"<think>\n</think>\n```\n{\"a\":1}```": `{"a":1}`,
	} {
		if got := cleanModelOutput(input); got != want {
			t.Errorf("clean(%q) = %q", input, got)
		}
	}
}
