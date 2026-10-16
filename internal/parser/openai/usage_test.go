package openai

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"llmapi-logger/internal/insights"
	base "llmapi-logger/internal/parser"
)

func tokens(value int64) *int64 { return &value }

func TestNormalizedUsage(t *testing.T) {
	t.Parallel()

	chatSSE := "data: {\"id\":\"chat-u\",\"model\":\"gpt-u\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}],\"usage\":null}\n\n" +
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":900,\"completion_tokens\":30,\"total_tokens\":930," +
		"\"prompt_tokens_details\":{\"cached_tokens\":512},\"completion_tokens_details\":{\"reasoning_tokens\":12}}}\n\n" +
		"data: [DONE]\n\n"
	responsesSSE := "event: response.created\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-u\",\"usage\":null}}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-u\",\"model\":\"gpt-r\",\"output\":[]," +
		"\"usage\":{\"input_tokens\":2048,\"input_tokens_details\":{\"cached_tokens\":1024},\"output_tokens\":77," +
		"\"output_tokens_details\":{\"reasoning_tokens\":64},\"total_tokens\":2125}}}\n\n"
	for _, test := range []struct {
		name      string
		parser    string
		response  string
		stream    bool
		want      insights.Usage
		wantInput *int64
	}{
		{
			name: "chat json cached and reasoning", parser: ChatCompletions,
			response: `{"id":"c","usage":{"prompt_tokens":1000,"completion_tokens":50,"total_tokens":1050,
                "prompt_tokens_details":{"cached_tokens":800},"completion_tokens_details":{"reasoning_tokens":20}}}`,
			want:      insights.Usage{UncachedInput: tokens(200), CacheRead: tokens(800), CacheWrite: tokens(0), Output: tokens(50), Reasoning: tokens(20)},
			wantInput: tokens(1000),
		},
		{
			name: "chat json without details", parser: ChatCompletions,
			response:  `{"id":"c","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
			want:      insights.Usage{UncachedInput: tokens(10), CacheWrite: tokens(0), Output: tokens(5)},
			wantInput: tokens(10),
		},
		{
			name: "chat json cached above prompt clamps", parser: ChatCompletions,
			response:  `{"id":"c","usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":9}}}`,
			want:      insights.Usage{UncachedInput: tokens(0), CacheRead: tokens(9), CacheWrite: tokens(0), Output: tokens(1)},
			wantInput: tokens(5),
		},
		{
			name: "chat json without usage", parser: ChatCompletions,
			response: `{"id":"c","choices":[]}`,
		},
		{
			name: "chat stream final usage chunk", parser: ChatCompletions, response: chatSSE, stream: true,
			want:      insights.Usage{UncachedInput: tokens(388), CacheRead: tokens(512), CacheWrite: tokens(0), Output: tokens(30), Reasoning: tokens(12)},
			wantInput: tokens(900),
		},
		{
			name: "responses json", parser: Responses,
			response: `{"id":"r","output":[],"usage":{"input_tokens":300,"input_tokens_details":{"cached_tokens":100},
                "output_tokens":40,"output_tokens_details":{"reasoning_tokens":10},"total_tokens":340}}`,
			want:      insights.Usage{UncachedInput: tokens(200), CacheRead: tokens(100), CacheWrite: tokens(0), Output: tokens(40), Reasoning: tokens(10)},
			wantInput: tokens(300),
		},
		{
			name: "responses stream completed usage", parser: Responses, response: responsesSSE, stream: true,
			want:      insights.Usage{UncachedInput: tokens(1024), CacheRead: tokens(1024), CacheWrite: tokens(0), Output: tokens(77), Reasoning: tokens(64)},
			wantInput: tokens(2048),
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			implementation, err := New(test.parser)
			if err != nil {
				t.Fatal(err)
			}
			response := base.BodySource{Present: true, Complete: true, Data: []byte(test.response)}
			if test.stream {
				response.ContentType = "text/event-stream"
			}
			result := implementation.Parse(context.Background(), base.Input{Response: response})
			if !reflect.DeepEqual(result.Normalized, test.want) {
				t.Fatalf("normalized = %s, want %s", formatUsage(result.Normalized), formatUsage(test.want))
			}
			// parsed_results keeps the provider's raw prompt total.
			if !reflect.DeepEqual(result.Usage.Input, test.wantInput) {
				t.Fatalf("usage input = %v, want %v", result.Usage.Input, test.wantInput)
			}
		})
	}
}

func formatUsage(usage insights.Usage) string {
	encoded, _ := json.Marshal(usage)
	return string(encoded)
}
