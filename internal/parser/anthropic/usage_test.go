package anthropic

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

	stream := func(start, delta string) string {
		return "event: message_start\n" +
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-u\",\"model\":\"claude-u\",\"usage\":" + start + "}}\n\n" +
			"event: message_delta\n" +
			"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":" + delta + "}\n\n" +
			"event: message_stop\n" +
			"data: {\"type\":\"message_stop\"}\n\n"
	}
	for _, test := range []struct {
		name       string
		response   string
		stream     bool
		want       insights.Usage
		wantInput  *int64
		wantPrompt *int64
		wantOutput *int64
	}{
		{
			name:      "json without cache",
			response:  `{"id":"m","content":[],"usage":{"input_tokens":11,"output_tokens":13}}`,
			want:      insights.Usage{UncachedInput: tokens(11), Output: tokens(13)},
			wantInput: tokens(11), wantPrompt: tokens(11), wantOutput: tokens(13),
		},
		{
			name: "json with cache read and write",
			response: `{"id":"m","content":[],"usage":{"input_tokens":50,"cache_read_input_tokens":2000,
                "cache_creation_input_tokens":300,"output_tokens":120}}`,
			want:      insights.Usage{UncachedInput: tokens(50), CacheRead: tokens(2000), CacheWrite: tokens(300), Output: tokens(120)},
			wantInput: tokens(50), wantPrompt: tokens(2350), wantOutput: tokens(120),
		},
		{
			name: "stream merges start usage with cumulative delta output",
			response: stream(`{"input_tokens":40,"cache_read_input_tokens":1500,"cache_creation_input_tokens":0,"output_tokens":1}`,
				`{"output_tokens":88}`),
			stream:    true,
			want:      insights.Usage{UncachedInput: tokens(40), CacheRead: tokens(1500), CacheWrite: tokens(0), Output: tokens(88)},
			wantInput: tokens(40), wantPrompt: tokens(1540), wantOutput: tokens(88),
		},
		{
			name: "stream prefers later reported input and cache fields",
			response: stream(`{"input_tokens":40,"cache_read_input_tokens":0,"cache_creation_input_tokens":256,"output_tokens":1}`,
				`{"input_tokens":42,"cache_read_input_tokens":1500,"cache_creation_input_tokens":null,"output_tokens":90}`),
			stream:    true,
			want:      insights.Usage{UncachedInput: tokens(42), CacheRead: tokens(1500), CacheWrite: tokens(256), Output: tokens(90)},
			wantInput: tokens(42), wantPrompt: tokens(1798), wantOutput: tokens(90),
		},
		{
			name:     "json without usage",
			response: `{"id":"m","content":[]}`,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := base.BodySource{Present: true, Complete: true, Data: []byte(test.response)}
			if test.stream {
				response.ContentType = "text/event-stream"
			}
			result := New().Parse(context.Background(), base.Input{Response: response})
			if !reflect.DeepEqual(result.Normalized, test.want) {
				t.Fatalf("normalized = %s, want %s", formatUsage(result.Normalized), formatUsage(test.want))
			}
			if !reflect.DeepEqual(result.Normalized.PromptTotal(), test.wantPrompt) {
				t.Fatalf("prompt total = %v, want %v", result.Normalized.PromptTotal(), test.wantPrompt)
			}
			// parsed_results semantics are unchanged: usage_input stays the
			// uncached input_tokens value.
			if !reflect.DeepEqual(result.Usage.Input, test.wantInput) || !reflect.DeepEqual(result.Usage.Output, test.wantOutput) {
				t.Fatalf("usage = %+v", result.Usage)
			}
		})
	}
}

func formatUsage(usage insights.Usage) string {
	encoded, _ := json.Marshal(usage)
	return string(encoded)
}
