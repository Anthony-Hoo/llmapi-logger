package gemini

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

	streamData := "data: {\"responseId\":\"gem-u\",\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"x\"}]}}]," +
		"\"usageMetadata\":{\"promptTokenCount\":4000,\"cachedContentTokenCount\":3000,\"candidatesTokenCount\":2,\"totalTokenCount\":4002}}\n\n" +
		"data: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"y\"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"index\":0,\"finishReason\":\"STOP\",\"content\":{\"parts\":[]}}]," +
		"\"usageMetadata\":{\"promptTokenCount\":4000,\"cachedContentTokenCount\":3000,\"candidatesTokenCount\":25,\"thoughtsTokenCount\":100,\"totalTokenCount\":4125}}\n\n"
	for _, test := range []struct {
		name      string
		parser    string
		response  string
		stream    bool
		want      insights.Usage
		wantInput *int64
	}{
		{
			name: "json cached with thoughts", parser: GenerateContent,
			response: `{"candidates":[],"usageMetadata":{"promptTokenCount":1200,"cachedContentTokenCount":1000,
                "candidatesTokenCount":30,"thoughtsTokenCount":70,"totalTokenCount":1300}}`,
			want:      insights.Usage{UncachedInput: tokens(200), CacheRead: tokens(1000), CacheWrite: tokens(0), Output: tokens(100), Reasoning: tokens(70)},
			wantInput: tokens(1200),
		},
		{
			name: "json without cache or thoughts", parser: GenerateContent,
			response:  `{"candidates":[],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8}}`,
			want:      insights.Usage{UncachedInput: tokens(3), CacheWrite: tokens(0), Output: tokens(5)},
			wantInput: tokens(3),
		},
		{
			name: "json thoughts only output", parser: GenerateContent,
			response:  `{"candidates":[],"usageMetadata":{"promptTokenCount":3,"thoughtsTokenCount":9}}`,
			want:      insights.Usage{UncachedInput: tokens(3), CacheWrite: tokens(0), Output: tokens(9), Reasoning: tokens(9)},
			wantInput: tokens(3),
		},
		{
			name: "json cached above prompt clamps", parser: GenerateContent,
			response:  `{"candidates":[],"usageMetadata":{"promptTokenCount":3,"cachedContentTokenCount":8}}`,
			want:      insights.Usage{UncachedInput: tokens(0), CacheRead: tokens(8), CacheWrite: tokens(0)},
			wantInput: tokens(3),
		},
		{
			name: "json without usage", parser: GenerateContent,
			response: `{"candidates":[]}`,
		},
		{
			name: "stream uses last usage snapshot", parser: StreamGenerateContent, response: streamData, stream: true,
			want:      insights.Usage{UncachedInput: tokens(1000), CacheRead: tokens(3000), CacheWrite: tokens(0), Output: tokens(125), Reasoning: tokens(100)},
			wantInput: tokens(4000),
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
			result := implementation.Parse(context.Background(), base.Input{
				Endpoint: "/v1beta/models/gemini-example:generateContent",
				Response: response,
			})
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
