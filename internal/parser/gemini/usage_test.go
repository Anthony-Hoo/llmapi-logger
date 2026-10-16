package gemini

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
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

func TestJSONArrayStreamMatchesEquivalentSSE(t *testing.T) {
	t.Parallel()
	chunks := []string{
		`{"responseId":"gem-a","modelVersion":"gemini-example","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Hi"}]}}],"usageMetadata":{"promptTokenCount":4000,"cachedContentTokenCount":3000,"candidatesTokenCount":2,"totalTokenCount":4002}}`,
		`{"candidates":[{"index":0,"content":{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{"q":"x"}}}]}}]}`,
		`{"candidates":[{"index":0,"finishReason":"STOP","content":{"role":"model","parts":[{"text":"!"}]}}],"usageMetadata":{"promptTokenCount":4000,"cachedContentTokenCount":3000,"candidatesTokenCount":25,"thoughtsTokenCount":100,"totalTokenCount":4125}}`,
	}
	array := "[\n  " + strings.Join(chunks, ",\n  ") + "\n]\n"
	sse := ""
	for _, chunk := range chunks {
		sse += "data: " + chunk + "\n\n"
	}
	implementation, err := New(StreamGenerateContent)
	if err != nil {
		t.Fatal(err)
	}
	parse := func(contentType, body string) base.Result {
		return implementation.Parse(context.Background(), base.Input{
			Endpoint: "/v1beta/models/gemini-example:streamGenerateContent",
			Response: base.BodySource{Present: true, Complete: true, ContentType: contentType, Data: []byte(body)},
		})
	}
	fromArray, fromSSE := parse("application/json", array), parse("text/event-stream", sse)

	want := insights.Usage{UncachedInput: tokens(1000), CacheRead: tokens(3000), CacheWrite: tokens(0), Output: tokens(125), Reasoning: tokens(100)}
	if fromArray.Status != base.StatusOK || !reflect.DeepEqual(fromArray.Normalized, want) {
		t.Fatalf("array status %q normalized = %s, want %s", fromArray.Status, formatUsage(fromArray.Normalized), formatUsage(want))
	}
	if fromArray.ObservedStream == nil || !*fromArray.ObservedStream {
		t.Fatalf("array stream must be observed as a stream: %v", fromArray.ObservedStream)
	}
	for name, pair := range map[string][2]any{
		"usage":          {fromArray.Usage, fromSSE.Usage},
		"normalized":     {fromArray.Normalized, fromSSE.Normalized},
		"status":         {fromArray.Status, fromSSE.Status},
		"response id":    {fromArray.ResponseID, fromSSE.ResponseID},
		"response model": {fromArray.ResponseModel, fromSSE.ResponseModel},
		"tool calls":     {fromArray.ToolCallCount, fromSSE.ToolCallCount},
		"has tool call":  {fromArray.HasToolCall, fromSSE.HasToolCall},
		"conversation":   {fromArray.Conversation, fromSSE.Conversation},
		"parsed json":    {string(fromArray.ParsedJSON), string(fromSSE.ParsedJSON)},
	} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s differs: array %+v, sse %+v", name, pair[0], pair[1])
		}
	}

	// A broken element degrades to partial like a malformed SSE event, and a
	// non-array garbage body still fails.
	partial := parse("application/json", `[`+chunks[0]+`, 7]`)
	if partial.Status != base.StatusPartial || partial.Normalized.Output == nil {
		t.Fatalf("array with a bad element = status %q normalized %+v", partial.Status, partial.Normalized)
	}
	if broken := parse("application/json", `[`); broken.Status != base.StatusError {
		t.Fatalf("truncated array status = %q", broken.Status)
	}
}

func TestNormalizedUsageAddsToolUsePromptTokens(t *testing.T) {
	t.Parallel()
	first := `{"responseId":"gem-t","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"a"}]}}],"usageMetadata":{"promptTokenCount":100,"cachedContentTokenCount":40,"candidatesTokenCount":2,"totalTokenCount":112}}`
	last := `{"candidates":[{"index":0,"finishReason":"STOP","content":{"role":"model","parts":[{"text":"b"}]}}],"usageMetadata":{"promptTokenCount":100,"cachedContentTokenCount":40,"toolUsePromptTokenCount":25,"candidatesTokenCount":5,"thoughtsTokenCount":3,"totalTokenCount":133}}`
	want := insights.Usage{UncachedInput: tokens(85), CacheRead: tokens(40), CacheWrite: tokens(0), Output: tokens(8), Reasoning: tokens(3)}

	for _, test := range []struct {
		name, parser, contentType, body string
		want                            insights.Usage
	}{
		{"json", GenerateContent, "application/json", last, want},
		{"sse", StreamGenerateContent, "text/event-stream", "data: " + first + "\n\ndata: " + last + "\n\n", want},
		{"json array", StreamGenerateContent, "application/json", "[" + first + "," + last + "]", want},
		{
			"clamped with cached above prompt", GenerateContent, "application/json",
			`{"candidates":[],"usageMetadata":{"promptTokenCount":3,"cachedContentTokenCount":8,"toolUsePromptTokenCount":6}}`,
			insights.Usage{UncachedInput: tokens(6), CacheRead: tokens(8), CacheWrite: tokens(0)},
		},
		{
			"tool use only", GenerateContent, "application/json",
			`{"candidates":[],"usageMetadata":{"toolUsePromptTokenCount":6}}`,
			insights.Usage{UncachedInput: tokens(6)},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			implementation, err := New(test.parser)
			if err != nil {
				t.Fatal(err)
			}
			result := implementation.Parse(context.Background(), base.Input{
				Endpoint: "/v1beta/models/gemini-example:generateContent",
				Response: base.BodySource{Present: true, Complete: true, ContentType: test.contentType, Data: []byte(test.body)},
			})
			if !reflect.DeepEqual(result.Normalized, test.want) {
				t.Fatalf("normalized = %s, want %s", formatUsage(result.Normalized), formatUsage(test.want))
			}
		})
	}
}
