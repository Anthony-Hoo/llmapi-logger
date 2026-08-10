package anthropic

import (
	"bytes"
	"context"
	"testing"

	base "llmapi-logger/internal/parser"
)

func TestParseAnthropicJSON(t *testing.T) {
	t.Parallel()

	result := New().Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "model":"claude-request","stream":false,
            "messages":[{"role":"user","content":"private"},{"role":"assistant","content":[{"type":"tool_use","name":"hidden","input":{"secret":"canary"}}]}]
        }`)},
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "id":"msg-1","model":"claude-response",
            "content":[{"type":"text","text":"private answer"},{"type":"tool_use","name":"hidden2","input":{}}],
            "usage":{"input_tokens":11,"output_tokens":13}
        }`)},
	})
	if result.Status != base.StatusOK || result.RequestModel != "claude-request" || result.ResponseModel != "claude-response" || result.ResponseID != "msg-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.MessageCount == nil || *result.MessageCount != 2 || result.ToolCallCount == nil || *result.ToolCallCount != 2 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.Usage.Input == nil || *result.Usage.Input != 11 || result.Usage.Output == nil || *result.Usage.Output != 13 || result.Usage.Total != nil {
		t.Fatalf("unexpected usage: %+v", result.Usage)
	}
	if bytes.Contains(result.ParsedJSON, []byte("canary")) || bytes.Contains(result.ParsedJSON, []byte("private answer")) {
		t.Fatalf("parsed summary contains sensitive content: %s", result.ParsedJSON)
	}
}

func TestParseAnthropicSSEUsesLatestUsageAndTerminal(t *testing.T) {
	t.Parallel()

	data := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-s\",\"model\":\"claude-s\",\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"hidden\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":8}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	result := New().Parse(context.Background(), base.Input{
		Request:  base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"claude-s","stream":true,"messages":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(data)},
	})
	if result.Status != base.StatusOK || result.ObservedStream == nil || !*result.ObservedStream || result.ResponseID != "msg-s" {
		t.Fatalf("unexpected SSE result: %+v", result)
	}
	if result.Usage.Input == nil || *result.Usage.Input != 5 || result.Usage.Output == nil || *result.Usage.Output != 8 {
		t.Fatalf("unexpected SSE usage: %+v", result.Usage)
	}
	if result.ToolCallCount == nil || *result.ToolCallCount != 1 {
		t.Fatalf("unexpected tool count: %+v", result)
	}
}

func TestAnthropicMissingMessageStopIsPartial(t *testing.T) {
	t.Parallel()

	result := New().Parse(context.Background(), base.Input{
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte("data: {\"type\":\"ping\"}\n\n")},
	})
	if result.Status != base.StatusPartial || result.ErrorCode != "missing_message_stop" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAnthropicUnterminatedMessageStopIsPartial(t *testing.T) {
	t.Parallel()

	result := New().Parse(context.Background(), base.Input{
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte("data: {\"type\":\"message_stop\"}")},
	})
	if result.Status != base.StatusPartial || result.ErrorCode != "unterminated_sse_event" {
		t.Fatalf("result = %+v", result)
	}
}
