package anthropic

import (
	"bytes"
	"context"
	"testing"

	"llmapi-logger/internal/conversation"
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
	if result.Conversation == nil || len(result.Conversation.Messages) != 3 || result.Conversation.Messages[1].Content[0].Type != conversation.PartToolCall ||
		result.Conversation.Messages[1].Content[0].Arguments != `{"secret":"canary"}` || result.Conversation.Messages[2].Content[0].Text != "private answer" {
		t.Fatalf("unexpected conversation: %+v", result.Conversation)
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
	if result.Conversation == nil || len(result.Conversation.Messages) != 1 || result.Conversation.Messages[0].Role != conversation.RoleAssistant ||
		len(result.Conversation.Messages[0].Content) != 1 || result.Conversation.Messages[0].Content[0].Type != conversation.PartToolCall {
		t.Fatalf("unexpected SSE conversation: %+v", result.Conversation)
	}
}

func TestAnthropicSSEAggregatesThinkingTextAndToolArguments(t *testing.T) {
	t.Parallel()

	data := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"content\":[]}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"check \"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"facts\"}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"Answer \"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"here\"}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"lookup\",\"input\":{}}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\\\"x\\\"}\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	result := New().Parse(context.Background(), base.Input{Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(data)}})
	if result.Conversation == nil || len(result.Conversation.Messages) != 1 || len(result.Conversation.Messages[0].Content) != 3 {
		t.Fatalf("conversation = %+v", result.Conversation)
	}
	parts := result.Conversation.Messages[0].Content
	if parts[0].Type != conversation.PartReasoning || parts[0].Text != "check facts" || parts[1].Text != "Answer here" ||
		parts[2].Type != conversation.PartToolCall || parts[2].ID != "tool-1" || parts[2].Arguments != `{"q":"x"}` {
		t.Fatalf("parts = %+v", parts)
	}
}

func TestAnthropicRequestNormalizesPureToolResultMessage(t *testing.T) {
	t.Parallel()

	result := New().Parse(context.Background(), base.Input{Request: base.BodySource{
		Present: true, Complete: true, Data: []byte(`{
			"model":"claude-test",
			"messages":[
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":{"ok":true}}]},
				{"role":"user","content":[{"type":"text","text":"continue"},{"type":"tool_result","tool_use_id":"call-2","content":"done"}]}
			]
		}`),
	}})
	if result.Conversation == nil || len(result.Conversation.Messages) != 2 {
		t.Fatalf("conversation = %+v", result.Conversation)
	}
	if result.Conversation.Messages[0].Role != conversation.RoleTool || result.Conversation.Messages[0].Content[0].Result != `{"ok":true}` {
		t.Fatalf("pure tool result message = %+v", result.Conversation.Messages[0])
	}
	if result.Conversation.Messages[1].Role != conversation.RoleUser {
		t.Fatalf("mixed message role = %q, want user", result.Conversation.Messages[1].Role)
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
