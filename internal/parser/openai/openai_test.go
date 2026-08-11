package openai

import (
	"bytes"
	"context"
	"testing"

	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
)

func TestParseChatJSONExtractsOnlyCompactFields(t *testing.T) {
	t.Parallel()

	implementation, err := New(ChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("secret-tool-argument")
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "model":"gpt-request","stream":false,
            "messages":[{"role":"user","content":"private prompt"},{"role":"assistant","tool_calls":[{"id":"1","function":{"name":"hidden","arguments":"secret-tool-argument"}}]}]
        }`)},
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "id":"resp-1","model":"gpt-response",
            "choices":[{"message":{"content":"private answer","tool_calls":[{"id":"2","function":{"name":"hidden2","arguments":"{}"}}]}}],
            "usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}
        }`)},
	})
	if result.Status != base.StatusOK || result.RequestModel != "gpt-request" || result.ResponseModel != "gpt-response" || result.ResponseID != "resp-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.MessageCount == nil || *result.MessageCount != 2 || result.ToolCallCount == nil || *result.ToolCallCount != 2 || result.HasToolCall == nil || !*result.HasToolCall {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.Usage.Input == nil || *result.Usage.Input != 3 || result.Usage.Output == nil || *result.Usage.Output != 5 || result.Usage.Total == nil || *result.Usage.Total != 8 {
		t.Fatalf("unexpected usage: %+v", result.Usage)
	}
	if bytes.Contains(result.ParsedJSON, secret) || bytes.Contains(result.ParsedJSON, []byte("private prompt")) || bytes.Contains(result.ParsedJSON, []byte("private answer")) {
		t.Fatalf("parsed summary contains sensitive content: %s", result.ParsedJSON)
	}
	if result.Conversation == nil || len(result.Conversation.Messages) != 3 || result.Conversation.Messages[0].Content[0].Text != "private prompt" ||
		result.Conversation.Messages[1].Content[0].Arguments != "secret-tool-argument" || result.Conversation.Messages[2].Role != conversation.RoleAssistant {
		t.Fatalf("unexpected conversation: %+v", result.Conversation)
	}
}

func TestChatSSEAggregatesReasoningTextAndToolCallIntoOneAssistantMessage(t *testing.T) {
	t.Parallel()

	implementation, _ := New(ChatCompletions)
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-stream","stream":true,"messages":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"think \"}}]}\n\n" +
				"data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"carefully\",\"content\":\"Hello \"}}]}\n\n" +
				"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world\",\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"function\":{\"name\":\"weather\",\"arguments\":\"{\\\"city\\\":\"}}]}}]}\n\n" +
				"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Paris\\\"}\"}}]}}]}\n\n" +
				"data: [DONE]\n\n")},
	})
	if result.Status != base.StatusOK || result.Conversation == nil || len(result.Conversation.Messages) != 1 {
		t.Fatalf("unexpected result: %+v conversation=%+v", result, result.Conversation)
	}
	message := result.Conversation.Messages[0]
	if message.Role != conversation.RoleAssistant || message.Phase != conversation.PhaseResponse || len(message.Content) != 3 {
		t.Fatalf("message = %+v", message)
	}
	if message.Content[0].Type != conversation.PartReasoning || message.Content[0].Text != "think carefully" ||
		message.Content[1].Type != conversation.PartText || message.Content[1].Text != "Hello world" ||
		message.Content[2].Type != conversation.PartToolCall || message.Content[2].ID != "call-1" ||
		message.Content[2].Name != "weather" || message.Content[2].Arguments != `{"city":"Paris"}` {
		t.Fatalf("parts = %+v", message.Content)
	}
}

func TestChatLegacyFunctionMessageIsToolResult(t *testing.T) {
	t.Parallel()

	implementation, _ := New(ChatCompletions)
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{
			"model":"gpt-legacy",
			"messages":[{"role":"function","name":"weather","content":"{\"temperature\":21}"}]
		}`)},
	})
	if result.Conversation == nil || len(result.Conversation.Messages) != 1 {
		t.Fatalf("conversation = %+v", result.Conversation)
	}
	message := result.Conversation.Messages[0]
	if message.Role != conversation.RoleTool || len(message.Content) != 1 ||
		message.Content[0].Type != conversation.PartToolResult || message.Content[0].Name != "weather" ||
		message.Content[0].Result != `{"temperature":21}` {
		t.Fatalf("legacy function message = %+v", message)
	}
}

func TestResponsesReasoningSummaryArrayRendersAsReasoning(t *testing.T) {
	t.Parallel()

	implementation, _ := New(Responses)
	result := implementation.Parse(context.Background(), base.Input{
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
			"id":"resp-reasoning",
			"output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"checked the evidence"}]}]
		}`)},
	})
	if result.Conversation == nil || len(result.Conversation.Messages) != 1 {
		t.Fatalf("conversation = %+v", result.Conversation)
	}
	part := result.Conversation.Messages[0].Content[0]
	if part.Type != conversation.PartReasoning || part.Text != "checked the evidence" {
		t.Fatalf("reasoning summary = %+v", part)
	}
}

func TestParseChatAndResponsesSSE(t *testing.T) {
	t.Parallel()

	chat, _ := New(ChatCompletions)
	chatResult := chat.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-stream","stream":true,"messages":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"data: {\"id\":\"chat-1\",\"model\":\"gpt-stream\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\"}}]}}]}\n\n" +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":4,\"total_tokens\":6}}\n\n" +
				"data: [DONE]\n\n")},
	})
	if chatResult.Status != base.StatusOK || chatResult.ObservedStream == nil || !*chatResult.ObservedStream || chatResult.ResponseID != "chat-1" {
		t.Fatalf("unexpected chat SSE result: %+v", chatResult)
	}
	if chatResult.ToolCallCount == nil || *chatResult.ToolCallCount != 1 || chatResult.Usage.Total == nil || *chatResult.Usage.Total != 6 {
		t.Fatalf("unexpected chat SSE counts: %+v", chatResult)
	}

	responses, _ := New(Responses)
	responsesResult := responses.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-r","stream":true,"input":[{"role":"user","content":"x"}]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"event: response.completed\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-r\",\"model\":\"gpt-r2\",\"output\":[{\"id\":\"call-1\",\"type\":\"function_call\"}],\"usage\":{\"input_tokens\":7,\"output_tokens\":9,\"total_tokens\":16}}}\n\n")},
	})
	if responsesResult.Status != base.StatusOK || responsesResult.ResponseID != "resp-r" || responsesResult.ResponseModel != "gpt-r2" {
		t.Fatalf("unexpected Responses SSE result: %+v", responsesResult)
	}
	if responsesResult.ToolCallCount == nil || *responsesResult.ToolCallCount != 1 || responsesResult.Usage.Total == nil || *responsesResult.Usage.Total != 16 {
		t.Fatalf("unexpected Responses SSE counts: %+v", responsesResult)
	}
}

func TestMissingOpenAITerminalEventIsPartial(t *testing.T) {
	t.Parallel()

	implementation, _ := New(ChatCompletions)
	result := implementation.Parse(context.Background(), base.Input{
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte("data: {\"id\":\"x\",\"choices\":[]}\n\n")},
	})
	if result.Status != base.StatusPartial || result.ErrorCode != "missing_terminal_event" {
		t.Fatalf("result = %+v", result)
	}
}

func TestUnterminatedOpenAITailEventIsPartial(t *testing.T) {
	t.Parallel()

	implementation, _ := New(ChatCompletions)
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-stream","stream":true,"messages":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"data: {\"id\":\"chat-tail\",\"choices\":[]}\n\n" +
				"data: [DONE]",
		)},
	})
	if result.Status != base.StatusPartial || result.ErrorCode != "unterminated_sse_event" || result.ResponseID != "chat-tail" {
		t.Fatalf("result = %+v", result)
	}
}

func TestResponsesSSEDeduplicatesOutputItemsAgainstTerminalSnapshot(t *testing.T) {
	t.Parallel()

	implementation, _ := New(Responses)
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-r","stream":true,"input":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"event: response.output_item.added\n" +
				"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"call-1\",\"type\":\"function_call\"}}\n\n" +
				"event: response.output_item.done\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"id\":\"call-1\",\"type\":\"function_call\"}}\n\n" +
				"event: response.completed\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-r\",\"output\":[{\"id\":\"call-1\",\"type\":\"function_call\"}]}}\n\n",
		)},
	})
	if result.Status != base.StatusOK || result.ToolCallCount == nil || *result.ToolCallCount != 1 || result.HasToolCall == nil || !*result.HasToolCall {
		t.Fatalf("result = %+v", result)
	}
}

func TestResponsesRootErrorEventIsTerminalAndSafe(t *testing.T) {
	t.Parallel()

	implementation, _ := New(Responses)
	result := implementation.Parse(context.Background(), base.Input{
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{"model":"gpt-r","stream":true,"input":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"event: error\n" +
				"data: {\"type\":\"error\",\"code\":\"server_error\",\"message\":\"private provider detail\",\"param\":null}\n\n",
		)},
	})
	if result.Status != base.StatusOK || result.ErrorType != "error" || result.ErrorCode != "server_error" {
		t.Fatalf("result = %+v", result)
	}
	if bytes.Contains(result.ParsedJSON, []byte("private provider detail")) {
		t.Fatalf("parsed summary leaked error message: %s", result.ParsedJSON)
	}
}
