package gemini

import (
	"bytes"
	"context"
	"testing"

	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/policyclass"
)

func TestParseGeminiJSONUsesPathModel(t *testing.T) {
	t.Parallel()

	implementation, _ := New(GenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-2.5-pro:generateContent",
		Request: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "model":"must-not-win",
            "contents":[{"role":"user","parts":[{"text":"private prompt"}]},{"role":"model","parts":[{"functionCall":{"name":"hidden","args":{"secret":"canary"}}}]}]
        }`)},
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
            "modelVersion":"gemini-response","responseId":"gem-1",
            "candidates":[{"content":{"parts":[{"text":"private answer"},{"functionCall":{"name":"hidden2","args":{}}}]}}],
            "usageMetadata":{"promptTokenCount":17,"candidatesTokenCount":19,"totalTokenCount":36}
        }`)},
	})
	if result.Status != base.StatusOK || result.RequestModel != "gemini-2.5-pro" || result.ResponseModel != "gemini-response" || result.ResponseID != "gem-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.RequestedStream == nil || *result.RequestedStream || result.MessageCount == nil || *result.MessageCount != 2 || result.ToolCallCount == nil || *result.ToolCallCount != 2 {
		t.Fatalf("unexpected request/count fields: %+v", result)
	}
	if result.Usage.Total == nil || *result.Usage.Total != 36 {
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

func TestParseGeminiSSEUsesLastUsageSnapshot(t *testing.T) {
	t.Parallel()

	implementation, _ := New(StreamGenerateContent)
	data := "data: {\"responseId\":\"gem-s\",\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"private\"}]}}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":1,\"totalTokenCount\":4}}\n\n" +
		"data: {\"modelVersion\":\"gemini-s2\",\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"hidden\",\"args\":{}}}]}}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":5,\"totalTokenCount\":8}}\n\n"
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-flash:streamGenerateContent",
		Request:  base.BodySource{Present: true, Complete: true, Data: []byte(`{"contents":[]}`)},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(data)},
	})
	if result.Status != base.StatusOK || result.RequestedStream == nil || !*result.RequestedStream || result.ObservedStream == nil || !*result.ObservedStream {
		t.Fatalf("unexpected SSE result: %+v", result)
	}
	if result.ResponseID != "gem-s" || result.ResponseModel != "gemini-s2" || result.Usage.Total == nil || *result.Usage.Total != 8 {
		t.Fatalf("unexpected SSE summary: %+v", result)
	}
	if result.ToolCallCount == nil || *result.ToolCallCount != 1 {
		t.Fatalf("unexpected tool count: %+v", result)
	}
	if result.Conversation == nil || len(result.Conversation.Messages) != 1 || result.Conversation.Messages[0].Role != conversation.RoleAssistant ||
		len(result.Conversation.Messages[0].Content) != 2 || result.Conversation.Messages[0].Content[0].Text != "private" ||
		result.Conversation.Messages[0].Content[1].Type != conversation.PartToolCall {
		t.Fatalf("unexpected SSE conversation: %+v", result.Conversation)
	}
}

func TestParseGeminiErrorEnvelope(t *testing.T) {
	t.Parallel()

	implementation, _ := New(GenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-test:generateContent",
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"private detail"}}`)},
	})
	if result.Status != base.StatusOK || result.ErrorType != "INVALID_ARGUMENT" || result.ErrorCode != "400" {
		t.Fatalf("result = %+v", result)
	}
	if bytes.Contains(result.ParsedJSON, []byte("private detail")) {
		t.Fatalf("parsed summary contains error message: %s", result.ParsedJSON)
	}
}

func TestGeminiUnterminatedTailEventIsPartial(t *testing.T) {
	t.Parallel()

	implementation, _ := New(StreamGenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-test:streamGenerateContent",
		Response: base.BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte(
			"data: {\"responseId\":\"gem-tail\",\"candidates\":[]}",
		)},
	})
	if result.Status != base.StatusPartial || result.ErrorCode != "unterminated_sse_event" || result.ResponseID != "gem-tail" {
		t.Fatalf("result = %+v", result)
	}
}

func TestGeminiErrorEnvelopeClassifiesPolicyMessage(t *testing.T) {
	t.Parallel()

	implementation, _ := New(GenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-test:generateContent",
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
			"error":{"code":400,"status":"INVALID_ARGUMENT","message":"This request violates our content policy."}
		}`)},
	})
	if result.UpstreamErrorClass != policyclass.ClassContentPolicy {
		t.Fatalf("upstream error class = %q, want %q", result.UpstreamErrorClass, policyclass.ClassContentPolicy)
	}
	if bytes.Contains(result.ParsedJSON, []byte("content policy")) {
		t.Fatalf("parsed summary leaked error message: %s", result.ParsedJSON)
	}
}

func TestGeminiPromptFeedbackBlocksAsContentFilter(t *testing.T) {
	t.Parallel()

	implementation, _ := New(GenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-test:generateContent",
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
			"promptFeedback":{"blockReason":"SAFETY"},"candidates":[]
		}`)},
	})
	if result.Status != base.StatusOK || result.UpstreamErrorClass != policyclass.ClassContentFilter {
		t.Fatalf("result = %+v", result)
	}
}

func TestGeminiSafetyFinishReasonIsContentFilter(t *testing.T) {
	t.Parallel()

	implementation, _ := New(GenerateContent)
	result := implementation.Parse(context.Background(), base.Input{
		Endpoint: "/v1beta/models/gemini-test:generateContent",
		Response: base.BodySource{Present: true, Complete: true, Data: []byte(`{
			"responseId":"gem-safety",
			"candidates":[{"finishReason":"SAFETY","content":{"parts":[]}}]
		}`)},
	})
	if result.Status != base.StatusOK || result.UpstreamErrorClass != policyclass.ClassContentFilter {
		t.Fatalf("result = %+v", result)
	}
}

func TestGeminiPromptFeedbackClassificationAcrossTransports(t *testing.T) {
	t.Parallel()

	for _, transport := range []string{"json", "sse", "array"} {
		for _, reason := range []string{"BLOCK_REASON_UNSPECIFIED", "SAFETY"} {
			t.Run(transport+"/"+reason, func(t *testing.T) {
				t.Parallel()
				payload := `{"promptFeedback":{"blockReason":"` + reason + `"},"candidates":[]}`
				variant := GenerateContent
				contentType := "application/json"
				switch transport {
				case "sse":
					variant = StreamGenerateContent
					contentType = "text/event-stream"
					payload = "data: " + payload + "\n\n"
				case "array":
					variant = StreamGenerateContent
					payload = "[" + payload + "]"
				}
				implementation, err := New(variant)
				if err != nil {
					t.Fatal(err)
				}
				result := implementation.Parse(context.Background(), base.Input{
					Response: base.BodySource{Present: true, Complete: true, ContentType: contentType, Data: []byte(payload)},
				})
				want := ""
				if reason == "SAFETY" {
					want = policyclass.ClassContentFilter
				}
				if result.Status != base.StatusOK || result.UpstreamErrorClass != want {
					t.Fatalf("status=%q, class=%q; want status=%q, class=%q", result.Status, result.UpstreamErrorClass, base.StatusOK, want)
				}
			})
		}
	}
}
