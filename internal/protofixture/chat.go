package protofixture

import (
	"fmt"
	"net/http"
)

// groups splits items into runs that share a group: one user message, one
// assistant answer or one batch of tool results.
func groups(items []item) [][]item {
	result := make([][]item, 0, len(items))
	for start := 0; start < len(items); {
		end := start + 1
		for end < len(items) && items[end].group == items[start].group {
			end++
		}
		result = append(result, items[start:end])
		start = end
	}
	return result
}

func openAIError(conversation *Conversation, status int) ([]byte, string, string) {
	message := conversation.text.sentence(60)
	var errorType, param string
	var code any
	switch status {
	case http.StatusBadRequest:
		errorType, code, param = "invalid_request_error", "context_length_exceeded", "input"
	case http.StatusUnauthorized:
		errorType, code = "invalid_request_error", "invalid_api_key"
	case http.StatusUnprocessableEntity:
		errorType, code = "invalid_request_error", "unprocessable_entity"
	case http.StatusTooManyRequests:
		errorType, code = "rate_limit_error", "rate_limit_exceeded"
	case http.StatusServiceUnavailable:
		// NewAPI's own envelope when no upstream channel is available.
		errorType, code = "new_api_error", "model_not_available"
	default:
		errorType, code = "server_error", nil
	}
	var paramValue any
	if param != "" {
		paramValue = param
	}
	body := mustJSON(obj("error", obj("message", message, "type", errorType, "param", paramValue, "code", code)))
	codeText, _ := code.(string)
	return body, errorType, codeText
}

type chatRenderer struct{}

func (chatRenderer) path(*Conversation) string { return "/v1/chat/completions" }

func openAITools(conversation *Conversation, responses bool) []any {
	tools := make([]any, 0, len(conversation.tools))
	for _, definition := range conversation.tools {
		parameters := obj("type", "object",
			"properties", obj(definition.parameter, obj("type", "string", "description", definition.description[:min(60, len(definition.description))]),
				"limit", obj("type", "integer")),
			"required", []string{definition.parameter},
			"additionalProperties", false)
		if responses {
			tools = append(tools, obj("type", "function", "name", definition.name, "description", definition.description,
				"strict", false, "parameters", parameters))
		} else {
			tools = append(tools, obj("type", "function", "function", obj("name", definition.name,
				"description", definition.description, "parameters", parameters)))
		}
	}
	return tools
}

func chatCallID(value item) string { return "call_" + value.callID }

func (chatRenderer) request(conversation *Conversation, items []item, features Features) ([]byte, int, int) {
	messages := []any{obj("role", "system", "content", conversation.system)}
	toolCalls := 0
	for _, run := range groups(items) {
		switch run[0].kind {
		case kindUser:
			value := run[0]
			if value.image != nil {
				messages = append(messages, obj("role", "user", "content", []any{
					obj("type", "text", "text", value.text),
					obj("type", "image_url", "image_url", obj("url", dataURLPNG(value.image), "detail", "low")),
				}))
			} else {
				messages = append(messages, obj("role", "user", "content", value.text))
			}
		case kindToolResult:
			for _, value := range run {
				messages = append(messages, obj("role", "tool", "tool_call_id", chatCallID(value), "content", value.text))
			}
		default:
			var content any
			calls := make([]any, 0)
			for _, value := range run {
				switch value.kind {
				case kindAssistant:
					content = value.text
				case kindToolCall:
					calls = append(calls, obj("id", chatCallID(value), "type", "function",
						"function", obj("name", value.name, "arguments", value.args)))
				}
			}
			message := obj("role", "assistant", "content", content)
			if len(calls) > 0 {
				message = message.with("tool_calls", calls)
				toolCalls += len(calls)
			}
			messages = append(messages, message)
		}
	}
	body := obj("model", conversation.model, "messages", messages, "tools", openAITools(conversation, false),
		"tool_choice", "auto", "parallel_tool_calls", true, "prompt_cache_key", conversation.key,
		"temperature", 1, "stream", conversation.stream)
	if conversation.stream {
		body = body.with("stream_options", obj("include_usage", true))
	}
	if features.Extensions {
		body = body.with("x_bench_client", obj("trace", conversation.text.hex(8), "flags", []int{1, 2}))
	}
	return mustJSON(body), len(messages), toolCalls
}

func chatUsage(usage usageNumbers) object {
	return obj("prompt_tokens", usage.input, "completion_tokens", usage.output, "total_tokens", usage.total(),
		"prompt_tokens_details", obj("cached_tokens", usage.cached, "audio_tokens", 0),
		"completion_tokens_details", obj("reasoning_tokens", usage.reasoning, "audio_tokens", 0,
			"accepted_prediction_tokens", 0, "rejected_prediction_tokens", 0))
}

func chatUsageEffect(usage usageNumbers) *usageEffect {
	return &usageEffect{input: int64Pointer(usage.input), output: int64Pointer(usage.output), total: int64Pointer(usage.total())}
}

func (chatRenderer) answer(conversation *Conversation, reply answer, features Features) rendered {
	id := "chatcmpl-" + reply.id
	fingerprint := "fp_" + conversation.text.hex(5)
	var text, reasoning string
	calls := make([]item, 0)
	for _, value := range reply.items {
		switch value.kind {
		case kindAssistant:
			text = value.text
		case kindReasoning:
			reasoning = value.text
		case kindToolCall:
			calls = append(calls, value)
		}
	}
	finishReason := "stop"
	if len(calls) > 0 {
		finishReason = "tool_calls"
	}
	if !conversation.stream {
		message := obj("role", "assistant")
		if text != "" {
			message = message.with("content", text)
		} else {
			message = message.with("content", nil)
		}
		if reasoning != "" {
			message = message.with("reasoning_content", reasoning)
		}
		keys := make([]string, 0, len(calls))
		if len(calls) > 0 {
			values := make([]any, 0, len(calls))
			for index, call := range calls {
				values = append(values, obj("id", chatCallID(call), "type", "function",
					"function", obj("name", call.name, "arguments", call.args)))
				keys = append(keys, fmt.Sprintf("choice:0:%d", index))
			}
			message = message.with("tool_calls", values)
		}
		message = message.with("refusal", nil).with("annotations", []any{})
		body := obj("id", id, "object", "chat.completion", "created", reply.created, "model", conversation.responseModel,
			"choices", []any{obj("index", 0, "message", message, "logprobs", nil, "finish_reason", finishReason)},
			"usage", chatUsage(reply.usage), "service_tier", "default", "system_fingerprint", fingerprint)
		if features.Extensions {
			body = body.with("x_bench_gateway", obj("channel", conversation.text.word(), "latency_ms", 12))
		}
		return rendered{header: jsonHeader(), json: true, chunks: []chunk{{
			data:   mustJSON(body),
			effect: effect{model: conversation.responseModel, id: id, usage: chatUsageEffect(reply.usage), toolKeys: keys},
		}}}
	}

	chunks := make([]chunk, 0, 64)
	base := func(delta object, finish any) object {
		value := obj("id", id, "object", "chat.completion.chunk", "created", reply.created,
			"model", conversation.responseModel, "service_tier", "default", "system_fingerprint", fingerprint,
			"choices", []any{obj("index", 0, "delta", delta, "logprobs", nil, "finish_reason", finish)})
		if features.UsageShapes {
			value = value.with("usage", nil)
		}
		if features.Extensions {
			value = value.with("obfuscation", conversation.text.alnum(6))
		}
		return value
	}
	add := func(payload object, extra effect) {
		extra.model, extra.id = conversation.responseModel, id
		chunks = append(chunks, chunk{data: sseEvent("", payload), effect: extra})
	}
	add(base(obj("role", "assistant", "content", "", "refusal", nil), nil), effect{})
	if features.Extensions {
		chunks = append(chunks, chunk{data: []byte(": keep-alive\n\n")})
	}
	for _, piece := range splitDeltas(reasoning, conversation.options.DeltaBytes) {
		add(base(obj("reasoning_content", piece), nil), effect{})
	}
	for _, piece := range splitDeltas(text, conversation.options.DeltaBytes) {
		add(base(obj("content", piece), nil), effect{})
	}
	for index, call := range calls {
		key := fmt.Sprintf("choice:0:%d", index)
		add(base(obj("tool_calls", []any{obj("index", index, "id", chatCallID(call), "type", "function",
			"function", obj("name", call.name, "arguments", ""))}), nil), effect{toolKeys: []string{key}})
		for _, piece := range splitDeltas(call.args, conversation.options.DeltaBytes) {
			add(base(obj("tool_calls", []any{obj("index", index, "function", obj("arguments", piece))}), nil), effect{toolKeys: []string{key}})
		}
	}
	if features.Extensions {
		add(obj("id", id, "object", "chat.completion.chunk", "created", reply.created, "model", conversation.responseModel,
			"choices", []any{}, "x_bench_event", obj("kind", "heartbeat", "sequence", len(chunks))), effect{})
	}
	add(base(obj(), finishReason), effect{closing: true})
	add(obj("id", id, "object", "chat.completion.chunk", "created", reply.created, "model", conversation.responseModel,
		"service_tier", "default", "system_fingerprint", fingerprint, "choices", []any{}, "usage", chatUsage(reply.usage)),
		effect{closing: true, usage: chatUsageEffect(reply.usage)})
	chunks = append(chunks, chunk{data: []byte("data: [DONE]\n\n"), effect: effect{closing: true, terminal: true}})
	return rendered{header: sseHeader(), chunks: chunks}
}

func (chatRenderer) errorBody(conversation *Conversation, status int) ([]byte, string, string) {
	return openAIError(conversation, status)
}
