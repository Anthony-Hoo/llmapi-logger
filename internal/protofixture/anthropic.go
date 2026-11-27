package protofixture

import (
	"fmt"
	"net/http"
)

type anthropicRenderer struct{}

func (anthropicRenderer) path(*Conversation) string { return "/v1/messages" }

func anthropicCallID(value item) string { return "toolu_" + value.callID }

func anthropicCitation(conversation *Conversation, text string) object {
	end := min(len(text), 48)
	return obj("type", "char_location", "cited_text", text[:end], "document_index", 0,
		"document_title", conversation.text.word(), "start_char_index", 0, "end_char_index", end)
}

func anthropicBlock(conversation *Conversation, value item, includeCitation bool) object {
	switch value.kind {
	case kindReasoning:
		return obj("type", "thinking", "thinking", value.text, "signature", value.signature)
	case kindToolCall:
		return obj("type", "tool_use", "id", anthropicCallID(value), "name", value.name, "input", value.argsValue)
	default:
		block := obj("type", "text", "text", value.text)
		if value.citation && includeCitation {
			block = block.with("citations", []any{anthropicCitation(conversation, value.text)})
		}
		return block
	}
}

func (anthropicRenderer) request(conversation *Conversation, items []item, features Features) ([]byte, int, int) {
	messages := make([]any, 0, len(items))
	toolCalls := 0
	for _, run := range groups(items) {
		switch run[0].kind {
		case kindUser:
			value := run[0]
			content := []any{obj("type", "text", "text", value.text)}
			if value.image != nil {
				content = append(content, obj("type", "image", "source", obj("type", "base64", "media_type", "image/png",
					"data", base64PNG(value.image))))
			}
			messages = append(messages, obj("role", "user", "content", content))
		case kindToolResult:
			content := make([]any, 0, len(run))
			for _, value := range run {
				content = append(content, obj("type", "tool_result", "tool_use_id", anthropicCallID(value), "content", value.text))
			}
			messages = append(messages, obj("role", "user", "content", content))
		default:
			content := make([]any, 0, len(run))
			for _, value := range run {
				if value.kind == kindToolCall {
					toolCalls++
				}
				content = append(content, anthropicBlock(conversation, value, true))
			}
			messages = append(messages, obj("role", "assistant", "content", content))
		}
	}
	// Claude Code marks the last user block as a cache breakpoint.
	tools := make([]any, 0, len(conversation.tools))
	for _, definition := range conversation.tools {
		tools = append(tools, obj("name", definition.name, "description", definition.description,
			"input_schema", obj("type", "object", "properties", obj(definition.parameter, obj("type", "string"),
				"limit", obj("type", "integer")), "required", []string{definition.parameter})))
	}
	body := obj("model", conversation.model, "max_tokens", 32000, "messages", messages,
		"system", []any{obj("type", "text", "text", conversation.system, "cache_control", obj("type", "ephemeral"))},
		"tools", tools, "metadata", obj("user_id", "user_"+conversation.text.hex(32)+"_account__session_"+conversation.key),
		"thinking", obj("type", "enabled", "budget_tokens", 10000), "stream", conversation.stream)
	if features.Extensions {
		body = body.with("context_management", obj("edits", []any{})).with("x_bench_client", obj("trace", conversation.text.hex(8)))
	}
	return mustJSON(body), len(messages), toolCalls
}

func anthropicUsage(usage usageNumbers, shapes bool) object {
	uncached := max(0, usage.input-usage.cached-usage.cacheWrite)
	value := obj("input_tokens", uncached, "cache_creation_input_tokens", usage.cacheWrite,
		"cache_read_input_tokens", usage.cached)
	if shapes {
		value = value.with("cache_creation", obj("ephemeral_5m_input_tokens", usage.cacheWrite, "ephemeral_1h_input_tokens", 0)).
			with("server_tool_use", obj("web_search_requests", 0))
	}
	return value.with("output_tokens", usage.output).with("service_tier", "standard")
}

func (anthropicRenderer) answer(conversation *Conversation, reply answer, features Features) rendered {
	id := "msg_" + reply.id
	stopReason := "end_turn"
	for _, value := range reply.items {
		if value.kind == kindToolCall {
			stopReason = "tool_use"
		}
	}
	uncached := max(0, reply.usage.input-reply.usage.cached-reply.usage.cacheWrite)
	if !conversation.stream {
		content := make([]any, 0, len(reply.items))
		keys := make([]string, 0)
		for index, value := range reply.items {
			content = append(content, anthropicBlock(conversation, value, true))
			if value.kind == kindToolCall {
				keys = append(keys, fmt.Sprintf("block:%d", index))
			}
		}
		body := obj("id", id, "type", "message", "role", "assistant", "model", conversation.responseModel,
			"content", content, "stop_reason", stopReason, "stop_sequence", nil,
			"usage", anthropicUsage(reply.usage, features.UsageShapes))
		if features.Extensions {
			body = body.with("container", nil).with("x_bench_gateway", obj("channel", conversation.text.word()))
		}
		return rendered{header: jsonHeader(), json: true, chunks: []chunk{{
			data: mustJSON(body),
			effect: effect{model: conversation.responseModel, id: id, toolKeys: keys,
				usage: &usageEffect{perField: true, input: int64Pointer(uncached), output: int64Pointer(reply.usage.output)}},
		}}}
	}

	chunks := make([]chunk, 0, 64)
	add := func(eventType string, payload object, extra effect) {
		payload = append(object{{key: "type", value: eventType}}, payload...)
		chunks = append(chunks, chunk{data: sseEvent(eventType, payload), effect: extra})
	}
	startUsage := anthropicUsage(usageNumbers{input: reply.usage.input, cached: reply.usage.cached,
		cacheWrite: reply.usage.cacheWrite, output: 1}, features.UsageShapes)
	add("message_start", obj("message", obj("id", id, "type", "message", "role", "assistant",
		"model", conversation.responseModel, "content", []any{}, "stop_reason", nil, "stop_sequence", nil, "usage", startUsage)),
		effect{model: conversation.responseModel, id: id,
			usage: &usageEffect{perField: true, input: int64Pointer(uncached), output: int64Pointer(1)}})
	add("ping", obj(), effect{})
	index := 0
	for _, value := range reply.items {
		switch value.kind {
		case kindReasoning:
			add("content_block_start", obj("index", index, "content_block", obj("type", "thinking", "thinking", "", "signature", "")), effect{})
			for _, piece := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				add("content_block_delta", obj("index", index, "delta", obj("type", "thinking_delta", "thinking", piece)), effect{})
			}
			add("content_block_delta", obj("index", index, "delta", obj("type", "signature_delta", "signature", value.signature)), effect{})
		case kindToolCall:
			add("content_block_start", obj("index", index, "content_block", obj("type", "tool_use", "id", anthropicCallID(value),
				"name", value.name, "input", obj())), effect{toolKeys: []string{fmt.Sprintf("block:%d", index)}})
			for _, piece := range splitDeltas(value.args, conversation.options.DeltaBytes) {
				add("content_block_delta", obj("index", index, "delta", obj("type", "input_json_delta", "partial_json", piece)), effect{})
			}
		default:
			add("content_block_start", obj("index", index, "content_block", obj("type", "text", "text", "")), effect{})
			for _, piece := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				add("content_block_delta", obj("index", index, "delta", obj("type", "text_delta", "text", piece)), effect{})
			}
			if value.citation {
				add("content_block_delta", obj("index", index, "delta", obj("type", "citations_delta",
					"citation", anthropicCitation(conversation, value.text))), effect{})
			}
		}
		add("content_block_stop", obj("index", index), effect{})
		index++
	}
	if features.Extensions {
		add("bench_extension", obj("detail", obj("kind", conversation.text.word(), "sequence", len(chunks))), effect{})
		add("content_block_start", obj("index", index, "content_block", obj("type", "server_tool_use",
			"id", "srvtoolu_"+conversation.text.alnum(24), "name", "web_search", "input", obj("query", conversation.text.word()))), effect{})
		add("content_block_stop", obj("index", index), effect{})
		add("ping", obj(), effect{})
	}
	deltaUsage := obj("output_tokens", reply.usage.output)
	deltaEffect := &usageEffect{perField: true, output: int64Pointer(reply.usage.output)}
	if features.UsageShapes {
		// Newer API versions repeat the cumulative input counters here.
		deltaUsage = obj("input_tokens", uncached, "cache_creation_input_tokens", reply.usage.cacheWrite,
			"cache_read_input_tokens", reply.usage.cached, "output_tokens", reply.usage.output)
		deltaEffect.input = int64Pointer(uncached)
	}
	add("message_delta", obj("delta", obj("stop_reason", stopReason, "stop_sequence", nil), "usage", deltaUsage),
		effect{usage: deltaEffect, closing: true})
	add("message_stop", obj(), effect{terminal: true, closing: true})
	return rendered{header: sseHeader(), chunks: chunks}
}

func (anthropicRenderer) errorBody(conversation *Conversation, status int) ([]byte, string, string) {
	errorType := "api_error"
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		errorType = "invalid_request_error"
	case http.StatusUnauthorized:
		errorType = "authentication_error"
	case http.StatusTooManyRequests:
		errorType = "rate_limit_error"
	case http.StatusServiceUnavailable:
		errorType = "overloaded_error"
	}
	body := mustJSON(obj("type", "error", "error", obj("type", errorType, "message", conversation.text.sentence(60)),
		"request_id", "req_"+conversation.text.alnum(24)))
	return body, errorType, ""
}
