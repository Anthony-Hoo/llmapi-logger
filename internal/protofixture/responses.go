package protofixture

type responsesRenderer struct{}

func (responsesRenderer) path(*Conversation) string { return "/v1/responses" }

func responsesCallID(value item) string { return "call_" + value.callID }

func (responsesRenderer) request(conversation *Conversation, items []item, features Features) ([]byte, int, int) {
	input := make([]any, 0, len(items))
	toolCalls := 0
	for _, value := range items {
		switch value.kind {
		case kindUser:
			content := []any{obj("type", "input_text", "text", value.text)}
			if value.image != nil {
				content = append(content, obj("type", "input_image", "image_url", dataURLPNG(value.image), "detail", "auto"))
			}
			input = append(input, obj("type", "message", "role", "user", "content", content))
		case kindAssistant:
			input = append(input, obj("type", "message", "role", "assistant",
				"content", []any{obj("type", "output_text", "text", value.text)}))
		case kindReasoning:
			input = append(input, obj("type", "reasoning",
				"summary", []any{obj("type", "summary_text", "text", value.text)},
				"content", nil, "encrypted_content", value.signature))
		case kindToolCall:
			input = append(input, obj("type", "function_call", "name", value.name, "arguments", value.args,
				"call_id", responsesCallID(value)))
			toolCalls++
		case kindToolResult:
			input = append(input, obj("type", "function_call_output", "call_id", responsesCallID(value), "output", value.text))
		}
	}
	body := obj("model", conversation.model, "instructions", conversation.system, "input", input,
		"tools", openAITools(conversation, true), "tool_choice", "auto", "parallel_tool_calls", true,
		"reasoning", obj("effort", "medium", "summary", "auto"), "store", false, "stream", conversation.stream,
		"include", []string{"reasoning.encrypted_content"}, "prompt_cache_key", conversation.key)
	if features.Extensions {
		body = body.with("text", obj("verbosity", "medium")).with("x_bench_client", obj("trace", conversation.text.hex(8)))
	}
	return mustJSON(body), len(input), toolCalls
}

func responsesUsage(usage usageNumbers) object {
	return obj("input_tokens", usage.input, "input_tokens_details", obj("cached_tokens", usage.cached),
		"output_tokens", usage.output, "output_tokens_details", obj("reasoning_tokens", usage.reasoning),
		"total_tokens", usage.total())
}

func responsesOutputItem(value item, complete bool) object {
	status := "completed"
	if !complete {
		status = "in_progress"
	}
	switch value.kind {
	case kindReasoning:
		summary := []any{}
		if complete {
			summary = []any{obj("type", "summary_text", "text", value.text)}
		}
		result := obj("id", value.id, "type", "reasoning", "summary", summary)
		if complete {
			result = result.with("encrypted_content", value.signature)
		}
		return result
	case kindToolCall:
		arguments := ""
		if complete {
			arguments = value.args
		}
		return obj("id", value.id, "type", "function_call", "status", status, "arguments", arguments,
			"call_id", responsesCallID(value), "name", value.name)
	default:
		content := []any{}
		if complete {
			content = []any{obj("type", "output_text", "annotations", []any{}, "logprobs", []any{}, "text", value.text)}
		}
		return obj("id", value.id, "type", "message", "status", status, "content", content, "role", "assistant")
	}
}

func (responsesRenderer) answer(conversation *Conversation, reply answer, features Features) rendered {
	id := "resp_" + reply.id
	output := make([]any, 0, len(reply.items))
	keys := make([]string, 0)
	for _, value := range reply.items {
		output = append(output, responsesOutputItem(value, true))
		if value.kind == kindToolCall {
			keys = append(keys, "response:id:"+value.id)
		}
	}
	responseObject := func(status string, output []any, usage any) object {
		return obj("id", id, "object", "response", "created_at", reply.created, "status", status,
			"background", false, "error", nil, "incomplete_details", nil, "instructions", conversation.system,
			"max_output_tokens", nil, "model", conversation.responseModel, "output", output,
			"parallel_tool_calls", true, "previous_response_id", nil, "prompt_cache_key", conversation.key,
			"reasoning", obj("effort", "medium", "summary", "auto"), "service_tier", "default", "store", false,
			"temperature", 1, "text", obj("format", obj("type", "text"), "verbosity", "medium"),
			"tool_choice", "auto", "tools", openAITools(conversation, true), "top_p", 1, "truncation", "disabled",
			"usage", usage, "user", nil, "metadata", obj())
	}
	usageEffect := &usageEffect{input: int64Pointer(reply.usage.input), output: int64Pointer(reply.usage.output), total: int64Pointer(reply.usage.total())}
	if !conversation.stream {
		body := responseObject("completed", output, responsesUsage(reply.usage))
		if features.Extensions {
			body = body.with("x_bench_gateway", obj("channel", conversation.text.word()))
		}
		return rendered{header: jsonHeader(), json: true, chunks: []chunk{{
			data:   mustJSON(body),
			effect: effect{model: conversation.responseModel, id: id, usage: usageEffect, toolKeys: keys},
		}}}
	}

	chunks := make([]chunk, 0, 64)
	sequence := 0
	add := func(eventType string, payload object, extra effect) {
		payload = append(object{{key: "type", value: eventType}}, payload...)
		payload = payload.with("sequence_number", sequence)
		sequence++
		chunks = append(chunks, chunk{data: sseEvent(eventType, payload), effect: extra})
	}
	add("response.created", obj("response", responseObject("in_progress", []any{}, nil)), effect{model: conversation.responseModel, id: id})
	add("response.in_progress", obj("response", responseObject("in_progress", []any{}, nil)), effect{model: conversation.responseModel, id: id})
	for index, value := range reply.items {
		var key []string
		if value.kind == kindToolCall {
			key = []string{"response:id:" + value.id}
		}
		add("response.output_item.added", obj("output_index", index, "item", responsesOutputItem(value, false)), effect{toolKeys: key})
		switch value.kind {
		case kindReasoning:
			add("response.reasoning_summary_part.added", obj("item_id", value.id, "output_index", index, "summary_index", 0,
				"part", obj("type", "summary_text", "text", "")), effect{})
			for _, piece := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				add("response.reasoning_summary_text.delta", obj("item_id", value.id, "output_index", index, "summary_index", 0,
					"delta", piece), effect{})
			}
			add("response.reasoning_summary_text.done", obj("item_id", value.id, "output_index", index, "summary_index", 0,
				"text", value.text), effect{})
			add("response.reasoning_summary_part.done", obj("item_id", value.id, "output_index", index, "summary_index", 0,
				"part", obj("type", "summary_text", "text", value.text)), effect{})
		case kindToolCall:
			for _, piece := range splitDeltas(value.args, conversation.options.DeltaBytes) {
				add("response.function_call_arguments.delta", obj("item_id", value.id, "output_index", index, "delta", piece), effect{})
			}
			add("response.function_call_arguments.done", obj("item_id", value.id, "output_index", index, "arguments", value.args), effect{})
		default:
			add("response.content_part.added", obj("item_id", value.id, "output_index", index, "content_index", 0,
				"part", obj("type", "output_text", "annotations", []any{}, "logprobs", []any{}, "text", "")), effect{})
			for _, piece := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				delta := obj("item_id", value.id, "output_index", index, "content_index", 0, "delta", piece, "logprobs", []any{})
				if features.Extensions {
					delta = delta.with("obfuscation", conversation.text.alnum(5))
				}
				add("response.output_text.delta", delta, effect{})
			}
			if features.Extensions {
				// A real event the parser does not consume, and one no
				// provider sends.
				add("response.output_text.annotation.added", obj("item_id", value.id, "output_index", index, "content_index", 0,
					"annotation_index", 0, "annotation", obj("type", "url_citation", "start_index", 0, "end_index", 4,
						"url", "https://example.com/"+conversation.text.word(), "title", conversation.text.word())), effect{})
				add("response.x_bench_extension.added", obj("item_id", value.id, "detail", obj("kind", conversation.text.word())), effect{})
				chunks = append(chunks, chunk{data: []byte(": keep-alive\n\n")})
			}
			add("response.output_text.done", obj("item_id", value.id, "output_index", index, "content_index", 0,
				"text", value.text, "logprobs", []any{}), effect{})
			add("response.content_part.done", obj("item_id", value.id, "output_index", index, "content_index", 0,
				"part", obj("type", "output_text", "annotations", []any{}, "logprobs", []any{}, "text", value.text)), effect{})
		}
		add("response.output_item.done", obj("output_index", index, "item", responsesOutputItem(value, true)), effect{toolKeys: key})
	}
	add("response.completed", obj("response", responseObject("completed", output, responsesUsage(reply.usage))),
		effect{model: conversation.responseModel, id: id, usage: usageEffect, toolKeys: keys, terminal: true, closing: true})
	return rendered{header: sseHeader(), chunks: chunks}
}

func (responsesRenderer) errorBody(conversation *Conversation, status int) ([]byte, string, string) {
	return openAIError(conversation, status)
}
