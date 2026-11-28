package protofixture

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
)

type geminiRenderer struct{}

func (geminiRenderer) path(conversation *Conversation) string {
	if conversation.stream {
		return "/v1beta/models/" + conversation.model + ":streamGenerateContent?alt=sse"
	}
	return "/v1beta/models/" + conversation.model + ":generateContent"
}

func geminiPart(value item) object {
	switch value.kind {
	case kindReasoning:
		return obj("text", value.text, "thought", true)
	case kindToolCall:
		// Thinking models attach an opaque signature to function calls; the
		// parser does not read it.
		return obj("functionCall", obj("name", value.name, "args", value.argsValue), "thoughtSignature", base64PNG([]byte(value.id)))
	default:
		return obj("text", value.text)
	}
}

func (geminiRenderer) request(conversation *Conversation, items []item, features Features) ([]byte, int, int) {
	contents := make([]any, 0, len(items))
	toolCalls := 0
	for _, run := range groups(items) {
		switch run[0].kind {
		case kindUser:
			value := run[0]
			parts := []any{obj("text", value.text)}
			if value.image != nil {
				parts = append(parts, obj("inlineData", obj("mimeType", "image/png", "data", base64PNG(value.image))))
			}
			contents = append(contents, obj("role", "user", "parts", parts))
		case kindToolResult:
			parts := make([]any, 0, len(run))
			for _, value := range run {
				parts = append(parts, obj("functionResponse", obj("id", "call_"+value.callID, "name", value.name,
					"response", obj("output", value.text))))
			}
			contents = append(contents, obj("role", "user", "parts", parts))
		default:
			parts := make([]any, 0, len(run))
			for _, value := range run {
				if value.kind == kindToolCall {
					toolCalls++
				}
				parts = append(parts, geminiPart(value))
			}
			contents = append(contents, obj("role", "model", "parts", parts))
		}
	}
	declarations := make([]any, 0, len(conversation.tools))
	for _, definition := range conversation.tools {
		declarations = append(declarations, obj("name", definition.name, "description", definition.description,
			"parametersJsonSchema", obj("type", "object", "properties", obj(definition.parameter, obj("type", "string"),
				"limit", obj("type", "integer")), "required", []string{definition.parameter})))
	}
	body := obj("contents", contents,
		"systemInstruction", obj("role", "user", "parts", []any{obj("text", conversation.system)}),
		"tools", []any{obj("functionDeclarations", declarations)},
		"generationConfig", obj("temperature", 0, "topP", 1, "thinkingConfig", obj("includeThoughts", true, "thinkingBudget", -1)))
	if features.Extensions {
		body = body.with("labels", obj("bench_trace", conversation.text.hex(4))).with("x_bench_client", obj("trace", conversation.text.hex(8)))
	}
	return mustJSON(body), len(contents), toolCalls
}

func geminiUsage(usage usageNumbers, candidates int64, shapes bool) (object, *usageEffect) {
	thoughts := usage.reasoning
	total := usage.input + candidates + thoughts + usage.toolPrompt
	value := obj("promptTokenCount", usage.input, "candidatesTokenCount", candidates, "totalTokenCount", total)
	if usage.cached > 0 {
		value = value.with("cachedContentTokenCount", usage.cached)
	}
	if thoughts > 0 {
		value = value.with("thoughtsTokenCount", thoughts)
	}
	if shapes {
		value = value.with("toolUsePromptTokenCount", usage.toolPrompt).
			with("promptTokensDetails", []any{obj("modality", "TEXT", "tokenCount", usage.input)}).
			with("cacheTokensDetails", []any{obj("modality", "TEXT", "tokenCount", usage.cached)}).
			with("candidatesTokensDetails", []any{obj("modality", "TEXT", "tokenCount", candidates)})
	}
	return value, &usageEffect{input: int64Pointer(usage.input), output: int64Pointer(candidates), total: int64Pointer(total)}
}

func (geminiRenderer) answer(conversation *Conversation, reply answer, features Features) rendered {
	responseID := conversation.text.alnum(22)
	candidatesTotal := max(1, reply.usage.output-reply.usage.reasoning)
	candidateExtras := func(candidate object) object {
		if features.Extensions {
			candidate = candidate.with("avgLogprobs", -0.25).
				with("citationMetadata", obj("citations", []any{obj("startIndex", 0, "endIndex", 4, "uri", "https://example.com/"+conversation.text.word())})).
				with("x_bench_candidate", obj("rank", 1))
		}
		return candidate
	}
	if !conversation.stream {
		parts := make([]any, 0, len(reply.items))
		keys := make([]string, 0)
		for index, value := range reply.items {
			parts = append(parts, geminiPart(value))
			if value.kind == kindToolCall {
				keys = append(keys, fmt.Sprintf("part:%d", index))
			}
		}
		usage, usageEffect := geminiUsage(reply.usage, candidatesTotal, features.UsageShapes)
		body := obj("candidates", []any{candidateExtras(obj("content", obj("role", "model", "parts", parts), "finishReason", "STOP", "index", 0))},
			"usageMetadata", usage, "modelVersion", conversation.responseModel, "responseId", responseID)
		if features.Extensions {
			body = body.with("createTime", "2026-01-01T00:00:00.000000Z")
		}
		return rendered{header: jsonHeader(), json: true, chunks: []chunk{{
			data:   mustJSON(body),
			effect: effect{model: conversation.responseModel, id: responseID, usage: usageEffect, toolKeys: keys},
		}}}
	}

	type piece struct {
		part      object
		candidate int64
		tool      bool
	}
	pieces := make([]piece, 0, 64)
	for _, value := range reply.items {
		switch value.kind {
		case kindToolCall:
			pieces = append(pieces, piece{part: geminiPart(value), candidate: int64(len(value.args) / 4), tool: true})
		case kindReasoning:
			for _, text := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				pieces = append(pieces, piece{part: obj("text", text, "thought", true)})
			}
		default:
			for _, text := range splitDeltas(value.text, conversation.options.DeltaBytes) {
				pieces = append(pieces, piece{part: obj("text", text), candidate: int64(len(text) / 4)})
			}
		}
	}
	chunks := make([]chunk, 0, len(pieces)+1)
	var produced int64
	for index, current := range pieces {
		last := index == len(pieces)-1
		produced += current.candidate
		count := min(max(1, produced), candidatesTotal)
		if last {
			count = candidatesTotal
		}
		candidate := obj("content", obj("role", "model", "parts", []any{current.part}), "index", 0)
		if last {
			candidate = candidateExtras(candidate.with("finishReason", "STOP"))
		}
		payload := obj("candidates", []any{candidate})
		extra := effect{model: conversation.responseModel, id: responseID, closing: last, terminal: last}
		if current.tool {
			extra.toolKeys = []string{fmt.Sprintf("piece:%d", index)}
		}
		// Every chunk repeats the cumulative usage, as the API does.
		usage, usageEffect := geminiUsage(reply.usage, count, features.UsageShapes)
		payload = payload.with("usageMetadata", usage)
		extra.usage = usageEffect
		payload = payload.with("modelVersion", conversation.responseModel).with("responseId", responseID)
		chunks = append(chunks, chunk{data: geminiEvent(payload), effect: extra})
	}
	return rendered{header: sseHeader(), chunks: chunks}
}

// geminiEvent frames one chunk the way the API does, with CRLF line ends.
func geminiEvent(payload any) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("data: ")
	buffer.Write(mustJSON(payload))
	buffer.WriteString("\r\n\r\n")
	return buffer.Bytes()
}

func (geminiRenderer) errorBody(conversation *Conversation, status int) ([]byte, string, string) {
	statusName := "INTERNAL"
	switch status {
	case http.StatusBadRequest:
		statusName = "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		statusName = "UNAUTHENTICATED"
	case http.StatusUnprocessableEntity:
		statusName = "FAILED_PRECONDITION"
	case http.StatusTooManyRequests:
		statusName = "RESOURCE_EXHAUSTED"
	case http.StatusServiceUnavailable:
		statusName = "UNAVAILABLE"
	}
	body := mustJSON(obj("error", obj("code", status, "message", conversation.text.sentence(60), "status", statusName,
		"details", []any{obj("@type", "type.googleapis.com/google.rpc.ErrorInfo", "reason", statusName, "domain", "example.com")})))
	return body, statusName, strconv.Itoa(status)
}
