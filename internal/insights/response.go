package insights

import (
	"strings"

	"llmapi-logger/internal/conversation"
)

// responseToolCall is one tool call of this response, with raw arguments.
type responseToolCall struct {
	name string
	args string
}

// responseToolCalls lists the tool calls of the response-phase messages.
func responseToolCalls(conv *conversation.Conversation) []responseToolCall {
	if conv == nil {
		return nil
	}
	var calls []responseToolCall
	for _, message := range conv.Messages {
		if message.Phase != conversation.PhaseResponse {
			continue
		}
		for _, part := range message.Content {
			if part.Type == conversation.PartToolCall {
				calls = append(calls, responseToolCall{name: part.Name, args: part.Arguments})
			}
		}
	}
	return calls
}

func (analysis *Analysis) applyResponse(input Input, vocab *Vocabulary) {
	analysis.ToolKindCounts = map[string]int{}
	if conv := input.Conversation; conv != nil {
		for _, message := range conv.Messages {
			if message.Phase != conversation.PhaseResponse {
				continue
			}
			for _, part := range message.Content {
				switch part.Type {
				case conversation.PartReasoning:
					analysis.ResponseKinds |= KindThinking
				case conversation.PartToolCall:
					analysis.ResponseKinds |= KindToolCall
					analysis.ResponseToolCalls++
					analysis.ToolKindCounts[vocab.callToolKind(part.Name, part.Arguments)]++
					analysis.Detail.FileOps = append(analysis.Detail.FileOps, vocab.fileOpsForCall(part.Name, part.Arguments)...)
				case conversation.PartText:
					if part.Text != "" {
						analysis.ResponseKinds |= KindText
					}
				}
			}
		}
	}
	analysis.StopReason = responseStopReason(input.Response)
	if analysis.StopReason == StopEndTurn && analysis.ResponseKinds&KindToolCall != 0 && reportsToolUseAsStop(input) {
		analysis.StopReason = StopToolUse
	}
}

// reportsToolUseAsStop is true for protocols whose finish reason is "stop" /
// "completed" even when the model called a tool.
func reportsToolUseAsStop(input Input) bool {
	switch strings.ToLower(input.Protocol) {
	case "gemini":
		return true
	case "openai":
		return openAIEndpoint(input.Endpoint, nil) == "responses"
	}
	return false
}

// responseObjects decodes a response body into JSON objects: one object, a
// JSON array of objects (Gemini stream without SSE), or SSE data events.
func responseObjects(body []byte) []map[string]any {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if value, err := decodeJSON([]byte(trimmed)); err == nil {
			if object := asMap(value); object != nil {
				return []map[string]any{object}
			}
			var objects []map[string]any
			for _, element := range asSlice(value) {
				if object := asMap(element); object != nil {
					objects = append(objects, object)
				}
			}
			return objects
		}
	}
	var objects []map[string]any
	var dataLines []string
	flush := func() {
		if len(dataLines) == 0 {
			return
		}
		payload := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if strings.TrimSpace(payload) == "[DONE]" {
			return
		}
		if value, err := decodeJSON([]byte(payload)); err == nil {
			if object := asMap(value); object != nil {
				objects = append(objects, object)
			}
		}
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return objects
}

// responseStopReason returns the normalized stop reason of a (possibly
// streamed) response, or "" when none is reported.
func responseStopReason(body []byte) string {
	stop := ""
	for _, object := range responseObjects(body) {
		if candidate := objectStopReason(object); candidate != "" {
			stop = candidate
		}
	}
	return stop
}

func objectStopReason(object map[string]any) string {
	// OpenAI chat completions and completions.
	for _, choice := range asSlice(object["choices"]) {
		if reason := normalizeStop(asString(asMap(choice)["finish_reason"])); reason != "" {
			return reason
		}
	}
	// Anthropic: message body, message_delta event, or message_start.
	for _, holder := range []map[string]any{object, asMap(object["delta"]), asMap(object["message"])} {
		if reason := normalizeStop(asString(holder["stop_reason"])); reason != "" {
			return reason
		}
	}
	// Gemini, optionally wrapped in a "response" envelope.
	for _, holder := range []map[string]any{object, asMap(object["response"])} {
		for _, candidate := range asSlice(holder["candidates"]) {
			if reason := normalizeStop(pickString(asMap(candidate), "finishReason", "finish_reason")); reason != "" {
				return reason
			}
		}
	}
	// OpenAI Responses: status on the object or on the response.completed envelope.
	for _, holder := range []map[string]any{object, asMap(object["response"])} {
		if holder == nil {
			continue
		}
		if reason := responsesStatusStop(holder); reason != "" {
			return reason
		}
	}
	return ""
}

func responsesStatusStop(holder map[string]any) string {
	switch strings.ToLower(asString(holder["status"])) {
	case "completed":
		return StopEndTurn
	case "incomplete":
		reason := strings.ToLower(asString(asMap(holder["incomplete_details"])["reason"]))
		if normalized := normalizeStop(reason); normalized != "" && normalized != StopOther {
			return normalized
		}
		return StopOther
	case "failed", "cancelled", "canceled":
		return StopOther
	}
	return ""
}

func normalizeStop(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "finish_reason_unspecified":
		return ""
	case "stop", "end_turn", "stop_sequence":
		return StopEndTurn
	case "tool_calls", "tool_use", "function_call":
		return StopToolUse
	case "length", "max_tokens", "max_output_tokens", "model_context_window_exceeded":
		return StopLength
	case "content_filter", "safety", "refusal", "recitation", "blocklist", "prohibited_content", "spii":
		return StopContentFilter
	}
	return StopOther
}

// maxOutputTokens reads the declared output limit.
func maxOutputTokens(root map[string]any) *int64 {
	candidates := []any{
		root["max_tokens"], root["max_completion_tokens"], root["max_output_tokens"],
		pickMap(root, "generationConfig", "generation_config")["maxOutputTokens"],
		pickMap(root, "generationConfig", "generation_config")["max_output_tokens"],
	}
	for _, candidate := range candidates {
		if value, ok := asInt64(candidate); ok && value > 0 {
			return &value
		}
	}
	return nil
}
