package openai

import (
	"context"
	"errors"
	"fmt"
	"strings"

	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

const (
	ChatCompletions  = "openai.chat_completions"
	Completions      = "openai.completions"
	Responses        = "openai.responses"
	ResponsesCompact = "openai.responses_compact"
	version          = "1"
)

type Parser struct {
	name string
}

func New(name string) (*Parser, error) {
	switch name {
	case ChatCompletions, Completions, Responses, ResponsesCompact:
		return &Parser{name: name}, nil
	default:
		return nil, fmt.Errorf("openai parser: unsupported name %q", name)
	}
}

func (implementation *Parser) Name() string    { return implementation.name }
func (implementation *Parser) Version() string { return version }

func (implementation *Parser) Parse(_ context.Context, input base.Input) base.Result {
	result := base.Result{Status: base.StatusOK}
	parsedSides := 0
	partial := false

	if input.Request.Present {
		root, err := protocolutil.Object(input.Request.Data)
		if err != nil {
			partial = true
		} else {
			parsedSides++
			parseRequest(root, implementation.name, &result)
		}
	}

	if input.Response.Present {
		if base.LooksLikeSSE(input.Response.ContentType, input.Response.Data) {
			if err := parseStream(input.Response.Data, &result); err != nil {
				partial = true
			} else {
				parsedSides++
			}
		} else {
			root, err := protocolutil.Object(input.Response.Data)
			if err != nil {
				partial = true
			} else {
				parsedSides++
				observed := false
				result.ObservedStream = &observed
				parseResponse(root, &result)
			}
		}
	}

	if parsedSides == 0 {
		result.Status = base.StatusError
		result.ErrorCode = "invalid_json"
	} else if partial {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			result.ErrorCode = "invalid_event"
		}
	}
	result.ParsedJSON = protocolutil.MarshalSafe(map[string]any{
		"protocol":        "openai",
		"endpoint":        implementation.name,
		"status":          result.Status,
		"message_count":   result.MessageCount,
		"tool_call_count": result.ToolCallCount,
		"has_tool_call":   result.HasToolCall,
	})
	return result
}

func parseRequest(root map[string]any, parserName string, result *base.Result) {
	result.RequestModel = protocolutil.String(root["model"])
	if stream, ok := protocolutil.Bool(root["stream"]); ok {
		result.RequestedStream = stream
	}

	messageCount := 0
	switch parserName {
	case ChatCompletions:
		messageCount = len(protocolutil.Slice(root["messages"]))
	case Completions:
		messageCount = protocolutil.Count(root["prompt"])
	case Responses, ResponsesCompact:
		messageCount = protocolutil.Count(root["input"])
	}
	result.MessageCount = protocolutil.IntPointer(messageCount)

	toolCount := countRequestToolCalls(root)
	result.ToolCallCount = protocolutil.IntPointer(toolCount)
	result.HasToolCall = protocolutil.BoolPointer(toolCount > 0)
}

func parseResponse(root map[string]any, result *base.Result) {
	parseResponseFields(root, result)
	mergeToolCount(result, countResponseToolCalls(root))
}

func parseResponseFields(root map[string]any, result *base.Result) {
	if value := protocolutil.String(root["id"]); value != "" {
		result.ResponseID = value
	}
	if value := protocolutil.String(root["model"]); value != "" {
		result.ResponseModel = value
	}
	applyUsage(protocolutil.Map(root["usage"]), result)
	if errorType, errorCode := protocolutil.ErrorFields(root); errorType != "" || errorCode != "" {
		result.ErrorType = errorType
		result.ErrorCode = errorCode
	}
}

func parseStream(data []byte, result *base.Result) error {
	events, tailClosed := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return errors.New("openai parser: empty SSE")
	}
	observed := true
	result.ObservedStream = &observed
	terminal := false
	validEvents := 0
	malformed := false
	toolKeys := make(map[string]struct{})

	for _, event := range events {
		payload := strings.TrimSpace(string(event.Data))
		if payload == "[DONE]" {
			terminal = true
			continue
		}
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			malformed = true
			continue
		}
		validEvents++
		parseResponseFields(root, result)

		eventType := protocolutil.String(root["type"])
		if eventType == "error" {
			result.ErrorType = eventType
			if code := protocolutil.String(root["code"]); code != "" {
				result.ErrorCode = code
			}
			terminal = true
		} else if strings.HasSuffix(eventType, ".completed") || strings.HasSuffix(eventType, ".failed") || strings.HasSuffix(eventType, ".incomplete") {
			terminal = true
		}
		if response := protocolutil.Map(root["response"]); response != nil {
			parseResponseFields(response, result)
		}
		collectStreamToolKeys(root, toolKeys)
	}
	mergeToolCount(result, len(toolKeys))
	if validEvents == 0 {
		return errors.New("openai parser: no valid SSE event")
	}
	if malformed || !tailClosed || !terminal {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			if malformed {
				result.ErrorCode = "invalid_sse_event"
			} else if !tailClosed {
				result.ErrorCode = "unterminated_sse_event"
			} else {
				result.ErrorCode = "missing_terminal_event"
			}
		}
	}
	return nil
}

func applyUsage(usage map[string]any, result *base.Result) {
	if usage == nil {
		return
	}
	result.Usage.Input = firstInt64(usage["input_tokens"], usage["prompt_tokens"])
	result.Usage.Output = firstInt64(usage["output_tokens"], usage["completion_tokens"])
	result.Usage.Total = protocolutil.Int64(usage["total_tokens"])
}

func countRequestToolCalls(root map[string]any) int {
	count := 0
	for _, messageValue := range protocolutil.Slice(root["messages"]) {
		message := protocolutil.Map(messageValue)
		count += len(protocolutil.Slice(message["tool_calls"]))
	}
	for _, itemValue := range protocolutil.Slice(root["input"]) {
		item := protocolutil.Map(itemValue)
		if isToolType(protocolutil.String(item["type"])) {
			count++
		}
	}
	return count
}

func countResponseToolCalls(root map[string]any) int {
	count := 0
	for _, choiceValue := range protocolutil.Slice(root["choices"]) {
		choice := protocolutil.Map(choiceValue)
		message := protocolutil.Map(choice["message"])
		count += len(protocolutil.Slice(message["tool_calls"]))
	}
	for _, itemValue := range protocolutil.Slice(root["output"]) {
		item := protocolutil.Map(itemValue)
		if isToolType(protocolutil.String(item["type"])) {
			count++
		}
	}
	return count
}

func collectStreamToolKeys(root map[string]any, keys map[string]struct{}) {
	for choicePosition, choiceValue := range protocolutil.Slice(root["choices"]) {
		choice := protocolutil.Map(choiceValue)
		choiceIndex := choicePosition
		if parsed := protocolutil.Int(choice["index"]); parsed != nil {
			choiceIndex = *parsed
		}
		for _, field := range []string{"delta", "message"} {
			container := protocolutil.Map(choice[field])
			for toolPosition, toolValue := range protocolutil.Slice(container["tool_calls"]) {
				tool := protocolutil.Map(toolValue)
				toolIndex := toolPosition
				if parsed := protocolutil.Int(tool["index"]); parsed != nil {
					toolIndex = *parsed
				}
				keys[fmt.Sprintf("choice:%d:%d", choiceIndex, toolIndex)] = struct{}{}
			}
		}
	}
	collectResponseOutputToolKeys(root, keys)
	if response := protocolutil.Map(root["response"]); response != nil {
		collectResponseOutputToolKeys(response, keys)
	}

	outputIndex := -1
	if parsed := protocolutil.Int(root["output_index"]); parsed != nil {
		outputIndex = *parsed
	}
	for _, field := range []string{"item", "output_item"} {
		item := protocolutil.Map(root[field])
		if item == nil || !isToolType(protocolutil.String(item["type"])) {
			continue
		}
		addResponseToolKey(keys, item, outputIndex, field)
	}
}

func collectResponseOutputToolKeys(root map[string]any, keys map[string]struct{}) {
	for outputIndex, itemValue := range protocolutil.Slice(root["output"]) {
		item := protocolutil.Map(itemValue)
		if item == nil || !isToolType(protocolutil.String(item["type"])) {
			continue
		}
		addResponseToolKey(keys, item, outputIndex, "output")
	}
}

func addResponseToolKey(keys map[string]struct{}, item map[string]any, outputIndex int, fallback string) {
	if identifier := protocolutil.String(item["id"]); identifier != "" {
		keys["response:id:"+identifier] = struct{}{}
		return
	}
	if outputIndex >= 0 {
		keys[fmt.Sprintf("response:index:%d", outputIndex)] = struct{}{}
		return
	}
	keys["response:fallback:"+fallback] = struct{}{}
}

func mergeToolCount(result *base.Result, count int) {
	if count <= 0 {
		if result.ToolCallCount == nil {
			result.ToolCallCount = protocolutil.IntPointer(0)
			result.HasToolCall = protocolutil.BoolPointer(false)
		}
		return
	}
	current := 0
	if result.ToolCallCount != nil {
		current = *result.ToolCallCount
	}
	current += count
	result.ToolCallCount = protocolutil.IntPointer(current)
	result.HasToolCall = protocolutil.BoolPointer(true)
}

func isToolType(value string) bool {
	return value == "function_call" || value == "tool_call" || value == "computer_call" || value == "file_search_call" || value == "web_search_call"
}

func firstInt64(values ...any) *int64 {
	for _, value := range values {
		if parsed := protocolutil.Int64(value); parsed != nil {
			return parsed
		}
	}
	return nil
}
