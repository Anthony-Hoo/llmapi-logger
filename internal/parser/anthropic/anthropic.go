package anthropic

import (
	"context"
	"errors"

	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

const (
	Messages = "anthropic.messages"
	version  = "1"
)

type Parser struct{}

func New() *Parser              { return &Parser{} }
func (*Parser) Name() string    { return Messages }
func (*Parser) Version() string { return version }

func (*Parser) Parse(_ context.Context, input base.Input) base.Result {
	result := base.Result{Status: base.StatusOK}
	parsedSides := 0
	partial := false

	if input.Request.Present {
		root, err := protocolutil.Object(input.Request.Data)
		if err != nil {
			partial = true
		} else {
			parsedSides++
			parseRequest(root, &result)
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
		"protocol":        "anthropic",
		"status":          result.Status,
		"message_count":   result.MessageCount,
		"tool_call_count": result.ToolCallCount,
		"has_tool_call":   result.HasToolCall,
	})
	return result
}

func parseRequest(root map[string]any, result *base.Result) {
	result.RequestModel = protocolutil.String(root["model"])
	if stream, ok := protocolutil.Bool(root["stream"]); ok {
		result.RequestedStream = stream
	}
	messages := protocolutil.Slice(root["messages"])
	result.MessageCount = protocolutil.IntPointer(len(messages))
	toolCount := 0
	for _, messageValue := range messages {
		message := protocolutil.Map(messageValue)
		toolCount += countToolBlocks(message["content"])
	}
	result.ToolCallCount = protocolutil.IntPointer(toolCount)
	result.HasToolCall = protocolutil.BoolPointer(toolCount > 0)
}

func parseResponse(root map[string]any, result *base.Result) {
	if value := protocolutil.String(root["id"]); value != "" {
		result.ResponseID = value
	}
	if value := protocolutil.String(root["model"]); value != "" {
		result.ResponseModel = value
	}
	applyUsage(protocolutil.Map(root["usage"]), result)
	if errorObject := protocolutil.Map(root["error"]); errorObject != nil {
		result.ErrorType = protocolutil.String(errorObject["type"])
		result.ErrorCode = protocolutil.String(errorObject["code"])
	}
	mergeToolCount(result, countToolBlocks(root["content"]))
}

func parseStream(data []byte, result *base.Result) error {
	events, tailClosed := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return errors.New("anthropic parser: empty SSE")
	}
	observed := true
	result.ObservedStream = &observed
	terminal := false
	valid := 0
	malformed := false
	toolIndexes := make(map[int]struct{})

	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			malformed = true
			continue
		}
		valid++
		eventType := protocolutil.String(root["type"])
		if eventType == "" {
			eventType = event.Event
		}
		switch eventType {
		case "message_start":
			message := protocolutil.Map(root["message"])
			parseResponse(message, result)
		case "content_block_start":
			block := protocolutil.Map(root["content_block"])
			if protocolutil.String(block["type"]) == "tool_use" {
				index := 0
				if parsed := protocolutil.Int(root["index"]); parsed != nil {
					index = *parsed
				}
				toolIndexes[index] = struct{}{}
			}
		case "message_delta":
			applyUsage(protocolutil.Map(root["usage"]), result)
		case "message_stop":
			terminal = true
		case "error":
			errorObject := protocolutil.Map(root["error"])
			result.ErrorType = protocolutil.String(errorObject["type"])
			result.ErrorCode = protocolutil.String(errorObject["code"])
			result.Status = base.StatusPartial
			terminal = true
		}
	}
	mergeToolCount(result, len(toolIndexes))
	if valid == 0 {
		return errors.New("anthropic parser: no valid SSE event")
	}
	if malformed || !tailClosed || !terminal {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			if malformed {
				result.ErrorCode = "invalid_sse_event"
			} else if !tailClosed {
				result.ErrorCode = "unterminated_sse_event"
			} else {
				result.ErrorCode = "missing_message_stop"
			}
		}
	}
	return nil
}

func applyUsage(usage map[string]any, result *base.Result) {
	if usage == nil {
		return
	}
	if value := protocolutil.Int64(usage["input_tokens"]); value != nil {
		result.Usage.Input = value
	}
	if value := protocolutil.Int64(usage["output_tokens"]); value != nil {
		result.Usage.Output = value
	}
}

func countToolBlocks(value any) int {
	count := 0
	for _, blockValue := range protocolutil.Slice(value) {
		block := protocolutil.Map(blockValue)
		if protocolutil.String(block["type"]) == "tool_use" {
			count++
		}
	}
	return count
}

func mergeToolCount(result *base.Result, increment int) {
	current := 0
	if result.ToolCallCount != nil {
		current = *result.ToolCallCount
	}
	current += increment
	result.ToolCallCount = protocolutil.IntPointer(current)
	result.HasToolCall = protocolutil.BoolPointer(current > 0)
}
