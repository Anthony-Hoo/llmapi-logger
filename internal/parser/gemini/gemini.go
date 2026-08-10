package gemini

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

const (
	GenerateContent       = "gemini.generate_content"
	StreamGenerateContent = "gemini.stream_generate_content"
	version               = "1"
)

type Parser struct {
	name string
}

func New(name string) (*Parser, error) {
	if name != GenerateContent && name != StreamGenerateContent {
		return nil, fmt.Errorf("gemini parser: unsupported name %q", name)
	}
	return &Parser{name: name}, nil
}

func (implementation *Parser) Name() string { return implementation.name }
func (*Parser) Version() string             { return version }

func (implementation *Parser) Parse(_ context.Context, input base.Input) base.Result {
	result := base.Result{Status: base.StatusOK}
	parsedSides := 0
	partial := false

	requestedStream := implementation.name == StreamGenerateContent
	result.RequestedStream = protocolutil.BoolPointer(requestedStream)
	result.RequestModel = modelFromEndpoint(input.Endpoint)

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
		"protocol":        "gemini",
		"endpoint":        implementation.name,
		"status":          result.Status,
		"message_count":   result.MessageCount,
		"tool_call_count": result.ToolCallCount,
		"has_tool_call":   result.HasToolCall,
	})
	return result
}

func parseRequest(root map[string]any, result *base.Result) {
	contents := protocolutil.Slice(root["contents"])
	result.MessageCount = protocolutil.IntPointer(len(contents))
	toolCount := 0
	for _, contentValue := range contents {
		content := protocolutil.Map(contentValue)
		toolCount += countFunctionCalls(content)
	}
	result.ToolCallCount = protocolutil.IntPointer(toolCount)
	result.HasToolCall = protocolutil.BoolPointer(toolCount > 0)
}

func parseResponse(root map[string]any, result *base.Result) {
	if value := protocolutil.String(root["modelVersion"]); value != "" {
		result.ResponseModel = value
	}
	if value := protocolutil.String(root["responseId"]); value != "" {
		result.ResponseID = value
	}
	usage := protocolutil.Map(root["usageMetadata"])
	if usage != nil {
		result.Usage.Input = protocolutil.Int64(usage["promptTokenCount"])
		result.Usage.Output = protocolutil.Int64(usage["candidatesTokenCount"])
		result.Usage.Total = protocolutil.Int64(usage["totalTokenCount"])
	}
	if errorObject := protocolutil.Map(root["error"]); errorObject != nil {
		result.ErrorType = protocolutil.String(errorObject["status"])
		result.ErrorCode = protocolutil.String(errorObject["code"])
	}
	toolCount := 0
	for _, candidateValue := range protocolutil.Slice(root["candidates"]) {
		candidate := protocolutil.Map(candidateValue)
		toolCount += countFunctionCalls(protocolutil.Map(candidate["content"]))
	}
	mergeToolCount(result, toolCount)
}

func parseStream(data []byte, result *base.Result) error {
	events, tailClosed := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return errors.New("gemini parser: empty SSE")
	}
	observed := true
	result.ObservedStream = &observed
	valid := 0
	malformed := false
	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			malformed = true
			continue
		}
		valid++
		parseResponse(root, result)
	}
	if valid == 0 {
		return errors.New("gemini parser: no valid SSE event")
	}
	if malformed || !tailClosed {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			if malformed {
				result.ErrorCode = "invalid_sse_event"
			} else {
				result.ErrorCode = "unterminated_sse_event"
			}
		}
	}
	return nil
}

func countFunctionCalls(content map[string]any) int {
	if content == nil {
		return 0
	}
	count := 0
	for _, partValue := range protocolutil.Slice(content["parts"]) {
		part := protocolutil.Map(partValue)
		if protocolutil.Map(part["functionCall"]) != nil {
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

func modelFromEndpoint(endpoint string) string {
	marker := "/models/"
	start := strings.Index(endpoint, marker)
	if start < 0 {
		return ""
	}
	modelAndOperation := endpoint[start+len(marker):]
	end := strings.LastIndex(modelAndOperation, ":")
	if end <= 0 {
		return ""
	}
	model, err := url.PathUnescape(modelAndOperation[:end])
	if err != nil {
		return ""
	}
	return model
}
