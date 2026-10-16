package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"llmapi-logger/internal/insights"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

const (
	GenerateContent       = "gemini.generate_content"
	StreamGenerateContent = "gemini.stream_generate_content"
	version               = "2"
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
		} else if looksLikeJSONArray(input.Response.Data) {
			// streamGenerateContent without alt=sse answers with one JSON array of
			// the same chunk objects an SSE stream would carry.
			if err := parseArrayStream(input.Response.Data, &result); err != nil {
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
				appendResponseConversation(root, &result)
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
	appendRequestConversation(root, result)
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
		result.Normalized = normalizeUsage(usage)
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
	if !accumulateStream(events, result) {
		return errors.New("gemini parser: no valid SSE event")
	}
	if malformed := streamMalformed(events); malformed || !tailClosed {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			if malformed {
				result.ErrorCode = "invalid_sse_event"
			} else {
				result.ErrorCode = "unterminated_sse_event"
			}
		}
	}
	appendStreamConversation(events, result)
	return nil
}

// accumulateStream folds every chunk object into result, so the last usage
// snapshot wins and tool calls add up. It reports whether any chunk was valid.
func accumulateStream(events []base.SSEEvent, result *base.Result) bool {
	valid := 0
	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			continue
		}
		valid++
		parseResponse(root, result)
	}
	return valid > 0
}

func streamMalformed(events []base.SSEEvent) bool {
	for _, event := range events {
		if _, err := protocolutil.Object(event.Data); err != nil {
			return true
		}
	}
	return false
}

func looksLikeJSONArray(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n\ufeff")
	return len(trimmed) > 0 && trimmed[0] == '['
}

// parseArrayStream handles a streamGenerateContent response delivered as a JSON
// array. Each element is treated exactly like one SSE event, so the result
// matches an equivalent SSE stream.
func parseArrayStream(data []byte, result *base.Result) error {
	var elements []json.RawMessage
	if err := base.DecodeJSON(data, &elements); err != nil {
		return err
	}
	if len(elements) == 0 {
		return errors.New("gemini parser: empty JSON array stream")
	}
	events := make([]base.SSEEvent, len(elements))
	for index, element := range elements {
		events[index] = base.SSEEvent{Data: element}
	}
	observed := true
	result.ObservedStream = &observed
	if !accumulateStream(events, result) {
		return errors.New("gemini parser: no valid JSON array element")
	}
	if streamMalformed(events) {
		result.Status = base.StatusPartial
		if result.ErrorCode == "" {
			result.ErrorCode = "invalid_event"
		}
	}
	appendStreamConversation(events, result)
	return nil
}

// normalizeUsage splits promptTokenCount, which includes cached content, into
// exclusive buckets. candidatesTokenCount excludes thinking, so output adds
// thoughtsTokenCount back. toolUsePromptTokenCount counts the results of
// server-side tools (for example Google Search) that are fed back as input and
// is not part of promptTokenCount, so it joins the uncached bucket. Gemini does
// not report cache writes.
func normalizeUsage(usage map[string]any) insights.Usage {
	prompt := protocolutil.Int64(usage["promptTokenCount"])
	cached := protocolutil.Int64(usage["cachedContentTokenCount"])
	toolUse := protocolutil.Int64(usage["toolUsePromptTokenCount"])
	thoughts := protocolutil.Int64(usage["thoughtsTokenCount"])
	if toolUse != nil {
		toolUse = protocolutil.Int64Pointer(max(*toolUse, 0))
	}
	normalized := insights.Usage{
		UncachedInput: protocolutil.SumReported(protocolutil.NonNegativeDifference(prompt, cached), toolUse),
		CacheRead:     cached,
		Output:        protocolutil.SumReported(protocolutil.Int64(usage["candidatesTokenCount"]), thoughts),
		Reasoning:     thoughts,
	}
	if prompt != nil {
		normalized.CacheWrite = protocolutil.Int64Pointer(0)
	}
	return normalized
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
