package openai

import (
	"sort"
	"strings"

	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

func appendRequestConversation(root map[string]any, parserName string, result *base.Result) {
	switch parserName {
	case ChatCompletions:
		for _, value := range protocolutil.Slice(root["messages"]) {
			appendChatMessage(protocolutil.Map(value), conversation.PhaseRequest, conversation.DirectionClientToUpstream, result)
		}
	case Completions:
		appendPrompt(root["prompt"], result)
	case Responses, ResponsesCompact:
		if instructions := protocolutil.String(root["instructions"]); instructions != "" {
			appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleDeveloper, "", "", []conversation.Part{conversation.Text(instructions)})
		}
		appendResponsesInput(root["input"], result)
	}
}

func appendResponseConversation(root map[string]any, parserName string, result *base.Result) {
	switch parserName {
	case ChatCompletions:
		for _, value := range protocolutil.Slice(root["choices"]) {
			choice := protocolutil.Map(value)
			appendChatMessage(protocolutil.Map(choice["message"]), conversation.PhaseResponse, conversation.DirectionUpstreamToClient, result)
		}
	case Completions:
		for _, value := range protocolutil.Slice(root["choices"]) {
			choice := protocolutil.Map(value)
			if text := protocolutil.String(choice["text"]); text != "" {
				appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, conversation.RoleAssistant, "", "", []conversation.Part{conversation.Text(text)})
			}
		}
	case Responses, ResponsesCompact:
		for _, value := range protocolutil.Slice(root["output"]) {
			appendResponsesItem(protocolutil.Map(value), conversation.PhaseResponse, conversation.DirectionUpstreamToClient, result)
		}
	}
}

func appendPrompt(value any, result *base.Result) {
	if text, ok := value.(string); ok {
		appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleUser, "", "", []conversation.Part{conversation.Text(text)})
		return
	}
	for _, item := range protocolutil.Slice(value) {
		text := protocolutil.String(item)
		if text == "" {
			continue
		}
		appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleUser, "", "", []conversation.Part{conversation.Text(text)})
	}
}

func appendResponsesInput(value any, result *base.Result) {
	if text, ok := value.(string); ok {
		appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleUser, "", "", []conversation.Part{conversation.Text(text)})
		return
	}
	if item := protocolutil.Map(value); item != nil {
		appendResponsesItem(item, conversation.PhaseRequest, conversation.DirectionClientToUpstream, result)
		return
	}
	for _, itemValue := range protocolutil.Slice(value) {
		if text, ok := itemValue.(string); ok {
			appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleUser, "", "", []conversation.Part{conversation.Text(text)})
			continue
		}
		appendResponsesItem(protocolutil.Map(itemValue), conversation.PhaseRequest, conversation.DirectionClientToUpstream, result)
	}
}

func appendChatMessage(message map[string]any, phase, direction string, result *base.Result) {
	if message == nil {
		return
	}
	role := normalizeRole(protocolutil.String(message["role"]))
	if role == conversation.RoleUnknown && phase == conversation.PhaseResponse {
		role = conversation.RoleAssistant
	}
	name := protocolutil.String(message["name"])
	toolCallID := protocolutil.String(message["tool_call_id"])
	parts := make([]conversation.Part, 0)
	if role == conversation.RoleTool {
		parts = append(parts, conversation.Part{
			Type:       conversation.PartToolResult,
			ToolCallID: toolCallID,
			Name:       name,
			Result:     contentValueString(message["content"]),
		})
	} else {
		parts = append(parts, openAIContentParts(message["content"])...)
	}
	for _, field := range []string{"reasoning_content", "reasoning", "thinking"} {
		if text := protocolutil.String(message[field]); text != "" {
			parts = append([]conversation.Part{conversation.Reasoning(text)}, parts...)
			break
		}
	}
	for _, value := range protocolutil.Slice(message["tool_calls"]) {
		if part, ok := openAIToolCallPart(protocolutil.Map(value)); ok {
			parts = append(parts, part)
		}
	}
	if legacy := protocolutil.Map(message["function_call"]); legacy != nil {
		if part, ok := openAIToolCallPart(legacy); ok {
			parts = append(parts, part)
		}
	}
	appendMessage(result, phase, direction, role, name, toolCallID, parts)
}

func openAIContentParts(value any) []conversation.Part {
	if text, ok := value.(string); ok {
		if text == "" {
			return nil
		}
		return []conversation.Part{conversation.Text(text)}
	}
	if block := protocolutil.Map(value); block != nil {
		return openAIContentBlock(block)
	}
	parts := make([]conversation.Part, 0)
	for _, blockValue := range protocolutil.Slice(value) {
		if text, ok := blockValue.(string); ok {
			if text != "" {
				parts = append(parts, conversation.Text(text))
			}
			continue
		}
		parts = append(parts, openAIContentBlock(protocolutil.Map(blockValue))...)
	}
	return parts
}

func openAIContentBlock(block map[string]any) []conversation.Part {
	if block == nil {
		return nil
	}
	typeName := protocolutil.String(block["type"])
	switch typeName {
	case "text", "input_text", "output_text", "refusal":
		text := protocolutil.String(block["text"])
		if text == "" {
			text = protocolutil.String(block["refusal"])
		}
		if text == "" {
			return nil
		}
		return []conversation.Part{conversation.Text(text)}
	case "reasoning", "reasoning_text", "summary_text", "thinking":
		text := protocolutil.String(block["text"])
		if text == "" {
			text = protocolutil.String(block["content"])
		}
		if text == "" {
			return nil
		}
		return []conversation.Part{conversation.Reasoning(text)}
	case "function_call", "tool_call", "custom_tool_call", "computer_call", "file_search_call", "web_search_call":
		if part, ok := openAIToolCallPart(block); ok {
			return []conversation.Part{part}
		}
	case "function_call_output", "tool_result", "custom_tool_call_output", "computer_call_output":
		return []conversation.Part{{
			Type:       conversation.PartToolResult,
			ToolCallID: firstString(block["call_id"], block["tool_call_id"], block["id"]),
			Name:       protocolutil.String(block["name"]),
			Result:     firstValueString(block["output"], block["result"], block["content"]),
		}}
	}
	return []conversation.Part{conversation.Unknown(block)}
}

func openAIToolCallPart(tool map[string]any) (conversation.Part, bool) {
	if tool == nil {
		return conversation.Part{}, false
	}
	function := protocolutil.Map(tool["function"])
	if function == nil {
		function = tool
	}
	part := conversation.Part{
		Type:      conversation.PartToolCall,
		ID:        firstString(tool["call_id"], tool["id"]),
		Name:      firstString(function["name"], tool["name"]),
		Arguments: conversation.ValueString(firstValue(function["arguments"], tool["arguments"], tool["input"])),
	}
	return part, part.ID != "" || part.Name != "" || part.Arguments != ""
}

func appendResponsesItem(item map[string]any, phase, direction string, result *base.Result) {
	if item == nil {
		return
	}
	typeName := protocolutil.String(item["type"])
	switch typeName {
	case "message", "":
		role := normalizeRole(protocolutil.String(item["role"]))
		if role == conversation.RoleUnknown {
			if phase == conversation.PhaseResponse {
				role = conversation.RoleAssistant
			} else {
				role = conversation.RoleUser
			}
		}
		appendMessage(result, phase, direction, role, protocolutil.String(item["name"]), protocolutil.String(item["tool_call_id"]), openAIContentParts(item["content"]))
	case "function_call", "tool_call", "custom_tool_call", "computer_call", "file_search_call", "web_search_call":
		if part, ok := openAIToolCallPart(item); ok {
			appendMessage(result, phase, direction, conversation.RoleAssistant, "", "", []conversation.Part{part})
		}
	case "function_call_output", "tool_result", "custom_tool_call_output", "computer_call_output":
		callID := firstString(item["call_id"], item["tool_call_id"], item["id"])
		appendMessage(result, phase, direction, conversation.RoleTool, protocolutil.String(item["name"]), callID, []conversation.Part{{
			Type:       conversation.PartToolResult,
			ToolCallID: callID,
			Name:       protocolutil.String(item["name"]),
			Result:     firstValueString(item["output"], item["result"], item["content"]),
		}})
	case "reasoning":
		parts := openAIReasoningParts(firstValue(item["summary"], item["content"]))
		if len(parts) != 0 {
			appendMessage(result, phase, direction, conversation.RoleAssistant, "", "", parts)
		}
	default:
		parts := openAIContentParts(item["content"])
		if len(parts) == 0 {
			parts = []conversation.Part{conversation.Unknown(item)}
		}
		appendMessage(result, phase, direction, normalizeRole(protocolutil.String(item["role"])), "", "", parts)
	}
}

type chatStreamMessage struct {
	role       string
	name       string
	text       string
	reasoning  string
	tools      map[int]*streamToolCall
	toolOrder  []int
	finalValue map[string]any
}

type streamToolCall struct {
	id        string
	name      string
	arguments string
}

func appendStreamConversation(events []base.SSEEvent, parserName string, result *base.Result) {
	if parserName == Responses || parserName == ResponsesCompact {
		appendResponsesStreamConversation(events, result)
		return
	}
	messages := make(map[int]*chatStreamMessage)
	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			continue
		}
		for position, value := range protocolutil.Slice(root["choices"]) {
			choice := protocolutil.Map(value)
			index := position
			if parsed := protocolutil.Int(choice["index"]); parsed != nil {
				index = *parsed
			}
			message := messages[index]
			if message == nil {
				message = &chatStreamMessage{role: conversation.RoleAssistant, tools: make(map[int]*streamToolCall)}
				messages[index] = message
			}
			if final := protocolutil.Map(choice["message"]); final != nil {
				message.finalValue = final
				continue
			}
			delta := protocolutil.Map(choice["delta"])
			if delta == nil {
				delta = choice
			}
			if role := protocolutil.String(delta["role"]); role != "" {
				message.role = normalizeRole(role)
			}
			if name := protocolutil.String(delta["name"]); name != "" {
				message.name = name
			}
			message.text += protocolutil.String(delta["content"])
			if parserName == Completions {
				message.text += protocolutil.String(choice["text"])
			}
			for _, field := range []string{"reasoning_content", "reasoning", "thinking"} {
				if text := protocolutil.String(delta[field]); text != "" {
					message.reasoning += text
					break
				}
			}
			mergeChatStreamTools(message, delta)
		}
	}
	indexes := sortedKeys(messages)
	for _, index := range indexes {
		message := messages[index]
		if message.finalValue != nil {
			appendChatMessage(message.finalValue, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, result)
			continue
		}
		parts := make([]conversation.Part, 0, 2+len(message.tools))
		if message.reasoning != "" {
			parts = append(parts, conversation.Reasoning(message.reasoning))
		}
		if message.text != "" {
			parts = append(parts, conversation.Text(message.text))
		}
		for _, toolIndex := range message.toolOrder {
			tool := message.tools[toolIndex]
			parts = append(parts, conversation.Part{Type: conversation.PartToolCall, ID: tool.id, Name: tool.name, Arguments: tool.arguments})
		}
		appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, message.role, message.name, "", parts)
	}
}

func mergeChatStreamTools(message *chatStreamMessage, delta map[string]any) {
	values := protocolutil.Slice(delta["tool_calls"])
	if legacy := protocolutil.Map(delta["function_call"]); legacy != nil {
		values = append(values, legacy)
	}
	for position, value := range values {
		tool := protocolutil.Map(value)
		index := position
		if parsed := protocolutil.Int(tool["index"]); parsed != nil {
			index = *parsed
		}
		aggregate := message.tools[index]
		if aggregate == nil {
			aggregate = &streamToolCall{}
			message.tools[index] = aggregate
			message.toolOrder = append(message.toolOrder, index)
		}
		if id := firstString(tool["call_id"], tool["id"]); id != "" {
			aggregate.id = id
		}
		function := protocolutil.Map(tool["function"])
		if function == nil {
			function = tool
		}
		aggregate.name += protocolutil.String(function["name"])
		aggregate.arguments += protocolutil.String(function["arguments"])
	}
}

type responsesStreamItem struct {
	index     int
	item      map[string]any
	text      string
	reasoning string
	arguments string
}

func appendResponsesStreamConversation(events []base.SSEEvent, result *base.Result) {
	items := make(map[int]*responsesStreamItem)
	var terminalResponse map[string]any
	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			continue
		}
		if response := protocolutil.Map(root["response"]); response != nil && len(protocolutil.Slice(response["output"])) != 0 {
			terminalResponse = response
		}
		index := 0
		if parsed := protocolutil.Int(root["output_index"]); parsed != nil {
			index = *parsed
		}
		aggregate := items[index]
		if aggregate == nil {
			aggregate = &responsesStreamItem{index: index}
			items[index] = aggregate
		}
		for _, field := range []string{"item", "output_item"} {
			if item := protocolutil.Map(root[field]); item != nil {
				aggregate.item = item
			}
		}
		eventType := protocolutil.String(root["type"])
		switch {
		case strings.Contains(eventType, "function_call_arguments.delta"):
			aggregate.arguments += protocolutil.String(root["delta"])
		case strings.Contains(eventType, "reasoning") && strings.HasSuffix(eventType, ".delta"):
			aggregate.reasoning += protocolutil.String(root["delta"])
		case strings.Contains(eventType, "output_text.delta") || strings.Contains(eventType, "refusal.delta"):
			aggregate.text += protocolutil.String(root["delta"])
		}
	}
	if terminalResponse != nil {
		appendResponseConversation(terminalResponse, Responses, result)
		return
	}
	indexes := sortedKeys(items)
	for _, index := range indexes {
		aggregate := items[index]
		if aggregate.item != nil {
			item := aggregate.item
			if aggregate.arguments != "" && protocolutil.String(item["arguments"]) == "" {
				item = cloneObject(item)
				item["arguments"] = aggregate.arguments
			}
			before := conversationLength(result)
			appendResponsesItem(item, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, result)
			if conversationLength(result) > before {
				continue
			}
		}
		parts := make([]conversation.Part, 0, 2)
		if aggregate.reasoning != "" {
			parts = append(parts, conversation.Reasoning(aggregate.reasoning))
		}
		if aggregate.text != "" {
			parts = append(parts, conversation.Text(aggregate.text))
		}
		appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, conversation.RoleAssistant, "", "", parts)
	}
}

func appendMessage(result *base.Result, phase, direction, role, name, toolCallID string, parts []conversation.Part) {
	if role == "" {
		role = conversation.RoleUnknown
	}
	conversation.Ensure(&result.Conversation).Append(conversation.Message{
		Role: role, Phase: phase, Direction: direction, Name: name, ToolCallID: toolCallID, Content: parts,
	})
}

func normalizeRole(role string) string {
	switch role {
	case "function":
		return conversation.RoleTool
	case conversation.RoleSystem, conversation.RoleDeveloper, conversation.RoleUser, conversation.RoleAssistant, conversation.RoleTool:
		return role
	default:
		return conversation.RoleUnknown
	}
}

func openAIReasoningParts(value any) []conversation.Part {
	if text, ok := value.(string); ok {
		if text == "" {
			return nil
		}
		return []conversation.Part{conversation.Reasoning(text)}
	}
	parts := openAIContentParts(value)
	for index := range parts {
		if parts[index].Type == conversation.PartText {
			parts[index] = conversation.Reasoning(parts[index].Text)
		}
	}
	return parts
}

func contentValueString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	parts := openAIContentParts(value)
	if len(parts) == 1 && (parts[0].Type == conversation.PartText || parts[0].Type == conversation.PartReasoning) {
		return parts[0].Text
	}
	return conversation.ValueString(value)
}

func firstString(values ...any) string {
	for _, value := range values {
		if text := protocolutil.String(value); text != "" {
			return text
		}
	}
	return ""
}

func firstValue(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstValueString(values ...any) string {
	return conversation.ValueString(firstValue(values...))
}

func sortedKeys[T any](values map[int]T) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func cloneObject(value map[string]any) map[string]any {
	cloned := make(map[string]any, len(value)+1)
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func conversationLength(result *base.Result) int {
	if result.Conversation == nil {
		return 0
	}
	return len(result.Conversation.Messages)
}
