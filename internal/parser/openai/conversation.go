package openai

import (
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
