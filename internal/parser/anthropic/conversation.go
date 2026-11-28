package anthropic

import (
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

func appendRequestConversation(root map[string]any, result *base.Result) {
	if parts := anthropicContentParts(root["system"]); len(parts) != 0 {
		appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleSystem, "", "", parts)
	}
	for _, value := range protocolutil.Slice(root["messages"]) {
		message := protocolutil.Map(value)
		parts := anthropicContentParts(message["content"])
		role := normalizeRole(protocolutil.String(message["role"]))
		if role == conversation.RoleUser && onlyToolResults(parts) {
			role = conversation.RoleTool
		}
		appendMessage(result, conversation.PhaseRequest, conversation.DirectionClientToUpstream,
			role, protocolutil.String(message["name"]), "", parts)
	}
}

// appendResponseConversation reads a Message body, non-stream or folded from
// a stream.
func appendResponseConversation(root map[string]any, result *base.Result) {
	role := normalizeRole(protocolutil.String(root["role"]))
	if role == conversation.RoleUnknown {
		role = conversation.RoleAssistant
	}
	appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, role, "", "", anthropicContentParts(root["content"]))
}

func anthropicContentParts(value any) []conversation.Part {
	if text, ok := value.(string); ok {
		if text == "" {
			return nil
		}
		return []conversation.Part{conversation.Text(text)}
	}
	if block := protocolutil.Map(value); block != nil {
		return anthropicBlockParts(block)
	}
	parts := make([]conversation.Part, 0)
	for _, value := range protocolutil.Slice(value) {
		if text, ok := value.(string); ok {
			if text != "" {
				parts = append(parts, conversation.Text(text))
			}
			continue
		}
		parts = append(parts, anthropicBlockParts(protocolutil.Map(value))...)
	}
	return parts
}

func anthropicBlockParts(block map[string]any) []conversation.Part {
	if block == nil {
		return nil
	}
	switch protocolutil.String(block["type"]) {
	case "text":
		if text := protocolutil.String(block["text"]); text != "" {
			return []conversation.Part{conversation.Text(text)}
		}
	case "thinking":
		if text := protocolutil.String(block["thinking"]); text != "" {
			return []conversation.Part{conversation.Reasoning(text)}
		}
	case "tool_use":
		return []conversation.Part{{
			Type: conversation.PartToolCall, ID: protocolutil.String(block["id"]),
			Name: protocolutil.String(block["name"]), Arguments: conversation.ValueString(block["input"]),
		}}
	case "tool_result":
		return []conversation.Part{{
			Type: conversation.PartToolResult, ToolCallID: protocolutil.String(block["tool_use_id"]),
			Name: protocolutil.String(block["name"]), Result: anthropicResultString(block["content"]),
		}}
	}
	return []conversation.Part{conversation.Unknown(block)}
}

func anthropicResultString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	parts := anthropicContentParts(value)
	if len(parts) == 1 && parts[0].Type == conversation.PartText {
		return parts[0].Text
	}
	return conversation.ValueString(value)
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
	case conversation.RoleSystem, conversation.RoleDeveloper, conversation.RoleUser, conversation.RoleAssistant, conversation.RoleTool:
		return role
	default:
		return conversation.RoleUnknown
	}
}

func onlyToolResults(parts []conversation.Part) bool {
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part.Type != conversation.PartToolResult {
			return false
		}
	}
	return true
}
