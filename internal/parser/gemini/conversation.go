package gemini

import (
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
)

func appendRequestConversation(root map[string]any, result *base.Result) {
	if instruction := protocolutil.Map(root["systemInstruction"]); instruction != nil {
		appendContent(result, instruction, conversation.PhaseRequest, conversation.DirectionClientToUpstream, conversation.RoleSystem)
	}
	for _, value := range protocolutil.Slice(root["contents"]) {
		appendContent(result, protocolutil.Map(value), conversation.PhaseRequest, conversation.DirectionClientToUpstream, "")
	}
}

func appendResponseConversation(root map[string]any, result *base.Result) {
	for _, value := range protocolutil.Slice(root["candidates"]) {
		candidate := protocolutil.Map(value)
		appendContent(result, protocolutil.Map(candidate["content"]), conversation.PhaseResponse, conversation.DirectionUpstreamToClient, conversation.RoleAssistant)
	}
}

func appendContent(result *base.Result, content map[string]any, phase, direction, defaultRole string) {
	if content == nil {
		return
	}
	role := normalizeRole(protocolutil.String(content["role"]))
	if role == conversation.RoleUnknown && defaultRole != "" {
		role = defaultRole
	}
	parts := geminiParts(content)
	if role == conversation.RoleUser && onlyToolResults(parts) {
		role = conversation.RoleTool
	}
	conversation.Ensure(&result.Conversation).Append(conversation.Message{
		Role: role, Phase: phase, Direction: direction, Content: parts,
	})
}

func geminiParts(content map[string]any) []conversation.Part {
	if content == nil {
		return nil
	}
	parts := make([]conversation.Part, 0)
	for _, value := range protocolutil.Slice(content["parts"]) {
		part := protocolutil.Map(value)
		if text := protocolutil.String(part["text"]); text != "" {
			if thought, ok := protocolutil.Bool(part["thought"]); ok && thought != nil && *thought {
				parts = append(parts, conversation.Reasoning(text))
			} else {
				parts = append(parts, conversation.Text(text))
			}
			continue
		}
		if call := protocolutil.Map(part["functionCall"]); call != nil {
			parts = append(parts, conversation.Part{
				Type: conversation.PartToolCall, ID: protocolutil.String(call["id"]),
				Name: protocolutil.String(call["name"]), Arguments: conversation.ValueString(call["args"]),
			})
			continue
		}
		if response := protocolutil.Map(part["functionResponse"]); response != nil {
			parts = append(parts, conversation.Part{
				Type: conversation.PartToolResult, ToolCallID: protocolutil.String(response["id"]),
				Name: protocolutil.String(response["name"]), Result: conversation.ValueString(response["response"]),
			})
			continue
		}
		parts = append(parts, conversation.Unknown(part))
	}
	return parts
}

func normalizeRole(role string) string {
	switch role {
	case "model", conversation.RoleAssistant:
		return conversation.RoleAssistant
	case conversation.RoleSystem, conversation.RoleDeveloper, conversation.RoleUser, conversation.RoleTool:
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
