package anthropic

import (
	"sort"

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

type streamBlock struct {
	blockType   string
	id          string
	name        string
	text        string
	reasoning   string
	input       any
	partialJSON string
	unknown     map[string]any
}

func appendStreamConversation(events []base.SSEEvent, result *base.Result) {
	role := conversation.RoleAssistant
	blocks := make(map[int]*streamBlock)
	var initialContent any
	for _, event := range events {
		root, err := protocolutil.Object(event.Data)
		if err != nil {
			continue
		}
		eventType := protocolutil.String(root["type"])
		if eventType == "" {
			eventType = event.Event
		}
		switch eventType {
		case "message_start":
			message := protocolutil.Map(root["message"])
			if parsed := normalizeRole(protocolutil.String(message["role"])); parsed != conversation.RoleUnknown {
				role = parsed
			}
			initialContent = message["content"]
		case "content_block_start":
			index := streamIndex(root)
			block := protocolutil.Map(root["content_block"])
			blocks[index] = &streamBlock{
				blockType: protocolutil.String(block["type"]), id: protocolutil.String(block["id"]),
				name: protocolutil.String(block["name"]), text: protocolutil.String(block["text"]),
				reasoning: protocolutil.String(block["thinking"]), input: block["input"], unknown: block,
			}
		case "content_block_delta":
			index := streamIndex(root)
			block := blocks[index]
			if block == nil {
				block = &streamBlock{}
				blocks[index] = block
			}
			delta := protocolutil.Map(root["delta"])
			switch protocolutil.String(delta["type"]) {
			case "text_delta":
				block.blockType = "text"
				block.text += protocolutil.String(delta["text"])
			case "thinking_delta":
				block.blockType = "thinking"
				block.reasoning += protocolutil.String(delta["thinking"])
			case "input_json_delta":
				block.blockType = "tool_use"
				block.partialJSON += protocolutil.String(delta["partial_json"])
			}
		}
	}
	if len(blocks) == 0 {
		appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, role, "", "", anthropicContentParts(initialContent))
		return
	}
	indexes := make([]int, 0, len(blocks))
	for index := range blocks {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	parts := make([]conversation.Part, 0, len(indexes))
	for _, index := range indexes {
		block := blocks[index]
		switch block.blockType {
		case "text":
			if block.text != "" {
				parts = append(parts, conversation.Text(block.text))
			}
		case "thinking":
			if block.reasoning != "" {
				parts = append(parts, conversation.Reasoning(block.reasoning))
			}
		case "tool_use":
			arguments := block.partialJSON
			if arguments == "" {
				arguments = conversation.ValueString(block.input)
			}
			parts = append(parts, conversation.Part{Type: conversation.PartToolCall, ID: block.id, Name: block.name, Arguments: arguments})
		default:
			parts = append(parts, conversation.Unknown(block.unknown))
		}
	}
	appendMessage(result, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, role, "", "", parts)
}

func streamIndex(root map[string]any) int {
	if parsed := protocolutil.Int(root["index"]); parsed != nil {
		return *parsed
	}
	return 0
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
