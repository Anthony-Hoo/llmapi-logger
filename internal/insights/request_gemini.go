package insights

import (
	"sort"
	"strings"
)

func (b *builder) gemini(root map[string]any) any {
	switch system := pick(root, "systemInstruction", "system_instruction").(type) {
	case string:
		b.beginMessage()
		b.addText("system", system)
	case map[string]any:
		b.beginMessage()
		for _, value := range asSlice(system["parts"]) {
			b.addText("system", asString(asMap(value)["text"]))
		}
	}
	var toolsValue any
	if tools := asSlice(root["tools"]); len(tools) != 0 {
		for _, value := range tools {
			b.geminiTool(asMap(value), value)
		}
		toolsValue = root["tools"]
	}
	for _, value := range asSlice(root["contents"]) {
		content := asMap(value)
		if content == nil {
			continue
		}
		role := strings.ToLower(asString(content["role"]))
		switch role {
		case "model":
			role = "assistant"
		case "function", "tool":
			role = "tool"
		default:
			role = "user"
		}
		b.beginMessage()
		for _, partValue := range asSlice(content["parts"]) {
			b.geminiPart(role, asMap(partValue))
		}
	}
	return toolsValue
}

func (b *builder) geminiTool(tool map[string]any, raw any) {
	declarations := asSlice(pick(tool, "functionDeclarations", "function_declarations"))
	if len(declarations) == 0 {
		// Built-in tools (googleSearch, codeExecution, ...) are one definition each.
		keys := make([]string, 0, len(tool))
		for key := range tool {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) != 0 {
			b.addToolDef(keys[0], raw, "")
		}
		return
	}
	for _, value := range declarations {
		declaration := asMap(value)
		b.addToolDef(asString(declaration["name"]), value, asString(declaration["description"]))
	}
}

func (b *builder) geminiPart(role string, part map[string]any) {
	if part == nil {
		return
	}
	if text, ok := part["text"].(string); ok {
		if thought, _ := part["thought"].(bool); thought {
			b.addReasoning(text, 0)
			return
		}
		b.addText(role, text)
		return
	}
	if inline := pickMap(part, "inlineData", "inline_data"); inline != nil {
		mime := pickString(inline, "mimeType", "mime_type")
		data := asString(inline["data"])
		if strings.HasPrefix(strings.ToLower(mime), "image/") {
			b.addMedia(role, "image", mime, geminiImageTokens, data)
		} else {
			b.addMedia(role, "file", firstNonEmpty(mime, "file"), fileTokens(base64DecodedLen(data), true), data)
		}
		return
	}
	if file := pickMap(part, "fileData", "file_data"); file != nil {
		mime := pickString(file, "mimeType", "mime_type")
		identity := pickString(file, "fileUri", "file_uri")
		if strings.HasPrefix(strings.ToLower(mime), "image/") {
			b.addMedia(role, "image", mime, geminiImageTokens, identity)
		} else {
			b.addMedia(role, "file", firstNonEmpty(mime, "file"), fileTokens(0, false), identity)
		}
		return
	}
	if call := pickMap(part, "functionCall", "function_call"); call != nil {
		b.addToolCall(asString(call["name"]), asString(call["id"]), jsonString(call["args"]))
		return
	}
	if response := pickMap(part, "functionResponse", "function_response"); response != nil {
		b.addToolResult(asString(response["id"]), asString(response["name"]), jsonString(response["response"]), 0)
		return
	}
	b.addText(role, jsonString(part))
}
