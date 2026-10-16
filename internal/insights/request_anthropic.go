package insights

import "strings"

func (b *builder) anthropic(root map[string]any) any {
	switch system := root["system"].(type) {
	case string:
		b.beginMessage()
		b.addText("system", system)
	case []any:
		b.beginMessage()
		for _, value := range system {
			if text, ok := value.(string); ok {
				b.addText("system", text)
				continue
			}
			block := asMap(value)
			b.addText("system", asString(block["text"]))
		}
	}
	var toolsValue any
	if tools := asSlice(root["tools"]); len(tools) != 0 {
		for _, value := range tools {
			tool := asMap(value)
			b.addToolDef(firstNonEmpty(asString(tool["name"]), asString(tool["type"])), value, asString(tool["description"]))
		}
		toolsValue = root["tools"]
	}
	for _, value := range asSlice(root["messages"]) {
		message := asMap(value)
		if message == nil {
			continue
		}
		role := strings.ToLower(asString(message["role"]))
		b.beginMessage()
		switch content := message["content"].(type) {
		case string:
			b.addText(role, content)
		case []any:
			for _, blockValue := range content {
				if text, ok := blockValue.(string); ok {
					b.addText(role, text)
					continue
				}
				b.anthropicBlock(role, asMap(blockValue))
			}
		}
	}
	return toolsValue
}

func (b *builder) anthropicBlock(role string, block map[string]any) {
	if block == nil {
		return
	}
	blockType := strings.ToLower(asString(block["type"]))
	switch {
	case blockType == "text":
		b.addText(role, asString(block["text"]))
	case blockType == "image":
		b.anthropicImage(role, asMap(block["source"]))
	case blockType == "document":
		b.anthropicDocument(role, block)
	case blockType == "tool_use" || strings.HasSuffix(blockType, "_tool_use"):
		b.addToolCall(asString(block["name"]), asString(block["id"]), jsonString(block["input"]))
	case blockType == "tool_result":
		text, extra := b.anthropicResultText(block["content"])
		b.addToolResult(asString(block["tool_use_id"]), asString(block["name"]), text, extra)
	case strings.HasSuffix(blockType, "_tool_result"):
		b.addToolResult(asString(block["tool_use_id"]), asString(block["name"]), jsonString(block["content"]), 0)
	case blockType == "thinking":
		b.addReasoning(asString(block["thinking"]), len(asString(block["signature"])))
	case blockType == "redacted_thinking":
		b.addReasoning("", len(asString(block["data"])))
	default:
		b.addText(role, jsonString(block))
	}
}

func (b *builder) anthropicImage(role string, source map[string]any) {
	label := firstNonEmpty(asString(source["media_type"]), "image")
	width, height, known := 0, 0, false
	identity := asString(source["url"])
	if asString(source["type"]) == "base64" {
		data := asString(source["data"])
		width, height, known = imageDimensions(data)
		identity = data
	}
	b.addMedia(role, "image", label, anthropicImageTokens(width, height, known), identity)
}

func (b *builder) anthropicDocument(role string, block map[string]any) {
	source := asMap(block["source"])
	label := firstNonEmpty(asString(source["media_type"]), "document")
	switch asString(source["type"]) {
	case "base64":
		data := asString(source["data"])
		b.addMedia(role, "file", label, fileTokens(base64DecodedLen(data), true), data)
	case "text":
		data := asString(source["data"])
		b.addMedia(role, "file", label, bytesTokens(len(data)), data)
	default:
		identity := firstNonEmpty(asString(source["url"]), asString(source["file_id"]), jsonString(source))
		b.addMedia(role, "file", label, fileTokens(0, false), identity)
	}
}

// anthropicResultText flattens tool_result content and prices embedded images.
func (b *builder) anthropicResultText(content any) (string, int64) {
	switch typed := content.(type) {
	case string:
		return typed, 0
	case []any:
		var texts []string
		var extra int64
		for _, value := range typed {
			block := asMap(value)
			switch strings.ToLower(asString(block["type"])) {
			case "text":
				texts = append(texts, asString(block["text"]))
			case "image":
				source := asMap(block["source"])
				width, height, known := 0, 0, false
				if asString(source["type"]) == "base64" {
					width, height, known = imageDimensions(asString(source["data"]))
				}
				extra += anthropicImageTokens(width, height, known)
			default:
				if block != nil {
					texts = append(texts, jsonString(block))
				}
			}
		}
		return strings.Join(texts, "\n"), extra
	case nil:
		return "", 0
	}
	return jsonString(content), 0
}
