package insights

import (
	"strings"
)

// openAIEndpoint picks chat | responses | completions from the parser endpoint
// name, falling back to the body shape.
func openAIEndpoint(endpoint string, root map[string]any) string {
	lower := strings.ToLower(endpoint)
	switch {
	case strings.Contains(lower, "response"):
		return "responses"
	case strings.Contains(lower, "chat"):
		return "chat"
	case strings.Contains(lower, "completion"):
		return "completions"
	}
	switch {
	case root["messages"] != nil:
		return "chat"
	case root["input"] != nil:
		return "responses"
	case root["prompt"] != nil:
		return "completions"
	}
	return "chat"
}

// openAI adds the request's items and returns the raw tools value for ToolsFPR.
func (b *builder) openAI(root map[string]any, endpoint string) any {
	switch openAIEndpoint(endpoint, root) {
	case "responses":
		return b.openAIResponses(root)
	case "completions":
		b.openAICompletions(root)
		return nil
	default:
		return b.openAIChat(root)
	}
}

func isInstructionRole(role string) bool {
	return role == "system" || role == "developer"
}

func (b *builder) openAIChat(root map[string]any) any {
	messages := asSlice(root["messages"])
	lead := 0
	for lead < len(messages) && isInstructionRole(strings.ToLower(asString(asMap(messages[lead])["role"]))) {
		lead++
	}
	for _, message := range messages[:lead] {
		b.openAIMessage(asMap(message))
	}
	toolsValue := b.openAIChatTools(root)
	for _, message := range messages[lead:] {
		b.openAIMessage(asMap(message))
	}
	return toolsValue
}

func (b *builder) openAIChatTools(root map[string]any) any {
	if tools := asSlice(root["tools"]); len(tools) != 0 {
		for _, value := range tools {
			tool := asMap(value)
			function := asMap(tool["function"])
			name := asString(function["name"])
			description := asString(function["description"])
			if function == nil {
				name = firstNonEmpty(asString(tool["name"]), asString(tool["type"]))
				description = asString(tool["description"])
			}
			b.addToolDef(name, value, description)
		}
		return root["tools"]
	}
	if functions := asSlice(root["functions"]); len(functions) != 0 {
		for _, value := range functions {
			function := asMap(value)
			b.addToolDef(asString(function["name"]), value, asString(function["description"]))
		}
		return root["functions"]
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (b *builder) openAIMessage(message map[string]any) {
	if message == nil {
		return
	}
	role := strings.ToLower(asString(message["role"]))
	b.beginMessage()
	if role == "tool" || role == "function" {
		text, extra := b.openAIContentText(message["content"])
		b.addToolResult(asString(message["tool_call_id"]), asString(message["name"]), text, extra)
		return
	}
	b.addReasoning(pickString(message, "reasoning_content", "reasoning"), 0)
	b.openAIContent(role, message["content"])
	for _, value := range asSlice(message["tool_calls"]) {
		call := asMap(value)
		function := asMap(call["function"])
		b.addToolCall(asString(function["name"]), asString(call["id"]), jsonString(function["arguments"]))
	}
	if function := asMap(message["function_call"]); function != nil {
		b.addToolCall(asString(function["name"]), "", jsonString(function["arguments"]))
	}
}

func (b *builder) openAIContent(role string, content any) {
	switch typed := content.(type) {
	case string:
		b.addText(role, typed)
	case []any:
		for _, part := range typed {
			if text, ok := part.(string); ok {
				b.addText(role, text)
				continue
			}
			b.openAIPart(role, asMap(part))
		}
	case map[string]any:
		b.openAIPart(role, typed)
	}
}

func (b *builder) openAIPart(role string, part map[string]any) {
	if part == nil {
		return
	}
	switch partType := strings.ToLower(asString(part["type"])); partType {
	case "text", "input_text", "output_text":
		b.addText(role, asString(part["text"]))
	case "refusal":
		b.addText(role, firstNonEmpty(asString(part["refusal"]), asString(part["text"])))
	case "image_url", "input_image":
		url, detail := imageURLAndDetail(part)
		b.openAIImage(role, url, detail)
	case "input_audio", "audio":
		audio := asMap(part["input_audio"])
		if audio == nil {
			audio = part
		}
		data := asString(audio["data"])
		b.addMedia(role, "file", firstNonEmpty(asString(audio["format"]), "audio"),
			fileTokens(base64DecodedLen(data), data != ""), data)
	case "file", "input_file":
		file := asMap(part["file"])
		if file == nil {
			file = part
		}
		data := firstNonEmpty(asString(file["file_data"]), asString(file["data"]))
		label := "file"
		if mime, payload, ok := splitDataURL(data); ok {
			label, data = firstNonEmpty(mime, label), payload
		}
		known := data != ""
		identity := firstNonEmpty(data, asString(file["file_id"]), asString(file["file_url"]), asString(file["filename"]))
		b.addMedia(role, "file", label, fileTokens(base64DecodedLen(data), known), identity)
	default:
		if text := asString(part["text"]); text != "" {
			b.addText(role, text)
			return
		}
		b.addText(role, jsonString(part))
	}
}

func imageURLAndDetail(part map[string]any) (url, detail string) {
	detail = asString(part["detail"])
	switch typed := part["image_url"].(type) {
	case string:
		url = typed
	case map[string]any:
		url = asString(typed["url"])
		if value := asString(typed["detail"]); value != "" {
			detail = value
		}
	}
	if url == "" {
		url = firstNonEmpty(asString(part["file_id"]), asString(part["url"]))
	}
	return url, detail
}

func (b *builder) openAIImage(role, url, detail string) {
	label := "image"
	width, height, known := 0, 0, false
	if mime, payload, ok := splitDataURL(url); ok {
		label = firstNonEmpty(mime, label)
		width, height, known = imageDimensions(payload)
	}
	b.addMedia(role, "image", label, openAIImageTokens(width, height, known, detail), url)
}

// openAIContentText flattens tool output content to text plus extra tokens for
// embedded images.
func (b *builder) openAIContentText(content any) (string, int64) {
	switch typed := content.(type) {
	case string:
		return typed, 0
	case []any:
		var texts []string
		var extra int64
		for _, value := range typed {
			if text, ok := value.(string); ok {
				texts = append(texts, text)
				continue
			}
			part := asMap(value)
			switch strings.ToLower(asString(part["type"])) {
			case "image_url", "input_image":
				url, detail := imageURLAndDetail(part)
				width, height, known := 0, 0, false
				if _, payload, ok := splitDataURL(url); ok {
					width, height, known = imageDimensions(payload)
				}
				extra += openAIImageTokens(width, height, known, detail)
			default:
				if text := firstNonEmpty(asString(part["text"]), asString(part["output"])); text != "" {
					texts = append(texts, text)
				} else if part != nil {
					texts = append(texts, jsonString(part))
				}
			}
		}
		return strings.Join(texts, "\n"), extra
	case nil:
		return "", 0
	}
	return jsonString(content), 0
}

func (b *builder) openAIResponses(root map[string]any) any {
	if instructions := asString(root["instructions"]); instructions != "" {
		b.beginMessage()
		b.addText("system", instructions)
	}
	var input []any
	switch typed := root["input"].(type) {
	case string:
		input = []any{map[string]any{"role": "user", "content": typed}}
	case []any:
		input = typed
	}
	lead := 0
	for lead < len(input) {
		item := asMap(input[lead])
		itemType := asString(item["type"])
		if (itemType == "" || itemType == "message") && isInstructionRole(strings.ToLower(asString(item["role"]))) {
			lead++
			continue
		}
		break
	}
	for _, item := range input[:lead] {
		b.openAIResponseItem(asMap(item))
	}
	toolsValue := b.openAIResponseTools(root)
	for _, item := range input[lead:] {
		b.openAIResponseItem(asMap(item))
	}
	return toolsValue
}

func (b *builder) openAIResponseTools(root map[string]any) any {
	tools := asSlice(root["tools"])
	if len(tools) == 0 {
		return nil
	}
	for _, value := range tools {
		tool := asMap(value)
		name := firstNonEmpty(asString(tool["name"]), asString(asMap(tool["function"])["name"]), asString(tool["type"]))
		b.addToolDef(name, value, asString(tool["description"]))
	}
	return root["tools"]
}

func (b *builder) openAIResponseItem(item map[string]any) {
	if item == nil {
		return
	}
	itemType := strings.ToLower(asString(item["type"]))
	if itemType == "" && item["role"] != nil {
		itemType = "message"
	}
	switch {
	case itemType == "message":
		b.beginMessage()
		b.openAIContent(strings.ToLower(asString(item["role"])), item["content"])
	case itemType == "reasoning":
		b.beginMessage()
		var texts []string
		for _, key := range []string{"summary", "content"} {
			for _, value := range asSlice(item[key]) {
				if text := asString(asMap(value)["text"]); text != "" {
					texts = append(texts, text)
				}
			}
		}
		b.addReasoning(strings.Join(texts, "\n"), len(asString(item["encrypted_content"])))
	case itemType == "item_reference":
	case strings.HasSuffix(itemType, "_call_output") || strings.HasSuffix(itemType, "_output"):
		b.beginMessage()
		text, extra := b.openAIContentText(item["output"])
		b.addToolResult(firstNonEmpty(asString(item["call_id"]), asString(item["id"])), asString(item["name"]), text, extra)
	case strings.HasSuffix(itemType, "_call"):
		b.beginMessage()
		args := item["arguments"]
		if args == nil {
			args = firstNonNil(item["input"], item["action"], item["arguments"])
		}
		b.addToolCall(firstNonEmpty(asString(item["name"]), itemType), firstNonEmpty(asString(item["call_id"]), asString(item["id"])), jsonString(args))
	default:
		b.beginMessage()
		role := strings.ToLower(asString(item["role"]))
		if role == "" {
			role = "assistant"
		}
		b.add(itemSpec{
			category: CategoryAssistant, role: role, kind: "text", label: itemType,
			tokens: textTokens(jsonString(item)), text: jsonString(item),
			canon: map[string]any{"t": jsonString(item)},
		})
	}
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func (b *builder) openAICompletions(root map[string]any) {
	switch prompt := root["prompt"].(type) {
	case string:
		b.beginMessage()
		b.addText("user", prompt)
	case []any:
		for _, value := range prompt {
			b.beginMessage()
			switch typed := value.(type) {
			case string:
				b.addText("user", typed)
			case []any: // pre-tokenized prompt
				b.add(itemSpec{
					category: CategoryUser, role: "user", kind: "text",
					tokens: int64(len(typed)), canon: map[string]any{"t": jsonString(typed)},
				})
			}
		}
	}
}
