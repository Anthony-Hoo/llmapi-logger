package contentpolicy

import (
	"encoding/json"
	"errors"
	"strings"
)

var (
	errUnsupportedParser  = errors.New("contentpolicy: unsupported parser")
	errUnparseableRequest = errors.New("contentpolicy: request body is not a JSON object")
)

// segment is one piece of extractable request text with its policy scope.
type segment struct {
	Scope string
	Text  string
}

// rawSegment carries the extraction-time role before the latest user message
// is known. User text segments are marked instead of assigned a scope.
type rawSegment struct {
	scope    string
	text     string
	userText bool
	message  int
}

// extractRequest converts one provider request body into ordered segments.
// Unsupported parsers and non-object JSON are reported as sentinel errors so
// the caller can fail open with a stable log code.
func extractRequest(parserName string, data []byte) ([]segment, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return nil, errUnparseableRequest
	}

	var raw []rawSegment
	switch parserName {
	case "openai.chat_completions":
		raw = extractOpenAIChat(root)
	case "openai.completions":
		raw = extractOpenAICompletions(root)
	case "openai.responses", "openai.responses_compact":
		raw = extractOpenAIResponses(root)
	case "anthropic.messages":
		raw = extractAnthropic(root)
	case "gemini.generate_content", "gemini.stream_generate_content":
		raw = extractGemini(root)
	default:
		return nil, errUnsupportedParser
	}
	return finalizeSegments(raw), nil
}

func finalizeSegments(raw []rawSegment) []segment {
	lastUserMessage := -1
	for _, item := range raw {
		if item.userText && item.message > lastUserMessage {
			lastUserMessage = item.message
		}
	}

	segments := make([]segment, 0, len(raw))
	for _, item := range raw {
		if item.text == "" {
			continue
		}
		scope := item.scope
		if item.userText {
			if item.message == lastUserMessage {
				scope = ScopeLatestUser
			} else {
				scope = ScopeUserHistory
			}
		}
		segments = append(segments, segment{Scope: scope, Text: item.text})
	}
	return segments
}

func addSegment(raw *[]rawSegment, scope, text string) {
	if text == "" {
		return
	}
	*raw = append(*raw, rawSegment{scope: scope, text: text})
}

func addUserText(raw *[]rawSegment, text string, message int) {
	if text == "" {
		return
	}
	*raw = append(*raw, rawSegment{text: text, userText: true, message: message})
}

// markUserMessage preserves chronology even when a user message has no
// extractable text (for example, an image-only message).
func markUserMessage(raw *[]rawSegment, message int) {
	*raw = append(*raw, rawSegment{userText: true, message: message})
}

// appendContent splits a provider content value into text segments. Media and
// unknown structural blocks are deliberately ignored; only explicit text
// fields are scanned.
func appendContent(raw *[]rawSegment, value any, scope string, message int, user bool) {
	switch typed := value.(type) {
	case string:
		if user {
			addUserText(raw, typed, message)
		} else {
			addSegment(raw, scope, typed)
		}
	case []any:
		for _, item := range typed {
			switch part := item.(type) {
			case string:
				if user {
					addUserText(raw, part, message)
				} else {
					addSegment(raw, scope, part)
				}
			case map[string]any:
				appendContent(raw, contentText(part), scope, message, user)
			}
		}
	case map[string]any:
		text := contentText(typed)
		if text == "" {
			return
		}
		if user {
			addUserText(raw, text, message)
		} else {
			addSegment(raw, scope, text)
		}
	}
}

// contentText returns the explicit text carried by one content block. Image,
// audio, file and other media blocks have no text field and are skipped.
func contentText(block map[string]any) string {
	if block == nil {
		return ""
	}
	for _, key := range []string{"text", "refusal", "content", "thinking"} {
		if text, ok := block[key].(string); ok && text != "" {
			return text
		}
	}
	for _, key := range []string{"summary", "content"} {
		value := block[key]
		if text := flattenText(value); text != "" {
			return text
		}
	}
	return ""
}

// flattenText joins text values from a string, content block array or nested
// content object. Structured media are skipped rather than serialized.
func flattenText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := flattenText(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		for _, key := range []string{"text", "refusal", "content", "output", "result"} {
			if text := flattenText(typed[key]); text != "" {
				return text
			}
		}
		return ""
	default:
		return ""
	}
}

func valueText(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

func firstText(values ...any) string {
	for _, value := range values {
		if text, ok := value.(string); ok && text != "" {
			return text
		}
	}
	return ""
}

func firstValueText(values ...any) string {
	for _, value := range values {
		if value == nil {
			continue
		}
		if text := valueText(value); text != "" {
			return text
		}
	}
	return ""
}

func asMap(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func asSlice(value any) []any {
	result, _ := value.([]any)
	return result
}

func asString(value any) string {
	text, _ := value.(string)
	return text
}

func addToolCall(raw *[]rawSegment, name, arguments string) {
	text := strings.TrimSpace(name)
	args := strings.TrimSpace(arguments)
	switch {
	case text != "" && args != "":
		text += "\n" + args
	case args != "":
		text = args
	case text == "":
		return
	}
	addSegment(raw, ScopeToolCalls, text)
}

func addToolResult(raw *[]rawSegment, name, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	if name = strings.TrimSpace(name); name != "" {
		text = name + "\n" + text
	}
	addSegment(raw, ScopeToolResults, text)
}

func addToolDefinition(raw *[]rawSegment, name, description string, schema any) {
	parts := make([]string, 0, 3)
	if name = strings.TrimSpace(name); name != "" {
		parts = append(parts, name)
	}
	if description = strings.TrimSpace(description); description != "" {
		parts = append(parts, description)
	}
	if schemaText := valueText(schema); schemaText != "" && schemaText != "null" {
		parts = append(parts, schemaText)
	}
	addSegment(raw, ScopeToolDefinitions, strings.Join(parts, "\n"))
}

// --- OpenAI Chat / Completions ---

func extractOpenAIChat(root map[string]any) []rawSegment {
	var raw []rawSegment
	for index, value := range asSlice(root["messages"]) {
		message := asMap(value)
		if message == nil {
			continue
		}
		role := strings.ToLower(asString(message["role"]))
		switch role {
		case "system", "developer":
			appendContent(&raw, message["content"], ScopeSystem, index, false)
		case "user":
			markUserMessage(&raw, index)
			appendContent(&raw, message["content"], "", index, true)
		case "assistant", "model":
			appendContent(&raw, message["content"], ScopeAssistant, index, false)
			addSegment(&raw, ScopeAssistant, asString(message["refusal"]))
			if reasoning := firstText(message["reasoning_content"], message["reasoning"], message["thinking"]); reasoning != "" {
				addSegment(&raw, ScopeAssistant, reasoning)
			}
			for _, callValue := range asSlice(message["tool_calls"]) {
				call := asMap(callValue)
				if custom := asMap(call["custom"]); custom != nil {
					addToolCall(&raw, asString(custom["name"]), asString(custom["input"]))
					continue
				}
				function := asMap(call["function"])
				if function == nil {
					function = call
				}
				addToolCall(&raw, firstText(function["name"], call["name"]), firstValueText(function["arguments"], call["arguments"]))
			}
			if function := asMap(message["function_call"]); function != nil {
				addToolCall(&raw, asString(function["name"]), firstValueText(function["arguments"]))
			}
		case "tool", "function":
			addToolResult(&raw, asString(message["name"]), flattenText(message["content"]))
		default:
			appendContent(&raw, message["content"], ScopeAssistant, index, false)
		}
	}
	addOpenAICompatibleToolDefinitions(&raw, root)
	return raw
}

func extractOpenAICompletions(root map[string]any) []rawSegment {
	var raw []rawSegment
	switch prompt := root["prompt"].(type) {
	case string:
		addUserText(&raw, prompt, 0)
	case []any:
		// Each string is an independent current prompt, not conversation history.
		for _, value := range prompt {
			switch typed := value.(type) {
			case string:
				addUserText(&raw, typed, 0)
			case []any:
				// Pre-tokenized prompts contain token ids rather than text.
				continue
			}
		}
	}
	return raw
}

// --- OpenAI Responses ---

func extractOpenAIResponses(root map[string]any) []rawSegment {
	var raw []rawSegment
	if instructions := asString(root["instructions"]); instructions != "" {
		addSegment(&raw, ScopeSystem, instructions)
	}
	switch input := root["input"].(type) {
	case string:
		addUserText(&raw, input, 0)
	case map[string]any:
		appendResponseItem(&raw, input, 0)
	case []any:
		for index, value := range input {
			if text, ok := value.(string); ok {
				addUserText(&raw, text, index)
				continue
			}
			appendResponseItem(&raw, value, index)
		}
	}
	addResponsesToolDefinitions(&raw, root)
	return raw
}

func appendResponseItem(raw *[]rawSegment, value any, index int) {
	if text, ok := value.(string); ok {
		addUserText(raw, text, index)
		return
	}
	item := asMap(value)
	if item == nil {
		return
	}
	itemType := strings.ToLower(asString(item["type"]))
	if itemType == "" && item["role"] != nil {
		itemType = "message"
	}
	switch {
	case itemType == "message" || itemType == "":
		role := strings.ToLower(asString(item["role"]))
		switch role {
		case "system", "developer":
			appendContent(raw, item["content"], ScopeSystem, index, false)
		case "assistant":
			appendContent(raw, item["content"], ScopeAssistant, index, false)
		case "user":
			markUserMessage(raw, index)
			appendContent(raw, item["content"], "", index, true)
		default:
			appendContent(raw, item["content"], ScopeAssistant, index, false)
		}
	case itemType == "reasoning":
		addSegment(raw, ScopeAssistant, reasoningText(item))
	case strings.HasSuffix(itemType, "_call_output") || strings.HasSuffix(itemType, "_output"):
		addToolResult(raw, asString(item["name"]), responseToolOutputText(firstValue(item["output"], item["result"], item["content"])))
	case strings.HasSuffix(itemType, "_call"):
		addToolCall(raw, asString(item["name"]), firstValueText(item["arguments"], item["input"], item["action"]))
	case itemType == "item_reference":
		return
	default:
		if role := strings.ToLower(asString(item["role"])); role != "" {
			switch role {
			case "user":
				markUserMessage(raw, index)
				appendContent(raw, item["content"], "", index, true)
			case "system", "developer":
				appendContent(raw, item["content"], ScopeSystem, index, false)
			default:
				appendContent(raw, item["content"], ScopeAssistant, index, false)
			}
			return
		}
		if text := asString(item["text"]); text != "" {
			addSegment(raw, ScopeAssistant, text)
		}
	}
}

// responseToolOutputText reads explicit output text, including shell outputs,
// without serializing image/file payloads, correlation IDs or other metadata.
func responseToolOutputText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		var parts []string
		for _, item := range typed {
			if text := responseToolOutputText(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		var parts []string
		for _, key := range []string{"text", "refusal", "content", "output", "result", "stdout", "stderr"} {
			if text := responseToolOutputText(typed[key]); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func reasoningText(item map[string]any) string {
	var parts []string
	for _, key := range []string{"summary", "content"} {
		for _, value := range asSlice(item[key]) {
			if text := contentText(asMap(value)); text != "" {
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// --- Anthropic ---

func extractAnthropic(root map[string]any) []rawSegment {
	var raw []rawSegment
	switch system := root["system"].(type) {
	case string:
		addSegment(&raw, ScopeSystem, system)
	case []any:
		for _, value := range system {
			if text, ok := value.(string); ok {
				addSegment(&raw, ScopeSystem, text)
				continue
			}
			if text := contentText(asMap(value)); text != "" {
				addSegment(&raw, ScopeSystem, text)
			}
		}
	}
	for index, value := range asSlice(root["messages"]) {
		message := asMap(value)
		if message == nil {
			continue
		}
		role := strings.ToLower(asString(message["role"]))
		if role == "user" {
			markUserMessage(&raw, index)
		}
		switch content := message["content"].(type) {
		case string:
			if role == "user" {
				addUserText(&raw, content, index)
			} else if content != "" {
				addSegment(&raw, ScopeAssistant, content)
			}
		case []any:
			for _, blockValue := range content {
				block := asMap(blockValue)
				if block == nil {
					if text, ok := blockValue.(string); ok && text != "" {
						if role == "user" {
							addUserText(&raw, text, index)
						} else {
							addSegment(&raw, ScopeAssistant, text)
						}
					}
					continue
				}
				blockType := strings.ToLower(asString(block["type"]))
				switch blockType {
				case "text":
					if text := asString(block["text"]); text != "" {
						if role == "user" {
							addUserText(&raw, text, index)
						} else {
							addSegment(&raw, ScopeAssistant, text)
						}
					}
				case "thinking":
					if text := asString(block["thinking"]); text != "" {
						addSegment(&raw, ScopeAssistant, text)
					}
				case "tool_use", "server_tool_use":
					addToolCall(&raw, asString(block["name"]), valueText(block["input"]))
				case "tool_result":
					addToolResult(&raw, asString(block["name"]), flattenText(block["content"]))
				default:
					if text := contentText(block); text != "" {
						if role == "user" {
							addUserText(&raw, text, index)
						} else {
							addSegment(&raw, ScopeAssistant, text)
						}
					}
				}
			}
		}
	}
	for _, value := range asSlice(root["tools"]) {
		tool := asMap(value)
		addToolDefinition(&raw, asString(tool["name"]), asString(tool["description"]), tool["input_schema"])
	}
	return raw
}

// --- Gemini ---

func extractGemini(root map[string]any) []rawSegment {
	var raw []rawSegment
	if instruction := asMap(root["systemInstruction"]); instruction != nil {
		for _, value := range asSlice(instruction["parts"]) {
			if text, ok := value.(string); ok {
				addSegment(&raw, ScopeSystem, text)
				continue
			}
			if text := contentText(asMap(value)); text != "" {
				addSegment(&raw, ScopeSystem, text)
			}
		}
	} else if instruction := asString(root["systemInstruction"]); instruction != "" {
		addSegment(&raw, ScopeSystem, instruction)
	}
	for index, value := range asSlice(root["contents"]) {
		content := asMap(value)
		if content == nil {
			continue
		}
		role := strings.ToLower(asString(content["role"]))
		// Gemini permits role omission for user content.
		if role == "" {
			role = "user"
		}
		if role == "user" {
			markUserMessage(&raw, index)
		}
		for _, partValue := range asSlice(content["parts"]) {
			part := asMap(partValue)
			if part == nil {
				continue
			}
			if thought, _ := part["thought"].(bool); thought {
				if text := asString(part["text"]); text != "" {
					addSegment(&raw, ScopeAssistant, text)
				}
				continue
			}
			if text := asString(part["text"]); text != "" {
				if role == "user" {
					addUserText(&raw, text, index)
				} else {
					addSegment(&raw, ScopeAssistant, text)
				}
				continue
			}
			if call := asMap(part["functionCall"]); call != nil {
				addToolCall(&raw, asString(call["name"]), valueText(call["args"]))
				continue
			}
			if response := asMap(part["functionResponse"]); response != nil {
				addToolResult(&raw, asString(response["name"]), valueText(response["response"]))
				continue
			}
			if code := asMap(part["executableCode"]); code != nil {
				if text := asString(code["code"]); text != "" {
					addSegment(&raw, ScopeAssistant, text)
				}
				continue
			}
			if result := asMap(part["codeExecutionResult"]); result != nil {
				addToolResult(&raw, "", firstText(result["output"]))
			}
		}
	}
	for _, value := range asSlice(root["tools"]) {
		tool := asMap(value)
		if tool == nil {
			continue
		}
		declarations := asSlice(tool["functionDeclarations"])
		if declarations == nil {
			declarations = asSlice(tool["function_declarations"])
		}
		for _, declaration := range declarations {
			entry := asMap(declaration)
			addToolDefinition(&raw, asString(entry["name"]), asString(entry["description"]), firstValue(entry["parameters"], entry["parametersJsonSchema"]))
		}
	}
	return raw
}

// --- shared tool definitions ---

func addOpenAICompatibleToolDefinitions(raw *[]rawSegment, root map[string]any) {
	for _, value := range asSlice(root["tools"]) {
		tool := asMap(value)
		if tool == nil {
			continue
		}
		if custom := asMap(tool["custom"]); custom != nil {
			addToolDefinition(raw, asString(custom["name"]), asString(custom["description"]), custom["format"])
			continue
		}
		function := asMap(tool["function"])
		if function == nil {
			function = tool
		}
		addToolDefinition(raw, firstText(function["name"], tool["name"]), firstText(function["description"], tool["description"]), firstValue(function["parameters"], tool["parameters"]))
	}
	for _, value := range asSlice(root["functions"]) {
		function := asMap(value)
		if function == nil {
			continue
		}
		addToolDefinition(raw, asString(function["name"]), asString(function["description"]), function["parameters"])
	}
}

func addResponsesToolDefinitions(raw *[]rawSegment, root map[string]any) {
	for _, value := range asSlice(root["tools"]) {
		tool := asMap(value)
		if tool == nil {
			continue
		}
		function := asMap(tool["function"])
		if function == nil {
			function = tool
		}
		addToolDefinition(raw, firstText(tool["name"], function["name"]), firstText(tool["description"], function["description"]), firstValue(tool["parameters"], tool["input_schema"], function["parameters"]))
	}
}

func firstValue(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
