package insights

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ctxItem is an Item plus the private data needed for fingerprints, injection
// checks and hints. The text never leaves the package except through Item
// summaries and the exported hint helpers.
type ctxItem struct {
	Item
	msg   int // message ordinal, groups parts of one message
	text  string
	canon []byte
}

type parsedRequest struct {
	root       map[string]any
	items      []ctxItem
	tools      []ToolDef
	toolsCanon []byte // nil when the request has no tool definitions
}

// builder accumulates context items in prompt order.
type builder struct {
	vocab           *Vocabulary
	items           []ctxItem
	tools           []ToolDef
	msg             int
	pendingOverhead int64
	callNames       map[string]string
}

type itemSpec struct {
	category string
	role     string
	kind     string
	label    string
	tokens   int64
	text     string
	summary  string
	canon    map[string]any
}

func parseRequest(input Input, vocab *Vocabulary) (*parsedRequest, error) {
	if len(bytes.TrimSpace(input.Request)) == 0 {
		return nil, errors.New("insights: empty request body")
	}
	value, err := decodeJSON(input.Request)
	if err != nil {
		return nil, errors.New("insights: request is not valid JSON")
	}
	root := asMap(value)
	if root == nil {
		return nil, errors.New("insights: request is not a JSON object")
	}
	builder := &builder{vocab: vocab, callNames: map[string]string{}}
	var toolsValue any
	switch strings.ToLower(input.Protocol) {
	case "openai":
		toolsValue = builder.openAI(root, input.Endpoint)
	case "anthropic":
		toolsValue = builder.anthropic(root)
	case "gemini":
		toolsValue = builder.gemini(root)
	default:
		return nil, errors.New("insights: unsupported protocol")
	}
	request := &parsedRequest{root: root, items: builder.items, tools: builder.tools}
	if len(builder.tools) != 0 && toolsValue != nil {
		request.toolsCanon = canonicalJSON(toolsValue)
	}
	for index := range request.items {
		request.items[index].Index = index
	}
	return request, nil
}

func (b *builder) beginMessage() {
	b.msg++
	b.pendingOverhead = messageOverheadTokens
}

func (b *builder) add(spec itemSpec) {
	tokens := spec.tokens + b.pendingOverhead
	b.pendingOverhead = 0
	canon := spec.canon
	if canon == nil {
		canon = map[string]any{}
	}
	canon["c"], canon["k"], canon["r"] = spec.category, spec.kind, spec.role
	summary := spec.summary
	if summary == "" {
		summary = summarize(spec.text)
	}
	b.items = append(b.items, ctxItem{
		Item: Item{
			Category: spec.category, Role: spec.role, Kind: spec.kind,
			Tokens: tokens, Label: spec.label, Summary: summary,
		},
		msg: b.msg, text: spec.text, canon: canonicalJSON(canon),
	})
}

// marker returns the injection marker a text starts with, if any.
func (b *builder) marker(text string) string {
	trimmed := strings.TrimLeft(text, " \t\r\n")
	for _, marker := range b.vocab.InjectionMarkers {
		if strings.HasPrefix(trimmed, marker) {
			return marker
		}
	}
	return ""
}

func (b *builder) volatilePrefix(text string) string {
	for _, prefix := range b.vocab.VolatileTextPrefixes {
		if strings.HasPrefix(text, prefix) {
			return prefix
		}
	}
	return ""
}

func (b *builder) addText(role, text string) {
	if text == "" {
		return
	}
	category, kind, label := CategoryUser, "text", ""
	switch role {
	case "system":
		category, kind = CategorySystem, "system"
	case "developer":
		category, kind = CategorySystem, "system"
		if marker := b.marker(text); marker != "" {
			category, kind, label = CategoryInjected, "text", marker
		}
	case "assistant":
		category = CategoryAssistant
	case "tool":
		category = CategoryToolResult
	default:
		role = "user"
		if marker := b.marker(text); marker != "" {
			category, label = CategoryInjected, marker
		}
	}
	canonText := text
	if prefix := b.volatilePrefix(text); prefix != "" {
		canonText = prefix
	}
	b.add(itemSpec{
		category: category, role: role, kind: kind, label: label,
		tokens: textTokens(text), text: text, canon: map[string]any{"t": canonText},
	})
}

func (b *builder) addReasoning(text string, encodedBytes int) {
	tokens := textTokens(text)
	if text == "" {
		if encodedBytes == 0 {
			return
		}
		tokens = bytesTokens(encodedBytes) + blockOverheadTokens
	}
	b.add(itemSpec{
		category: CategoryReasoning, role: "assistant", kind: "thinking",
		tokens: tokens, text: text, canon: map[string]any{"t": text, "n": encodedBytes},
	})
}

func (b *builder) addToolCall(name, id, args string) {
	if id != "" {
		b.callNames[id] = name
	}
	b.add(itemSpec{
		category: CategoryAssistant, role: "assistant", kind: "tool_call", label: name,
		tokens: bytesTokens(len(name)+len(args)) + blockOverheadTokens,
		text:   args, canon: map[string]any{"n": name, "i": id, "a": args},
	})
}

func (b *builder) addToolResult(id, name, text string, extraTokens int64) {
	if name == "" {
		name = b.callNames[id]
	}
	b.add(itemSpec{
		category: CategoryToolResult, role: "tool", kind: "tool_result", label: name,
		tokens: textTokens(text) + extraTokens,
		text:   text, canon: map[string]any{"i": id, "t": text, "x": extraTokens},
	})
}

func (b *builder) addMedia(role, kind, label string, tokens int64, identity string) {
	if role == "" {
		role = "user"
	}
	b.add(itemSpec{
		category: CategoryMedia, role: role, kind: kind, label: label, tokens: tokens,
		canon: map[string]any{"h": sha256Hex(identity), "l": label},
	})
}

func (b *builder) addToolDef(name string, raw any, description string) {
	encoded := canonicalJSON(raw)
	tokens := bytesTokens(len(encoded)) + blockOverheadTokens
	b.tools = append(b.tools, ToolDef{Name: name, Tokens: tokens, Source: b.toolSource(name)})
	b.items = append(b.items, ctxItem{
		Item: Item{
			Category: CategoryTools, Role: "system", Kind: "tool_def",
			Tokens: tokens, Label: name, Summary: summarize(description),
		},
		msg: b.msg, canon: canonicalJSON(map[string]any{"c": CategoryTools, "k": "tool_def", "d": json.RawMessage(encoded)}),
	})
}

func (b *builder) toolSource(name string) string {
	if len(name) >= 5 && strings.EqualFold(name[:5], "mcp__") {
		rest := name[5:]
		if index := strings.LastIndex(rest, "__"); index > 0 {
			return "mcp:" + rest[:index]
		}
		return "mcp:unknown"
	}
	if _, ok := b.vocab.ToolKinds[strings.ToLower(name)]; ok {
		return "builtin"
	}
	return "custom"
}
