package sessionanalysis

import (
	"encoding/json"
	"regexp"
	"strings"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
)

// ToolStatus is the outcome of one tool call as far as its result shows.
type ToolStatus int

// Tool statuses.
const (
	StatusUnknown ToolStatus = iota
	StatusOK
	StatusFailed
)

// ToolCall is one tool call of one agent, normalized for signals and packs.
// Command and Paths are sensitive and only ever reach the encrypted pack.
type ToolCall struct {
	ID      string
	Name    string
	Kind    string // read, write, search, shell, spawn, web, plan, mcp, other
	Class   string // shell class (test, lint, …) or the MCP server name
	Label   string // command head or git subcommand, for shell calls
	Command string
	Paths   []string
	ArgFPR  []byte
	Status  ToolStatus
	Result  string
	// Turn is the index of the user turn this call followed, -1 before any.
	Turn int
	// Child is the index of the spawned node for spawn calls, -1 otherwise.
	Child int

	arguments string
	hasResult bool
}

// UserTurn is one message a person typed.
type UserTurn struct {
	Text       string
	Correction bool
	ErrorPaste bool
	Images     []string
	AuditID    string
	StartedNS  int64
	// AssistantBefore is the assistant's last text before this turn.
	AssistantBefore string
}

// Node is one agent of the session.
type Node struct {
	Key       string
	Role      string
	ParentKey string
	Depth     int
	Parent    int
	Task      string
	TaskAudit string
	Turns     []UserTurn
	Calls     []ToolCall
	Final     string
	FinalID   string
	FirstNS   int64
	Children  []int
	Rules     []string
	Interrupt int
	Loaded    bool
}

// segment is the extraction of one conversation snapshot.
type segment struct {
	turns       []UserTurn
	calls       []ToolCall
	rules       []string
	interrupts  int
	final       string
	lastText    string
	pendingText string
}

var imageTypes = regexp.MustCompile(`"(?:type|media_type|mime_type|mimeType)"\s*:\s*"([^"]+)"`)

// extractSegment walks one decrypted conversation. withResponse adds the
// response-phase assistant text as the final answer.
func extractSegment(view *conversation.Conversation, vocab *Vocabulary, insightsVocab *insights.Vocabulary, withResponse bool) segment {
	var seg segment
	results := map[string]string{}
	for _, message := range view.Messages {
		if message.Phase == conversation.PhaseResponse {
			if !withResponse {
				continue
			}
			for _, part := range message.Content {
				switch part.Type {
				case conversation.PartText:
					if message.Role == conversation.RoleAssistant && strings.TrimSpace(part.Text) != "" {
						seg.final = part.Text
					}
				case conversation.PartToolCall:
					seg.calls = append(seg.calls, ToolCall{ID: part.ID, Name: part.Name, arguments: part.Arguments, Turn: len(seg.turns) - 1, Child: -1})
				}
			}
			continue
		}
		switch message.Role {
		case conversation.RoleUser:
			typed := make([]string, 0, 1)
			images := make([]string, 0)
			for _, part := range message.Content {
				switch part.Type {
				case conversation.PartText:
					lower := headLower(strings.TrimSpace(part.Text), 200)
					if containsAny(lower, vocab.interrupts) {
						seg.interrupts++
					}
					if insightsVocab.IsInjectedUserText(part.Text) {
						seg.rules = append(seg.rules, part.Text)
						continue
					}
					if hasAnyPrefix(lower, vocab.summaryPrefixes) {
						continue
					}
					if cleaned := cleanUserText(part.Text); cleaned != "" {
						typed = append(typed, cleaned)
					}
				case conversation.PartToolResult:
					results[part.ToolCallID] = part.Result
				case conversation.PartUnknown:
					if placeholder := mediaPlaceholder(part.Data); placeholder != "" {
						images = append(images, placeholder)
					}
				}
			}
			if len(typed) == 0 {
				continue
			}
			seg.turns = append(seg.turns, UserTurn{
				Text:            strings.Join(typed, "\n\n"),
				Images:          images,
				AssistantBefore: seg.pendingText,
			})
			seg.pendingText = ""
		case conversation.RoleAssistant:
			for _, part := range message.Content {
				switch part.Type {
				case conversation.PartText:
					if strings.TrimSpace(part.Text) != "" {
						seg.pendingText = part.Text
						seg.lastText = part.Text
					}
				case conversation.PartToolCall:
					seg.calls = append(seg.calls, ToolCall{ID: part.ID, Name: part.Name, arguments: part.Arguments, Turn: len(seg.turns) - 1, Child: -1})
				}
			}
		case conversation.RoleTool:
			for _, part := range message.Content {
				if part.Type == conversation.PartToolResult {
					id := part.ToolCallID
					if id == "" {
						id = message.ToolCallID
					}
					results[id] = part.Result
				}
			}
		}
	}
	if seg.final == "" {
		seg.final = seg.lastText
	}
	for index := range seg.calls {
		if result, ok := results[seg.calls[index].ID]; ok && seg.calls[index].ID != "" {
			seg.calls[index].Result = result
			seg.calls[index].hasResult = true
		}
	}
	return seg
}

var commandTags = regexp.MustCompile(`(?s)<command-name>\s*(/?[^<\s]+)\s*</command-name>`)
var commandArgs = regexp.MustCompile(`(?s)<command-args>(.*?)</command-args>`)
var commandMessage = regexp.MustCompile(`(?s)<command-message>.*?</command-message>`)
var inlineReminder = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// cleanUserText removes inline system reminders, rewrites slash-command
// markup and collapses blank lines (doc 24 section 6.3 step 4).
func cleanUserText(text string) string {
	text = inlineReminder.ReplaceAllString(text, "")
	if match := commandTags.FindStringSubmatch(text); match != nil {
		name := match[1]
		if !strings.HasPrefix(name, "/") {
			name = "/" + name
		}
		arguments := ""
		if args := commandArgs.FindStringSubmatch(text); args != nil {
			arguments = strings.TrimSpace(args[1])
		}
		text = commandMessage.ReplaceAllString(text, "")
		text = commandTags.ReplaceAllString(text, "")
		text = commandArgs.ReplaceAllString(text, "")
		rest := strings.TrimSpace(text)
		text = "[命令 " + name + "]"
		if arguments != "" {
			text += " " + arguments
		}
		if rest != "" {
			text += "\n" + rest
		}
	}
	return collapseBlankLines(text)
}

func mediaPlaceholder(data string) string {
	if data == "" {
		return ""
	}
	mediaType := ""
	for _, match := range imageTypes.FindAllStringSubmatch(data, -1) {
		if strings.Contains(match[1], "/") {
			mediaType = match[1]
			break
		}
	}
	lower := strings.ToLower(data)
	switch {
	case strings.HasPrefix(mediaType, "image/") || strings.Contains(lower, "input_image") || strings.Contains(lower, `"image`):
		if mediaType == "" {
			mediaType = "image"
		}
		return "[图片 " + mediaType + "]"
	case mediaType != "" || strings.Contains(lower, "input_file") || strings.Contains(lower, `"document"`) || strings.Contains(lower, `"file"`):
		if mediaType == "" {
			mediaType = "file"
		}
		return "[附件 " + mediaType + "]"
	}
	return ""
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(text string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// classifyCall fills Kind, Class, Label, Paths and Status of one call.
func classifyCall(call *ToolCall, vocab *Vocabulary, insightsVocab *insights.Vocabulary, client string) {
	hasResult := call.hasResult
	name := strings.ToLower(strings.TrimSpace(call.Name))
	arguments := call.arguments
	kind := toolKindOf(name, insightsVocab)
	if class, ok := vocab.toolClasses[name]; ok {
		kind = class
	}
	switch kind {
	case insights.ToolKindFileRead:
		call.Kind = "read"
	case insights.ToolKindFileWrite:
		call.Kind = "write"
		call.Paths = writePaths(name, arguments, insightsVocab)
	case insights.ToolKindSearch:
		call.Kind = "search"
	case insights.ToolKindShell:
		call.Kind = "shell"
		call.Command = shellCommandsFromArgs(arguments)
		call.Class, call.Label = vocab.classifyShell(call.Command)
		switch call.Class {
		case "read":
			call.Kind, call.Class, call.Label = "read", "", ""
		case "search":
			call.Kind, call.Class, call.Label = "search", "", ""
		}
	case insights.ToolKindSpawn:
		call.Kind = "spawn"
	case insights.ToolKindMCP:
		call.Kind = "mcp"
		call.Class = mcpServer(name)
	case "web", "plan":
		call.Kind = kind
	default:
		call.Kind = "other"
		call.Label = sanitizeLabel(name)
	}
	switch {
	case vocab.hasFailurePhrase(call.Result):
		call.Status = StatusFailed
	case kind == insights.ToolKindShell && hasResult:
		if code, ok := vocab.exitCode(call.Result); ok {
			if code == 0 {
				call.Status = StatusOK
			} else {
				call.Status = StatusFailed
			}
		} else if vocab.okWithoutExit[client] {
			call.Status = StatusOK
		} else {
			call.Status = StatusUnknown
		}
	case hasResult:
		call.Status = StatusOK
	default:
		call.Status = StatusUnknown
	}
}

func toolKindOf(name string, vocab *insights.Vocabulary) string {
	if vocab == nil {
		return insights.ToolKindOther
	}
	if kind, ok := vocab.ToolKinds[name]; ok {
		return kind
	}
	for prefix, kind := range vocab.ToolKindPrefixes {
		if strings.HasPrefix(name, prefix) {
			return kind
		}
	}
	return insights.ToolKindOther
}

func mcpServer(name string) string {
	trimmed := strings.TrimPrefix(name, "mcp__")
	if server, _, ok := strings.Cut(trimmed, "__"); ok && server != "" {
		return sanitizeLabel(server)
	}
	return sanitizeLabel(trimmed)
}

var patchFileHeader = regexp.MustCompile(`(?m)^\*\*\* (?:Update|Add|Delete) File: (.+)$`)
var diffFileHeader = regexp.MustCompile(`(?m)^\+\+\+ (?:b/)?(\S+)`)

// writePaths extracts the target paths of a file-writing call.
func writePaths(name, arguments string, vocab *insights.Vocabulary) []string {
	paths := make([]string, 0, 1)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || path == "/dev/null" {
			return
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		paths = append(paths, path)
	}
	var decoded map[string]any
	if json.Unmarshal([]byte(arguments), &decoded) == nil {
		if vocab != nil {
			for _, key := range vocab.FileOps.PathKeys {
				if text, ok := decoded[key].(string); ok {
					add(text)
				}
			}
			for _, key := range vocab.FileOps.PatchKeys {
				if text, ok := decoded[key].(string); ok {
					for _, match := range patchFileHeader.FindAllStringSubmatch(text, -1) {
						add(match[1])
					}
					for _, match := range diffFileHeader.FindAllStringSubmatch(text, -1) {
						add(match[1])
					}
				}
			}
		}
	} else {
		// Codex apply_patch passes the patch itself as the raw input.
		for _, match := range patchFileHeader.FindAllStringSubmatch(arguments, -1) {
			add(match[1])
		}
	}
	return paths
}
