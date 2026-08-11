// Package conversation defines the protocol-neutral, sensitive conversation
// view stored inside the encrypted parser result and exposed only by the
// Admin Token protected audit detail endpoint.
package conversation

import (
	"encoding/json"
	"unicode/utf8"
)

const (
	SchemaVersion = 1

	PhaseRequest  = "request"
	PhaseResponse = "response"

	DirectionClientToUpstream = "client_to_upstream"
	DirectionUpstreamToClient = "upstream_to_client"

	RoleSystem    = "system"
	RoleDeveloper = "developer"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
	RoleUnknown   = "unknown"

	PartText       = "text"
	PartReasoning  = "reasoning"
	PartToolCall   = "tool_call"
	PartToolResult = "tool_result"
	PartUnknown    = "unknown"

	maxUnknownDataBytes = 4096
)

// Conversation is the stable JSON DTO consumed by the management UI.
type Conversation struct {
	SchemaVersion int       `json:"schema_version"`
	Messages      []Message `json:"messages"`
}

// Message preserves the audit side, direction, role, and display order.
type Message struct {
	Index      int    `json:"index"`
	Role       string `json:"role"`
	Phase      string `json:"phase"`
	Direction  string `json:"direction"`
	Name       string `json:"name,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Content    []Part `json:"content"`
}

// Part is a tagged union represented with optional JSON fields. Arguments
// and results are strings so the UI can render provider JSON and plain text
// without protocol-specific branches.
type Part struct {
	Index      int    `json:"index"`
	Type       string `json:"type"`
	Text       string `json:"text,omitempty"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Result     string `json:"result,omitempty"`
	Data       string `json:"data,omitempty"`
}

// New returns an empty conversation with a non-nil messages array.
func New() *Conversation {
	return &Conversation{SchemaVersion: SchemaVersion, Messages: make([]Message, 0)}
}

// Ensure initializes a conversation lazily.
func Ensure(target **Conversation) *Conversation {
	if *target == nil {
		*target = New()
	}
	return *target
}

// Append assigns stable message and part indexes and skips empty messages.
func (conversation *Conversation) Append(message Message) {
	if conversation == nil || len(message.Content) == 0 {
		return
	}
	message.Index = len(conversation.Messages)
	message.Content = append([]Part(nil), message.Content...)
	for index := range message.Content {
		message.Content[index].Index = index
	}
	conversation.Messages = append(conversation.Messages, message)
}

func Text(text string) Part {
	return Part{Type: PartText, Text: text}
}

func Reasoning(text string) Part {
	return Part{Type: PartReasoning, Text: text}
}

// ValueString preserves strings and encodes structured values as compact JSON.
func ValueString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// Unknown serializes an unsupported provider block for best-effort audit UI.
func Unknown(value any) Part {
	data := ValueString(value)
	if len(data) > maxUnknownDataBytes {
		data = data[:maxUnknownDataBytes]
		for !utf8.ValidString(data) {
			data = data[:len(data)-1]
		}
		data += "...[truncated]"
	}
	return Part{Type: PartUnknown, Data: data}
}
