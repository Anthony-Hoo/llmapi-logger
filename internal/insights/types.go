// Package insights derives context composition, usage, session and agent-tree
// facts from parsed LLM traffic (doc/features/20-context-insights.md).
//
// The analyzer runs inside the asynchronous parser worker, never on the proxy
// byte path. Its plaintext output is numbers, enums and keyed fingerprints;
// message text, tool names, file paths and raw agent IDs only leave this
// package inside Detail, which callers must encrypt before storage.
package insights

import (
	"net/http"

	"llmapi-logger/internal/conversation"
)

// AnalysisVersion is bumped whenever stored analysis would change for the same
// evidence. The backfill job recomputes rows with an older version.
const AnalysisVersion = 6

// Composition categories, in display order.
const (
	CategorySystem     = "system"
	CategoryTools      = "tools"
	CategoryUser       = "user"
	CategoryInjected   = "injected"
	CategoryAssistant  = "assistant"
	CategoryReasoning  = "reasoning"
	CategoryToolResult = "tool_result"
	CategoryMedia      = "media"
)

// Categories lists every composition category in display order.
var Categories = []string{
	CategorySystem, CategoryTools, CategoryUser, CategoryInjected,
	CategoryAssistant, CategoryReasoning, CategoryToolResult, CategoryMedia,
}

// Stop reasons, normalized across protocols.
const (
	StopEndTurn       = "end_turn"
	StopToolUse       = "tool_use"
	StopLength        = "length"
	StopContentFilter = "content_filter"
	StopOther         = "other"
)

// Response block kinds, stored as a bit set in resp_kinds.
const (
	KindThinking = 1 << iota
	KindToolCall
	KindText
)

// Event flags, stored as a bit set in event_flags.
const (
	EventModelSwitch = 1 << iota
	EventCompaction
	EventPrune
	EventSystemChanged
	EventToolsChanged
	EventInjected
)

// Session link sources.
const (
	SessionLinkAgent        = "agent"        // client agent node identifier
	SessionLinkConversation = "conversation" // OpenAI turns.conversation_id
	SessionLinkExplicit     = "explicit"     // body metadata session key
	SessionLinkInferred     = "inferred"     // keyed hash of key, system and opener
	SessionLinkRoot         = "root"         // no prior step; the session starts here
)

// Agent roles. Only main and subagent are tree nodes; the others are auxiliary
// requests attached to the node that issued them.
const (
	RoleMain       = "main"
	RoleSubagent   = "subagent"
	RoleCompaction = "compaction"
	RoleTitle      = "title"
	RoleReview     = "review"
	RoleAuxiliary  = "auxiliary"
)

// Agent link sources, in decreasing precision.
const (
	LinkHeader  = "header"
	LinkBody    = "body"
	LinkContent = "content"
)

// Tool kinds used for plaintext per-response counts. Tool names themselves are
// never stored in plaintext.
const (
	ToolKindFileRead  = "file_read"
	ToolKindFileWrite = "file_write"
	ToolKindSearch    = "search"
	ToolKindShell     = "shell"
	ToolKindSpawn     = "spawn"
	ToolKindMCP       = "mcp"
	ToolKindOther     = "other"
)

// Usage is the normalized, mutually exclusive usage breakdown. Nil means the
// upstream did not report the bucket. Output includes reasoning tokens;
// Reasoning is a subset of Output kept for display.
type Usage struct {
	UncachedInput *int64 `json:"uncached_input"`
	CacheRead     *int64 `json:"cache_read"`
	CacheWrite    *int64 `json:"cache_write"`
	Output        *int64 `json:"output"`
	Reasoning     *int64 `json:"reasoning"`
}

// PromptTotal returns uncached + cache read + cache write, or nil when no
// input bucket was reported.
func (usage Usage) PromptTotal() *int64 {
	if usage.UncachedInput == nil && usage.CacheRead == nil && usage.CacheWrite == nil {
		return nil
	}
	var total int64
	for _, value := range []*int64{usage.UncachedInput, usage.CacheRead, usage.CacheWrite} {
		if value != nil {
			total += *value
		}
	}
	return &total
}

// CategoryValues holds one integer per composition category.
type CategoryValues struct {
	System     int64 `json:"system"`
	Tools      int64 `json:"tools"`
	User       int64 `json:"user"`
	Injected   int64 `json:"injected"`
	Assistant  int64 `json:"assistant"`
	Reasoning  int64 `json:"reasoning"`
	ToolResult int64 `json:"tool_result"`
	Media      int64 `json:"media"`
}

// Sum returns the total over all categories.
func (values CategoryValues) Sum() int64 {
	return values.System + values.Tools + values.User + values.Injected +
		values.Assistant + values.Reasoning + values.ToolResult + values.Media
}

// ItemCounts holds the plaintext structural counts of one request.
type ItemCounts struct {
	Items       int `json:"items"`
	ToolDefs    int `json:"tool_defs"`
	ToolResults int `json:"tool_results"`
	Media       int `json:"media"`
}

// Input is everything the analyzer may read for one audit. Request and
// Response are decoded plaintext bodies (JSON, or SSE text for streams).
// Headers contains only the vocabulary allowlist of inbound request headers.
type Input struct {
	AuditID          string
	Protocol         string // "openai" | "anthropic" | "gemini"
	Endpoint         string // parser endpoint, e.g. "chat_completions", "responses", "messages"
	StartedAtNS      int64
	EndedAtNS        int64
	Request          []byte
	RequestComplete  bool
	Response         []byte
	ResponseComplete bool
	ResponseIsStream bool
	Headers          http.Header
	RequestModel     string
	ResponseModel    string
	Usage            Usage
	FirstEventNS     *int64 // relative to StartedAtNS, from the stream timeline
	LastEventNS      *int64
	// Conversation is the protocol parser's DTO. Its response-phase messages
	// describe this response (already decoded from SSE); the request side is
	// re-read from Request because the DTO drops tool definitions and media.
	Conversation *conversation.Conversation
}

// Fingerprinter produces keyed, non-reversible 32-byte tags. Implementations
// derive their key from the audit master key with an analysis-specific domain
// label; tags never leave the process except as stored BLOB columns.
type Fingerprinter interface {
	Fingerprint(domain string, value []byte) []byte
}

// AgentIdentity is what the request itself says about its agent. Raw IDs are
// sensitive: only their fingerprints are stored in plaintext columns.
type AgentIdentity struct {
	Client     string `json:"client"` // codex | claude_code | opencode | dsh | custom | unknown
	Role       string `json:"role"`
	RootID     string `json:"root_id,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	ParentID   string `json:"parent_id,omitempty"`
	Name       string `json:"name,omitempty"`
	LinkSource string `json:"link_source,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
}

// Analysis is the analyzer output for one audit before session linking.
type Analysis struct {
	Version           int
	Model             string
	Usage             Usage
	MaxOutputTokens   *int64
	Estimate          CategoryValues
	Counts            ItemCounts
	StopReason        string
	ResponseKinds     int
	ResponseToolCalls int
	ToolKindCounts    map[string]int
	TurnStart         bool
	SystemFPR         []byte
	ToolsFPR          []byte
	SessionKeyFPR     []byte // explicit or inferred session key, nil when absent
	SessionKeySource  string // SessionLinkExplicit or SessionLinkInferred
	FirstEventNS      *int64
	GenerationNS      *int64
	Agent             AgentIdentity
	SpawnHintFPRs     [][]byte // fingerprints of spawn prompts in this response
	ChildHintFPRs     [][]byte // fingerprints of this request's opening user text blocks
	Detail            Detail
}

// Detail is encrypted before storage and only decrypted for one audit's
// composition view.
type Detail struct {
	Items     []Item        `json:"items"`
	Tools     []ToolDef     `json:"tools"`
	FileOps   []FileOp      `json:"file_ops"`
	Agent     AgentIdentity `json:"agent"`
	ItemFPRs  []string      `json:"item_fprs"` // hex keyed fingerprints, request order
	Truncated bool          `json:"truncated,omitempty"`
}

// Item is one request context item in prompt order.
type Item struct {
	Index    int    `json:"index"`
	Category string `json:"category"`
	Role     string `json:"role"`
	Kind     string `json:"kind"` // text | thinking | tool_call | tool_result | image | file | tool_def | system
	Tokens   int64  `json:"tokens"`
	Label    string `json:"label,omitempty"`   // tool name, injected marker, media type
	Summary  string `json:"summary,omitempty"` // at most 160 runes of leading text
}

// ToolDef is one tool definition offered to the model.
type ToolDef struct {
	Name   string `json:"name"`
	Tokens int64  `json:"tokens"`
	Source string `json:"source"` // builtin | mcp:<server> | custom
}

// FileOp is one file operation decoded from a response tool call.
type FileOp struct {
	Tool         string `json:"tool"`
	Op           string `json:"op"` // read | write | search | shell
	Path         string `json:"path,omitempty"`
	AddedLines   int    `json:"added_lines,omitempty"`
	RemovedLines int    `json:"removed_lines,omitempty"`
}
