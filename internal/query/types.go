// Package query exposes a safe, read-only view of encrypted audit evidence.
// It maps storage rows to API DTOs and is the only layer that decrypts raw
// Body chunks for the management server.
package query

import (
	"errors"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var (
	ErrInvalidQuery = errors.New("query: invalid request")
	ErrNotFound     = errors.New("query: audit evidence not found")
	ErrNotReady     = errors.New("query: audit evidence is still being captured")
	ErrIntegrity    = errors.New("query: encrypted evidence failed integrity checks")
)

// Side selects the raw evidence boundary exposed by the management API.
type Side string

const (
	SideRequest  Side = "request"
	SideResponse Side = "response"
)

// Filter contains optional exact-match filters for the local audit list.
type Filter struct {
	FromNS        *int64
	ToNS          *int64
	Protocol      string
	Path          string
	Model         string
	UserAgent     string
	StatusCode    *int
	ForwardStatus string
	BlockedBy     string
	BlockCode     string
	CaptureStatus string
	NewAPITokenID *int64
	TokenName     string
}

// Cursor is the opaque-in-practice keyset represented by two query values.
type Cursor struct {
	BeforeStartedAtNS int64  `json:"before_started_at_ns,string"`
	BeforeID          string `json:"before_id"`
}

// AuditSummary is the non-secret list projection.
type AuditSummary struct {
	AuditID       string  `json:"audit_id"`
	StartedAtNS   int64   `json:"started_at_ns,string"`
	EndedAtNS     *int64  `json:"ended_at_ns,string"`
	RouteID       string  `json:"route_id"`
	Protocol      string  `json:"protocol"`
	ParserName    string  `json:"parser_name"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Mode          string  `json:"mode"`
	StatusCode    *int    `json:"status_code"`
	ForwardStatus string  `json:"forward_status"`
	CaptureStatus string  `json:"capture_status"`
	ParseStatus   string  `json:"parse_status"`
	BlockedBy     *string `json:"blocked_by"`
	BlockCode     *string `json:"block_code"`
	ErrorCode     *string `json:"error_code"`
	RequestModel  *string `json:"request_model"`
	ResponseModel *string `json:"response_model"`
	UserAgent     *string `json:"user_agent"`
	NewAPITokenID *int64  `json:"newapi_token_id"`
	TokenName     *string `json:"token_name"`
	MaskedKey     *string `json:"masked_key"`
}

// Page is a newest-first keyset page.
type Page struct {
	Items      []AuditSummary `json:"items"`
	NextCursor *Cursor        `json:"next_cursor"`
}

type Stage struct {
	Stage         string  `json:"stage"`
	State         string  `json:"state"`
	Proto         string  `json:"proto"`
	Method        string  `json:"method"`
	Host          string  `json:"host"`
	StatusCode    *int    `json:"status_code"`
	ContentLength *int64  `json:"content_length"`
	StartedAtNS   int64   `json:"started_at_ns,string"`
	EndedAtNS     *int64  `json:"ended_at_ns,string"`
	ErrorCode     *string `json:"error_code"`
}

type Header struct {
	Stage       string `json:"stage"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	ValueIndex  int    `json:"value_index"`
	ValueLength int    `json:"value_length"`
	Value       string `json:"value"`
}

type Body struct {
	Stage          string  `json:"stage"`
	ObservedLength int64   `json:"observed_length"`
	StoredLength   int64   `json:"stored_length"`
	SHA256         *string `json:"sha256"`
	HashComplete   bool    `json:"hash_complete"`
	EOFSeen        bool    `json:"eof_seen"`
	State          string  `json:"state"`
	ErrorCode      *string `json:"error_code"`
}

type ParsedResult struct {
	ParserName      string  `json:"parser_name"`
	ParserVersion   string  `json:"parser_version"`
	Status          string  `json:"status"`
	RequestModel    *string `json:"request_model"`
	ResponseModel   *string `json:"response_model"`
	RequestedStream *bool   `json:"requested_stream"`
	ObservedStream  *bool   `json:"observed_stream"`
	ResponseID      *string `json:"response_id"`
	UsageInput      *int64  `json:"usage_input"`
	UsageOutput     *int64  `json:"usage_output"`
	UsageTotal      *int64  `json:"usage_total"`
	ErrorType       *string `json:"error_type"`
	ErrorCode       *string `json:"error_code"`
	MessageCount    *int64  `json:"message_count"`
	ToolCallCount   *int64  `json:"tool_call_count"`
	HasToolCall     *bool   `json:"has_tool_call"`
	ParsedAtNS      int64   `json:"parsed_at_ns,string"`
}

type TokenLink struct {
	NewAPITokenID int64  `json:"newapi_token_id"`
	TokenName     string `json:"token_name"`
	MaskedKey     string `json:"masked_key"`
	LinkedAtNS    int64  `json:"linked_at_ns,string"`
}

// Detail is sensitive and may only be returned by the Admin Token protected
// endpoint. Raw Body bytes still require a separate, explicit request.
type Detail struct {
	Audit        AuditSummary               `json:"audit"`
	RequestURI   string                     `json:"request_uri"`
	Stages       []Stage                    `json:"stages"`
	Headers      []Header                   `json:"headers"`
	Bodies       []Body                     `json:"bodies"`
	ParsedResult *ParsedResult              `json:"parsed_result"`
	Conversation *conversation.Conversation `json:"conversation"`
	TokenLink    *TokenLink                 `json:"token_link"`
}

// RawMetadata is safe to expose as HTTP response headers.
type RawMetadata struct {
	ObservedLength int64
	StoredLength   int64
	SHA256         string
	Complete       bool
	State          string
}

func stageForSide(side Side) (string, error) {
	switch side {
	case SideRequest:
		return sqlite.StageRequestSent, nil
	case SideResponse:
		return sqlite.StageResponseReceived, nil
	default:
		return "", ErrInvalidQuery
	}
}
