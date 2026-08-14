// Package parser asynchronously converts encrypted HTTP evidence into a small
// protocol-neutral summary. It never participates in request forwarding.
package parser

import (
	"context"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	StatusOK      = sqlite.ParseOK
	StatusPartial = sqlite.ParsePartial
	StatusError   = sqlite.ParseError
	StatusSkipped = sqlite.ParseSkipped

	MaxDecodedBodyBytes = 64 << 20
	MaxGzipRatio        = 50
	QueueCapacity       = 100
)

// Parser extracts only fields useful for the local audit list and detail UI.
type Parser interface {
	Name() string
	Version() string
	Parse(context.Context, Input) Result
}

// AuditNormalizer is implemented by parsers that can losslessly split a
// decoded provider request/response into envelopes and content-addressed items.
type AuditNormalizer interface {
	NormalizeAudit(context.Context, Input, Result) (auditmodel.Turn, error)
}

// Store is the narrow persistence surface used by Worker.
type Store interface {
	ResetProcessingParses(context.Context) error
	ListPendingParseIDs(context.Context, int) ([]string, error)
	LoadParserAudit(context.Context, string) (sqlite.ParserAudit, error)
	ClaimPendingParse(context.Context, string) (bool, error)
	ReleaseProcessingParse(context.Context, string) error
	LoadParserStage(context.Context, string, string) (sqlite.ParserStage, error)
	ReadParserChunks(context.Context, string, string, int64, int) ([]sqlite.BodyChunk, error)
	SaveParsedResult(context.Context, sqlite.ParsedResult) error
	SaveParsedAudit(context.Context, sqlite.ParsedAudit) error
}

// BodySource is one decoded request or response body. Complete reports that
// all stored chunks and the HTTP content encoding were verified.
type BodySource struct {
	Present         bool
	Complete        bool
	ContentType     string
	ContentEncoding string
	Data            []byte
	ErrorCode       string
}

// Input is the immutable evidence view supplied to one protocol parser.
type Input struct {
	AuditID    string
	Protocol   string
	Endpoint   string
	Request    BodySource
	Response   BodySource
	StatusCode *int
}

// Usage keeps provider-reported counters nullable. Parsers do not invent
// missing totals.
type Usage struct {
	Input  *int64
	Output *int64
	Total  *int64
}

// Result is the compact, queryable parser output. ParsedJSON is plaintext only
// in memory and is encrypted by Worker before it crosses the storage boundary.
type Result struct {
	Status          string
	RequestModel    string
	ResponseModel   string
	RequestedStream *bool
	ObservedStream  *bool
	ResponseID      string
	Usage           Usage
	ErrorType       string
	ErrorCode       string
	MessageCount    *int
	ToolCallCount   *int
	HasToolCall     *bool
	Conversation    *conversation.Conversation
	ParsedJSON      []byte
}

// IsUsable reports whether at least one trusted public field was extracted.
func (result Result) IsUsable() bool {
	return result.RequestModel != "" || result.ResponseModel != "" || result.RequestedStream != nil ||
		result.ObservedStream != nil || result.ResponseID != "" || result.Usage.Input != nil ||
		result.Usage.Output != nil || result.Usage.Total != nil || result.ErrorType != "" ||
		result.ErrorCode != "" || result.MessageCount != nil || result.ToolCallCount != nil || result.HasToolCall != nil
}
