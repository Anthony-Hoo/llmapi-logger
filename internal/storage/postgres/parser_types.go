package postgres

import "llmapi-logger/internal/storage"

// ParserAudit is the narrow audit metadata view required by the asynchronous
// parser worker.
type ParserAudit = storage.ParserAudit

// ParserStage is one parser-relevant HTTP stage plus its encrypted content
// metadata. Body is nil when the stage had no observed body stream.
type ParserStage = storage.ParserStage

// ParsedResult is the latest compact protocol summary for one audit. Sensitive
// structured details are accepted only as already encrypted ParsedJSONEnc.
type ParsedResult = storage.ParsedResult

type parseClaim struct {
	AuditID string
	Claimed bool
}

func validateParsedResult(result ParsedResult) error {
	if result.AuditID == "" || result.ParserName == "" || result.ParserVersion == "" || result.ParsedAtNS == 0 {
		return errInvalidParsedResult
	}
	if result.Status != ParseOK && result.Status != ParsePartial && result.Status != ParseError && result.Status != ParseSkipped {
		return errInvalidParsedResult
	}
	if invalidOptionalInt64(result.UsageInput) || invalidOptionalInt64(result.UsageOutput) || invalidOptionalInt64(result.UsageTotal) ||
		invalidOptionalInt(result.MessageCount) || invalidOptionalInt(result.ToolCallCount) {
		return errInvalidParsedResult
	}
	return nil
}

func invalidOptionalInt64(value *int64) bool {
	return value != nil && *value < 0
}

func invalidOptionalInt(value *int) bool {
	return value != nil && *value < 0
}

func cloneParsedResult(result ParsedResult) ParsedResult {
	result.RequestModel = cloneString(result.RequestModel)
	result.ResponseModel = cloneString(result.ResponseModel)
	result.RequestedStream = cloneBool(result.RequestedStream)
	result.ObservedStream = cloneBool(result.ObservedStream)
	result.ResponseID = cloneString(result.ResponseID)
	result.UsageInput = cloneInt64(result.UsageInput)
	result.UsageOutput = cloneInt64(result.UsageOutput)
	result.UsageTotal = cloneInt64(result.UsageTotal)
	result.ErrorType = cloneString(result.ErrorType)
	result.ErrorCode = cloneString(result.ErrorCode)
	result.UpstreamErrorClass = cloneString(result.UpstreamErrorClass)
	result.MessageCount = cloneInt(result.MessageCount)
	result.ToolCallCount = cloneInt(result.ToolCallCount)
	result.HasToolCall = cloneBool(result.HasToolCall)
	result.ParsedJSONEnc = cloneBytes(result.ParsedJSONEnc)
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
