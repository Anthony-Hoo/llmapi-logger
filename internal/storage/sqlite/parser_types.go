package sqlite

// ParserAudit is the narrow audit metadata view required by the asynchronous
// parser worker.
type ParserAudit struct {
	AuditID       string
	Protocol      string
	ParserName    string
	Path          string
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
}

// ParserStage is one parser-relevant HTTP stage plus its encrypted content
// metadata. Body is nil when the stage had no observed body stream.
type ParserStage struct {
	Stage   HTTPStage
	Body    *BodyStream
	Headers []HTTPHeader
}

// ParsedResult is the latest compact protocol summary for one audit. Sensitive
// structured details are accepted only as already encrypted ParsedJSONEnc.
type ParsedResult struct {
	AuditID         string
	ParserName      string
	ParserVersion   string
	Status          string
	RequestModel    *string
	ResponseModel   *string
	RequestedStream *bool
	ObservedStream  *bool
	ResponseID      *string
	UsageInput      *int64
	UsageOutput     *int64
	UsageTotal      *int64
	ErrorType       *string
	ErrorCode       *string
	MessageCount    *int
	ToolCallCount   *int
	HasToolCall     *bool
	ParsedJSONEnc   []byte
	ParsedAtNS      int64
}

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
