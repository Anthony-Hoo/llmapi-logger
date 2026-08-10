package sqlite

// AuditQueryFilter contains the narrow, non-secret fields supported by the
// local audit browser. Empty values mean that the filter is not applied.
type AuditQueryFilter struct {
	FromNS        *int64
	ToNS          *int64
	Protocol      string
	Path          string
	Model         string
	StatusCode    *int
	ForwardStatus string
	BlockedBy     string
	BlockCode     string
	CaptureStatus string
	NewAPITokenID *int64
	TokenName     string
}

// AuditQueryCursor is the keyset cursor for the fixed newest-first ordering.
// Both fields must be provided together by callers.
type AuditQueryCursor struct {
	BeforeStartedAtNS int64
	BeforeID          string
}

// AuditListRow is one non-secret audit summary. It intentionally excludes the
// encrypted request URI, Header values, Body chunks, and parsed JSON.
type AuditListRow struct {
	AuditID       string
	StartedAtNS   int64
	EndedAtNS     *int64
	RouteID       string
	Protocol      string
	ParserName    string
	Method        string
	Path          string
	Mode          string
	StatusCode    *int
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
	BlockedBy     *string
	BlockCode     *string
	ErrorCode     *string
	RequestModel  *string
	ResponseModel *string
	NewAPITokenID *int64
	TokenName     *string
}

// AuditListPage contains a keyset-paginated result. HasMore is computed by
// reading one extra row and does not require an additional COUNT query.
type AuditListPage struct {
	Rows    []AuditListRow
	HasMore bool
}

// HeaderMetadata is safe to return from the normal detail endpoint. The
// encrypted value is deliberately absent.
type HeaderMetadata struct {
	Stage       string
	Kind        string
	Name        string
	ValueIndex  int
	ValueLength int
}

// ParsedResultSummary is the narrow, non-secret projection of parsed_results.
type ParsedResultSummary struct {
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
	MessageCount    *int64
	ToolCallCount   *int64
	HasToolCall     *bool
	ParsedAtNS      int64
}

// TokenLinkSummary contains only the NewAPI token identifier and display name
// snapshot. It never contains the credential itself.
type TokenLinkSummary struct {
	NewAPITokenID int64
	TokenName     string
	LinkedAtNS    int64
}

// AuditQueryDetail is the safe detail projection used by the management API.
type AuditQueryDetail struct {
	Audit        AuditListRow
	Stages       []HTTPStage
	Headers      []HeaderMetadata
	Bodies       []BodyStream
	ParsedResult *ParsedResultSummary
	TokenLink    *TokenLinkSummary
}

// RawBodyMetadata describes one captured Body stream without containing Body
// bytes or ciphertext.
type RawBodyMetadata struct {
	AuditID        string
	Stage          string
	ObservedLength int64
	StoredLength   int64
	SHA256         []byte
	HashComplete   bool
	EOFSeen        bool
	State          string
	ErrorCode      *string
}
