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
	MaskedKey     *string
}

// AuditListPage contains a keyset-paginated result. HasMore is computed by
// reading one extra row and does not require an additional COUNT query.
type AuditListPage struct {
	Rows    []AuditListRow
	HasMore bool
}

// HeaderEvidence is the encrypted value and its stable identity for one saved
// Header or Trailer entry. It is only consumed by the query service, which
// authenticates and decrypts the value before building the protected detail
// response.
type HeaderEvidence struct {
	Stage       string
	Kind        string
	Name        string
	ValueIndex  int
	ValueLength int
	ValueEnc    []byte
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
	ParsedJSONEnc   []byte
	ParsedAtNS      int64
}

// TokenLinkSummary contains only the NewAPI token identifier, display name,
// and source-provided masked credential snapshot. It never contains the
// original credential.
type TokenLinkSummary struct {
	NewAPITokenID int64
	TokenName     string
	MaskedKey     string
	LinkedAtNS    int64
}

// AuditQueryDetail is the encrypted evidence projection used only by the
// authenticated management query service. RequestURIEnc and Header ValueEnc
// and ParsedResult.ParsedJSONEnc must never be copied into list DTOs or
// returned without decryption.
type AuditQueryDetail struct {
	Audit         AuditListRow
	RequestURIEnc []byte
	Stages        []HTTPStage
	Headers       []HeaderEvidence
	Bodies        []BodyStream
	ParsedResult  *ParsedResultSummary
	TokenLink     *TokenLinkSummary
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
