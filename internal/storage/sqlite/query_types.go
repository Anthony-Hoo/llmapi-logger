package sqlite

import "llmapi-logger/internal/auditmodel"

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
	NewAPIUserID  *int64
	Username      string
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
	AuditID         string
	StartedAtNS     int64
	EndedAtNS       *int64
	RouteID         string
	Protocol        string
	ParserName      string
	Method          string
	Path            string
	Mode            string
	StatusCode      *int
	TTFTNS          *int64
	ForwardStatus   string
	CaptureStatus   string
	ParseStatus     string
	BlockedBy       *string
	BlockCode       *string
	ErrorCode       *string
	RequestModel    *string
	ResponseModel   *string
	NewAPIRequestID *string
	CallerStatus    string
	NewAPIUserID    *int64
	Username        *string
	NewAPITokenID   *int64
	TokenName       *string
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

// TokenLinkSummary contains only the NewAPI request, user, and token identity
// copied from the global system log.
type TokenLinkSummary struct {
	NewAPIRequestID string
	NewAPIUserID    int64
	Username        string
	NewAPITokenID   int64
	TokenName       string
	LinkedAtNS      int64
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
	TurnGraph     *TurnGraph
	TokenLink     *TokenLinkSummary
}

// TurnGraph is a transactionally consistent encrypted projection of one
// content-addressed turn. RequestRefs has already been reconstructed by
// applying the complete parent/delta chain, but object plaintext remains
// encrypted for the query service to authenticate and open.
type TurnGraph struct {
	TurnID                     string
	ConversationID             string
	ParentTurnID               *string
	ParentBase                 string
	LinkReason                 string
	LinkConfidence             int
	RequestLayout              string
	ResponseLayout             string
	RequestEnvelopeHash        []byte
	ResponseEnvelopeHash       []byte
	RequestRefs                []auditmodel.ObjectRef
	ResponseRefs               []auditmodel.ObjectRef
	RequestSequenceHash        []byte
	ResponseSequenceHash       []byte
	RequestReconstructionHash  []byte
	ResponseReconstructionHash []byte
	ReconstructionStatus       string
	PreviousResponseID         *string
	ResponseID                 *string
	CreatedAtNS                int64
	Objects                    []auditmodel.StoredContent
	Binaries                   []auditmodel.StoredBinary
}

// RawBodyMetadata describes one captured Body stream without containing Body
// bytes or ciphertext.
type RawBodyMetadata struct {
	AuditID        string
	Stage          string
	SourceStage    string
	RetentionState string
	ObservedLength int64
	StoredLength   int64
	SHA256         []byte
	HashComplete   bool
	EOFSeen        bool
	State          string
	ErrorCode      *string
}

// StoredStreamTimeline is the encrypted logical SSE timing sequence for one
// stage together with the observed body bound used during verification.
type StoredStreamTimeline struct {
	AuditID         string
	Stage           string
	ObservedLength  int64
	EventCount      int64
	FirstEventAtNS  *int64
	LastEventAtNS   *int64
	Complete        bool
	Compression     string
	PlaintextLength int64
	DataEnc         []byte
}
