// Package archive defines the cold archive format of stage 4 (doc/design/
// issue-59-stage4-cold-archive.md, sections C to F): the plaintext record of
// one archived audit, the column specification, the credential projection,
// the record digest, and the codecs of the line, objects, gaps and manifest
// files. It depends on no store: the snapshot reader fills a Record from
// PostgreSQL, the bundle writer encodes it, and the reader tool decodes it
// and hands it to the query layer's plaintext assembly (internal/query,
// plain.go).
package archive

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// FormatVersion is the archive format version this build writes into
// manifests, and the only one its reader accepts (Manifest.Validate). Version
// 1 is published and frozen (design R.10): its bundles stay readable by every
// later reader, so nothing that version 1 bundles depend on may change. Version
// 0 was the trial format (design Q14); its bundles are refused and re-exported.
const FormatVersion = "1"

// FormatName is the manifest's format field.
const FormatName = "llmapi-logger-archive"

// Request context forms of a turn (C.4).
const (
	ContextDelta        = "delta"
	ContextMaterialized = "materialized"
)

var (
	// ErrFormat reports a line, object entry, gap entry or manifest that does
	// not follow the format: a missing or unknown key, a value of the wrong
	// shape, a non-canonical encoding, or fields that disagree.
	ErrFormat = errors.New("archive: malformed archive data")
	// ErrNotMaterialized reports a delta-form turn whose request refs have not
	// been materialised from its parent yet; its digest cannot be computed.
	ErrNotMaterialized = errors.New("archive: turn request refs are not materialised")
	// ErrIntegrity reports plaintext that does not match the hash or length
	// the record carries for it.
	ErrIntegrity = errors.New("archive: archived content failed integrity checks")
)

func formatError(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrFormat}, arguments...)...)
}

// Record is one archived audit: every archived table row of C.2 and E.3 in
// plaintext, with credentials in projected form (D.3). Text values are Go
// strings holding the stored bytes, which need not be valid UTF-8; nil
// pointers and nil byte slices are SQL NULL. Lists are kept in the order E.2
// defines; Canonicalize sorts them.
//
// The line head (audit_id, conversation_id, protocol, started_at_ns,
// ended_at_ns) is not stored separately: it is derived from Audit and Turn.
type Record struct {
	// Revision is the line's revision (1 for the first export). It is not
	// part of the record digest.
	Revision        int64
	Audit           AuditRow
	Stages          []Stage
	Headers         Headers
	Bodies          []storage.BodyStream
	RawChunks       []RawChunk
	Timelines       []Timeline
	ParsedResult    *ParsedResult
	TokenLink       *TokenLink
	Turn            *Turn
	Conversation    *Conversation
	ProjectIdentity *ProjectIdentity
	IntegrityEvents []IntegrityEvent
}

// AuditRow is the audit_records row. RequestURI and UserAgent are the D.3
// projections of request_uri_enc and user_agent_enc; UserAgent is nil when
// user_agent_enc is NULL and never empty. EndedAtNS is not nullable: only
// ended audits are archived (B.1), and E.2 encodes it without a NULL marker.
type AuditRow struct {
	AuditID           string
	SchemaGeneration  int64
	StartedAtNS       int64
	EndedAtNS         int64
	RouteID           string
	Protocol          string
	ParserName        string
	Method            string
	Path              string
	RequestURI        RequestURI
	Mode              string
	StatusCode        *int64
	TTFTNS            *int64
	ForwardStatus     string
	CaptureStatus     string
	ParseStatus       string
	BlockedBy         *string
	BlockCode         *string
	ErrorCode         *string
	NewAPIRequestID   *string
	CallerStatus      string
	CallerAttempts    int64
	CallerNextAtNS    *int64
	CallerUpdatedAtNS *int64
	APIKeyFPR         []byte
	ParseSaveFailures int64
	ParseNextAtNS     *int64
	CaptureVersion    int64
	UserAgent         []ProjectedValue
}

// Stage is one http_stages row. HTTPStage.AuditID is not archived: it is the
// record's audit_id, which the decoder fills in.
type Stage struct {
	storage.HTTPStage
	ContentType     *string
	ContentEncoding *string
}

// Headers is the single logical header form of both capture versions (Q5
// 甲): the flat list headerblock.Expand returns, with each value projected.
// For version 1 BlockPresent is false and BlockStages nil. For version 2
// BlockPresent says whether an http_header_blocks row exists and BlockStages
// lists the stages that have a section in it, in stage order (nil when there
// is no block).
type Headers struct {
	CaptureVersion int64
	BlockPresent   bool
	BlockStages    []string
	Values         []HeaderValue
}

// HeaderValue is one Header or Trailer value of the flat list.
type HeaderValue struct {
	Stage      string
	Kind       string
	Name       string
	ValueIndex int64
	Value      ProjectedValue
}

// RawChunk is the metadata of one owning body_chunks row of a full stage and
// the SHA-256 of its plaintext; the bytes are a raw_chunk entry of the
// objects file.
type RawChunk struct {
	Stage           string
	Seq             int64
	Offset          int64
	PlaintextLength int64
	ObservedAtNS    int64
	SHA256          [32]byte
}

// Timeline is one stream_timelines row with timeline_enc opened and
// decompressed. Plaintext is nil when timeline_enc is NULL.
type Timeline struct {
	Stage           string
	EventCount      int64
	FirstEventAtNS  *int64
	LastEventAtNS   *int64
	Complete        bool
	PlaintextLength int64
	Plaintext       []byte
}

// ParsedResult is the parsed_results row. ParsedJSON is parsed_json_enc
// opened and, when it was a gzip stream, decompressed; nil is NULL. A record
// decoded from a line whose parsed_json was split into the objects file has
// ParsedJSON nil and ParsedJSONRef set; JoinParsedJSON rebuilds the bytes.
type ParsedResult struct {
	ParserName         string
	ParserVersion      string
	Status             string
	RequestModel       *string
	ResponseModel      *string
	RequestedStream    *bool
	ObservedStream     *bool
	ResponseID         *string
	UsageInput         *int64
	UsageOutput        *int64
	UsageTotal         *int64
	ErrorType          *string
	ErrorCode          *string
	UpstreamErrorClass *string
	MessageCount       *int64
	ToolCallCount      *int64
	HasToolCall        *bool
	ParsedJSON         []byte
	ParsedJSONRef      *ParsedJSONRef
	ParsedAtNS         int64
}

// ParsedJSONRef is the line's reference to a parsed_json that the objects
// file holds as Parts parsed_json_part entries (C.2).
type ParsedJSONRef struct {
	SHA256 [32]byte
	Length int64
	Parts  int64
}

// TokenLink is the token_links row.
type TokenLink struct {
	NewAPIUserID           int64
	Username               string
	NewAPITokenID          int64
	TokenName              string
	LinkedAtNS             int64
	BillingState           string
	Quota                  *int64
	QuotaPerUnit           *float64
	BilledPromptTokens     *int64
	BilledCompletionTokens *int64
	BillingAttempts        int64
}

// Turn is the turns row and everything the turn references.
//
// RequestRefs are the materialised request refs the record digest covers. A
// materialized-form context carries them; a delta-form context carries only
// its turn_context_ops, so after decoding RequestRefs is nil until
// Materialize applies the ops to the parent's refs. The exporter sets both.
type Turn struct {
	Row           TurnRow
	Context       RequestContext
	RequestRefs   []auditmodel.ObjectRef
	ResponseItems []ResponseItem
	Objects       []ObjectMeta
	BinaryRefs    []BinaryRef
	ExternalRefs  []ExternalRef
	Binaries      []BinaryMeta
}

// TurnRow is the turns row without audit_id, which is the record's.
type TurnRow struct {
	TurnID                     string
	ConversationID             string
	ParentTurnID               *string
	ParentBase                 string
	LinkReason                 string
	LinkConfidence             int64
	RequestLayout              string
	ResponseLayout             string
	RequestEnvelopeHash        []byte
	ResponseEnvelopeHash       []byte
	RequestItemCount           int64
	ResponseItemCount          int64
	RequestSequenceHash        []byte
	ResponseSequenceHash       []byte
	RequestReconstructionHash  []byte
	ResponseReconstructionHash []byte
	ReconstructionStatus       string
	PreviousResponseID         *string
	ResponseID                 *string
	CreatedAtNS                int64
}

// RequestContext is the request context of C.4: Form is ContextDelta with
// the turn_context_ops rows in Ops, or ContextMaterialized with the refs in
// Refs.
type RequestContext struct {
	Form string
	Ops  []ContextOp
	Refs []auditmodel.ObjectRef
}

// ContextOp is one turn_context_ops row without turn_id.
type ContextOp struct {
	OpIndex      int64
	Operation    string
	ItemCount    int64
	Slot         *string
	ObjectHash   []byte
	SemanticHash []byte
}

// ResponseItem is one turn_response_items row without turn_id.
type ResponseItem struct {
	Ordinal      int64
	Slot         string
	ObjectHash   []byte
	SemanticHash []byte
}

// ObjectMeta is the archived metadata of one content object the turn
// references.
type ObjectMeta struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	PlaintextLength int64
}

// BinaryRef is one content_binary_refs row.
type BinaryRef struct {
	ObjectHash  []byte
	JSONPointer string
	BinaryHash  []byte
	MediaType   string
	Encoding    string
}

// ExternalRef is one content_external_refs row with value_enc opened.
type ExternalRef struct {
	ObjectHash  []byte
	JSONPointer string
	RefKind     string
	ValueHash   []byte
	Value       string
}

// BinaryMeta is the archived metadata of one binary object.
type BinaryMeta struct {
	Hash            []byte
	MediaType       string
	PlaintextLength int64
}

// Conversation is the conversations row without updated_at_ns (Q7).
type Conversation struct {
	ConversationID string
	Protocol       string
	KeyHash        []byte
	CreatedAtNS    int64
}

// ProjectIdentity is the audit_project_identity row with identity_enc
// opened; Identity is nil when identity_enc is NULL.
type ProjectIdentity struct {
	IdentityVersion int64
	ExtractedAtNS   int64
	Source          string
	BodyScanned     bool
	IdentityFPR     []byte
	RemoteFPR       []byte
	RepoRootFPR     []byte
	CwdFPR          []byte
	Identity        []byte
}

// IntegrityEvent is a copy of one integrity_events row of the audit.
type IntegrityEvent struct {
	Sequence      int64
	EventType     string
	PreviousMAC   []byte
	PayloadDigest []byte
	EventMAC      []byte
	CreatedAtNS   int64
}

// ConversationID is the line head's conversation_id: the turn's, or nil.
func (record *Record) ConversationID() *string {
	if record.Turn == nil {
		return nil
	}
	id := record.Turn.Row.ConversationID
	return &id
}

// Operations returns the delta-form context as auditmodel operations.
func (context RequestContext) Operations() ([]auditmodel.ContextOp, error) {
	operations := make([]auditmodel.ContextOp, 0, len(context.Ops))
	for index, op := range context.Ops {
		if index > 0 && op.OpIndex <= context.Ops[index-1].OpIndex {
			return nil, formatError("turn_context_ops not in op_index order")
		}
		operation := auditmodel.ContextOp{Operation: op.Operation, Count: int(op.ItemCount)}
		if op.Operation == auditmodel.OperationInsert {
			if op.Slot == nil {
				return nil, formatError("insert operation without a slot")
			}
			operation.Ref = &auditmodel.ObjectRef{Slot: *op.Slot, ObjectHash: op.ObjectHash, SemanticHash: op.SemanticHash}
		} else if op.Slot != nil || op.ObjectHash != nil || op.SemanticHash != nil {
			return nil, formatError("%s operation with a reference", op.Operation)
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

// ContextOpsFrom converts stored context operations to their archived rows.
func ContextOpsFrom(operations []auditmodel.ContextOp) []ContextOp {
	rows := make([]ContextOp, 0, len(operations))
	for index, operation := range operations {
		row := ContextOp{OpIndex: int64(index), Operation: operation.Operation, ItemCount: int64(operation.Count)}
		if operation.Ref != nil {
			slot := operation.Ref.Slot
			row.Slot = &slot
			row.ObjectHash = bytes.Clone(operation.Ref.ObjectHash)
			row.SemanticHash = bytes.Clone(operation.Ref.SemanticHash)
		}
		rows = append(rows, row)
	}
	return rows
}

// ResponseRefs returns the response items as object refs in ordinal order.
func (turn *Turn) ResponseRefs() []auditmodel.ObjectRef {
	refs := make([]auditmodel.ObjectRef, 0, len(turn.ResponseItems))
	for _, item := range turn.ResponseItems {
		refs = append(refs, auditmodel.ObjectRef{Slot: item.Slot, ObjectHash: item.ObjectHash, SemanticHash: item.SemanticHash})
	}
	return refs
}

// Materialize sets RequestRefs and checks them against request_item_count
// and request_sequence_hash. A materialized context provides the refs
// itself and the parent arguments are ignored. A delta context is applied
// to its base: nothing for a root turn, otherwise the parent's materialised
// request refs, followed by the parent's response refs when parent_base is
// post_turn (auditmodel.ContextBase). The reader passes the refs of the
// parent line, which C.4 places earlier in the same segment.
func (turn *Turn) Materialize(parentRequest, parentResponse []auditmodel.ObjectRef) error {
	var refs []auditmodel.ObjectRef
	switch turn.Context.Form {
	case ContextMaterialized:
		refs = cloneRefs(turn.Context.Refs)
		if int64(len(refs)) != turn.Row.RequestItemCount || !auditmodel.EqualHash(auditmodel.SequenceHash(refs), turn.Row.RequestSequenceHash) {
			return fmt.Errorf("%w: materialised request refs do not match the turn", ErrIntegrity)
		}
	case ContextDelta:
		operations, err := turn.Context.Operations()
		if err != nil {
			return err
		}
		base, err := auditmodel.ContextBase(turn.Row.ParentTurnID != nil, turn.Row.ParentBase, parentRequest, parentResponse)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		applied, err := auditmodel.ApplyContext(base, operations, int(turn.Row.RequestItemCount), turn.Row.RequestSequenceHash)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		refs = cloneRefs(applied)
	default:
		return formatError("unknown request context form %q", turn.Context.Form)
	}
	turn.RequestRefs = refs
	return nil
}

func cloneRefs(refs []auditmodel.ObjectRef) []auditmodel.ObjectRef {
	if refs == nil {
		return nil
	}
	out := make([]auditmodel.ObjectRef, len(refs))
	for index, ref := range refs {
		out[index] = auditmodel.ObjectRef{Slot: ref.Slot, ObjectHash: bytes.Clone(ref.ObjectHash), SemanticHash: bytes.Clone(ref.SemanticHash)}
	}
	return out
}

// ObjectSource supplies the plaintext the line does not hold, from the
// segment's objects file: content objects by object_hash (the canonical JSON
// text) and binary objects by binary_hash. A missing object is an error.
type ObjectSource interface {
	ContentPlaintext(hash []byte) ([]byte, error)
	BinaryData(hash []byte) ([]byte, error)
}

// PlainDetail converts the record to the query layer's plaintext input (R.1).
//
//   - The request URI is nil and credential header values are empty: the
//     archive holds only their projections. Detail and Summary overwrite the
//     three places R.1 item 5 names with the projected forms; callers of
//     query.BuildDetail on this value directly must do the same.
//   - parsedJSON supplies the joined parsed_json when the line split it into
//     the objects file (ParsedJSONRef set); it is checked against the
//     reference. It is ignored otherwise.
//   - A turn must be materialised (Turn.Materialize) first.
//   - Audit.ConversationTurns stays nil: it is a query-time count over the
//     hot conversation, not a property of the audit (A.3).
func (record *Record) PlainDetail(objects ObjectSource, parsedJSON []byte) (query.PlainDetail, error) {
	plain := query.PlainDetail{
		Audit:  record.listRow(),
		Stages: make([]storage.HTTPStage, 0, len(record.Stages)),
		Bodies: make([]storage.BodyStream, 0, len(record.Bodies)),
	}
	for _, stage := range record.Stages {
		row := stage.HTTPStage
		row.AuditID = record.Audit.AuditID
		plain.Stages = append(plain.Stages, row)
	}
	plain.Headers = make([]headerblock.Value, 0, len(record.Headers.Values))
	for _, header := range record.Headers.Values {
		value := []byte{}
		if !header.Value.Omitted {
			value = []byte(header.Value.Value)
		}
		plain.Headers = append(plain.Headers, headerblock.Value{Stage: header.Stage, Kind: header.Kind, Name: header.Name, ValueIndex: int(header.ValueIndex), Value: value})
	}
	for _, body := range record.Bodies {
		body.AuditID = record.Audit.AuditID
		plain.Bodies = append(plain.Bodies, body)
	}
	if parsed := record.ParsedResult; parsed != nil {
		opened, err := parsed.plaintext(parsedJSON)
		if err != nil {
			return query.PlainDetail{}, err
		}
		plain.ParsedResult = &query.PlainParsedResult{Summary: parsed.summary(), ParsedJSON: opened}
	}
	if record.Turn != nil {
		graph, err := record.Turn.plainGraph(objects)
		if err != nil {
			return query.PlainDetail{}, err
		}
		plain.TurnGraph = graph
	}
	if link := record.TokenLink; link != nil {
		summary := &storage.TokenLinkSummary{
			NewAPIUserID: link.NewAPIUserID, Username: link.Username,
			NewAPITokenID: link.NewAPITokenID, TokenName: link.TokenName,
			LinkedAtNS: link.LinkedAtNS, BillingState: link.BillingState,
			Quota: link.Quota, QuotaPerUnit: link.QuotaPerUnit,
			BilledPromptTokens: link.BilledPromptTokens, BilledCompletionTokens: link.BilledCompletionTokens,
		}
		if record.Audit.NewAPIRequestID != nil {
			summary.NewAPIRequestID = *record.Audit.NewAPIRequestID
		}
		plain.TokenLink = summary
	}
	return plain, nil
}

// listRow is the summary row the store's detail and list queries build by
// joining audit_records with parsed_results, token_links and turns.
func (record *Record) listRow() storage.AuditListRow {
	audit := record.Audit
	ended := audit.EndedAtNS
	row := storage.AuditListRow{
		AuditID: audit.AuditID, StartedAtNS: audit.StartedAtNS, EndedAtNS: &ended,
		RouteID: audit.RouteID, Protocol: audit.Protocol, ParserName: audit.ParserName,
		Method: audit.Method, Path: audit.Path, Mode: audit.Mode,
		StatusCode: intPointer(audit.StatusCode), TTFTNS: audit.TTFTNS,
		ForwardStatus: audit.ForwardStatus, CaptureStatus: audit.CaptureStatus, ParseStatus: audit.ParseStatus,
		BlockedBy: audit.BlockedBy, BlockCode: audit.BlockCode, ErrorCode: audit.ErrorCode,
		NewAPIRequestID: audit.NewAPIRequestID, CallerStatus: audit.CallerStatus,
		ConversationID: record.ConversationID(), CaptureVersion: int(audit.CaptureVersion),
	}
	if parsed := record.ParsedResult; parsed != nil {
		row.RequestModel, row.ResponseModel = parsed.RequestModel, parsed.ResponseModel
		row.ParsedErrorType, row.ParsedErrorCode = parsed.ErrorType, parsed.ErrorCode
		row.UpstreamErrorClass = parsed.UpstreamErrorClass
	}
	if link := record.TokenLink; link != nil {
		userID, tokenID := link.NewAPIUserID, link.NewAPITokenID
		username, tokenName := link.Username, link.TokenName
		row.NewAPIUserID, row.NewAPITokenID = &userID, &tokenID
		row.Username, row.TokenName = &username, &tokenName
	}
	return row
}

func intPointer(value *int64) *int {
	if value == nil {
		return nil
	}
	converted := int(*value)
	return &converted
}

func (parsed *ParsedResult) summary() storage.ParsedResultSummary {
	return storage.ParsedResultSummary{
		ParserName: parsed.ParserName, ParserVersion: parsed.ParserVersion, Status: parsed.Status,
		RequestModel: parsed.RequestModel, ResponseModel: parsed.ResponseModel,
		RequestedStream: parsed.RequestedStream, ObservedStream: parsed.ObservedStream,
		ResponseID: parsed.ResponseID, UsageInput: parsed.UsageInput, UsageOutput: parsed.UsageOutput,
		UsageTotal: parsed.UsageTotal, ErrorType: parsed.ErrorType, ErrorCode: parsed.ErrorCode,
		UpstreamErrorClass: parsed.UpstreamErrorClass, MessageCount: parsed.MessageCount,
		ToolCallCount: parsed.ToolCallCount, HasToolCall: parsed.HasToolCall, ParsedAtNS: parsed.ParsedAtNS,
	}
}

// plaintext returns the parsed JSON of the row, from the line or, for a
// split one, from joined, which must match the reference.
func (parsed *ParsedResult) plaintext(joined []byte) ([]byte, error) {
	if parsed.ParsedJSONRef == nil {
		return parsed.ParsedJSON, nil
	}
	if int64(len(joined)) != parsed.ParsedJSONRef.Length || sha256Sum(joined) != parsed.ParsedJSONRef.SHA256 {
		return nil, fmt.Errorf("%w: parsed_json parts do not match the reference", ErrIntegrity)
	}
	return joined, nil
}

func (turn *Turn) plainGraph(objects ObjectSource) (*query.PlainTurnGraph, error) {
	if turn.RequestRefs == nil && turn.Row.RequestItemCount > 0 {
		return nil, ErrNotMaterialized
	}
	if objects == nil {
		return nil, errors.New("archive: nil object source")
	}
	row := turn.Row
	graph := &query.PlainTurnGraph{TurnGraph: storage.TurnGraph{
		TurnID: row.TurnID, ConversationID: row.ConversationID, ParentTurnID: row.ParentTurnID,
		ParentBase: row.ParentBase, LinkReason: row.LinkReason, LinkConfidence: int(row.LinkConfidence),
		RequestLayout: row.RequestLayout, ResponseLayout: row.ResponseLayout,
		RequestEnvelopeHash: row.RequestEnvelopeHash, ResponseEnvelopeHash: row.ResponseEnvelopeHash,
		RequestRefs: cloneRefs(turn.RequestRefs), ResponseRefs: turn.ResponseRefs(),
		RequestSequenceHash: row.RequestSequenceHash, ResponseSequenceHash: row.ResponseSequenceHash,
		RequestReconstructionHash: row.RequestReconstructionHash, ResponseReconstructionHash: row.ResponseReconstructionHash,
		ReconstructionStatus: row.ReconstructionStatus, PreviousResponseID: row.PreviousResponseID,
		ResponseID: row.ResponseID, CreatedAtNS: row.CreatedAtNS,
	}}
	if graph.RequestRefs == nil {
		graph.RequestRefs = []auditmodel.ObjectRef{}
	}
	for _, object := range turn.Objects {
		data, err := objects.ContentPlaintext(object.Hash)
		if err != nil {
			return nil, err
		}
		graph.Objects = append(graph.Objects, query.PlainObject{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind, PlaintextLength: object.PlaintextLength, Plaintext: data})
	}
	for _, binary := range turn.Binaries {
		data, err := objects.BinaryData(binary.Hash)
		if err != nil {
			return nil, err
		}
		graph.Binaries = append(graph.Binaries, query.PlainBinary{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength, Data: data})
	}
	return graph, nil
}

// Detail returns what query.Service.Get returns for this audit, after the
// credential projection: query.BuildDetail on PlainDetail, with the request
// URI, the header values and their lengths replaced by the archived
// projections (R.1 item 5). It is directly comparable with ProjectDetail of
// the hot side's Detail.
func (record *Record) Detail(objects ObjectSource, parsedJSON []byte) (ProjectedDetail, error) {
	plain, err := record.PlainDetail(objects, parsedJSON)
	if err != nil {
		return ProjectedDetail{}, err
	}
	detail, err := query.BuildDetail(plain)
	if err != nil {
		return ProjectedDetail{}, err
	}
	detail.RequestURI = ""
	detail.Headers = nil
	projected := ProjectedDetail{Detail: detail, RequestURI: record.Audit.RequestURI, Headers: append([]HeaderValue(nil), record.Headers.Values...)}
	if projected.Headers == nil {
		projected.Headers = []HeaderValue{}
	}
	return projected, nil
}

// Summary returns what query.Service.List returns for this audit's row,
// after the credential projection, with ConversationTurns nil. Its
// User-Agent is the first inbound value: version 2 from the projected
// user_agent, version 1 from the projected headers the store's
// QueryRequestHeaderEvidence selects (request_received, kind header, name
// user-agent in any case), ordered by lower-cased name, then value_index,
// then name.
func (record *Record) Summary() ProjectedSummary {
	summary := query.BuildSummary(record.listRow(), nil)
	summary.ConversationTurns = nil
	projected := ProjectedSummary{Summary: summary}
	values := record.inboundUserAgents()
	if len(values) > 0 {
		first := values[0]
		projected.UserAgent = &first
	}
	return projected
}

func (record *Record) inboundUserAgents() []ProjectedValue {
	if record.Audit.CaptureVersion != storage.CaptureVersion1 {
		return record.Audit.UserAgent
	}
	var matches []HeaderValue
	for _, header := range record.Headers.Values {
		if header.Stage == storage.StageRequestReceived && header.Kind == storage.HeaderKindHeader && strings.ToLower(header.Name) == "user-agent" {
			matches = append(matches, header)
		}
	}
	sortStable(matches, func(left, right HeaderValue) int {
		if c := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)); c != 0 {
			return c
		}
		if left.ValueIndex != right.ValueIndex {
			return compareInt(left.ValueIndex, right.ValueIndex)
		}
		return strings.Compare(left.Name, right.Name)
	})
	values := make([]ProjectedValue, 0, len(matches))
	for _, match := range matches {
		values = append(values, match.Value)
	}
	return values
}

// SelectBody returns the body_streams row that serves side, using the stage
// preference of query.RawStages, and false when no preferred stage has one.
func (record *Record) SelectBody(side query.Side) (storage.BodyStream, bool, error) {
	stages, err := query.RawStages(side)
	if err != nil {
		return storage.BodyStream{}, false, err
	}
	for _, stage := range stages {
		for _, body := range record.Bodies {
			if body.Stage == stage {
				body.AuditID = record.Audit.AuditID
				return body, true, nil
			}
		}
	}
	return storage.BodyStream{}, false, nil
}

// RawMetadata is the store's RawBodyMeta for one body row.
func (record *Record) RawMetadata(body storage.BodyStream) storage.RawBodyMetadata {
	return storage.RawBodyMetadata{
		AuditID: record.Audit.AuditID, Stage: body.Stage, SourceStage: body.SourceStage,
		RetentionState: body.RetentionState, ObservedLength: body.ObservedLength,
		StoredLength: body.StoredLength, SHA256: body.SHA256, HashComplete: body.HashComplete,
		EOFSeen: body.EOFSeen, State: body.State, ErrorCode: body.ErrorCode,
	}
}

// OwningChunks returns the raw chunks a body row is served from: those of
// its source stage, in seq order, as the store's StreamBodyChunks reads them.
func (record *Record) OwningChunks(body storage.BodyStream) []RawChunk {
	var chunks []RawChunk
	for _, chunk := range record.RawChunks {
		if chunk.Stage == body.SourceStage {
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}

// StoredTimeline is the store's QueryStreamTimeline for one body row: the
// timeline of the body's source stage, with the body's own observed length,
// and the timeline plaintext. It returns false when the source stage has no
// timeline row.
func (record *Record) StoredTimeline(body storage.BodyStream) (storage.StoredStreamTimeline, []byte, bool) {
	for _, timeline := range record.Timelines {
		if timeline.Stage != body.SourceStage {
			continue
		}
		return storage.StoredStreamTimeline{
			AuditID: record.Audit.AuditID, Stage: timeline.Stage, ObservedLength: body.ObservedLength,
			EventCount: timeline.EventCount, FirstEventAtNS: timeline.FirstEventAtNS,
			LastEventAtNS: timeline.LastEventAtNS, Complete: timeline.Complete,
			Compression: auditmodel.CompressionNone, PlaintextLength: timeline.PlaintextLength,
		}, timeline.Plaintext, true
	}
	return storage.StoredStreamTimeline{}, nil, false
}
