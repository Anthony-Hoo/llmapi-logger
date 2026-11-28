package archivecli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/query"
)

// Export kinds: the Agent facade's single-audit exports (agentExportKinds of
// internal/web, design K.1) plus detail, the whole projected query.Detail.
const (
	KindConversation     = "conversation"
	KindHeaders          = "headers"
	KindRequest          = "request"
	KindResponse         = "response"
	KindRawRequest       = "raw-request"
	KindRawResponse      = "raw-response"
	KindTimelineRequest  = "timeline-request"
	KindTimelineResponse = "timeline-response"
	KindDetail           = "detail"
)

// ExportKinds lists the kinds in help order.
var ExportKinds = []string{
	KindConversation, KindHeaders, KindRequest, KindResponse, KindRawRequest, KindRawResponse,
	KindTimelineRequest, KindTimelineResponse, KindDetail,
}

func knownKind(kind string) bool {
	for _, known := range ExportKinds {
		if known == kind {
			return true
		}
	}
	return false
}

// Export writes one export of the audit's highest revision to destination,
// built only from the bundle through the query layer's plaintext half, with
// credentials in projected form. The JSON kinds are encoded as the facade
// encodes them (encoding/json, one value and a newline); the raw kinds are
// the body bytes. A JSON export is built completely before the first byte is
// written; a raw body streams, one chunk in memory at a time.
func Export(ctx context.Context, reader *Reader, auditID, kind string, destination io.Writer) error {
	if !knownKind(kind) {
		return &cliError{code: codeUsage, message: "unknown export kind; use one of " + strings.Join(ExportKinds, ", ")}
	}
	audit, err := reader.Audit(ctx, auditID)
	if err != nil {
		return err
	}
	return ExportAudit(ctx, audit, kind, destination)
}

// ExportAudit is Export for an audit already read.
func ExportAudit(ctx context.Context, audit *AuditRecord, kind string, destination io.Writer) error {
	switch kind {
	case KindConversation:
		return ExportConversation(ctx, audit, destination)
	case KindHeaders:
		return ExportHeaders(ctx, audit, destination)
	case KindRequest:
		return ExportRequest(ctx, audit, destination)
	case KindResponse:
		return ExportResponse(ctx, audit, destination)
	case KindRawRequest:
		return ExportRaw(ctx, audit, query.SideRequest, destination)
	case KindRawResponse:
		return ExportRaw(ctx, audit, query.SideResponse, destination)
	case KindTimelineRequest:
		return ExportTimeline(audit, query.SideRequest, destination)
	case KindTimelineResponse:
		return ExportTimeline(audit, query.SideResponse, destination)
	case KindDetail:
		return ExportDetail(ctx, audit, destination)
	}
	return &cliError{code: codeUsage, message: "unknown export kind; use one of " + strings.Join(ExportKinds, ", ")}
}

// ExportConversation writes the conversation export: Detail.Conversation,
// as the facade serves it, or not_available when the record has none.
func ExportConversation(ctx context.Context, audit *AuditRecord, destination io.Writer) error {
	detail, err := audit.Detail(ctx)
	if err != nil {
		return err
	}
	if detail.Detail.Conversation == nil {
		return &cliError{code: codeNotAvailable, message: "this record has no conversation"}
	}
	return WriteConversation(destination, detail.Detail.Conversation)
}

// ExportHeaders writes the headers export in projected form.
func ExportHeaders(ctx context.Context, audit *AuditRecord, destination io.Writer) error {
	detail, err := audit.Detail(ctx)
	if err != nil {
		return err
	}
	return WriteHeaders(destination, audit.Record.Audit.AuditID, detail.Headers)
}

// ExportRequest writes the rebuilt provider request.
func ExportRequest(ctx context.Context, audit *AuditRecord, destination io.Writer) error {
	turn, err := audit.Turn(ctx)
	if err != nil {
		return err
	}
	return WriteProviderBody(destination, turn.Request)
}

// ExportResponse writes the rebuilt provider response, or not_available for
// a turn without one (response layout none), as the facade reports it.
func ExportResponse(ctx context.Context, audit *AuditRecord, destination io.Writer) error {
	turn, err := audit.Turn(ctx)
	if err != nil {
		return err
	}
	if turn.Turn.ResponseLayout == auditmodel.LayoutNone {
		return &cliError{code: codeNotAvailable, message: "this record's turn has no response"}
	}
	return WriteProviderBody(destination, turn.Response)
}

// ExportTimeline writes the stream timeline of one side.
func ExportTimeline(audit *AuditRecord, side query.Side, destination io.Writer) error {
	timeline, err := audit.Timeline(side)
	if err != nil {
		return err
	}
	return WriteTimeline(destination, timeline)
}

// ExportRaw streams the raw body of one side.
func ExportRaw(ctx context.Context, audit *AuditRecord, side query.Side, destination io.Writer) error {
	return audit.StreamRaw(ctx, side, destination)
}

// ExportDetail writes the projected detail.
func ExportDetail(ctx context.Context, audit *AuditRecord, destination io.Writer) error {
	detail, err := audit.Detail(ctx)
	if err != nil {
		return err
	}
	return WriteDetail(destination, detail)
}

// ExportConversationTurns writes the conversation export of every audit of
// the conversation in turn order, one JSON object per line:
// {"audit_id", "turn_id", "created_at_ns", "conversation"}, where
// conversation is what ExportConversation writes for that audit (null when
// the audit has none).
func ExportConversationTurns(ctx context.Context, reader *Reader, conversationID string, destination io.Writer) error {
	return reader.ConversationTurns(ctx, conversationID, func(audit *AuditRecord) error {
		detail, err := audit.Detail(ctx)
		if err != nil {
			return err
		}
		turn := audit.Record.Turn.Row
		return encodeFacadeJSON(destination, struct {
			AuditID      string                     `json:"audit_id"`
			TurnID       string                     `json:"turn_id"`
			CreatedAtNS  int64                      `json:"created_at_ns,string"`
			Conversation *conversation.Conversation `json:"conversation"`
		}{audit.Record.Audit.AuditID, turn.TurnID, turn.CreatedAtNS, detail.Detail.Conversation})
	})
}

// encodeFacadeJSON is the facade's writeJSON encoding: encoding/json's
// default encoder (HTML escaping on) with its trailing newline.
func encodeFacadeJSON(destination io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if _, err := destination.Write(encoded); err != nil {
		return &cliError{code: codeWriteFailed, message: messages[codeWriteFailed]}
	}
	return nil
}

// WriteConversation writes a conversation export.
func WriteConversation(destination io.Writer, conversation *conversation.Conversation) error {
	return encodeFacadeJSON(destination, conversation)
}

// WriteProviderBody writes a rebuilt provider request or response.
func WriteProviderBody(destination io.Writer, body any) error {
	return encodeFacadeJSON(destination, body)
}

// ProjectedHeader is one header of the headers export: the facade's shape
// (stage, kind, name_untrusted, value_index, then value_untrusted or
// value_omitted, and length) with the keyed fingerprint value_fpr of an
// omitted credential (design D.3, D.4).
type ProjectedHeader struct {
	Stage          string  `json:"stage"`
	Kind           string  `json:"kind"`
	Name           string  `json:"name_untrusted"`
	ValueIndex     int64   `json:"value_index"`
	ValueUntrusted *string `json:"value_untrusted,omitempty"`
	ValueOmitted   string  `json:"value_omitted,omitempty"`
	Length         int64   `json:"length"`
	ValueFPR       string  `json:"value_fpr,omitempty"`
}

// ProjectHeaderList converts projected header values to the export shape.
// A value that is not valid UTF-8 is shown with U+FFFD, as the facade shows
// it; length stays the byte length of the stored value.
func ProjectHeaderList(headers []archive.HeaderValue) []ProjectedHeader {
	out := make([]ProjectedHeader, 0, len(headers))
	for _, header := range headers {
		item := ProjectedHeader{Stage: header.Stage, Kind: header.Kind, Name: header.Name, ValueIndex: header.ValueIndex}
		if header.Value.Omitted {
			item.ValueOmitted = archive.OmittedCredential
			item.Length = header.Value.Length
			item.ValueFPR = hex.EncodeToString(header.Value.Fingerprint[:])
		} else {
			value := header.Value.Value
			item.Length = int64(len(value))
			if !utf8.ValidString(value) {
				value = strings.ToValidUTF8(value, "�")
			}
			item.ValueUntrusted = &value
		}
		out = append(out, item)
	}
	return out
}

// WriteHeaders writes the headers export: {"audit_id", "headers": [...]}.
func WriteHeaders(destination io.Writer, auditID string, headers []archive.HeaderValue) error {
	return encodeFacadeJSON(destination, struct {
		AuditID string            `json:"audit_id"`
		Headers []ProjectedHeader `json:"headers"`
	}{auditID, ProjectHeaderList(headers)})
}

// TimelineExport is the facade's timeline export shape.
type TimelineExport struct {
	Stage          string          `json:"stage"`
	ObservedLength int64           `json:"observed_length"`
	EventCount     int64           `json:"event_count"`
	FirstEventAt   *string         `json:"first_event_at"`
	LastEventAt    *string         `json:"last_event_at"`
	Complete       bool            `json:"complete"`
	Points         []TimelinePoint `json:"points"`
}

// TimelinePoint is one point of TimelineExport.
type TimelinePoint struct {
	Offset     int64   `json:"offset"`
	ObservedAt *string `json:"observed_at"`
}

// TimelineOf converts the query layer's timeline to the export shape, with
// times as RFC 3339 UTC as the facade writes them.
func TimelineOf(timeline query.StreamTimeline) TimelineExport {
	out := TimelineExport{
		Stage: timeline.Stage, ObservedLength: timeline.ObservedLength, EventCount: timeline.EventCount,
		FirstEventAt: timePointer(timeline.FirstEventAtNS), LastEventAt: timePointer(timeline.LastEventAtNS),
		Complete: timeline.Complete, Points: make([]TimelinePoint, 0, len(timeline.Points)),
	}
	for _, point := range timeline.Points {
		out.Points = append(out.Points, TimelinePoint{Offset: point.Offset, ObservedAt: timeText(point.AtNS)})
	}
	return out
}

// WriteTimeline writes a timeline export.
func WriteTimeline(destination io.Writer, timeline query.StreamTimeline) error {
	return encodeFacadeJSON(destination, TimelineOf(timeline))
}

func timeText(ns int64) *string {
	if ns == 0 {
		return nil
	}
	formatted := time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
	return &formatted
}

func timePointer(ns *int64) *string {
	if ns == nil {
		return nil
	}
	return timeText(*ns)
}

// ProjectedValueJSON is a projected Header or User-Agent value as the detail
// export writes it: {"value"} or {"value_omitted", "length", "value_fpr"}.
type ProjectedValueJSON struct {
	Value        *string `json:"value,omitempty"`
	ValueOmitted string  `json:"value_omitted,omitempty"`
	Length       *int64  `json:"length,omitempty"`
	ValueFPR     string  `json:"value_fpr,omitempty"`
}

func projectedValueJSON(value archive.ProjectedValue) ProjectedValueJSON {
	if value.Omitted {
		length := value.Length
		return ProjectedValueJSON{ValueOmitted: archive.OmittedCredential, Length: &length, ValueFPR: hex.EncodeToString(value.Fingerprint[:])}
	}
	text := value.Value
	return ProjectedValueJSON{Value: &text}
}

// RequestURIJSON is the projected Request-URI of design D.3.
type RequestURIJSON struct {
	Path     string             `json:"path"`
	HasQuery bool               `json:"has_query"`
	Segments []QuerySegmentJSON `json:"segments"`
}

// QuerySegmentJSON is one query segment: {"raw"} or the credential form.
type QuerySegmentJSON struct {
	Raw          *string `json:"raw,omitempty"`
	RawName      *string `json:"raw_name,omitempty"`
	HasEquals    *bool   `json:"has_equals,omitempty"`
	ValueOmitted string  `json:"value_omitted,omitempty"`
	Length       *int64  `json:"length,omitempty"`
	ValueFPR     string  `json:"value_fpr,omitempty"`
}

func requestURIJSON(uri archive.RequestURI) RequestURIJSON {
	out := RequestURIJSON{Path: uri.Path, HasQuery: uri.HasQuery, Segments: make([]QuerySegmentJSON, 0, len(uri.Segments))}
	for _, segment := range uri.Segments {
		if !segment.Credential {
			raw := segment.Raw
			out.Segments = append(out.Segments, QuerySegmentJSON{Raw: &raw})
			continue
		}
		name, equals, length := segment.RawName, segment.HasEquals, segment.Length
		out.Segments = append(out.Segments, QuerySegmentJSON{RawName: &name, HasEquals: &equals, ValueOmitted: archive.OmittedCredential,
			Length: &length, ValueFPR: hex.EncodeToString(segment.Fingerprint[:])})
	}
	return out
}

// DetailHeader is one header of the detail export.
type DetailHeader struct {
	Stage      string `json:"stage"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	ValueIndex int64  `json:"value_index"`
	ProjectedValueJSON
}

// DetailExport is query.Detail as the archive can give it: request_uri and
// headers in projected form, audit.user_agent replaced by the projected
// user_agent (always null in a detail: query.Service.Get does not fill it).
type DetailExport struct {
	Audit        query.AuditSummary         `json:"audit"`
	UserAgent    *ProjectedValueJSON        `json:"user_agent"`
	RequestURI   RequestURIJSON             `json:"request_uri"`
	Stages       []query.Stage              `json:"stages"`
	Headers      []DetailHeader             `json:"headers"`
	Bodies       []query.Body               `json:"bodies"`
	ParsedResult *query.ParsedResult        `json:"parsed_result"`
	Turn         *query.Turn                `json:"turn"`
	Conversation *conversation.Conversation `json:"conversation"`
	TokenLink    *query.TokenLink           `json:"token_link"`
}

// DetailOf converts a projected detail to the detail export shape.
func DetailOf(projected archive.ProjectedDetail) DetailExport {
	detail := projected.Detail
	out := DetailExport{
		Audit: detail.Audit, RequestURI: requestURIJSON(projected.RequestURI), Stages: detail.Stages,
		Headers: make([]DetailHeader, 0, len(projected.Headers)), Bodies: detail.Bodies, ParsedResult: detail.ParsedResult,
		Turn: detail.Turn, Conversation: detail.Conversation, TokenLink: detail.TokenLink,
	}
	if projected.UserAgent != nil {
		value := projectedValueJSON(*projected.UserAgent)
		out.UserAgent = &value
	}
	for _, header := range projected.Headers {
		out.Headers = append(out.Headers, DetailHeader{Stage: header.Stage, Kind: header.Kind, Name: header.Name,
			ValueIndex: header.ValueIndex, ProjectedValueJSON: projectedValueJSON(header.Value)})
	}
	return out
}

// WriteDetail writes the detail export.
func WriteDetail(destination io.Writer, projected archive.ProjectedDetail) error {
	return encodeFacadeJSON(destination, DetailOf(projected))
}
