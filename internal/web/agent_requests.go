package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// Audit records on the facade (contract section 4.3.1). Every per-record
// endpoint passes authorizeAuditRead first, the gate the web uses, so a
// developer reads another key's record nowhere (D1-D3).

const agentCursorAudits = "audits"

// Unified audit states (contract section 4.1).
const (
	auditStateRunning   = "running"
	auditStateSucceeded = "succeeded"
	auditStateFailed    = "failed"
	auditStateBlocked   = "blocked"
	auditStateCancelled = "cancelled"
)

// auditState maps forward_status and status_code onto the unified state.
func auditState(forwardStatus string, statusCode *int) string {
	switch forwardStatus {
	case storage.ForwardInProgress:
		return auditStateRunning
	case storage.ForwardCompleted:
		if statusCode != nil && *statusCode >= 100 && *statusCode <= 399 {
			return auditStateSucceeded
		}
		return auditStateFailed
	case storage.ForwardRejected:
		return auditStateBlocked
	case storage.ForwardClientCancelled:
		return auditStateCancelled
	default:
		// newapi_error, proxy_error, interrupted and anything newer.
		return auditStateFailed
	}
}

// auditParse folds parse_status into the facade's parse field.
func auditParse(parseStatus string) string {
	if parseStatus == storage.ParsePending || parseStatus == storage.ParseProcessing {
		return "pending"
	}
	return parseStatus
}

// auditCapture renames the stored capture_chunk_missing.
func auditCapture(captureStatus string) string {
	if captureStatus == storage.CaptureChunkMissing {
		return "chunk_missing"
	}
	return captureStatus
}

// Incomplete reasons of an audit detail.
const (
	auditIncompleteInProgress = "in_progress"
	auditIncompleteParse      = "parse_pending"
	auditIncompleteCapture    = "capture_incomplete"
)

// auditDetailMeta is the meta of one audit record.
func auditDetailMeta(summary query.AuditSummary) agentapi.Meta {
	meta := agentapi.Meta{State: auditState(summary.ForwardStatus, summary.StatusCode), Complete: true}
	switch {
	case summary.ForwardStatus == storage.ForwardInProgress:
		meta.Complete, meta.IncompleteReason = false, auditIncompleteInProgress
	case auditParse(summary.ParseStatus) == "pending":
		meta.Complete, meta.IncompleteReason = false, auditIncompleteParse
	case summary.CaptureStatus != storage.CaptureComplete:
		meta.Complete, meta.IncompleteReason = false, auditIncompleteCapture
	}
	return meta
}

type agentCallerView struct {
	UserID               *int64  `json:"user_id"`
	UsernameUntrusted    *string `json:"username_untrusted"`
	DisplayNameUntrusted *string `json:"display_name_untrusted"`
	TokenID              *int64  `json:"token_id"`
	TokenNameUntrusted   *string `json:"token_name_untrusted"`
}

// agentAuditItem is one audit in the list and the head of a detail.
type agentAuditItem struct {
	AuditID            string          `json:"audit_id"`
	State              string          `json:"state"`
	StartedAt          *string         `json:"started_at"`
	EndedAt            *string         `json:"ended_at"`
	RouteID            string          `json:"route_id"`
	Protocol           string          `json:"protocol"`
	ParserName         string          `json:"parser_name"`
	Method             string          `json:"method"`
	Path               string          `json:"path"`
	Mode               string          `json:"mode"`
	StatusCode         *int            `json:"status_code"`
	TTFTMS             *float64        `json:"ttft_ms"`
	ForwardStatus      string          `json:"forward_status"`
	Parse              string          `json:"parse"`
	Capture            string          `json:"capture"`
	CallerStatus       string          `json:"caller_status"`
	CallerFinal        bool            `json:"caller_final"`
	RequestModel       *string         `json:"request_model"`
	ResponseModel      *string         `json:"response_model"`
	BlockedBy          *string         `json:"blocked_by"`
	BlockCode          *string         `json:"block_code"`
	ErrorCode          *string         `json:"error_code"`
	ParsedErrorType    *string         `json:"parsed_error_type"`
	ParsedErrorCode    *string         `json:"parsed_error_code"`
	UpstreamErrorClass *string         `json:"upstream_error_class"`
	NewAPIRequestID    *string         `json:"newapi_request_id"`
	Caller             agentCallerView `json:"caller"`
	UserAgentUntrusted *string         `json:"user_agent_untrusted"`
	ConversationID     *string         `json:"conversation_id"`
	ConversationTurns  *int64          `json:"conversation_turns"`
}

func agentAuditItemOf(summary query.AuditSummary) agentAuditItem {
	return agentAuditItem{
		AuditID: summary.AuditID, State: auditState(summary.ForwardStatus, summary.StatusCode),
		StartedAt: agentTime(summary.StartedAtNS), EndedAt: agentTimePointer(summary.EndedAtNS),
		RouteID: summary.RouteID, Protocol: summary.Protocol, ParserName: summary.ParserName,
		Method: summary.Method, Path: summary.Path, Mode: summary.Mode,
		StatusCode: summary.StatusCode, TTFTMS: agentMillis(summary.TTFTNS),
		ForwardStatus: summary.ForwardStatus,
		Parse:         auditParse(summary.ParseStatus), Capture: auditCapture(summary.CaptureStatus),
		CallerStatus: summary.CallerStatus, CallerFinal: summary.CallerStatus != storage.CallerPending,
		RequestModel: summary.RequestModel, ResponseModel: summary.ResponseModel,
		BlockedBy: summary.BlockedBy, BlockCode: summary.BlockCode, ErrorCode: summary.ErrorCode,
		ParsedErrorType: summary.ParsedErrorType, ParsedErrorCode: summary.ParsedErrorCode,
		UpstreamErrorClass: summary.UpstreamErrorClass, NewAPIRequestID: summary.NewAPIRequestID,
		Caller: agentCallerView{
			UserID: summary.NewAPIUserID, UsernameUntrusted: summary.Username, DisplayNameUntrusted: summary.DisplayName,
			TokenID: summary.NewAPITokenID, TokenNameUntrusted: summary.TokenName,
		},
		UserAgentUntrusted: summary.UserAgent,
		ConversationID:     summary.ConversationID, ConversationTurns: summary.ConversationTurns,
	}
}

type agentAuditList struct {
	Items           []agentAuditItem `json:"items"`
	NextCursor      string           `json:"next_cursor"`
	CollapseApplied bool             `json:"collapse_applied"`
}

// agentCallerFilterKeys are the facade names of the caller filters (D4).
var agentCallerFilterKeys = []string{"user_id", "username", "token_id", "token_name"}

const agentEmptyPageAction = "This page is empty but there is a next page: run the same command again with the returned cursor (--cursor)."

// serveAgentRequests is GET /requests, the equivalent of GET /api/v1/audits.
func (handler *managementHandler) serveAgentRequests(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if handler.query == nil {
		handler.writeAgentServiceFailure(writer, errAgentUnavailable, "")
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	filter, cursor, limit, err := handler.agentAuditFilter(values, call.Principal)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	scopeAuditFilter(call.Principal, &filter)
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	page, err := handler.query.List(ctx, filter, cursor, limit)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	handler.addCallerDisplayNames(page.Items)
	list := agentAuditList{Items: make([]agentAuditItem, 0, len(page.Items)), CollapseApplied: filter.Collapses()}
	for _, item := range page.Items {
		list.Items = append(list.Items, agentAuditItemOf(item))
	}
	if page.NextCursor != nil {
		list.NextCursor = wrapAgentCursor(agentCursorAudits, strconv.FormatInt(page.NextCursor.BeforeStartedAtNS, 10)+":"+page.NextCursor.BeforeID)
	}
	var actions []string
	if len(list.Items) == 0 && list.NextCursor != "" {
		actions = append(actions, agentEmptyPageAction)
	}
	writeAgentRead(writer, list, agentMetaOK(), true, actions...)
}

func (handler *managementHandler) agentAuditFilter(values url.Values, caller principal) (query.Filter, query.Cursor, int, error) {
	var filter query.Filter
	var cursor query.Cursor
	if !callerMayFilterByCaller(caller) {
		for _, key := range agentCallerFilterKeys {
			if values.Has(key) {
				return filter, cursor, 0, argError(key)
			}
		}
	}
	limit, err := parseAgentLimit(values, query.DefaultLimit, query.MaxLimit)
	if err != nil {
		return filter, cursor, 0, err
	}
	timeRange, err := parseAgentRange(values, handler.agent.Now())
	if err != nil {
		return filter, cursor, 0, err
	}
	filter.FromNS = timeRange.FromNS
	if timeRange.ToNS != nil {
		// The audit list's to_ns includes its end point; the facade's to does not.
		inclusive := *timeRange.ToNS - 1
		filter.ToNS = &inclusive
	}
	if status := values.Get("status"); values.Has("status") {
		switch status {
		case "error", "4xx", "5xx":
			filter.StatusClass = status
		default:
			code, ok := parseAgentID(status, false)
			if !ok || code < 100 || code > 599 {
				return filter, cursor, 0, argError("status")
			}
			value := int(code)
			filter.StatusCode = &value
		}
	}
	for _, numeric := range []struct {
		name   string
		target **int64
	}{{"user_id", &filter.NewAPIUserID}, {"token_id", &filter.NewAPITokenID}} {
		if !values.Has(numeric.name) {
			continue
		}
		id, ok := parseAgentID(values.Get(numeric.name), false)
		if !ok {
			return filter, cursor, 0, argError(numeric.name)
		}
		*numeric.target = &id
	}
	if values.Has("capture_status") && values.Get("capture_status") == "chunk_missing" {
		// The service accepts only the four states it filters on (contract
		// section 0, row 6); chunk_missing appears in results only.
		return filter, cursor, 0, argError("capture_status")
	}
	collapse, err := parseAgentBool(values, "collapse", true)
	if err != nil {
		return filter, cursor, 0, err
	}
	inner, err := unwrapAgentCursor(agentCursorAudits, values.Get("cursor"))
	if err != nil {
		return filter, cursor, 0, err
	}
	if inner != "" {
		timeText, id, ok := strings.Cut(inner, ":")
		at, parsed := parseAgentID(timeText, false)
		if !ok || !parsed || at <= 0 || id == "" {
			return filter, cursor, 0, argError("cursor")
		}
		cursor = query.Cursor{BeforeStartedAtNS: at, BeforeID: id}
	}
	filter.Protocol = values.Get("protocol")
	filter.Path = values.Get("path")
	filter.Model = values.Get("model")
	filter.UserAgent = values.Get("user_agent")
	filter.ForwardStatus = values.Get("forward_status")
	filter.BlockedBy = values.Get("blocked_by")
	filter.BlockCode = values.Get("block_code")
	filter.CaptureStatus = values.Get("capture_status")
	filter.UpstreamErrorClass = values.Get("upstream_error_class")
	filter.Conversation = values.Get("conversation")
	filter.Username = values.Get("username")
	filter.TokenName = values.Get("token_name")
	filter.CollapseConversations = collapse
	return filter, cursor, limit, nil
}

// authorizeAgentAudit runs the shared ownership gate for one audit id.
func (handler *managementHandler) authorizeAgentAudit(ctx context.Context, call agentCall) (string, error) {
	if handler.query == nil {
		return "", errAgentUnavailable
	}
	auditID := call.Params["id"]
	if err := authorizeAuditRead(ctx, handler.query, call.Principal, auditID); err != nil {
		return "", err
	}
	return auditID, nil
}

// Detail sub-objects. Field names follow the service types with times as
// _at and credential values masked.

type agentQueryParam struct {
	Name string `json:"name"`
	agentapi.MaskedValue
}

type agentRequestURI struct {
	Path  string            `json:"path"`
	Query []agentQueryParam `json:"query"`
	// QueryUnparsed is set when the query string could not be split into
	// parameters; no value is output then.
	QueryUnparsed bool `json:"query_unparsed,omitempty"`
}

// OmittedUnparsed is the value_omitted reason of a query parameter whose
// encoding could not be decoded: it is withheld rather than guessed at.
const omittedUnparsed = "unparsed"

// agentRequestURIOf splits a Request-URI into its path and masked query
// parameters (contract section 4.3.2). The raw query string never leaves.
func agentRequestURIOf(requestURI string) agentRequestURI {
	path, rawQuery, _ := strings.Cut(requestURI, "?")
	if cut := strings.IndexByte(rawQuery, '#'); cut >= 0 {
		rawQuery = rawQuery[:cut]
	}
	result := agentRequestURI{Path: path, Query: []agentQueryParam{}}
	if rawQuery == "" {
		return result
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, nameErr := url.QueryUnescape(rawName)
		value, valueErr := url.QueryUnescape(rawValue)
		if nameErr != nil || valueErr != nil {
			result.QueryUnparsed = true
			if nameErr != nil {
				name = rawName
			}
			result.Query = append(result.Query, agentQueryParam{Name: name,
				MaskedValue: agentapi.MaskedValue{ValueOmitted: omittedUnparsed, Length: len(rawValue)}})
			continue
		}
		result.Query = append(result.Query, agentQueryParam{Name: name, MaskedValue: agentapi.MaskValue(name, value)})
	}
	return result
}

type agentStage struct {
	Stage         string  `json:"stage"`
	State         string  `json:"state"`
	Proto         string  `json:"proto"`
	Method        string  `json:"method"`
	Host          string  `json:"host"`
	StatusCode    *int    `json:"status_code"`
	ContentLength *int64  `json:"content_length"`
	StartedAt     *string `json:"started_at"`
	EndedAt       *string `json:"ended_at"`
	ErrorCode     *string `json:"error_code"`
}

type agentHeader struct {
	Stage      string `json:"stage"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	ValueIndex int    `json:"value_index"`
	agentapi.MaskedValue
}

func agentHeadersOf(headers []query.Header, all bool) []agentHeader {
	out := make([]agentHeader, 0, len(headers))
	for _, header := range headers {
		if !all && header.Stage != storage.StageRequestReceived {
			continue
		}
		masked := agentapi.MaskValue(header.Name, header.Value)
		masked.Length = header.ValueLength
		out = append(out, agentHeader{Stage: header.Stage, Kind: header.Kind, Name: header.Name, ValueIndex: header.ValueIndex, MaskedValue: masked})
	}
	return out
}

type agentBody struct {
	Stage                  string  `json:"stage"`
	SourceStage            string  `json:"source_stage"`
	ObservedLength         int64   `json:"observed_length"`
	StoredLength           int64   `json:"stored_length"`
	SHA256                 *string `json:"sha256"`
	HashComplete           bool    `json:"hash_complete"`
	EOFSeen                bool    `json:"eof_seen"`
	State                  string  `json:"state"`
	RetentionState         string  `json:"retention_state"`
	FirstObservedAt        *string `json:"first_observed_at"`
	LastObservedAt         *string `json:"last_observed_at"`
	ChunkCount             int64   `json:"chunk_count"`
	StreamEventCount       int64   `json:"stream_event_count"`
	StreamTimelineComplete bool    `json:"stream_timeline_complete"`
	ErrorCode              *string `json:"error_code"`
}

type agentParsed struct {
	ParserName         string  `json:"parser_name"`
	ParserVersion      string  `json:"parser_version"`
	Status             string  `json:"status"`
	RequestModel       *string `json:"request_model"`
	ResponseModel      *string `json:"response_model"`
	RequestedStream    *bool   `json:"requested_stream"`
	ObservedStream     *bool   `json:"observed_stream"`
	ResponseID         *string `json:"response_id"`
	UsageInput         *int64  `json:"usage_input"`
	UsageOutput        *int64  `json:"usage_output"`
	UsageTotal         *int64  `json:"usage_total"`
	ErrorType          *string `json:"error_type"`
	ErrorCode          *string `json:"error_code"`
	UpstreamErrorClass *string `json:"upstream_error_class"`
	MessageCount       *int64  `json:"message_count"`
	ToolCallCount      *int64  `json:"tool_call_count"`
	HasToolCall        *bool   `json:"has_tool_call"`
	ParsedAt           *string `json:"parsed_at"`
}

type agentTurn struct {
	TurnID                       string  `json:"turn_id"`
	ConversationID               string  `json:"conversation_id"`
	ParentTurnID                 *string `json:"parent_turn_id"`
	ParentBase                   string  `json:"parent_base"`
	LinkReason                   string  `json:"link_reason"`
	LinkConfidence               int     `json:"link_confidence"`
	RequestLayout                string  `json:"request_layout"`
	ResponseLayout               string  `json:"response_layout"`
	RequestItemCount             int     `json:"request_item_count"`
	ResponseItemCount            int     `json:"response_item_count"`
	RequestSequenceSHA256        string  `json:"request_sequence_sha256"`
	ResponseSequenceSHA256       string  `json:"response_sequence_sha256"`
	RequestReconstructionSHA256  string  `json:"request_reconstruction_sha256"`
	ResponseReconstructionSHA256 string  `json:"response_reconstruction_sha256"`
	ReconstructionStatus         string  `json:"reconstruction_status"`
	PreviousResponseID           *string `json:"previous_response_id"`
	ResponseID                   *string `json:"response_id"`
	CreatedAt                    *string `json:"created_at"`
}

type agentBilling struct {
	NewAPIRequestID        string   `json:"newapi_request_id"`
	UserID                 int64    `json:"user_id"`
	UsernameUntrusted      string   `json:"username_untrusted"`
	TokenID                int64    `json:"token_id"`
	TokenNameUntrusted     string   `json:"token_name_untrusted"`
	LinkedAt               *string  `json:"linked_at"`
	BillingState           string   `json:"billing_state"`
	NewAPIQuota            *int64   `json:"newapi_quota"`
	CostUSD                *float64 `json:"cost_usd"`
	BilledPromptTokens     *int64   `json:"billed_prompt_tokens"`
	BilledCompletionTokens *int64   `json:"billed_completion_tokens"`
}

type agentConversationSummary struct {
	MessageCount  int            `json:"message_count"`
	Roles         map[string]int `json:"roles"`
	ToolCallCount int            `json:"tool_call_count"`
}

type agentAuditDetail struct {
	agentAuditItem
	BillingFinal        bool                      `json:"billing_final"`
	RequestURI          agentRequestURI           `json:"request_uri"`
	Stages              []agentStage              `json:"stages"`
	Headers             []agentHeader             `json:"headers"`
	HeadersScope        string                    `json:"headers_scope"`
	Bodies              []agentBody               `json:"bodies"`
	Parsed              *agentParsed              `json:"parsed"`
	Turn                *agentTurn                `json:"turn"`
	Billing             *agentBilling             `json:"billing"`
	ConversationSummary *agentConversationSummary `json:"conversation_summary"`
}

func agentAuditDetailOf(detail query.Detail, allHeaders bool) agentAuditDetail {
	out := agentAuditDetail{
		agentAuditItem: agentAuditItemOf(detail.Audit),
		BillingFinal:   detail.TokenLink == nil || detail.TokenLink.BillingState != storage.BillingUnchecked,
		RequestURI:     agentRequestURIOf(detail.RequestURI),
		Stages:         make([]agentStage, 0, len(detail.Stages)),
		Headers:        agentHeadersOf(detail.Headers, allHeaders),
		HeadersScope:   "inbound",
		Bodies:         make([]agentBody, 0, len(detail.Bodies)),
	}
	if allHeaders {
		out.HeadersScope = "all"
	}
	for _, stage := range detail.Stages {
		out.Stages = append(out.Stages, agentStage{
			Stage: stage.Stage, State: stage.State, Proto: stage.Proto, Method: stage.Method, Host: stage.Host,
			StatusCode: stage.StatusCode, ContentLength: stage.ContentLength,
			StartedAt: agentTime(stage.StartedAtNS), EndedAt: agentTimePointer(stage.EndedAtNS), ErrorCode: stage.ErrorCode,
		})
	}
	for _, body := range detail.Bodies {
		out.Bodies = append(out.Bodies, agentBody{
			Stage: body.Stage, SourceStage: body.SourceStage, ObservedLength: body.ObservedLength, StoredLength: body.StoredLength,
			SHA256: body.SHA256, HashComplete: body.HashComplete, EOFSeen: body.EOFSeen, State: body.State,
			RetentionState: body.RetentionState, FirstObservedAt: agentTimePointer(body.FirstObservedAtNS),
			LastObservedAt: agentTimePointer(body.LastObservedAtNS), ChunkCount: body.ChunkCount,
			StreamEventCount: body.StreamEventCount, StreamTimelineComplete: body.StreamTimelineComplete, ErrorCode: body.ErrorCode,
		})
	}
	if parsed := detail.ParsedResult; parsed != nil {
		out.Parsed = &agentParsed{
			ParserName: parsed.ParserName, ParserVersion: parsed.ParserVersion, Status: parsed.Status,
			RequestModel: parsed.RequestModel, ResponseModel: parsed.ResponseModel,
			RequestedStream: parsed.RequestedStream, ObservedStream: parsed.ObservedStream, ResponseID: parsed.ResponseID,
			UsageInput: parsed.UsageInput, UsageOutput: parsed.UsageOutput, UsageTotal: parsed.UsageTotal,
			ErrorType: parsed.ErrorType, ErrorCode: parsed.ErrorCode, UpstreamErrorClass: parsed.UpstreamErrorClass,
			MessageCount: parsed.MessageCount, ToolCallCount: parsed.ToolCallCount, HasToolCall: parsed.HasToolCall,
			ParsedAt: agentTime(parsed.ParsedAtNS),
		}
	}
	if turn := detail.Turn; turn != nil {
		out.Turn = &agentTurn{
			TurnID: turn.TurnID, ConversationID: turn.ConversationID, ParentTurnID: turn.ParentTurnID,
			ParentBase: turn.ParentBase, LinkReason: turn.LinkReason, LinkConfidence: turn.LinkConfidence,
			RequestLayout: turn.RequestLayout, ResponseLayout: turn.ResponseLayout,
			RequestItemCount: turn.RequestItemCount, ResponseItemCount: turn.ResponseItemCount,
			RequestSequenceSHA256: turn.RequestSequenceSHA256, ResponseSequenceSHA256: turn.ResponseSequenceSHA256,
			RequestReconstructionSHA256:  turn.RequestReconstructionSHA256,
			ResponseReconstructionSHA256: turn.ResponseReconstructionSHA256,
			ReconstructionStatus:         turn.ReconstructionStatus, PreviousResponseID: turn.PreviousResponseID,
			ResponseID: turn.ResponseID, CreatedAt: agentTime(turn.CreatedAtNS),
		}
	}
	if link := detail.TokenLink; link != nil {
		out.Billing = &agentBilling{
			NewAPIRequestID: link.NewAPIRequestID, UserID: link.NewAPIUserID, UsernameUntrusted: link.Username,
			TokenID: link.NewAPITokenID, TokenNameUntrusted: link.TokenName, LinkedAt: agentTime(link.LinkedAtNS),
			BillingState: link.BillingState, NewAPIQuota: link.NewAPIQuota, CostUSD: link.CostUSD,
			BilledPromptTokens: link.BilledPromptTokens, BilledCompletionTokens: link.BilledCompletionTokens,
		}
	}
	if detail.Conversation != nil {
		summary := &agentConversationSummary{Roles: map[string]int{}}
		for _, message := range detail.Conversation.Messages {
			summary.MessageCount++
			summary.Roles[message.Role]++
			for _, part := range message.Content {
				if part.Type == conversation.PartToolCall {
					summary.ToolCallCount++
				}
			}
		}
		out.ConversationSummary = summary
	}
	return out
}

// serveAgentRequest is GET /requests/{id}.
func (handler *managementHandler) serveAgentRequest(writer http.ResponseWriter, request *http.Request, call agentCall) {
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	allHeaders := false
	if values.Has("headers") {
		if values.Get("headers") != "all" {
			handler.writeAgentServiceFailure(writer, argError("headers"), "")
			return
		}
		allHeaders = true
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	detail, err := handler.agentAuditDetail(ctx, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentAuditDetailOf(detail, allHeaders), auditDetailMeta(detail.Audit), true)
}

func (handler *managementHandler) agentAuditDetail(ctx context.Context, call agentCall) (query.Detail, error) {
	auditID, err := handler.authorizeAgentAudit(ctx, call)
	if err != nil {
		return query.Detail{}, err
	}
	detail, err := handler.query.Get(ctx, auditID, callerReadScope(call.Principal))
	if err != nil {
		return query.Detail{}, err
	}
	addCallerDisplayName(&detail.Audit, handler.callerDisplayNames())
	if detail.Audit.UserAgent == nil {
		// query.Service.Get does not fill the User-Agent the list shows;
		// take it from the decrypted inbound headers the detail carries, by
		// the list's own rule (the first User-Agent value).
		detail.Audit.UserAgent = inboundUserAgent(detail.Headers)
	}
	return detail, nil
}

// inboundUserAgent is the first User-Agent value of the inbound request
// headers, or nil without one: the value the audit list shows.
func inboundUserAgent(headers []query.Header) *string {
	for _, header := range headers {
		if header.Stage == storage.StageRequestReceived && header.Kind == storage.HeaderKindHeader && strings.EqualFold(header.Name, "user-agent") {
			value := header.Value
			return &value
		}
	}
	return nil
}

// Export kinds of GET /requests/{id}/export/{what}.
var agentExportKinds = map[string]bool{
	"conversation": true, "headers": true, "request": true, "response": true,
	"raw-request": true, "raw-response": true, "timeline-request": true, "timeline-response": true,
}

type agentTimelinePoint struct {
	Offset     int64   `json:"offset"`
	ObservedAt *string `json:"observed_at"`
}

type agentTimeline struct {
	Stage          string               `json:"stage"`
	ObservedLength int64                `json:"observed_length"`
	EventCount     int64                `json:"event_count"`
	FirstEventAt   *string              `json:"first_event_at"`
	LastEventAt    *string              `json:"last_event_at"`
	Complete       bool                 `json:"complete"`
	Points         []agentTimelinePoint `json:"points"`
}

// serveAgentRequestExport is GET /requests/{id}/export/{what}. It answers the
// content itself, not an envelope; errors are failure envelopes.
func (handler *managementHandler) serveAgentRequestExport(writer http.ResponseWriter, request *http.Request, call agentCall) {
	what := call.Params["what"]
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	if !agentExportKinds[what] {
		handler.writeAgentServiceFailure(writer, argError("what"), "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	auditID, err := handler.authorizeAgentAudit(ctx, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	// Every export says whether it is complete, from the record's state
	// exactly as `requests get` derives meta (and, for a timeline or a raw
	// body, from the content's own completeness too).
	detail, err := handler.query.Get(ctx, auditID, callerReadScope(call.Principal))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	record := auditDetailMeta(detail.Audit)
	switch what {
	case "conversation", "headers":
		if what == "headers" {
			setExportCompleteness(writer.Header(), record, true, "")
			writeJSON(writer, http.StatusOK, map[string]any{"audit_id": auditID, "headers": agentHeadersOf(detail.Headers, true)})
			return
		}
		if detail.Conversation == nil {
			writeAgentFailure(writer, agentapi.CodeNotFound, "the record has no parsed conversation",
				"The record has not been parsed yet or carries no conversation. Check `parse` with `llmaudit requests get <id>`.", nil)
			return
		}
		setExportCompleteness(writer.Header(), record, true, "")
		writeJSON(writer, http.StatusOK, detail.Conversation)
	case "request", "response":
		reconstructed, err := handler.query.ReconstructTurn(ctx, auditID)
		if err != nil {
			handler.writeAgentServiceFailure(writer, err, "")
			return
		}
		body := reconstructed.Request
		if what == "response" {
			body = reconstructed.Response
		}
		setExportCompleteness(writer.Header(), record, true, "")
		writeJSON(writer, http.StatusOK, body)
	case "timeline-request", "timeline-response":
		timeline, err := handler.query.Timeline(ctx, auditID, query.Side(strings.TrimPrefix(what, "timeline-")))
		if err != nil {
			handler.writeAgentServiceFailure(writer, err, "")
			return
		}
		out := agentTimeline{
			Stage: timeline.Stage, ObservedLength: timeline.ObservedLength, EventCount: timeline.EventCount,
			FirstEventAt: agentTimePointer(timeline.FirstEventAtNS), LastEventAt: agentTimePointer(timeline.LastEventAtNS),
			Complete: timeline.Complete, Points: make([]agentTimelinePoint, 0, len(timeline.Points)),
		}
		for _, point := range timeline.Points {
			out.Points = append(out.Points, agentTimelinePoint{Offset: point.Offset, ObservedAt: agentTime(point.AtNS)})
		}
		setExportCompleteness(writer.Header(), record, timeline.Complete, exportIncompleteTimeline)
		writeJSON(writer, http.StatusOK, out)
	default:
		handler.serveAgentRaw(writer, ctx, auditID, query.Side(strings.TrimPrefix(what, "raw-")), record)
	}
}

// Completeness headers of an export (contract section 0.1 item 96). The
// export body is the content itself, so whether it is complete travels in
// headers: X-Audit-Complete is "true" or "false", and when false
// X-Audit-Incomplete-Reason names why. The client reads a missing or
// non-"true" header as incomplete.
const (
	headerExportComplete       = "X-Audit-Complete"
	headerExportIncomplete     = "X-Audit-Incomplete-Reason"
	exportIncompleteTimeline   = "timeline_incomplete"
	exportIncompleteRawCapture = auditIncompleteCapture
)

// setExportCompleteness writes the completeness of an export: the record's
// own meta first (in_progress, parse_pending, capture_incomplete, as
// `requests get` reports it), then the content's flag with contentReason.
func setExportCompleteness(header http.Header, record agentapi.Meta, contentComplete bool, contentReason string) {
	complete, reason := record.Complete, record.IncompleteReason
	if complete && !contentComplete {
		complete, reason = false, contentReason
	}
	header.Set(headerExportComplete, strconv.FormatBool(complete))
	if complete {
		header.Del(headerExportIncomplete)
	} else {
		header.Set(headerExportIncomplete, reason)
	}
}

// serveAgentRaw streams one raw body with the X-Audit-* metadata headers of
// the web route. An error before the first byte is a failure envelope.
func (handler *managementHandler) serveAgentRaw(writer http.ResponseWriter, ctx context.Context, auditID string, side query.Side, record agentapi.Meta) {
	metadata, err := handler.query.RawMeta(ctx, auditID, side)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	header := writer.Header()
	header.Set("Content-Type", "application/octet-stream")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Audit-Observed-Length", strconv.FormatInt(metadata.ObservedLength, 10))
	header.Set("X-Audit-Stored-Length", strconv.FormatInt(metadata.StoredLength, 10))
	// X-Audit-Complete is the web route's value ANDed with the record's
	// state, so an unfinished record's raw body is never called complete.
	setExportCompleteness(header, record, metadata.Complete, exportIncompleteRawCapture)
	header.Set("X-Audit-Missing-Chunks", strconv.FormatBool(metadata.MissingChunks))
	if metadata.SHA256 != "" {
		header.Set("X-Audit-SHA256", metadata.SHA256)
	}
	header.Set("Content-Length", strconv.FormatInt(metadata.StoredLength, 10))
	stream := newDelayedWriter(writer)
	if err := handler.query.StreamRaw(ctx, auditID, side, stream); err != nil {
		if !errors.Is(err, context.Canceled) {
			handler.logger.Warn("agent raw export failed", "audit_id", auditID, "side", string(side), "error_code", "raw_stream_failed")
		}
		if !stream.Committed() {
			clearRawHeaders(header)
			header.Del(headerExportIncomplete)
			handler.writeAgentServiceFailure(writer, err, "")
		}
		return
	}
	_ = stream.Commit()
}
