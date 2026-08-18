package query

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

var stableCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

const maxHeaderFilterScan = 2000

// Store is the read-only storage surface used by Service.
type Store interface {
	Healthy() bool
	ListAudits(context.Context, sqlite.AuditQueryFilter, sqlite.AuditQueryCursor, int) (sqlite.AuditListPage, error)
	QueryRequestHeaderEvidence(context.Context, string) ([]sqlite.HeaderEvidence, error)
	QueryAuditDetail(context.Context, string) (sqlite.AuditQueryDetail, error)
	QueryAuditScope(context.Context, string) (sqlite.AuditScopeRow, error)
	RawBodyMeta(context.Context, string, string) (sqlite.RawBodyMetadata, error)
	StreamBodyChunks(context.Context, string, string, func(sqlite.BodyChunk) error) error
	QueryStreamTimeline(context.Context, string, string) (sqlite.StoredStreamTimeline, error)
}

// Service validates management queries and keeps ciphertext out of API DTOs.
type Service struct {
	store  Store
	cipher security.Cipher
}

func New(store Store, cipher security.Cipher) (*Service, error) {
	if store == nil {
		return nil, errors.New("query: nil store")
	}
	if cipher == nil {
		return nil, errors.New("query: nil cipher")
	}
	return &Service{store: store, cipher: cipher}, nil
}

func (service *Service) Healthy() bool {
	return service != nil && service.store != nil && service.cipher != nil && service.store.Healthy()
}

func (service *Service) List(ctx context.Context, filter Filter, cursor Cursor, limit int) (Page, error) {
	if ctx == nil {
		return Page{}, invalid("nil context")
	}
	if limit == 0 {
		limit = DefaultLimit
	}
	if err := validateList(filter, cursor, limit); err != nil {
		return Page{}, err
	}

	storageFilter := sqlite.AuditQueryFilter{
		FromNS:        filter.FromNS,
		ToNS:          filter.ToNS,
		Protocol:      filter.Protocol,
		Path:          filter.Path,
		Model:         filter.Model,
		StatusCode:    filter.StatusCode,
		ForwardStatus: filter.ForwardStatus,
		BlockedBy:     filter.BlockedBy,
		BlockCode:     filter.BlockCode,
		CaptureStatus: filter.CaptureStatus,
		NewAPIUserID:  filter.NewAPIUserID,
		Username:      filter.Username,
		NewAPITokenID: filter.NewAPITokenID,
		TokenName:     filter.TokenName,
		Scope:         storageScope(filter.Scope),
	}
	storageCursor := sqlite.AuditQueryCursor{
		BeforeStartedAtNS: cursor.BeforeStartedAtNS,
		BeforeID:          cursor.BeforeID,
	}
	if filter.UserAgent != "" {
		return service.listWithHeaderFilters(ctx, storageFilter, storageCursor, filter, limit)
	}

	storagePage, err := service.store.ListAudits(ctx, storageFilter, storageCursor, limit)
	if err != nil {
		return Page{}, fmt.Errorf("query: list audits: %w", err)
	}

	page := Page{Items: make([]AuditSummary, 0, len(storagePage.Rows))}
	for _, row := range storagePage.Rows {
		userAgent, _, err := service.readUserAgent(ctx, row.AuditID, "")
		if err != nil {
			return Page{}, err
		}
		summary := mapAudit(row)
		summary.UserAgent = userAgent
		page.Items = append(page.Items, summary)
	}
	if storagePage.HasMore && len(page.Items) != 0 {
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &Cursor{BeforeStartedAtNS: last.StartedAtNS, BeforeID: last.AuditID}
	}
	return page, nil
}

func (service *Service) listWithHeaderFilters(ctx context.Context, storageFilter sqlite.AuditQueryFilter, cursor sqlite.AuditQueryCursor, filter Filter, limit int) (Page, error) {
	page := Page{Items: make([]AuditSummary, 0, limit)}
	scanned := 0
	for scanned < maxHeaderFilterScan {
		batchLimit := min(MaxLimit, maxHeaderFilterScan-scanned)
		storagePage, err := service.store.ListAudits(ctx, storageFilter, cursor, batchLimit)
		if err != nil {
			return Page{}, fmt.Errorf("query: list audits for header filter: %w", err)
		}
		if len(storagePage.Rows) == 0 {
			return page, nil
		}
		for index, row := range storagePage.Rows {
			scanned++
			userAgent, matches, err := service.readUserAgent(ctx, row.AuditID, filter.UserAgent)
			if err != nil {
				return Page{}, err
			}
			if matches {
				summary := mapAudit(row)
				summary.UserAgent = userAgent
				page.Items = append(page.Items, summary)
				if len(page.Items) == limit {
					if index < len(storagePage.Rows)-1 || storagePage.HasMore {
						page.NextCursor = cursorForRow(row)
					}
					return page, nil
				}
			}
			cursor = sqlite.AuditQueryCursor{BeforeStartedAtNS: row.StartedAtNS, BeforeID: row.AuditID}
		}
		if !storagePage.HasMore {
			return page, nil
		}
	}
	if cursor.BeforeID != "" {
		page.NextCursor = &Cursor{BeforeStartedAtNS: cursor.BeforeStartedAtNS, BeforeID: cursor.BeforeID}
	}
	return page, nil
}

func (service *Service) readUserAgent(ctx context.Context, auditID, needle string) (*string, bool, error) {
	headers, err := service.store.QueryRequestHeaderEvidence(ctx, auditID)
	if err != nil {
		return nil, false, fmt.Errorf("query: read request headers: %w", err)
	}
	var userAgent *string
	matched := needle == ""
	userAgentNeedle := strings.ToLower(needle)
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "user-agent") {
			continue
		}
		plaintext, err := service.decryptHeader(auditID, header)
		if err != nil {
			return nil, false, err
		}
		value := string(plaintext)
		clear(plaintext)
		if userAgent == nil {
			userAgent = &value
		}
		if needle != "" && strings.Contains(strings.ToLower(value), userAgentNeedle) {
			matched = true
		}
	}
	return userAgent, matched && userAgent != nil, nil
}

func (service *Service) decryptHeader(auditID string, header sqlite.HeaderEvidence) ([]byte, error) {
	aad, err := security.AAD(auditID, "header", header.Stage, header.Kind, header.Name, strconv.Itoa(header.ValueIndex))
	if err != nil {
		return nil, ErrIntegrity
	}
	plaintext, err := service.cipher.Decrypt(aad, header.ValueEnc)
	if err != nil || len(plaintext) != header.ValueLength {
		clear(plaintext)
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

func cursorForRow(row sqlite.AuditListRow) *Cursor {
	return &Cursor{BeforeStartedAtNS: row.StartedAtNS, BeforeID: row.AuditID}
}

func storageScope(scope *Scope) *sqlite.AuditScope {
	if scope == nil {
		return nil
	}
	return &sqlite.AuditScope{Fingerprint: scope.Fingerprint, TokenID: scope.TokenID}
}

// Authorize reports whether a developer session may read one audit, and is the
// gate every per-audit endpoint calls before doing any expensive work. An audit
// that does not exist and one that belongs to somebody else both return
// ErrNotFound, so the response never confirms that another tenant's audit
// exists.
func (service *Service) Authorize(ctx context.Context, auditID string, scope *Scope) error {
	if ctx == nil {
		return invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return err
	}
	if scope == nil {
		// Administrator sessions carry no scope and read everything.
		return nil
	}
	storage := storageScope(scope)
	if err := storage.Validate(); err != nil {
		return invalid("invalid session scope")
	}
	row, err := service.store.QueryAuditScope(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query: authorize audit: %w", err)
	}
	if !storage.Allows(row) {
		return ErrNotFound
	}
	return nil
}

func (service *Service) Get(ctx context.Context, auditID string) (Detail, error) {
	if ctx == nil {
		return Detail{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return Detail{}, err
	}
	storageDetail, err := service.store.QueryAuditDetail(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return Detail{}, ErrNotFound
	}
	if err != nil {
		return Detail{}, fmt.Errorf("query: get audit: %w", err)
	}

	detail := Detail{
		Audit:   mapAudit(storageDetail.Audit),
		Stages:  make([]Stage, 0, len(storageDetail.Stages)),
		Headers: make([]Header, 0, len(storageDetail.Headers)),
		Bodies:  make([]Body, 0, len(storageDetail.Bodies)),
	}
	requestURIAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		return Detail{}, ErrIntegrity
	}
	requestURI, err := service.cipher.Decrypt(requestURIAAD, storageDetail.RequestURIEnc)
	if err != nil {
		return Detail{}, ErrIntegrity
	}
	detail.RequestURI = string(requestURI)
	clear(requestURI)
	for _, stage := range storageDetail.Stages {
		detail.Stages = append(detail.Stages, Stage{
			Stage:         stage.Stage,
			State:         stage.State,
			Proto:         stage.Proto,
			Method:        stage.Method,
			Host:          stage.Host,
			StatusCode:    stage.StatusCode,
			ContentLength: stage.ContentLength,
			StartedAtNS:   stage.StartedAtNS,
			EndedAtNS:     stage.EndedAtNS,
			ErrorCode:     stage.ErrorCode,
		})
	}
	for _, header := range storageDetail.Headers {
		aad, err := security.AAD(
			auditID,
			"header",
			header.Stage,
			header.Kind,
			header.Name,
			strconv.Itoa(header.ValueIndex),
		)
		if err != nil {
			return Detail{}, ErrIntegrity
		}
		plaintext, err := service.cipher.Decrypt(aad, header.ValueEnc)
		if err != nil || len(plaintext) != header.ValueLength {
			clear(plaintext)
			return Detail{}, ErrIntegrity
		}
		value := string(plaintext)
		clear(plaintext)
		detail.Headers = append(detail.Headers, Header{
			Stage:       header.Stage,
			Kind:        header.Kind,
			Name:        header.Name,
			ValueIndex:  header.ValueIndex,
			ValueLength: header.ValueLength,
			Value:       value,
		})
	}
	for _, body := range storageDetail.Bodies {
		var digest *string
		if len(body.SHA256) != 0 {
			encoded := hex.EncodeToString(body.SHA256)
			digest = &encoded
		}
		detail.Bodies = append(detail.Bodies, Body{
			Stage:                  body.Stage,
			SourceStage:            body.SourceStage,
			ObservedLength:         body.ObservedLength,
			StoredLength:           body.StoredLength,
			SHA256:                 digest,
			HashComplete:           body.HashComplete,
			EOFSeen:                body.EOFSeen,
			State:                  body.State,
			RetentionState:         body.RetentionState,
			FirstObservedAtNS:      body.FirstObservedAtNS,
			LastObservedAtNS:       body.LastObservedAtNS,
			ChunkCount:             body.ChunkCount,
			StreamEventCount:       body.StreamEventCount,
			StreamTimelineComplete: body.StreamTimelineComplete,
			ErrorCode:              body.ErrorCode,
		})
	}
	if parsed := storageDetail.ParsedResult; parsed != nil {
		detail.ParsedResult = &ParsedResult{
			ParserName:      parsed.ParserName,
			ParserVersion:   parsed.ParserVersion,
			Status:          parsed.Status,
			RequestModel:    parsed.RequestModel,
			ResponseModel:   parsed.ResponseModel,
			RequestedStream: parsed.RequestedStream,
			ObservedStream:  parsed.ObservedStream,
			ResponseID:      parsed.ResponseID,
			UsageInput:      parsed.UsageInput,
			UsageOutput:     parsed.UsageOutput,
			UsageTotal:      parsed.UsageTotal,
			ErrorType:       parsed.ErrorType,
			ErrorCode:       parsed.ErrorCode,
			MessageCount:    parsed.MessageCount,
			ToolCallCount:   parsed.ToolCallCount,
			HasToolCall:     parsed.HasToolCall,
			ParsedAtNS:      parsed.ParsedAtNS,
		}
		if len(parsed.ParsedJSONEnc) != 0 {
			aad, aadErr := security.AAD(auditID, "parsed_json", parsed.ParserName)
			if aadErr != nil {
				return Detail{}, ErrIntegrity
			}
			plaintext, decryptErr := service.cipher.Decrypt(aad, parsed.ParsedJSONEnc)
			if decryptErr != nil {
				return Detail{}, ErrIntegrity
			}
			var envelope struct {
				Conversation *conversation.Conversation `json:"conversation"`
			}
			decodeErr := json.Unmarshal(plaintext, &envelope)
			clear(plaintext)
			if decodeErr != nil || !validConversation(envelope.Conversation) {
				return Detail{}, ErrIntegrity
			}
			detail.Conversation = envelope.Conversation
		}
	}
	if storageDetail.TurnGraph != nil {
		reconstructed, reconstructErr := reconstructTurnGraph(service.cipher, storageDetail.Audit.ParserName, storageDetail.TurnGraph)
		if reconstructErr != nil {
			return Detail{}, ErrIntegrity
		}
		detail.Turn = &reconstructed.Turn
		detail.Conversation = reconstructed.Conversation
	}
	if token := storageDetail.TokenLink; token != nil {
		detail.TokenLink = &TokenLink{
			NewAPIRequestID: token.NewAPIRequestID,
			NewAPIUserID:    token.NewAPIUserID,
			Username:        token.Username,
			NewAPITokenID:   token.NewAPITokenID,
			TokenName:       token.TokenName,
			LinkedAtNS:      token.LinkedAtNS,
		}
	}
	return detail, nil
}

func validConversation(value *conversation.Conversation) bool {
	if value == nil {
		return true
	}
	if value.SchemaVersion != conversation.SchemaVersion || value.Messages == nil {
		return false
	}
	for messageIndex, message := range value.Messages {
		if message.Index != messageIndex || message.Content == nil || !validConversationRole(message.Role) ||
			!validConversationPhase(message.Phase, message.Direction) {
			return false
		}
		for partIndex, part := range message.Content {
			if part.Index != partIndex || !validConversationPart(part.Type) {
				return false
			}
		}
	}
	return true
}

func validConversationRole(role string) bool {
	switch role {
	case conversation.RoleSystem, conversation.RoleDeveloper, conversation.RoleUser,
		conversation.RoleAssistant, conversation.RoleTool, conversation.RoleUnknown:
		return true
	default:
		return false
	}
}

func validConversationPhase(phase, direction string) bool {
	return phase == conversation.PhaseRequest && direction == conversation.DirectionClientToUpstream ||
		phase == conversation.PhaseResponse && direction == conversation.DirectionUpstreamToClient
}

func validConversationPart(partType string) bool {
	switch partType {
	case conversation.PartText, conversation.PartReasoning, conversation.PartToolCall,
		conversation.PartToolResult, conversation.PartUnknown:
		return true
	default:
		return false
	}
}

func (service *Service) RawMeta(ctx context.Context, auditID string, side Side) (RawMetadata, error) {
	if ctx == nil {
		return RawMetadata{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return RawMetadata{}, err
	}
	_, metadata, err := service.selectRawBody(ctx, auditID, side)
	if errors.Is(err, sql.ErrNoRows) {
		return RawMetadata{}, ErrNotFound
	}
	if err != nil {
		return RawMetadata{}, fmt.Errorf("query: read raw metadata: %w", err)
	}
	if metadata.State == sqlite.StageStateStreaming {
		return RawMetadata{}, ErrNotReady
	}
	if metadata.RetentionState == sqlite.RetentionPending {
		return RawMetadata{}, ErrNotReady
	}
	if metadata.RetentionState == sqlite.RetentionMetadata {
		return RawMetadata{}, ErrNotRetained
	}
	encodedDigest := ""
	if len(metadata.SHA256) != 0 {
		encodedDigest = hex.EncodeToString(metadata.SHA256)
	}
	complete := metadata.State == sqlite.StageStateComplete && metadata.HashComplete && metadata.EOFSeen && metadata.StoredLength == metadata.ObservedLength
	return RawMetadata{
		ObservedLength: metadata.ObservedLength,
		StoredLength:   metadata.StoredLength,
		SHA256:         encodedDigest,
		Complete:       complete,
		State:          metadata.State,
	}, nil
}

func mapAudit(row sqlite.AuditListRow) AuditSummary {
	return AuditSummary{
		AuditID:         row.AuditID,
		StartedAtNS:     row.StartedAtNS,
		EndedAtNS:       row.EndedAtNS,
		RouteID:         row.RouteID,
		Protocol:        row.Protocol,
		ParserName:      row.ParserName,
		Method:          row.Method,
		Path:            row.Path,
		Mode:            row.Mode,
		StatusCode:      row.StatusCode,
		TTFTNS:          row.TTFTNS,
		ForwardStatus:   row.ForwardStatus,
		CaptureStatus:   row.CaptureStatus,
		ParseStatus:     row.ParseStatus,
		BlockedBy:       row.BlockedBy,
		BlockCode:       row.BlockCode,
		ErrorCode:       row.ErrorCode,
		RequestModel:    row.RequestModel,
		ResponseModel:   row.ResponseModel,
		NewAPIRequestID: row.NewAPIRequestID,
		CallerStatus:    row.CallerStatus,
		NewAPIUserID:    row.NewAPIUserID,
		Username:        row.Username,
		NewAPITokenID:   row.NewAPITokenID,
		TokenName:       row.TokenName,
	}
}

func validateList(filter Filter, cursor Cursor, limit int) error {
	if limit < 1 || limit > MaxLimit {
		return invalid("limit must be between 1 and 200")
	}
	if (cursor.BeforeStartedAtNS == 0) != (cursor.BeforeID == "") {
		return invalid("both cursor fields are required")
	}
	if cursor.BeforeStartedAtNS < 0 {
		return invalid("cursor time must not be negative")
	}
	if cursor.BeforeID != "" {
		if err := validateAuditID(cursor.BeforeID); err != nil {
			return err
		}
	}
	if filter.FromNS != nil && *filter.FromNS < 0 || filter.ToNS != nil && *filter.ToNS < 0 {
		return invalid("time filters must not be negative")
	}
	if filter.FromNS != nil && filter.ToNS != nil && *filter.FromNS > *filter.ToNS {
		return invalid("from_ns must not exceed to_ns")
	}
	if filter.StatusCode != nil && (*filter.StatusCode < 100 || *filter.StatusCode > 599) {
		return invalid("status_code must be an HTTP status")
	}
	if filter.NewAPITokenID != nil && *filter.NewAPITokenID < 0 {
		return invalid("newapi_token_id must not be negative")
	}
	if filter.NewAPIUserID != nil && *filter.NewAPIUserID <= 0 {
		return invalid("newapi_user_id must be positive")
	}
	if filter.ForwardStatus != "" && !validForwardStatus(filter.ForwardStatus) {
		return invalid("invalid forward_status")
	}
	if filter.CaptureStatus != "" && !validCaptureStatus(filter.CaptureStatus) {
		return invalid("invalid capture_status")
	}
	if filter.BlockCode != "" && !stableCode.MatchString(filter.BlockCode) {
		return invalid("invalid block_code")
	}
	if filter.Path != "" && (!strings.HasPrefix(filter.Path, "/") || len(filter.Path) > 2048) {
		return invalid("invalid path")
	}
	for name, value := range map[string]string{
		"protocol":   filter.Protocol,
		"model":      filter.Model,
		"user_agent": filter.UserAgent,
		"blocked_by": filter.BlockedBy,
		"username":   filter.Username,
		"token_name": filter.TokenName,
	} {
		if len(value) > 512 || strings.ContainsRune(value, '\x00') || strings.TrimSpace(value) != value {
			return invalid("invalid " + name)
		}
	}
	if filter.Scope != nil {
		if err := storageScope(filter.Scope).Validate(); err != nil {
			return invalid("invalid session scope")
		}
	}
	return nil
}

func validateAuditID(auditID string) error {
	if auditID == "" || len(auditID) > 128 || strings.ContainsAny(auditID, "/\\\x00\r\n\t ") {
		return invalid("invalid audit_id")
	}
	return nil
}

func validForwardStatus(status string) bool {
	switch status {
	case sqlite.ForwardInProgress, sqlite.ForwardCompleted, sqlite.ForwardRejected,
		sqlite.ForwardClientCancelled, sqlite.ForwardNewAPIError, sqlite.ForwardProxyError,
		sqlite.ForwardInterrupted:
		return true
	default:
		return false
	}
}

func validCaptureStatus(status string) bool {
	switch status {
	case sqlite.CapturePending, sqlite.CaptureComplete, sqlite.CapturePartial, sqlite.CaptureFailed:
		return true
	default:
		return false
	}
}

func invalid(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidQuery, detail)
}
