package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/query"
)

const queryTimeout = 10 * time.Second

func (handler *managementHandler) serveHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (handler *managementHandler) serveReady(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	status := ReadyStatus{
		Status:        "healthy",
		Database:      "ok",
		EncryptionKey: "ok",
	}
	if handler.readiness != nil {
		status = handler.readiness(request.Context())
	} else if handler.query == nil || !handler.query.Healthy() {
		status.Status = "degraded"
		status.Database = "unavailable"
		status.EncryptionKey = "unknown"
	}
	responseStatus := http.StatusOK
	if status.Status == "not_ready" {
		responseStatus = http.StatusServiceUnavailable
	}
	writeJSON(writer, responseStatus, status)
}

func (handler *managementHandler) serveAuditList(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return
	}
	filter, cursor, limit, err := parseListQuery(request.URL.Query())
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid audit list query")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	page, err := handler.query.List(ctx, filter, cursor, limit)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (handler *managementHandler) serveAuditResource(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/audits/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" {
		handler.serveAuditDetail(writer, request, parts[0])
		return
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "raw" {
		handler.serveRaw(writer, request, parts[0], query.Side(parts[2]))
		return
	}
	http.NotFound(writer, request)
}

func (handler *managementHandler) serveAuditDetail(writer http.ResponseWriter, request *http.Request, auditID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	detail, err := handler.query.Get(ctx, auditID)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, detail)
}

func (handler *managementHandler) serveRaw(writer http.ResponseWriter, request *http.Request, auditID string, side query.Side) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	metadata, err := handler.query.RawMeta(ctx, auditID, side)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Audit-Observed-Length", strconv.FormatInt(metadata.ObservedLength, 10))
	writer.Header().Set("X-Audit-Stored-Length", strconv.FormatInt(metadata.StoredLength, 10))
	writer.Header().Set("X-Audit-Complete", strconv.FormatBool(metadata.Complete))
	if metadata.SHA256 != "" {
		writer.Header().Set("X-Audit-SHA256", metadata.SHA256)
	}
	writer.Header().Set("Content-Length", strconv.FormatInt(metadata.StoredLength, 10))

	stream := newDelayedWriter(writer)
	if err := handler.query.StreamRaw(ctx, auditID, side, stream); err != nil {
		if !errors.Is(err, context.Canceled) {
			handler.logger.Warn("raw audit body stream failed",
				"audit_id", auditID,
				"side", string(side),
				"error_code", "raw_stream_failed",
			)
		}
		if !stream.Committed() {
			clearRawHeaders(writer.Header())
			handler.writeQueryError(writer, err)
		}
		return
	}
	if err := stream.Commit(); err != nil {
		return
	}
}

func (handler *managementHandler) writeQueryError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, query.ErrInvalidQuery):
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid management query")
	case errors.Is(err, query.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "audit evidence not found")
	case errors.Is(err, query.ErrNotReady):
		writeError(writer, http.StatusConflict, "raw_not_finalized", "audit evidence is still being captured")
	case errors.Is(err, query.ErrIntegrity):
		writeError(writer, http.StatusInternalServerError, "evidence_unavailable", "audit evidence could not be verified")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusServiceUnavailable, "query_timeout", "audit query timed out")
	case errors.Is(err, context.Canceled):
		return
	default:
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
	}
}

func parseListQuery(values url.Values) (query.Filter, query.Cursor, int, error) {
	allowed := map[string]bool{
		"limit": true, "before_started_at_ns": true, "before_id": true,
		"from_ns": true, "to_ns": true, "protocol": true, "path": true,
		"model": true, "status_code": true, "forward_status": true,
		"blocked_by": true, "block_code": true, "capture_status": true,
		"newapi_token_id": true, "token_name": true,
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return query.Filter{}, query.Cursor{}, 0, fmt.Errorf("invalid query key %q", key)
		}
	}

	limit := query.DefaultLimit
	if values.Has("limit") {
		parsed, err := parseInt(values.Get("limit"))
		if err != nil {
			return query.Filter{}, query.Cursor{}, 0, err
		}
		limit = parsed
	}
	fromNS, err := optionalInt64(values, "from_ns")
	if err != nil {
		return query.Filter{}, query.Cursor{}, 0, err
	}
	toNS, err := optionalInt64(values, "to_ns")
	if err != nil {
		return query.Filter{}, query.Cursor{}, 0, err
	}
	statusCode, err := optionalInt(values, "status_code")
	if err != nil {
		return query.Filter{}, query.Cursor{}, 0, err
	}
	newAPITokenID, err := optionalInt64(values, "newapi_token_id")
	if err != nil {
		return query.Filter{}, query.Cursor{}, 0, err
	}
	beforeNS, err := optionalInt64(values, "before_started_at_ns")
	if err != nil {
		return query.Filter{}, query.Cursor{}, 0, err
	}
	cursor := query.Cursor{BeforeID: values.Get("before_id")}
	if beforeNS != nil {
		cursor.BeforeStartedAtNS = *beforeNS
	}
	filter := query.Filter{
		FromNS:        fromNS,
		ToNS:          toNS,
		Protocol:      values.Get("protocol"),
		Path:          values.Get("path"),
		Model:         values.Get("model"),
		StatusCode:    statusCode,
		ForwardStatus: values.Get("forward_status"),
		BlockedBy:     values.Get("blocked_by"),
		BlockCode:     values.Get("block_code"),
		CaptureStatus: values.Get("capture_status"),
		NewAPITokenID: newAPITokenID,
		TokenName:     values.Get("token_name"),
	}
	return filter, cursor, limit, nil
}

func optionalInt64(values url.Values, name string) (*int64, error) {
	if !values.Has(name) {
		return nil, nil
	}
	value, err := strconv.ParseInt(values.Get(name), 10, 64)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func optionalInt(values url.Values, name string) (*int, error) {
	if !values.Has(name) {
		return nil, nil
	}
	value, err := parseInt(values.Get(name))
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func parseInt(value string) (int, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(parsed), nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func methodNotAllowed(writer http.ResponseWriter, methods ...string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func clearRawHeaders(header http.Header) {
	for _, name := range []string{
		"Content-Length", "Content-Type", "X-Audit-Observed-Length",
		"X-Audit-Stored-Length", "X-Audit-Complete", "X-Audit-SHA256",
	} {
		header.Del(name)
	}
}
