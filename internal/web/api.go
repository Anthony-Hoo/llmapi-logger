package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/uaguard"
)

const queryTimeout = 10 * time.Second

const maxLoginBodyBytes = 4096

const maxRuleBodyBytes = 16 << 10

// sessionResponse describes the caller to the UI. It never carries the admin
// token, the submitted API key, or the key fingerprint.
type sessionResponse struct {
	Status    string             `json:"status"`
	Role      role               `json:"role"`
	ExpiresAt string             `json:"expires_at"`
	Identity  *developerIdentity `json:"identity,omitempty"`
}

// serveSession is dispatched before the authenticating middleware, because
// logging in and out must work without a session. GET therefore authenticates
// itself.
func (handler *managementHandler) serveSession(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	switch request.Method {
	case http.MethodGet:
		handler.serveSessionInfo(writer, request)
	case http.MethodPost:
		handler.serveLogin(writer, request)
	case http.MethodDelete:
		if handler.authenticator != nil {
			handler.authenticator.clearSessionCookie(writer, request)
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodPost, http.MethodDelete)
	}
}

func (handler *managementHandler) serveSessionInfo(writer http.ResponseWriter, request *http.Request) {
	if handler.authenticator == nil {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
		return
	}
	caller, ok := handler.authenticator.resolve(request)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
		return
	}
	response := sessionResponse{Status: "authenticated", Role: caller.Role}
	if !caller.ExpiresAt.IsZero() {
		response.ExpiresAt = caller.ExpiresAt.Format(time.RFC3339)
	}
	if caller.Role == roleDeveloper {
		identity := caller.Identity
		response.Identity = &identity
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveLogin(writer http.ResponseWriter, request *http.Request) {
	if allowed, retryAfter := handler.logins.allow(request); !allowed {
		writeLoginRateLimited(writer, retryAfter)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxLoginBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var credentials struct {
		Token  string `json:"token"`
		APIKey string `json:"api_key"`
	}
	if err := decoder.Decode(&credentials); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_login", "invalid login request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_login", "invalid login request")
		return
	}
	if handler.authenticator == nil || (credentials.Token == "") == (credentials.APIKey == "") {
		writeError(writer, http.StatusBadRequest, "invalid_login", "provide exactly one of token or api_key")
		return
	}
	if credentials.APIKey != "" {
		handler.loginDeveloper(writer, request, credentials.APIKey)
		return
	}
	if !handler.authenticator.validAdminToken(credentials.Token) {
		handler.logins.recordFailure(request)
		writeError(writer, http.StatusUnauthorized, "unauthorized", "invalid admin token")
		return
	}
	handler.logins.recordSuccess(request)
	expires := handler.authenticator.issueSessionCookie(writer, request)
	writeJSON(writer, http.StatusOK, sessionResponse{
		Status: "authenticated", Role: roleAdmin, ExpiresAt: expires.Format(time.RFC3339),
	})
}

// loginDeveloper authenticates a NewAPI user API key against NewAPI itself and
// binds the resulting scope into the session cookie. The key is used only for
// that single upstream request and is never stored or logged.
func (handler *managementHandler) loginDeveloper(writer http.ResponseWriter, request *http.Request, apiKey string) {
	if !handler.developer.usable() {
		writeError(writer, http.StatusForbidden, "developer_login_disabled", "developer sign-in is disabled")
		return
	}
	fingerprint := handler.developer.Fingerprints.Fingerprint(apiKey)
	if len(fingerprint) == 0 {
		handler.logins.recordFailure(request)
		writeError(writer, http.StatusUnauthorized, "unauthorized", "invalid api key")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	identity, err := handler.developer.ValidateKey(ctx, handler.developer.NewAPIURL, handler.developer.HTTPClient, apiKey)
	if err != nil {
		if errors.Is(err, newapi.ErrKeyRejected) {
			handler.logins.recordFailure(request)
			writeError(writer, http.StatusUnauthorized, "unauthorized", "invalid api key")
			return
		}
		handler.logger.Warn("developer sign-in could not reach newapi", "error_category", "newapi_unavailable")
		writeError(writer, http.StatusBadGateway, "newapi_unavailable", "could not verify the api key with NewAPI")
		return
	}

	payload := developerSessionPayload{Fingerprint: fingerprint}
	if identity.HasIdentity {
		tokenID := identity.TokenID
		payload.TokenID = &tokenID
		payload.UserID = identity.UserID
		payload.Username = identity.Username
		payload.TokenName = identity.TokenName
	}
	expires, err := handler.authenticator.issueDeveloperCookie(writer, request, payload)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "session_unavailable", "could not start the session")
		return
	}
	handler.logins.recordSuccess(request)
	response := sessionResponse{
		Status: "authenticated", Role: roleDeveloper, ExpiresAt: expires.Format(time.RFC3339),
		Identity: &developerIdentity{
			UserID: payload.UserID, Username: payload.Username,
			TokenID: payload.TokenID, TokenName: payload.TokenName,
		},
	}
	writeJSON(writer, http.StatusOK, response)
}

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
	scope := handler.sessionScope(request)
	filter, cursor, limit, err := parseListQuery(request.URL.Query(), scope != nil)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid audit list query")
		return
	}
	// Applied after parsing so no query string can reach or replace it.
	filter.Scope = scope
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	page, err := handler.query.List(ctx, filter, cursor, limit)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	handler.addCallerDisplayNames(page.Items)
	writeJSON(writer, http.StatusOK, page)
}

func (handler *managementHandler) serveNewAPICallers(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	response := struct {
		Items       []newapi.User `json:"items"`
		RefreshedAt *time.Time    `json:"refreshed_at"`
	}{Items: []newapi.User{}}
	if handler.users != nil {
		snapshot := handler.users.Snapshot()
		response.Items = snapshot.Users
		if !snapshot.RefreshedAt.IsZero() {
			refreshedAt := snapshot.RefreshedAt
			response.RefreshedAt = &refreshedAt
		}
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveUserAgentRuleCollection(writer http.ResponseWriter, request *http.Request) {
	if handler.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, "rules_unavailable", "user agent rules are unavailable")
		return
	}
	switch request.Method {
	case http.MethodGet:
		writeJSON(writer, http.StatusOK, map[string]any{"items": handler.rules.List()})
	case http.MethodPost:
		input, ok := decodeRuleInput(writer, request)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
		defer cancel()
		rule, err := handler.rules.Create(ctx, input)
		if err != nil {
			handler.writeRuleError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, rule)
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodPost)
	}
}

func (handler *managementHandler) serveUserAgentRuleResource(writer http.ResponseWriter, request *http.Request) {
	if handler.rules == nil {
		writeError(writer, http.StatusServiceUnavailable, "rules_unavailable", "user agent rules are unavailable")
		return
	}
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/user-agent-rules/")
	if remainder == "" || strings.Contains(remainder, "/") {
		http.NotFound(writer, request)
		return
	}
	id, err := strconv.ParseInt(remainder, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(writer, request)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	switch request.Method {
	case http.MethodPut:
		input, ok := decodeRuleInput(writer, request)
		if !ok {
			return
		}
		rule, err := handler.rules.Update(ctx, id, input)
		if err != nil {
			handler.writeRuleError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, rule)
	case http.MethodDelete:
		if err := handler.rules.Delete(ctx, id); err != nil {
			handler.writeRuleError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
	}
}

func decodeRuleInput(writer http.ResponseWriter, request *http.Request) (uaguard.RuleInput, bool) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRuleBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input uaguard.RuleInput
	if err := decoder.Decode(&input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_rule", "invalid user agent rule")
		return uaguard.RuleInput{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_rule", "invalid user agent rule")
		return uaguard.RuleInput{}, false
	}
	return input, true
}

func (handler *managementHandler) writeRuleError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, uaguard.ErrInvalidRule):
		writeError(writer, http.StatusBadRequest, "invalid_rule", "invalid name or regular expression")
	case errors.Is(err, uaguard.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "user agent rule not found")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusServiceUnavailable, "rules_timeout", "user agent rule update timed out")
	case errors.Is(err, context.Canceled):
		return
	default:
		writeError(writer, http.StatusServiceUnavailable, "rules_unavailable", "user agent rules are unavailable")
	}
}

func (handler *managementHandler) serveAuditResource(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/audits/")
	parts := strings.Split(remainder, "/")
	if parts[0] == "" {
		http.NotFound(writer, request)
		return
	}
	// One authorization gate in front of the whole audit resource family, so
	// detail, raw, reconstructed and timeline cannot drift apart.
	if !handler.authorizeAudit(writer, request, parts[0]) {
		return
	}
	if len(parts) == 1 {
		handler.serveAuditDetail(writer, request, parts[0])
		return
	}
	if len(parts) == 3 && parts[1] == "raw" {
		handler.serveRaw(writer, request, parts[0], query.Side(parts[2]))
		return
	}
	if len(parts) == 3 && parts[1] == "reconstructed" {
		handler.serveReconstructed(writer, request, parts[0], query.Side(parts[2]))
		return
	}
	if len(parts) == 3 && parts[1] == "timeline" {
		handler.serveTimeline(writer, request, parts[0], query.Side(parts[2]))
		return
	}
	http.NotFound(writer, request)
}

// authorizeAudit resolves whether the caller may read one audit at all. A
// developer asking for somebody else's audit, or for a record this proxy blocked
// on policy grounds, gets the same 404 as a missing audit so the response never
// reveals that it exists.
func (handler *managementHandler) authorizeAudit(writer http.ResponseWriter, request *http.Request, auditID string) bool {
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return false
	}
	scope := handler.sessionScope(request)
	if scope == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	if err := handler.query.Authorize(ctx, auditID, scope); err != nil {
		handler.writeQueryError(writer, err)
		return false
	}
	return true
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
	addCallerDisplayName(&detail.Audit, handler.callerDisplayNames())
	writeJSON(writer, http.StatusOK, detail)
}

func (handler *managementHandler) serveReconstructed(writer http.ResponseWriter, request *http.Request, auditID string, side query.Side) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return
	}
	if side != query.SideRequest && side != query.SideResponse {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid reconstruction side")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	reconstructed, err := handler.query.ReconstructTurn(ctx, auditID)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if side == query.SideRequest {
		writeJSON(writer, http.StatusOK, reconstructed.Request)
		return
	}
	writeJSON(writer, http.StatusOK, reconstructed.Response)
}

func (handler *managementHandler) serveTimeline(writer http.ResponseWriter, request *http.Request, auditID string, side query.Side) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.query == nil {
		writeError(writer, http.StatusServiceUnavailable, "query_unavailable", "audit query is unavailable")
		return
	}
	if side != query.SideRequest && side != query.SideResponse {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid timeline side")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	timeline, err := handler.query.Timeline(ctx, auditID, side)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, timeline)
}

func (handler *managementHandler) addCallerDisplayNames(audits []query.AuditSummary) {
	names := handler.callerDisplayNames()
	if len(names) == 0 {
		return
	}
	for index := range audits {
		addCallerDisplayName(&audits[index], names)
	}
}

func (handler *managementHandler) callerDisplayNames() map[int64]string {
	if handler.users == nil {
		return nil
	}
	users := handler.users.Snapshot().Users
	names := make(map[int64]string, len(users))
	for _, user := range users {
		if displayName := strings.TrimSpace(user.DisplayName); displayName != "" {
			names[user.ID] = displayName
		}
	}
	return names
}

func addCallerDisplayName(audit *query.AuditSummary, names map[int64]string) {
	if audit == nil || audit.NewAPIUserID == nil {
		return
	}
	displayName, ok := names[*audit.NewAPIUserID]
	if !ok {
		return
	}
	audit.DisplayName = &displayName
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
	case errors.Is(err, query.ErrNotRetained):
		writeError(writer, http.StatusGone, "raw_not_retained", "raw body was compacted after verified reconstruction")
	case errors.Is(err, query.ErrNoTurnGraph):
		writeError(writer, http.StatusConflict, "reconstruction_unavailable", "verified turn reconstruction is unavailable")
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

// callerFilterKeys select by NewAPI identity. A scoped session is already
// pinned to one caller, so accepting these would only invite the impression
// that the scope can be widened or narrowed from the query string.
var callerFilterKeys = []string{"newapi_user_id", "username", "newapi_token_id", "token_name"}

func parseListQuery(values url.Values, scoped bool) (query.Filter, query.Cursor, int, error) {
	allowed := map[string]bool{
		"limit": true, "before_started_at_ns": true, "before_id": true,
		"from_ns": true, "to_ns": true, "protocol": true, "path": true,
		"model": true, "user_agent": true,
		"status_code": true, "forward_status": true,
		"blocked_by": true, "block_code": true, "capture_status": true,
		"newapi_user_id": true, "username": true,
		"newapi_token_id": true, "token_name": true,
	}
	if scoped {
		for _, key := range callerFilterKeys {
			delete(allowed, key)
		}
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
	newAPIUserID, err := optionalInt64(values, "newapi_user_id")
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
		UserAgent:     values.Get("user_agent"),
		StatusCode:    statusCode,
		ForwardStatus: values.Get("forward_status"),
		BlockedBy:     values.Get("blocked_by"),
		BlockCode:     values.Get("block_code"),
		CaptureStatus: values.Get("capture_status"),
		NewAPIUserID:  newAPIUserID,
		Username:      values.Get("username"),
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
