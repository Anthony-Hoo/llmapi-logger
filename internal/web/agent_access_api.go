package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Web-side agent access endpoints (contract section 3.2). They use the web
// session like every /api/v1 route and serve both roles, so serveProtected
// dispatches them before its requireAdmin fallback. The wire format is the
// management API's (bare JSON, writeError), not the facade envelope.

const (
	agentAccessPathPrefix     = "/api/v1/agent-access/"
	agentAuthorizationsPath   = agentAccessPathPrefix + "authorizations"
	agentTokensPath           = agentAccessPathPrefix + "tokens"
	agentChangesPath          = agentAccessPathPrefix + "changes"
	maxAgentAuthorizationBody = 8 << 10
	defaultAgentChanges       = 50
)

func isAgentAccessPath(path string) bool {
	return path == "/api/v1/agent-access" || strings.HasPrefix(path, agentAccessPathPrefix)
}

// serveAgentAccess serves the family while the feature is on; serveProtected
// does not dispatch it while the feature is off, so that its paths answer
// like any unknown /api/v1 path. The check here is a second line.
func (handler *managementHandler) serveAgentAccess(writer http.ResponseWriter, request *http.Request) {
	if handler.agent == nil {
		http.NotFound(writer, request)
		return
	}
	path := request.URL.Path
	switch {
	case path == agentAuthorizationsPath:
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if !requireJSONContent(writer, request) {
			return
		}
		handler.serveAgentAuthorization(writer, request)
	case path == agentTokensPath:
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		handler.serveAgentTokenList(writer, request)
	case strings.HasPrefix(path, agentTokensPath+"/"):
		if request.Method != http.MethodDelete {
			methodNotAllowed(writer, http.MethodDelete)
			return
		}
		handler.serveAgentTokenRevoke(writer, request, strings.TrimPrefix(path, agentTokensPath+"/"))
	case path == agentInstallLinksPath:
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if !requireJSONContent(writer, request) {
			return
		}
		handler.serveAgentInstallLink(writer, request)
	case path == agentChangesPath:
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		// This family is dispatched before the administrator check of the
		// other routes; the change list is administrator-only.
		if !handler.requireAdmin(writer, request) {
			return
		}
		handler.serveAgentChanges(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

// requireJSONContent answers 415 unless the request declares a JSON body
// (Content-Type application/json, parameters allowed). A browser sends a
// cross-site form or text/plain POST without a CORS preflight; requiring
// application/json means such a request never reaches a state-changing
// handler of this family, whatever the session cookie's SameSite does.
func requireJSONContent(writer http.ResponseWriter, request *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err == nil && mediaType == "application/json" {
		return true
	}
	writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "the request body must be sent as application/json")
	return false
}

// agentViewer maps the web session onto the viewer of the token list.
func agentViewer(caller principal) agentaccess.Viewer {
	switch caller.Role {
	case roleAdmin:
		return agentaccess.Viewer{Role: agentapi.RoleAdmin}
	case roleDeveloper:
		viewer := agentaccess.Viewer{Role: agentapi.RoleDeveloper}
		if caller.Scope != nil {
			viewer.Scope = &agentaccess.Scope{
				Fingerprint: caller.Scope.Fingerprint, TokenID: caller.Scope.TokenID,
				UserID: caller.Identity.UserID, Username: caller.Identity.Username, TokenName: caller.Identity.TokenName,
			}
		}
		return viewer
	default:
		return agentaccess.Viewer{}
	}
}

type agentAuthorizationRequest struct {
	Challenge  string `json:"challenge"`
	Mode       string `json:"mode"`
	Port       *int   `json:"port"`
	DeviceName string `json:"device_name"`
	CLIVersion string `json:"cli_version"`
	Tier       string `json:"tier"`
	Decision   string `json:"decision"`
}

type agentAuthorizationResponse struct {
	Code        string `json:"code,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Denied      bool   `json:"denied,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// serveAgentAuthorization approves or denies one command-line login. The
// code in the response is the only copy; the page hands it to the loopback
// callback or shows it for pasting.
func (handler *managementHandler) serveAgentAuthorization(writer http.ResponseWriter, request *http.Request) {
	caller, ok := principalFrom(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxAgentAuthorizationBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body agentAuthorizationRequest
	if err := decoder.Decode(&body); err != nil {
		writeAgentFieldError(writer, "body")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAgentFieldError(writer, "body")
		return
	}
	authorization := agentaccess.AuthorizationRequest{
		Challenge: body.Challenge, Mode: body.Mode, DeviceName: body.DeviceName,
		CLIVersion: body.CLIVersion, Tier: agentapi.Tier(body.Tier),
	}
	if body.Port != nil {
		authorization.Port = *body.Port
		if authorization.Port == 0 {
			// An explicit zero is a bad port, not an omitted one.
			authorization.Port = -1
		}
	}
	grantor := agentaccess.Grantor{SessionExpiresAt: caller.ExpiresAt}
	viewer := agentViewer(caller)
	grantor.Role, grantor.Scope = viewer.Role, viewer.Scope

	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	switch body.Decision {
	case "approve":
		approved, err := handler.agent.Approve(ctx, grantor, authorization, loginLimiterKey(request))
		if err != nil {
			writeAgentAccessError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, agentAuthorizationResponse{
			Code: approved.Code, ExpiresIn: int(approved.ExpiresIn / time.Second), RedirectURI: approved.RedirectURI,
		})
	case "deny":
		redirect, err := handler.agent.Deny(ctx, grantor, authorization, loginLimiterKey(request))
		if err != nil {
			writeAgentAccessError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, agentAuthorizationResponse{Denied: true, RedirectURI: redirect})
	default:
		writeAgentFieldError(writer, "decision")
	}
}

type agentTokenItem struct {
	ID            int64   `json:"id"`
	DisplayPrefix string  `json:"display_prefix"`
	Role          string  `json:"role"`
	Tier          string  `json:"tier"`
	DeviceName    string  `json:"device_name"`
	CLIVersion    string  `json:"cli_version"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     string  `json:"expires_at"`
	LastUsedAt    *string `json:"last_used_at"`
	RevokedAt     *string `json:"revoked_at"`
}

// serveAgentTokenList lists every token, revoked and expired ones included,
// newest first: all of them for an administrator, and for a developer only
// the tokens whose scope equals the session's.
func (handler *managementHandler) serveAgentTokenList(writer http.ResponseWriter, request *http.Request) {
	caller, _ := principalFrom(request.Context())
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	tokens, err := handler.agent.ListTokens(ctx, agentViewer(caller))
	if err != nil {
		writeAgentAccessError(writer, err)
		return
	}
	items := make([]agentTokenItem, 0, len(tokens))
	for _, token := range tokens {
		items = append(items, agentTokenItem{
			ID: token.ID, DisplayPrefix: token.DisplayPrefix, Role: token.Role, Tier: token.Tier,
			DeviceName: token.DeviceName, CLIVersion: token.CLIVersion,
			CreatedAt: formatNS(token.CreatedAtNS), ExpiresAt: formatNS(token.ExpiresAtNS),
			LastUsedAt: optionalNS(token.LastUsedAtNS), RevokedAt: optionalNS(token.RevokedAtNS),
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

// serveAgentTokenRevoke is idempotent: revoked, expired, unknown and (for a
// developer) invisible tokens all answer 204.
func (handler *managementHandler) serveAgentTokenRevoke(writer http.ResponseWriter, request *http.Request, rawID string) {
	id, ok := parseAgentTokenID(rawID)
	if !ok {
		writeAgentFieldError(writer, "id")
		return
	}
	caller, _ := principalFrom(request.Context())
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	if err := handler.agent.RevokeToken(ctx, agentViewer(caller), id); err != nil {
		writeAgentAccessError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// agentChangeItem is one row of GET /api/v1/agent-access/changes: an
// agent_audit_log row of a write event, with the time as RFC 3339 and the
// changed key names as a list (contract section 3.2). It holds no values.
type agentChangeItem struct {
	ID          int64    `json:"id"`
	At          string   `json:"at"`
	Event       string   `json:"event"`
	TokenID     *int64   `json:"token_id"`
	Role        string   `json:"role"`
	Command     string   `json:"command"`
	CLIVersion  string   `json:"cli_version"`
	ObjectKind  string   `json:"object_kind"`
	ObjectID    string   `json:"object_id"`
	ChangedKeys []string `json:"changed_keys"`
	Outcome     string   `json:"outcome"`
	ErrorCode   string   `json:"error_code"`
}

// serveAgentChanges lists the newest write_applied, write_failed and
// write_denied rows; ?limit= is 1-200, default 50.
func (handler *managementHandler) serveAgentChanges(writer http.ResponseWriter, request *http.Request) {
	// URL.Query would drop a pair that does not decode, and ?limit=%zz would
	// then list the default page; refuse it like the facade does (contract
	// section 0.1 item 188).
	values, err := parseAgentQuery(request)
	if err != nil {
		writeAgentFieldError(writer, "query")
		return
	}
	for key, entries := range values {
		if key != "limit" || len(entries) != 1 {
			writeAgentFieldError(writer, key)
			return
		}
	}
	limit := defaultAgentChanges
	if values.Has("limit") {
		parsed, ok := parseAgentID(values.Get("limit"), false)
		if !ok || parsed < 1 || parsed > storage.AgentAuditListLimit {
			writeAgentFieldError(writer, "limit")
			return
		}
		limit = int(parsed)
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	entries, err := handler.agent.ListAudit(ctx, limit, agentaccess.WriteEvents)
	if err != nil {
		writeAgentAccessError(writer, err)
		return
	}
	items := make([]agentChangeItem, 0, len(entries))
	for _, entry := range entries {
		keys := []string{}
		if entry.ChangedKeys != "" {
			// Written by RecordWrite as a JSON array of names; an
			// unreadable value is shown as no keys rather than as text.
			if json.Unmarshal([]byte(entry.ChangedKeys), &keys) != nil {
				keys = []string{}
			}
		}
		items = append(items, agentChangeItem{
			ID: entry.ID, At: formatNS(entry.AtNS), Event: entry.Event, TokenID: entry.TokenID, Role: entry.Role,
			Command: entry.Command, CLIVersion: entry.CLIVersion, ObjectKind: entry.ObjectKind, ObjectID: entry.ObjectID,
			ChangedKeys: keys, Outcome: entry.Outcome, ErrorCode: entry.ErrorCode,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func parseAgentTokenID(raw string) (int64, bool) {
	if raw == "" || len(raw) > 18 {
		return 0, false
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil && id > 0
}

func formatNS(ns int64) string {
	return time.Unix(0, ns).UTC().Format(time.RFC3339)
}

func optionalNS(ns *int64) *string {
	if ns == nil {
		return nil
	}
	formatted := formatNS(*ns)
	return &formatted
}

func writeAgentFieldError(writer http.ResponseWriter, field string) {
	writeJSON(writer, http.StatusBadRequest, map[string]any{
		"error": map[string]string{"code": "invalid_argument", "message": "invalid " + field, "field": field},
	})
}

// writeAgentAccessError maps a service refusal onto the management API's
// error style.
func writeAgentAccessError(writer http.ResponseWriter, err error) {
	var coded *agentaccess.Error
	errors.As(err, &coded)
	switch agentaccess.CodeOf(err) {
	case agentapi.CodeInvalidArgument:
		field := "body"
		if coded != nil && coded.Field != "" {
			field = coded.Field
		}
		writeAgentFieldError(writer, field)
	case agentapi.CodeRateLimited:
		var wait time.Duration
		if coded != nil {
			wait = coded.RetryAfter
		}
		writeRateLimited(writer, wait, "too many agent authorizations by this session, try again later")
	case agentapi.CodeForbiddenRole:
		writeError(writer, http.StatusForbidden, "forbidden", "this session cannot authorize agent tokens")
	case agentapi.CodeRoleUnavailable:
		writeError(writer, http.StatusForbidden, "developer_login_disabled", "developer sign-in is disabled")
	case agentapi.CodeUnauthenticated:
		writeError(writer, http.StatusUnauthorized, "unauthorized", "the session has expired")
	case agentapi.CodeUpstreamUnavailable:
		writeError(writer, http.StatusServiceUnavailable, "storage_unavailable", "agent tokens are temporarily unavailable")
	default:
		writeError(writer, http.StatusInternalServerError, "internal", "internal error")
	}
}
