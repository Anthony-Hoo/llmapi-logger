package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The agent facade (doc/features/25-agent-access.md section 7). It is
// dispatched by ServeHTTP before serveProtected and has its own
// authentication: agent tokens only, never the session cookie or the admin
// token. Every endpoint is in agentapi's registry with the identities it
// admits and the tier it needs; the dispatcher checks both before the handler
// runs, and a path that is not registered is NOT_FOUND.

const agentPathPrefix = "/api/agent/"

const maxAgentTokenBodyBytes = 4096

// agentCall is what the dispatcher hands a facade handler. For an anonymous
// endpoint Identity is zero and Principal unset.
type agentCall struct {
	Endpoint  agentapi.Endpoint
	Params    map[string]string
	Identity  agentaccess.Identity
	Principal principal
	Meta      agentaccess.RequestMeta
}

// agentHandler serves one registered facade endpoint. The request context
// also carries Principal, so code shared with the web handlers can use
// principalFrom and sessionScope unchanged.
type agentHandler func(http.ResponseWriter, *http.Request, agentCall)

// agentHandlers binds every registry ID to its handler. NewHandler refuses to
// build when the registry and this table disagree.
func (handler *managementHandler) agentHandlers() map[string]agentHandler {
	handlers := map[string]agentHandler{
		"token.exchange": handler.serveAgentToken,
		"whoami":         handler.serveAgentWhoami,
		"logout":         handler.serveAgentLogout,
	}
	for id, serve := range handler.agentReadHandlers() {
		handlers[id] = serve
	}
	return handlers
}

// agentReadHandlers binds the read facade of contract sections 4.3 and 4.4.
func (handler *managementHandler) agentReadHandlers() map[string]agentHandler {
	return map[string]agentHandler{
		"requests.list":          handler.serveAgentRequests,
		"requests.get":           handler.serveAgentRequest,
		"requests.export":        handler.serveAgentRequestExport,
		"usage.composition":      handler.serveAgentUsageComposition,
		"usage.overview":         handler.serveAgentUsageOverview,
		"usage.sessions":         handler.serveAgentUsageSessions,
		"usage.trend":            handler.serveAgentUsageTrend,
		"usage.tree":             handler.serveAgentUsageTree,
		"weekly.me":              handler.serveAgentWeeklyMe,
		"weekly.report":          handler.serveAgentWeeklyReport,
		"weekly.trend":           handler.serveAgentWeeklyTrend,
		"weekly.project":         handler.serveAgentWeeklyProject,
		"weekly.unattributed":    handler.serveAgentWeeklyUnattributed,
		"analysis.overview":      handler.serveAgentAnalysisOverview,
		"analysis.users":         handler.serveAgentAnalysisUsers,
		"analysis.sessions":      handler.serveAgentAnalysisSessions,
		"analysis.pack":          handler.serveAgentAnalysisPack,
		"analysis.facet":         handler.serveAgentAnalysisFacet,
		"analysis.report":        handler.serveAgentAnalysisReport,
		"config.show":            handler.serveAgentConfigShow,
		"config.project-preview": handler.serveAgentProjectPreview,
		"callers.list":           handler.serveAgentCallers,
		"status":                 handler.serveAgentStatus,
	}
}

func bindAgentHandlers(registry *agentapi.Registry, handlers map[string]agentHandler) error {
	endpoints := registry.Endpoints()
	if len(endpoints) != len(handlers) {
		return fmt.Errorf("web: %d agent endpoints but %d handlers", len(endpoints), len(handlers))
	}
	for _, endpoint := range endpoints {
		if handlers[endpoint.ID] == nil {
			return fmt.Errorf("web: agent endpoint %q has no handler", endpoint.ID)
		}
	}
	return nil
}

func isAgentPath(path string) bool {
	return strings.HasPrefix(path, agentPathPrefix)
}

// serveAgent dispatches one facade request. The order is fixed: the feature
// switch first (so a disabled deployment answers every method and path the
// same way, with no limiter or version effect), then the client version,
// the registry, authentication and finally the endpoint's access and tier.
func (handler *managementHandler) serveAgent(writer http.ResponseWriter, request *http.Request) {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set(agentapi.HeaderLatest, agentapi.LatestVersion)
	header.Set(agentapi.HeaderMin, agentapi.MinVersion)
	if handler.agent == nil {
		writeAgentError(writer, agentapi.CodeFeatureDisabled, nil)
		return
	}
	if agentapi.ClientTooOld(request.Header.Get(agentapi.HeaderCLIVersion)) {
		writeAgentError(writer, agentapi.CodeClientTooOld, nil)
		return
	}
	endpoint, params, ok := handler.agentRegistry.Match(request.Method, request.URL.Path)
	if !ok {
		writeAgentError(writer, agentapi.CodeNotFound, nil)
		return
	}
	call := agentCall{
		Endpoint: endpoint, Params: params,
		Meta: agentaccess.RequestMeta{
			Command:    request.Header.Get(agentapi.HeaderCommand),
			CLIVersion: request.Header.Get(agentapi.HeaderCLIVersion),
		},
	}
	serve := handler.agentHandlerTable[endpoint.ID]
	if endpoint.Access == agentapi.AccessAnonymous {
		serve(writer, request, call)
		return
	}
	identity, err := handler.agent.Authenticate(request.Context(), request.Header.Get("Authorization"), loginLimiterKey(request))
	if err != nil {
		if code := agentaccess.CodeOf(err); code == agentapi.CodeUnauthenticated || code == agentapi.CodeTokenExpired ||
			code == agentapi.CodeTokenRevoked || code == agentapi.CodeRoleUnavailable {
			header.Set("WWW-Authenticate", `Bearer realm="audit-proxy-agent"`)
		}
		writeAgentServiceError(writer, err)
		return
	}
	caller, ok := agentPrincipal(identity)
	if !ok {
		// Second line behind agentaccess.RestoreIdentity: never hand a handler
		// a developer principal without a complete scope.
		header.Set("WWW-Authenticate", `Bearer realm="audit-proxy-agent"`)
		writeAgentError(writer, agentapi.CodeUnauthenticated, nil)
		return
	}
	if err := handler.agent.Permit(identity, endpoint); err != nil {
		writeAgentServiceError(writer, err)
		return
	}
	call.Identity, call.Principal = identity, caller
	serve(writer, request.WithContext(withPrincipal(request.Context(), caller)), call)
}

// agentPrincipal maps a token identity onto the principal web sessions use.
// Scope == nil means "reads everything" in this code base, so it fails closed
// on anything but an administrator without scope or a developer with a
// complete one.
func agentPrincipal(identity agentaccess.Identity) (principal, bool) {
	if identity.TokenID <= 0 || !identity.Tier.Valid() {
		return principal{}, false
	}
	caller := principal{ExpiresAt: identity.ExpiresAt, AgentTokenID: identity.TokenID, Tier: identity.Tier}
	switch identity.Role {
	case agentapi.RoleAdmin:
		if identity.Scope != nil {
			return principal{}, false
		}
		caller.Role = roleAdmin
	case agentapi.RoleDeveloper:
		scope := identity.Scope
		if scope == nil || len(scope.Fingerprint) != storage.APIKeyFingerprintSize ||
			(scope.TokenID != nil && *scope.TokenID < 0) || identity.Tier != agentapi.TierRead {
			return principal{}, false
		}
		var tokenID *int64
		if scope.TokenID != nil {
			value := *scope.TokenID
			tokenID = &value
		}
		caller.Role = roleDeveloper
		caller.Scope = &query.Scope{Fingerprint: append([]byte(nil), scope.Fingerprint...), TokenID: tokenID}
		caller.Identity = developerIdentity{UserID: scope.UserID, Username: scope.Username, TokenID: tokenID, TokenName: scope.TokenName}
	default:
		return principal{}, false
	}
	return caller, true
}

// writeAgentOK writes a success envelope.
func writeAgentOK(writer http.ResponseWriter, envelope agentapi.Envelope) {
	envelope.OK = true
	writeJSON(writer, http.StatusOK, envelope)
}

// writeAgentError writes a failure envelope with the code's status and
// default message and hint.
func writeAgentError(writer http.ResponseWriter, code agentapi.Code, details map[string]any) {
	writeJSON(writer, agentapi.HTTPStatus(code), agentapi.Failure(code, "", "", details))
}

// writeAgentServiceError maps an agentaccess error onto the envelope,
// including Retry-After and the offending field.
func writeAgentServiceError(writer http.ResponseWriter, err error) {
	code := agentaccess.CodeOf(err)
	var details map[string]any
	var coded *agentaccess.Error
	if errors.As(err, &coded) {
		if coded.Field != "" {
			details = map[string]any{"field": coded.Field}
		}
		if code == agentapi.CodeRateLimited {
			writer.Header().Set("Retry-After", retryAfterSeconds(coded.RetryAfter))
		}
	}
	writeAgentError(writer, code, details)
}

func retryAfterSeconds(wait time.Duration) string {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

// agentIdentityView is the developer identity of contract section 3.2: the
// same fields as the session response, never the key fingerprint.
func agentIdentityView(identity agentaccess.Identity) *developerIdentity {
	if identity.Role != agentapi.RoleDeveloper || identity.Scope == nil {
		return nil
	}
	view := developerIdentity{UserID: identity.Scope.UserID, Username: identity.Scope.Username, TokenName: identity.Scope.TokenName}
	if identity.Scope.TokenID != nil {
		value := *identity.Scope.TokenID
		view.TokenID = &value
	}
	return &view
}

type agentTokenResponse struct {
	Token     string             `json:"token"`
	Role      agentapi.Role      `json:"role"`
	Tier      agentapi.Tier      `json:"tier"`
	ExpiresAt string             `json:"expires_at"`
	Identity  *developerIdentity `json:"identity,omitempty"`
}

// serveAgentToken exchanges an authorization code (anonymous). The plaintext
// token appears in this response and nowhere else.
func (handler *managementHandler) serveAgentToken(writer http.ResponseWriter, request *http.Request, call agentCall) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxAgentTokenBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeAgentError(writer, agentapi.CodeInvalidArgument, map[string]any{"field": "body"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAgentError(writer, agentapi.CodeInvalidArgument, map[string]any{"field": "body"})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	issued, err := handler.agent.Exchange(ctx, body.Code, body.CodeVerifier, loginLimiterKey(request), call.Meta)
	if err != nil {
		writeAgentServiceError(writer, err)
		return
	}
	writeAgentOK(writer, agentapi.Success(agentTokenResponse{
		Token: issued.Token, Role: issued.Identity.Role, Tier: issued.Identity.Tier,
		ExpiresAt: issued.Identity.ExpiresAt.UTC().Format(time.RFC3339),
		Identity:  agentIdentityView(issued.Identity),
	}))
}

type agentFeatures struct {
	Insights        bool `json:"insights"`
	OrgReports      bool `json:"org_reports"`
	SessionAnalysis bool `json:"session_analysis"`
	WriteAllowed    bool `json:"write_allowed"`
}

type agentWhoamiResponse struct {
	Role       agentapi.Role      `json:"role"`
	Tier       agentapi.Tier      `json:"tier"`
	ExpiresAt  string             `json:"expires_at"`
	DeviceName string             `json:"device_name"`
	Identity   *developerIdentity `json:"identity,omitempty"`
	Features   agentFeatures      `json:"features"`
	ServerTime string             `json:"server_time"`
}

// serveAgentWhoami describes the calling token. It is a read result and so
// carries meta.
func (handler *managementHandler) serveAgentWhoami(writer http.ResponseWriter, _ *http.Request, call agentCall) {
	identity := call.Identity
	writeAgentOK(writer, agentapi.ReadSuccess(agentWhoamiResponse{
		Role: identity.Role, Tier: identity.Tier,
		ExpiresAt:  identity.ExpiresAt.UTC().Format(time.RFC3339),
		DeviceName: identity.DeviceName,
		Identity:   agentIdentityView(identity),
		Features: agentFeatures{
			Insights: handler.insights != nil, OrgReports: handler.org != nil,
			SessionAnalysis: handler.sessionAnalysis != nil, WriteAllowed: handler.agent.AllowWrite(),
		},
		ServerTime: handler.agent.Now().UTC().Format(time.RFC3339),
	}, agentapi.Meta{State: "authenticated", Complete: true}))
}

// serveAgentLogout revokes the calling token.
func (handler *managementHandler) serveAgentLogout(writer http.ResponseWriter, request *http.Request, call agentCall) {
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	if err := handler.agent.Logout(ctx, call.Identity, call.Meta); err != nil {
		writeAgentServiceError(writer, err)
		return
	}
	writeAgentOK(writer, agentapi.Success(map[string]bool{"revoked": true}))
}
