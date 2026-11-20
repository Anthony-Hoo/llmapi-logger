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
	// WriteSlot is the slot the request took of the write quota (or, for
	// the connection test, of the test quota), for a handler that gives it
	// back when the request is refused before doing what it counts (plan
	// creation, a connection test refused before any request was sent).
	WriteSlot agentaccess.QuotaSlot
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

		agentapi.EndpointDownload: handler.serveAgentDownload,
	}
	for id, serve := range handler.agentReadHandlers() {
		handlers[id] = serve
	}
	for id, serve := range handler.agentWriteHandlers() {
		handlers[id] = serve
	}
	return handlers
}

// agentWriteHandlers binds the write facade of contract section 4.5.
func (handler *managementHandler) agentWriteHandlers() map[string]agentHandler {
	return map[string]agentHandler{
		agentapi.EndpointPlanCreate: handler.serveAgentPlanCreate,
		agentapi.EndpointPlanApply:  handler.serveAgentPlanApply,
		agentapi.EndpointAPIKeySet:  handler.serveAgentAPIKeySet,
		agentapi.EndpointTestModel:  handler.serveAgentTestModel,
	}
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
		handler.recordWriteDenied(request, endpoint, call, identity, err)
		writeAgentServiceError(writer, err)
		return
	}
	slot, err := handler.takeAgentQuotas(endpoint, identity)
	if err != nil {
		handler.recordWriteDenied(request, endpoint, call, identity, err)
		writeAgentServiceError(writer, err)
		return
	}
	call.WriteSlot = slot
	call.Identity, call.Principal = identity, caller
	serve(writer, request.WithContext(withPrincipal(request.Context(), caller)), call)
}

// takeAgentQuotas applies the per-token limits of contract section 7 after
// the token and its permissions passed. Logout is never limited by a quota:
// revoking a token must always work. A request refused by one quota leaves
// the others as they were: a pack read refused by the sensitive-read quota
// gives back the general read slot it took. The write quota's slot is
// returned to the caller: a plan request that is refused gives it back
// (serveAgentPlanCreate), so only created plans count. So is the test
// quota's: a connection test refused before it sent anything gives it back
// (serveAgentTestModel).
func (handler *managementHandler) takeAgentQuotas(endpoint agentapi.Endpoint, identity agentaccess.Identity) (agentaccess.QuotaSlot, error) {
	switch {
	case endpoint.ID == "logout":
		return agentaccess.QuotaSlot{}, nil
	case endpoint.Tier == agentapi.TierRead:
		read, err := handler.agent.TakeSlot(agentaccess.QuotaRead, identity)
		if err != nil {
			return agentaccess.QuotaSlot{}, err
		}
		if endpoint.ID == "analysis.pack" || endpoint.ID == "analysis.facet" {
			if err := handler.agent.Take(agentaccess.QuotaSensitiveRead, identity); err != nil {
				handler.agent.Refund(read)
				return agentaccess.QuotaSlot{}, err
			}
		}
		return agentaccess.QuotaSlot{}, nil
	case endpoint.ID == agentapi.EndpointTestModel:
		return handler.agent.TakeSlot(agentaccess.QuotaTestModel, identity)
	default:
		return handler.agent.TakeSlot(agentaccess.QuotaWrite, identity)
	}
}

// recordWriteDenied writes the write_denied row of contract section 3.4 for
// a refused execution, key setting or connection test of an authenticated
// token. Plan creation is never audited. The rows of one token are capped
// (QuotaDeniedAudit): beyond the cap the refusal is answered as usual and
// not recorded, so a token without write rights cannot grow the table at the
// request rate.
func (handler *managementHandler) recordWriteDenied(request *http.Request, endpoint agentapi.Endpoint, call agentCall, identity agentaccess.Identity, err error) {
	audit := agentaccess.WriteAudit{Event: agentaccess.EventWriteDenied, Outcome: agentaccess.OutcomeDenied, ErrorCode: agentaccess.CodeOf(err)}
	switch endpoint.ID {
	case agentapi.EndpointPlanApply:
		audit.ObjectKind, audit.ObjectID = "plan", auditPlanID(call.Params["plan_id"])
	case agentapi.EndpointAPIKeySet:
		audit.ObjectKind, audit.ChangedKeys = agentKeyObject, []string{"api_key"}
	case agentapi.EndpointTestModel:
		audit.ObjectKind, audit.ObjectID = agentKeyObject, "test-model"
	default:
		return
	}
	if handler.agent.Take(agentaccess.QuotaDeniedAudit, identity) != nil {
		return
	}
	handler.agent.RecordWrite(request.Context(), identity, call.Meta, audit)
}

// auditPlanID is the plan id of a path when it has a plan id's shape, and
// empty otherwise: the change list shows it, and it must not carry text a
// client chose.
func auditPlanID(raw string) string {
	if agentaccess.ValidPlanID(raw) {
		return raw
	}
	return ""
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
// agentTokenBodyFields are the fields of the exchange body.
var agentTokenBodyFields = []string{"code", "code_verifier"}

func (handler *managementHandler) serveAgentToken(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		writeAgentError(writer, agentapi.CodeInvalidArgument, map[string]any{"field": err.(agentArgError).field})
		return
	}
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
func (handler *managementHandler) serveAgentWhoami(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	identity := call.Identity
	writeAgentOK(writer, agentapi.ReadSuccess(agentWhoamiResponse{
		Role: identity.Role, Tier: identity.Tier,
		ExpiresAt:  identity.ExpiresAt.UTC().Format(time.RFC3339),
		DeviceName: identity.DeviceName,
		Identity:   agentIdentityView(identity),
		Features: agentFeatures{
			Insights: handler.insights != nil, OrgReports: handler.org != nil,
			SessionAnalysis: handler.sessionAnalysis != nil,
			// The deployment switch is meaningful only to an administrator: a
			// developer can never hold a write token.
			WriteAllowed: handler.agent.AllowWrite() && identity.Role == agentapi.RoleAdmin,
		},
		ServerTime: handler.agent.Now().UTC().Format(time.RFC3339),
	}, agentapi.Meta{State: "authenticated", Complete: true}))
}

// serveAgentLogout revokes the calling token.
func (handler *managementHandler) serveAgentLogout(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	if err := handler.agent.Logout(ctx, call.Identity, call.Meta); err != nil {
		writeAgentServiceError(writer, err)
		return
	}
	writeAgentOK(writer, agentapi.Success(map[string]bool{"revoked": true}))
}
