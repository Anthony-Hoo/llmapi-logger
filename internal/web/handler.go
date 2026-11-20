// Package web implements the small authenticated management plane. Static UI
// files are public, while every API and health endpoint requires the same
// configured Bearer token regardless of the remote address.
package web

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentdist"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/uaguard"
)

// AuditQuery is the safe query surface consumed by the HTTP handlers.
type AuditQuery interface {
	Healthy() bool
	List(context.Context, query.Filter, query.Cursor, int) (query.Page, error)
	// Authorize gates every per-audit endpoint for scoped sessions. A nil
	// scope means an administrator and always passes.
	Authorize(context.Context, string, *query.Scope) error
	Get(context.Context, string, *query.Scope) (query.Detail, error)
	ReconstructTurn(context.Context, string) (query.ReconstructedTurn, error)
	Timeline(context.Context, string, query.Side) (query.StreamTimeline, error)
	RawMeta(context.Context, string, query.Side) (query.RawMetadata, error)
	StreamRaw(context.Context, string, query.Side, io.Writer) error
}

// UserCatalog exposes only the safe subset of NewAPI's global user directory.
type UserCatalog interface {
	Snapshot() newapi.UserSnapshot
}

// UserAgentRules is the authenticated dynamic policy surface.
type UserAgentRules interface {
	List() []uaguard.Rule
	Create(context.Context, uaguard.RuleInput) (uaguard.Rule, error)
	Update(context.Context, int64, uaguard.RuleInput) (uaguard.Rule, error)
	Delete(context.Context, int64) error
}

// ContentPolicyRules is the authenticated keyword policy surface. It is
// deliberately narrower than contentpolicy.RuleSet: the management plane edits
// rules and never evaluates a request, so Check/Requirements are omitted.
type ContentPolicyRules interface {
	Available() bool
	List() []contentpolicy.Rule
	Create(context.Context, contentpolicy.RuleInput) (contentpolicy.Rule, error)
	Update(context.Context, int64, contentpolicy.RuleInput) (contentpolicy.Rule, error)
	Delete(context.Context, int64) error
}

type ReadyStatus struct {
	Status        string `json:"status"`
	Database      string `json:"database"`
	EncryptionKey string `json:"encryption_key"`
	ParserQueue   int    `json:"parser_queue"`
	CallerQueue   int    `json:"caller_queue"`
}

// DeveloperLogin enables the second management identity. Fingerprints tags the
// submitted key exactly as the capture path tagged the requests it made, and
// ValidateKey authenticates it against NewAPI. All three fields are required
// together; without them developer login stays off.
type DeveloperLogin struct {
	Enabled      bool
	NewAPIURL    string
	HTTPClient   *http.Client
	Fingerprints *security.CredentialFingerprinter
	ValidateKey  func(context.Context, string, *http.Client, string) (newapi.TokenIdentity, error)
}

func (login DeveloperLogin) usable() bool {
	return login.Enabled && login.NewAPIURL != "" && login.Fingerprints != nil && login.ValidateKey != nil
}

type Options struct {
	AdminToken string
	Developer  DeveloperLogin
	Query      AuditQuery
	Insights   InsightsQuery
	Users      UserCatalog
	Rules      UserAgentRules
	// Policies is the keyword policy CRUD surface wired by app. Nil keeps the
	// management endpoints at a stable 503.
	Policies ContentPolicyRules
	// Org is the optional organisation report surface; nil keeps every
	// /api/v1/org route at 404 (doc/features/23-org-project-reports.md).
	Org       OrgReports
	Assets    fs.FS
	Readiness func(context.Context) ReadyStatus
	Logger    *slog.Logger

	// SessionAnalysis is nil unless session_analysis.enabled.
	SessionAnalysis SessionAnalysisQuery
	// SessionAnalysisSettings is nil unless session_analysis.enabled.
	SessionAnalysisSettings SessionAnalysisSettings

	// InjectedUserTextPrefixes is the effective vocabulary list of lower-cased
	// prefixes that mark client-injected user text
	// (insights.Vocabulary.InjectedUserTextPrefixes). The session response
	// carries it so the conversation view's user-input outline skips that text.
	InjectedUserTextPrefixes []string

	// AgentAccess is nil unless agent_access.enabled. While nil the facade
	// answers FEATURE_DISABLED for every request and /api/v1/agent-access/*
	// answers what any unknown /api/v1 path answers the same caller
	// (doc/features/25-agent-access.md).
	AgentAccess *agentaccess.Service
	// AgentDist serves the install links and the signed package downloads
	// (contract section 5). It is only used while AgentAccess is set; nil
	// there makes every download NOT_FOUND and install-links answer that no
	// packages ship with this deployment.
	AgentDist *agentdist.Service
	// AgentPublicURL is agent_access.public_url: the server address written
	// into install prompts. Empty means the address the browser is using.
	AgentPublicURL string
	// RetentionDays is the deployment's retention_days (0: kept forever). A
	// weekly.regenerate plan of a week older than it says what regenerating
	// loses (doc/features/25-agent-access-contract.md section 0.1).
	RetentionDays int
}

// NewHandler constructs the complete management handler. It rejects an empty
// token even when callers bind the resulting server only to loopback.
func NewHandler(options Options) (http.Handler, error) {
	if options.AdminToken == "" || strings.IndexFunc(options.AdminToken, unicode.IsSpace) >= 0 {
		return nil, errors.New("web: admin token must not be empty or contain whitespace")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	handler := &managementHandler{
		query:     options.Query,
		insights:  options.Insights,
		users:     options.Users,
		rules:     options.Rules,
		policies:  options.Policies,
		org:       options.Org,
		developer: options.Developer,
		readiness: options.Readiness,
		static:    newStaticHandler(options.Assets),
		logins:    newLoginLimiter(),
		logger:    options.Logger,

		sessionAnalysis: options.SessionAnalysis,

		sessionAnalysisSettings: options.SessionAnalysisSettings,

		injectedUserTextPrefixes: append([]string(nil), options.InjectedUserTextPrefixes...),

		agent:          options.AgentAccess,
		agentDist:      options.AgentDist,
		agentPublicURL: options.AgentPublicURL,
		agentRegistry:  agentapi.NewRegistry(agentapi.Endpoints),
		retentionDays:  options.RetentionDays,
	}
	if handler.agent != nil {
		handler.agentPlans = agentaccess.NewPlanStore(handler.agent.Now, nil)
	}
	handler.agentHandlerTable = handler.agentHandlers()
	if err := bindAgentHandlers(handler.agentRegistry, handler.agentHandlerTable); err != nil {
		return nil, err
	}
	handler.authenticator = newManagementAuth(options.AdminToken, options.Developer.usable())
	handler.auth = handler.authenticator.middleware(handler.serveProtected)
	return handler, nil
}

type managementHandler struct {
	query         AuditQuery
	insights      InsightsQuery
	users         UserCatalog
	rules         UserAgentRules
	policies      ContentPolicyRules
	org           OrgReports
	developer     DeveloperLogin
	readiness     func(context.Context) ReadyStatus
	static        http.Handler
	auth          http.Handler
	authenticator *managementAuth
	logins        *loginLimiter
	logger        *slog.Logger

	sessionAnalysis SessionAnalysisQuery

	sessionAnalysisSettings SessionAnalysisSettings

	injectedUserTextPrefixes []string

	agent             *agentaccess.Service
	agentRegistry     *agentapi.Registry
	agentHandlerTable map[string]agentHandler
	agentPlans        *agentaccess.PlanStore
	agentDist         *agentdist.Service
	agentPublicURL    string
	retentionDays     int
	// regenerateTimeout replaces orgRegenerateTimeout for an agent's weekly
	// regeneration when positive; only tests set it.
	regenerateTimeout time.Duration
}

func (handler *managementHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// The facade has its own authentication and never reaches the session
	// or admin-token middleware.
	if isAgentPath(request.URL.Path) {
		handler.serveAgent(writer, request)
		return
	}
	if request.URL.Path == "/api/v1/session" {
		handler.serveSession(writer, request)
		return
	}
	if protectedPath(request.URL.Path) {
		handler.auth.ServeHTTP(writer, request)
		return
	}
	switch {
	case request.URL.Path == "/":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			methodNotAllowed(writer, http.MethodGet, http.MethodHead)
			return
		}
		http.Redirect(writer, request, "/ui/", http.StatusTemporaryRedirect)
	case request.URL.Path == "/ui" || strings.HasPrefix(request.URL.Path, "/ui/"):
		if handler.agent != nil {
			// The UI now hosts the agent authorization page; a framing site
			// must not be able to click "authorize" for the user.
			writer.Header().Set("X-Frame-Options", "DENY")
			writer.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		}
		handler.static.ServeHTTP(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func protectedPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/metrics" ||
		path == "/api/v1" || strings.HasPrefix(path, "/api/v1/")
}

func (handler *managementHandler) serveProtected(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	// Audit reads are scoped per session; everything else -- health, the
	// caller directory and the dynamic policy surfaces -- is site-wide
	// operational surface and stays administrator-only.
	switch {
	case request.URL.Path == "/api/v1/audits":
		handler.serveAuditList(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/audits/"):
		handler.serveAuditResource(writer, request)
	case strings.HasPrefix(request.URL.Path, insightsPathPrefix):
		handler.serveInsights(writer, request)
	case isOrgPath(request.URL.Path):
		handler.serveOrg(writer, request)
	case strings.HasPrefix(request.URL.Path, sessionAnalysisPathPrefix):
		handler.serveSessionAnalysis(writer, request)
	case isAgentAccessPath(request.URL.Path) && handler.agent != nil:
		// Both roles authorize and manage their own agent tokens, so this
		// family must stay ahead of the administrator-only fallback. While
		// the feature is off the family is not dispatched at all: its paths
		// get exactly what any unknown /api/v1 path gets from the same caller
		// (403 for a developer, 404 for an administrator).
		handler.serveAgentAccess(writer, request)
	case !handler.requireAdmin(writer, request):
		return
	case request.URL.Path == "/healthz":
		handler.serveHealth(writer, request)
	case request.URL.Path == "/readyz":
		handler.serveReady(writer, request)
	case request.URL.Path == "/api/v1/newapi/callers":
		handler.serveNewAPICallers(writer, request)
	case request.URL.Path == sessionAnalysisSettingsPath:
		handler.serveSessionAnalysisSettings(writer, request)
	case request.URL.Path == sessionAnalysisSettingsTestPath:
		handler.serveSessionAnalysisSettingsTest(writer, request)
	case request.URL.Path == orgReportsSettingsPath:
		handler.serveOrgReportsSettings(writer, request)
	case request.URL.Path == "/api/v1/user-agent-rules":
		handler.serveUserAgentRuleCollection(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/user-agent-rules/"):
		handler.serveUserAgentRuleResource(writer, request)
	case request.URL.Path == "/api/v1/content-policy-rules":
		handler.serveContentPolicyRuleCollection(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/content-policy-rules/"):
		handler.serveContentPolicyRuleResource(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

// requireAdmin answers 403 rather than 404 for a developer: the endpoint plainly
// exists, it is the caller who lacks the role.
func (handler *managementHandler) requireAdmin(writer http.ResponseWriter, request *http.Request) bool {
	caller, ok := principalFrom(request.Context())
	if !ok || caller.Role != roleAdmin {
		writeError(writer, http.StatusForbidden, "forbidden", "administrator session required")
		return false
	}
	return true
}

// sessionScope returns the read scope of the current caller, and nil for an
// administrator.
func (handler *managementHandler) sessionScope(request *http.Request) *query.Scope {
	caller, ok := principalFrom(request.Context())
	if !ok {
		return nil
	}
	return callerReadScope(caller)
}

// requestPrincipal returns the authenticated caller of request; the zero
// principal (no role, no scope) when there is none.
func requestPrincipal(request *http.Request) principal {
	caller, _ := principalFrom(request.Context())
	return caller
}
