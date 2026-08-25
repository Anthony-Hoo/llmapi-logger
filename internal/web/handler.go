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
	"unicode"

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
	Users      UserCatalog
	Rules      UserAgentRules
	Assets     fs.FS
	Readiness  func(context.Context) ReadyStatus
	Logger     *slog.Logger
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
		users:     options.Users,
		rules:     options.Rules,
		developer: options.Developer,
		readiness: options.Readiness,
		static:    newStaticHandler(options.Assets),
		logins:    newLoginLimiter(),
		logger:    options.Logger,
	}
	handler.authenticator = newManagementAuth(options.AdminToken, options.Developer.usable())
	handler.auth = handler.authenticator.middleware(handler.serveProtected)
	return handler, nil
}

type managementHandler struct {
	query         AuditQuery
	users         UserCatalog
	rules         UserAgentRules
	developer     DeveloperLogin
	readiness     func(context.Context) ReadyStatus
	static        http.Handler
	auth          http.Handler
	authenticator *managementAuth
	logins        *loginLimiter
	logger        *slog.Logger
}

func (handler *managementHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
	// caller directory and the User-Agent policy -- is site-wide operational
	// surface and stays administrator-only.
	switch {
	case request.URL.Path == "/api/v1/audits":
		handler.serveAuditList(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/audits/"):
		handler.serveAuditResource(writer, request)
	case !handler.requireAdmin(writer, request):
		return
	case request.URL.Path == "/healthz":
		handler.serveHealth(writer, request)
	case request.URL.Path == "/readyz":
		handler.serveReady(writer, request)
	case request.URL.Path == "/api/v1/newapi/callers":
		handler.serveNewAPICallers(writer, request)
	case request.URL.Path == "/api/v1/user-agent-rules":
		handler.serveUserAgentRuleCollection(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/user-agent-rules/"):
		handler.serveUserAgentRuleResource(writer, request)
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
	return caller.Scope
}
