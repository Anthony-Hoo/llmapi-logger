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
	"llmapi-logger/internal/uaguard"
)

// AuditQuery is the safe query surface consumed by the HTTP handlers.
type AuditQuery interface {
	Healthy() bool
	List(context.Context, query.Filter, query.Cursor, int) (query.Page, error)
	Get(context.Context, string) (query.Detail, error)
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

type Options struct {
	AdminToken string
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
		readiness: options.Readiness,
		static:    newStaticHandler(options.Assets),
		logger:    options.Logger,
	}
	handler.authenticator = newManagementAuth(options.AdminToken)
	handler.auth = handler.authenticator.middleware(handler.serveProtected)
	return handler, nil
}

type managementHandler struct {
	query         AuditQuery
	users         UserCatalog
	rules         UserAgentRules
	readiness     func(context.Context) ReadyStatus
	static        http.Handler
	auth          http.Handler
	authenticator *managementAuth
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
	switch {
	case request.URL.Path == "/healthz":
		handler.serveHealth(writer, request)
	case request.URL.Path == "/readyz":
		handler.serveReady(writer, request)
	case request.URL.Path == "/api/v1/audits":
		handler.serveAuditList(writer, request)
	case request.URL.Path == "/api/v1/newapi/callers":
		handler.serveNewAPICallers(writer, request)
	case request.URL.Path == "/api/v1/user-agent-rules":
		handler.serveUserAgentRuleCollection(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/user-agent-rules/"):
		handler.serveUserAgentRuleResource(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/audits/"):
		handler.serveAuditResource(writer, request)
	default:
		http.NotFound(writer, request)
	}
}
