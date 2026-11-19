// Package agentaccess implements the agent token service of module 25
// (doc/features/25-agent-access.md sections 5 and 6): issuing tokens through
// an authorization code with PKCE, checking a token on every facade request,
// revoking tokens, the failed-lookup limiters and the agent audit log.
//
// Tokens resolve to the same two identities the web sessions have. A token is
// never a new kind of power: an administrator token reads everything, a
// developer token carries exactly the scope of the web session that
// authorized it, and a developer token whose scope cannot be fully restored is
// refused rather than treated as unscoped.
package agentaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Store is the persistence the service needs; the PostgreSQL store implements
// it. Create and Revoke must report a definitive outcome.
type Store interface {
	CreateAgentToken(context.Context, storage.AgentToken) (storage.AgentToken, error)
	FindAgentTokenByMAC(context.Context, []byte) (storage.AgentToken, error)
	RevokeAgentToken(ctx context.Context, id, atNS int64, scope *storage.AgentTokenScope) (bool, error)
	TouchAgentToken(ctx context.Context, id, atNS int64) error
	ListAgentTokens(context.Context, *storage.AgentTokenScope) ([]storage.AgentToken, error)
	InsertAgentAudit(context.Context, storage.AgentAuditEntry) error
	// ListAgentAudit returns the newest rows first; events, when not empty,
	// selects the rows of those events.
	ListAgentAudit(ctx context.Context, limit int, events []string) ([]storage.AgentAuditEntry, error)
}

// Token lifetimes (plan section 5.1). None is ever extended.
const (
	AdminReadLifetime  = 30 * 24 * time.Hour
	AdminWriteLifetime = 7 * 24 * time.Hour
	// MaxDeveloperLifetime is the web session lifetime; a developer token
	// expires with the session that authorized it.
	MaxDeveloperLifetime = 7 * 24 * time.Hour
)

// Limits (contract section 7).
const (
	lookupFailureLimit       = 10
	lookupFailureWindow      = 5 * time.Minute
	exchangeFailureLimit     = 10
	exchangeFailureWindow    = 5 * time.Minute
	authorizationLimit       = 20
	authorizationWindow      = 5 * time.Minute
	touchInterval            = time.Minute
	auditWriteTimeout        = 5 * time.Second
	touchWriteTimeout        = 5 * time.Second
	tokenKeyDomain           = "llmapi-logger/agent-token/v1\x00"
	tokenDisplayPrefixLength = 8
)

// Audit events (contract section 3.4).
const (
	EventAuthorizeApproved   = "authorize_approved"
	EventAuthorizeDenied     = "authorize_denied"
	EventTokenIssued         = "token_issued"
	EventTokenExchangeFailed = "token_exchange_failed"
	EventTokenRevoked        = "token_revoked"
	EventLinkIssued          = "link_issued"
	EventPackageDownloaded   = "package_downloaded"
	EventWriteApplied        = "write_applied"
	EventWriteFailed         = "write_failed"
	EventWriteDenied         = "write_denied"
	EventSensitiveRead       = "sensitive_read"
)

// ObjectKindToken is the object_kind of token events.
const ObjectKindToken = "agent_token"

// Error carries the facade error code of a refusal. Field names the offending
// request field of an INVALID_ARGUMENT; RetryAfter is set on RATE_LIMITED.
type Error struct {
	Code       agentapi.Code
	Field      string
	RetryAfter time.Duration
}

func (err *Error) Error() string {
	if err.Field != "" {
		return "agentaccess: " + string(err.Code) + " (" + err.Field + ")"
	}
	return "agentaccess: " + string(err.Code)
}

// CodeOf maps any error to its facade code; INTERNAL for an unclassified one.
func CodeOf(err error) agentapi.Code {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return agentapi.CodeInternal
}

func fail(code agentapi.Code) *Error { return &Error{Code: code} }

func invalid(field string) *Error { return &Error{Code: agentapi.CodeInvalidArgument, Field: field} }

// Scope is a developer's read scope, field for field the v2 session cookie
// payload. Fingerprint must never be sent to any client.
type Scope struct {
	Fingerprint []byte
	TokenID     *int64
	UserID      int64
	Username    string
	TokenName   string
}

// Identity is a resolved agent token.
type Identity struct {
	TokenID    int64
	Role       agentapi.Role
	Tier       agentapi.Tier
	ExpiresAt  time.Time
	DeviceName string
	CLIVersion string
	// Scope is nil for an administrator and always complete for a developer.
	Scope *Scope
}

// Viewer is a web session acting on the token list.
type Viewer struct {
	Role agentapi.Role
	// Scope is required for a developer.
	Scope *Scope
}

// RequestMeta is what the client says about itself. It is recorded in the
// audit log and never trusted.
type RequestMeta struct {
	Command    string
	CLIVersion string
}

// Options configures the service.
type Options struct {
	// AdminToken keys the token MAC; rotating it invalidates every token.
	AdminToken string
	Store      Store
	// AllowWrite is agent_access.allow_write.
	AllowWrite bool
	// DeveloperLogins is whether developer sign-in is usable. When it is not,
	// every developer token is refused with ROLE_UNAVAILABLE.
	DeveloperLogins bool
	Logger          *slog.Logger
	// Now and Random are injectable for tests.
	Now    func() time.Time
	Random io.Reader
}

// Service issues, checks and revokes agent tokens.
type Service struct {
	store           Store
	tokenKey        [sha256.Size]byte
	allowWrite      bool
	developerLogins bool
	logger          *slog.Logger
	now             func() time.Time
	random          io.Reader

	lookups        *windowLimiter
	exchanges      *windowLimiter
	authorizations *windowLimiter
	codes          *codeStore
	quotas         map[Quota]*windowLimiter

	touchMu   sync.Mutex
	touchedAt map[int64]time.Time
}

// New builds the service. The admin token must be the one the web handler
// uses, so that rotating it revokes agent tokens together with sessions.
func New(options Options) (*Service, error) {
	if options.AdminToken == "" {
		return nil, errors.New("agentaccess: admin token required")
	}
	if options.Store == nil {
		return nil, errors.New("agentaccess: store required")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	service := &Service{
		store:           options.Store,
		tokenKey:        sha256.Sum256([]byte(tokenKeyDomain + options.AdminToken)),
		allowWrite:      options.AllowWrite,
		developerLogins: options.DeveloperLogins,
		logger:          options.Logger,
		now:             options.Now,
		random:          options.Random,
		touchedAt:       make(map[int64]time.Time),
	}
	service.lookups = newWindowLimiter(lookupFailureLimit, lookupFailureWindow, service.now)
	service.exchanges = newWindowLimiter(exchangeFailureLimit, exchangeFailureWindow, service.now)
	service.authorizations = newWindowLimiter(authorizationLimit, authorizationWindow, service.now)
	service.codes = newCodeStore()
	service.quotas = newQuotaLimiters(service.now)
	return service, nil
}

// AllowWrite reports agent_access.allow_write.
func (service *Service) AllowWrite() bool { return service != nil && service.allowWrite }

// DeveloperLogins reports whether developer tokens can be used at all.
func (service *Service) DeveloperLogins() bool { return service != nil && service.developerLogins }

// Now is the service clock, for handlers that format server_time.
func (service *Service) Now() time.Time { return service.now() }

// RecordAudit appends one audit row. It never fails the caller: a write
// failure is logged with its event name only. Callers must not put a token,
// an authorization code, a key or a written value into any field.
func (service *Service) RecordAudit(ctx context.Context, entry storage.AgentAuditEntry) {
	if service == nil {
		return
	}
	if entry.AtNS <= 0 {
		entry.AtNS = service.now().UnixNano()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// The row describes something that already happened; the request being
	// cancelled must not lose it.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := service.store.InsertAgentAudit(writeCtx, entry); err != nil {
		service.logger.Warn("agent audit write failed", "error_category", "agent_audit_failed", "event", entry.Event)
	}
}

// auditFor fills the token-related fields of an audit row from an identity.
func auditFor(identity Identity, meta RequestMeta, event, outcome string) storage.AgentAuditEntry {
	tokenID := identity.TokenID
	entry := storage.AgentAuditEntry{
		Event: event, Role: string(identity.Role), Command: cleanCommand(meta.Command),
		CLIVersion: cleanVersion(meta.CLIVersion), Outcome: outcome,
	}
	if tokenID > 0 {
		entry.TokenID = &tokenID
		entry.ObjectKind = ObjectKindToken
		entry.ObjectID = formatID(tokenID)
	}
	return entry
}
