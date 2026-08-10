// Package audit coordinates encrypted evidence capture for one proxied HTTP
// exchange. It deliberately depends on storage abstractions rather than SQL.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	ModeAvailable = "available"
	ModeStrict    = "strict"
)

var ErrUnavailable = errors.New("audit unavailable")

// Store is the ordered persistence surface used by a Session. FinishAudit is
// a barrier for all earlier accepted asynchronous writes.
type Store interface {
	Healthy() bool
	BeginAudit(context.Context, sqlite.AuditRecord) error
	StartStage(context.Context, sqlite.HTTPStage) error
	StartBody(context.Context, sqlite.BodyStream) error
	AddHeaders(context.Context, []sqlite.HTTPHeader) error
	AddChunk(context.Context, sqlite.BodyChunk) error
	FinishStage(context.Context, sqlite.StageFinish) error
	FinishAudit(context.Context, sqlite.AuditFinish) error
}

// Sink is the proxy-facing audit admission interface. A nil Session always
// accompanies a non-nil error.
type Sink interface {
	Healthy() bool
	Mode() string
	Begin(context.Context, *http.Request, routing.Match) (*Session, error)
}

// Manager admits matched requests and constructs their sparse Sessions.
type Manager struct {
	store  Store
	cipher security.Cipher
	mode   string
	logger *slog.Logger

	now    func() time.Time
	random io.Reader
	cause  error

	notifyMu sync.RWMutex
	notify   func(string) bool
}

// NewManager constructs a live audit manager.
func NewManager(store Store, cipher security.Cipher, mode string, logger *slog.Logger) (*Manager, error) {
	if mode != ModeAvailable && mode != ModeStrict {
		return nil, fmt.Errorf("audit: invalid mode %q", mode)
	}
	if store == nil {
		return nil, errors.New("audit: nil store")
	}
	if cipher == nil {
		return nil, errors.New("audit: nil cipher")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		store:  store,
		cipher: cipher,
		mode:   mode,
		logger: logger,
		now:    time.Now,
		random: rand.Reader,
	}, nil
}

// NewUnavailable constructs a manager that preserves configured admission
// semantics when the database or key could not be initialized. Available mode
// continues without an audit; strict mode is rejected by the proxy.
func NewUnavailable(mode string, cause error, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if cause == nil {
		cause = ErrUnavailable
	}
	return &Manager{
		mode:   mode,
		logger: logger,
		now:    time.Now,
		random: rand.Reader,
		cause:  cause,
	}
}

// Mode returns the configured admission mode.
func (manager *Manager) Mode() string {
	if manager == nil {
		return ModeAvailable
	}
	return manager.mode
}

// Healthy reports whether new audit parents can currently be admitted.
func (manager *Manager) Healthy() bool {
	return manager != nil && manager.store != nil && manager.cipher != nil && manager.cause == nil && manager.store.Healthy()
}

// SetCompletionNotifier installs the non-blocking callback used to enqueue a
// successfully finalized audit for asynchronous parsing. A nil callback keeps
// capture independent from the parser subsystem.
func (manager *Manager) SetCompletionNotifier(notify func(string) bool) {
	if manager == nil {
		return
	}
	manager.notifyMu.Lock()
	manager.notify = notify
	manager.notifyMu.Unlock()
}

func (manager *Manager) completionNotifier() func(string) bool {
	if manager == nil {
		return nil
	}
	manager.notifyMu.RLock()
	defer manager.notifyMu.RUnlock()
	return manager.notify
}

// Begin synchronously commits the audit parent, then starts the inbound stage
// and installs its streaming Body observer before interceptor evaluation.
func (manager *Manager) Begin(ctx context.Context, request *http.Request, match routing.Match) (*Session, error) {
	if ctx == nil {
		return nil, errors.New("audit: nil context")
	}
	if request == nil {
		return nil, errors.New("audit: nil request")
	}
	if manager == nil || manager.store == nil || manager.cipher == nil || manager.cause != nil {
		return nil, manager.unavailableError()
	}
	if manager.mode == ModeStrict && !manager.store.Healthy() {
		return nil, fmt.Errorf("%w: store is unhealthy", ErrUnavailable)
	}

	auditID, err := generateAuditID(manager.random)
	if err != nil {
		return nil, fmt.Errorf("audit: generate id: %w", err)
	}
	requestURI := request.RequestURI
	if requestURI == "" && request.URL != nil {
		requestURI = request.URL.RequestURI()
	}
	requestURIAdditionalData, err := security.AAD(auditID, "request_uri")
	if err != nil {
		return nil, fmt.Errorf("audit: request URI AAD: %w", err)
	}
	requestURIEncrypted, err := manager.cipher.Encrypt(requestURIAdditionalData, []byte(requestURI))
	if err != nil {
		return nil, fmt.Errorf("audit: encrypt request URI: %w", err)
	}

	started := manager.now()
	path := "/"
	if request.URL != nil && request.URL.EscapedPath() != "" {
		path = request.URL.EscapedPath()
	}
	record := sqlite.AuditRecord{
		AuditID:       auditID,
		StartedAtNS:   started.UnixNano(),
		RouteID:       match.RouteID,
		Protocol:      protocolForParser(match.Parser),
		ParserName:    match.Parser,
		Method:        request.Method,
		Path:          path,
		RequestURIEnc: requestURIEncrypted,
		Mode:          manager.mode,
		ForwardStatus: sqlite.ForwardInProgress,
		CaptureStatus: sqlite.CapturePending,
		ParseStatus:   sqlite.ParsePending,
	}
	if err := manager.store.BeginAudit(ctx, record); err != nil {
		return nil, fmt.Errorf("audit: begin record: %w", err)
	}

	session := newSession(manager, ctx, auditID, match.RouteID, started)
	session.WrapRequestReceived(request)
	return session, nil
}

func (manager *Manager) unavailableError() error {
	if manager == nil || manager.cause == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, manager.cause)
}

func generateAuditID(source io.Reader) (string, error) {
	if source == nil {
		return "", errors.New("nil random source")
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return "apx_" + strings.ToLower(encoded), nil
}

func protocolForParser(parser string) string {
	protocol, _, _ := strings.Cut(parser, ".")
	if protocol == "" {
		return "unknown"
	}
	return protocol
}
