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
	"net/url"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/parser/streamterminal"
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
	InsertAuditGaps(context.Context, []sqlite.AuditGap) error
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
	store        Store
	cipher       security.Cipher
	fingerprints *security.CredentialFingerprinter
	mode         string
	logger       *slog.Logger

	now    func() time.Time
	random io.Reader
	cause  error
	gaps   *gapBuffer

	notifyMu     sync.RWMutex
	notify       func(string) bool
	callerNotify func(string) bool
}

// NewManager constructs a live audit manager. A nil fingerprinter disables
// credential scoping: every record is then stored without an API key tag and no
// developer session can match it.
func NewManager(store Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, mode string, logger *slog.Logger) (*Manager, error) {
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
	manager := &Manager{
		store:        store,
		cipher:       cipher,
		fingerprints: fingerprints,
		mode:         mode,
		logger:       logger,
		now:          time.Now,
		random:       rand.Reader,
	}
	manager.gaps = newGapBuffer(store, logger, func() time.Time { return manager.now() })
	return manager, nil
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
	manager := &Manager{
		mode:   mode,
		logger: logger,
		now:    time.Now,
		random: rand.Reader,
		cause:  cause,
	}
	manager.gaps = newGapBuffer(nil, logger, func() time.Time { return manager.now() })
	return manager
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

// StartGapFlusher begins the small best-effort loop that persists aggregate
// available-mode gaps. It does not rebuild unavailable startup dependencies.
func (manager *Manager) StartGapFlusher(ctx context.Context) {
	if manager != nil && manager.gaps != nil {
		manager.gaps.start(ctx)
	}
}

// CloseGaps stops the flusher and makes one final bounded persistence attempt.
func (manager *Manager) CloseGaps(ctx context.Context) {
	if manager != nil && manager.gaps != nil {
		manager.gaps.close(ctx)
	}
}

func (manager *Manager) recordGap(reason string) {
	if manager == nil || manager.mode != ModeAvailable || manager.gaps == nil {
		return
	}
	manager.gaps.record(reason)
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

// SetCallerNotifier installs the non-blocking callback used to wake the
// request-id based NewAPI caller worker after an audit commits.
func (manager *Manager) SetCallerNotifier(notify func(string) bool) {
	if manager == nil {
		return
	}
	manager.notifyMu.Lock()
	manager.callerNotify = notify
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

func (manager *Manager) callerNotifier() func(string) bool {
	if manager == nil {
		return nil
	}
	manager.notifyMu.RLock()
	defer manager.notifyMu.RUnlock()
	return manager.callerNotify
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
		if manager != nil {
			manager.recordGap(sqlite.GapReasonDBUnavailable)
		}
		return nil, manager.unavailableError()
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
		manager.recordGap(sqlite.GapReasonEncryption)
		return nil, fmt.Errorf("audit: request URI AAD: %w", err)
	}
	requestURIEncrypted, err := manager.cipher.Encrypt(requestURIAdditionalData, []byte(requestURI))
	if err != nil {
		manager.recordGap(sqlite.GapReasonEncryption)
		return nil, fmt.Errorf("audit: encrypt request URI: %w", err)
	}

	started := manager.now()
	path := "/"
	var query url.Values
	if request.URL != nil {
		if request.URL.EscapedPath() != "" {
			path = request.URL.EscapedPath()
		}
		query = request.URL.Query()
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
		// Tagging the credential here, before interceptors run, is what lets a
		// developer session see its own rejected requests too.
		APIKeyFPR: manager.fingerprints.FingerprintRequest(request.Header, query),
	}
	if err := manager.store.BeginAudit(ctx, record); err != nil {
		manager.recordGap(gapReasonForWrite(err))
		return nil, fmt.Errorf("audit: begin record: %w", err)
	}
	if manager.gaps != nil {
		manager.gaps.trigger()
	}
	session := newSession(manager, ctx, auditID, match.RouteID, started)
	session.terminalMatcher = streamterminal.MatcherFor(match.Parser)
	session.WrapRequestReceived(request)
	return session, nil
}

func gapReasonForWrite(err error) string {
	switch {
	case errors.Is(err, sqlite.ErrQueueFull):
		return sqlite.GapReasonQueueFull
	case errors.Is(err, sqlite.ErrClosed):
		return sqlite.GapReasonDBUnavailable
	default:
		return sqlite.GapReasonWrite
	}
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
