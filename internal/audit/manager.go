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
	"sync/atomic"
	"time"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/parser/streamterminal"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const (
	ModeAvailable = "available"
	ModeStrict    = "strict"
)

var ErrUnavailable = errors.New("audit unavailable")

// Store is the ordered persistence surface used by a Session.
// FinishAuditWithResult is a barrier for earlier asynchronous writes and
// returns the effective committed outcome for the completion log.
//
// The legacy write path uses StartStage through FinishAuditWithResult. The
// unified write path uses BeginAudit with the inbound stage, Checkpoint (not
// waited for) and CommitAudit (waited for; a barrier like
// FinishAuditWithResult). A store that implements the methods but cannot
// serve the unified path says so through SupportsUnifiedWrite.
type Store interface {
	Healthy() bool
	BeginAudit(context.Context, storage.AuditRecord) error
	StartStage(context.Context, storage.HTTPStage) error
	StartBody(context.Context, storage.BodyStream) error
	AddHeaders(context.Context, []storage.HTTPHeader) error
	AddChunk(context.Context, storage.BodyChunk) error
	FinishStage(context.Context, storage.StageFinish) error
	FinishAuditWithResult(context.Context, storage.AuditFinish) (storage.AuditFinish, error)
	Checkpoint(context.Context, storage.AuditCheckpoint) error
	CommitAudit(context.Context, storage.AuditCommit) (storage.AuditFinish, error)
	InsertAuditGaps(context.Context, []storage.AuditGap) error
}

// unifiedWriteSupport is implemented by a store that may be unable to serve
// the unified write path. A store without the method serves it.
type unifiedWriteSupport interface {
	SupportsUnifiedWrite() bool
}

// headerBlockSupport is implemented by a store that can write the version 2
// header block. A store without the method cannot.
type headerBlockSupport interface {
	SupportsHeaderBlock() bool
}

// Write paths of Options.WritePath.
const (
	WritePathLegacy  = "legacy"
	WritePathUnified = "unified"
)

// Defaults of the unified write path (design F.1, B.8).
const (
	DefaultStageBytes    = 8 << 20
	DefaultGlobalBytes   = 256 << 20
	DefaultCommitRetries = 3
	MaxCommitRetries     = 5
)

// Options selects the write path of a Manager. The zero value is the legacy
// path.
type Options struct {
	// WritePath is WritePathLegacy (or empty) or WritePathUnified.
	WritePath string
	// CommitRetries is the initial retry count of CommitAudit, 0 to 5; see
	// SetCommitRetries.
	CommitRetries int
	// StageBytes and GlobalBytes are the plaintext the unified path keeps in
	// memory per stage and for the whole process. Zero means the default.
	StageBytes  int64
	GlobalBytes int64
	// Stager takes sealed chunks the memory budget cannot hold
	// (*staging.Stager). Nil means no staging: content beyond the budget is
	// not retained (design F.6).
	Stager ChunkStager
	// Now and Random replace the clock and the audit id source, for
	// deterministic tests and tools. Nil means time.Now and crypto/rand.
	Now    func() time.Time
	Random io.Reader
	// Sleep replaces the wait between CommitAudit attempts. Nil is time.Sleep.
	Sleep func(time.Duration)
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
	// handover takes committed audits on the unified write path (handover.go).
	handover func(handover.Job) bool

	// unified selects the unified write path for every session.
	unified bool
	// captureVersion is the capture_version the unified path writes.
	captureVersion int
	// commitRetries is the live retry count of CommitAudit (SetCommitRetries).
	commitRetries atomic.Int32
	stageBytes    int64
	budget        *memoryBudget
	stager        ChunkStager
	// sleep waits between CommitAudit attempts; tests replace it.
	sleep func(time.Duration)
}

// NewManager constructs a live audit manager on the legacy write path. A nil
// fingerprinter disables credential scoping: every record is then stored
// without an API key tag and no developer session can match it.
func NewManager(store Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, mode string, logger *slog.Logger) (*Manager, error) {
	return NewManagerWithOptions(store, cipher, fingerprints, mode, logger, Options{})
}

// NewManagerWithOptions constructs a live audit manager with an explicit write
// path. It refuses the unified path at construction, not per request, when
// the store cannot serve it.
func NewManagerWithOptions(store Store, cipher security.Cipher, fingerprints *security.CredentialFingerprinter, mode string, logger *slog.Logger, options Options) (*Manager, error) {
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
	switch options.WritePath {
	case "", WritePathLegacy, WritePathUnified:
	default:
		return nil, fmt.Errorf("audit: invalid write path %q", options.WritePath)
	}
	if options.CommitRetries < 0 || options.CommitRetries > MaxCommitRetries {
		return nil, fmt.Errorf("audit: commit retries must be between 0 and %d, got %d", MaxCommitRetries, options.CommitRetries)
	}
	stageBytes, globalBytes := options.StageBytes, options.GlobalBytes
	if stageBytes == 0 {
		stageBytes = DefaultStageBytes
	}
	if globalBytes == 0 {
		globalBytes = DefaultGlobalBytes
	}
	if stageBytes < bodyChunkSize || stageBytes > globalBytes {
		return nil, fmt.Errorf("audit: stage memory budget must be at least %d and at most the global budget", bodyChunkSize)
	}
	manager := &Manager{
		store:        store,
		cipher:       cipher,
		fingerprints: fingerprints,
		mode:         mode,
		logger:       logger,
		now:          time.Now,
		random:       rand.Reader,
		stageBytes:   stageBytes,
		budget:       &memoryBudget{limit: globalBytes},
		stager:       options.Stager,
		sleep:        time.Sleep,
	}
	if manager.stager == nil {
		manager.stager = unavailableStager{}
	} else if queue, ok := manager.stager.(interface{ SetBudget(staging.Budget) }); ok {
		// The staging write queue counts against the same budget (F.5).
		queue.SetBudget(queueBudget{budget: manager.budget})
	}
	if options.Now != nil {
		manager.now = options.Now
	}
	if options.Random != nil {
		manager.random = options.Random
	}
	if options.Sleep != nil {
		manager.sleep = options.Sleep
	}
	manager.commitRetries.Store(int32(options.CommitRetries))
	if options.WritePath == WritePathUnified {
		if support, ok := store.(unifiedWriteSupport); ok && !support.SupportsUnifiedWrite() {
			return nil, errors.New("audit: the store cannot serve audit.write_path unified")
		}
		manager.unified = true
		manager.captureVersion = captureVersionFor(store)
	}
	manager.gaps = newGapBuffer(store, logger, func() time.Time { return manager.now() })
	return manager, nil
}

// captureVersionFor is the single place that chooses the capture version of
// the unified path: version 2 (the header block) on a store that writes it,
// which is PostgreSQL; version 1 otherwise, which is SQLite (H.2).
func captureVersionFor(store Store) int {
	if support, ok := store.(headerBlockSupport); ok && support.SupportsHeaderBlock() {
		return storage.CaptureVersion2
	}
	return storage.CaptureVersion1
}

// SetCommitRetries changes how many times a session retries a CommitAudit
// that failed with a retryable error, from 0 to 5; values outside the range
// are clamped. Sessions read it once, when their first attempt is prepared,
// so a change applies to commits that start afterwards. The legacy write path
// does not use it.
func (manager *Manager) SetCommitRetries(retries int) {
	if manager == nil {
		return
	}
	manager.commitRetries.Store(int32(min(max(retries, 0), MaxCommitRetries)))
}

// CommitRetries returns the current retry count of CommitAudit.
func (manager *Manager) CommitRetries() int {
	if manager == nil {
		return 0
	}
	return int(manager.commitRetries.Load())
}

// MemoryInUse returns the body plaintext the unified path's sessions hold in
// the global memory budget.
func (manager *Manager) MemoryInUse() int64 {
	if manager == nil {
		return 0
	}
	return manager.budget.Used()
}

// WritePath returns the write path the manager's sessions use.
func (manager *Manager) WritePath() string {
	if manager != nil && manager.unified {
		return WritePathUnified
	}
	return WritePathLegacy
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
			manager.recordGap(storage.GapReasonDBUnavailable)
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
		manager.recordGap(storage.GapReasonEncryption)
		return nil, fmt.Errorf("audit: request URI AAD: %w", err)
	}
	requestURIEncrypted, err := manager.cipher.Encrypt(requestURIAdditionalData, []byte(requestURI))
	if err != nil {
		manager.recordGap(storage.GapReasonEncryption)
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
	record := storage.AuditRecord{
		AuditID:       auditID,
		StartedAtNS:   started.UnixNano(),
		RouteID:       match.RouteID,
		Protocol:      protocolForParser(match.Parser),
		ParserName:    match.Parser,
		Method:        request.Method,
		Path:          path,
		RequestURIEnc: requestURIEncrypted,
		Mode:          manager.mode,
		ForwardStatus: storage.ForwardInProgress,
		CaptureStatus: storage.CapturePending,
		ParseStatus:   storage.ParsePending,
		// Tagging the credential here, before interceptors run, is what lets a
		// developer session see its own rejected requests too.
		APIKeyFPR: manager.fingerprints.FingerprintRequest(request.Header, query),
	}
	if manager.unified {
		return manager.beginUnified(ctx, request, match, record, started)
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
	case errors.Is(err, storage.ErrQueueFull):
		return storage.GapReasonQueueFull
	case errors.Is(err, storage.ErrClosed):
		return storage.GapReasonDBUnavailable
	default:
		return storage.GapReasonWrite
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
