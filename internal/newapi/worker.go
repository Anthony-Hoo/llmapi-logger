package newapi

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

const (
	callerQueueCapacity = 128
	callerScanLimit     = 128
	defaultScanInterval = time.Second
	lookupTimeout       = 10 * time.Second
	maxLookupAttempts   = 6
)

var retryDelays = [...]time.Duration{
	500 * time.Millisecond,
	time.Second,
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

// CallerStore is the small persistence surface used by the single caller
// worker. Pending work remains in SQLite when the in-memory wake queue fills.
type CallerStore interface {
	ListDueCallerLookups(context.Context, int64, int) ([]sqlite.CallerLookup, error)
	UpsertTokenLink(context.Context, sqlite.TokenLink) error
	RetryCallerLookup(context.Context, sqlite.CallerRetry) error
}

// IdentityLookup is implemented by Client and kept injectable for tests.
type IdentityLookup interface {
	LookupRequest(context.Context, string) (RequestIdentity, bool, error)
}

// Worker resolves completed audit request IDs through NewAPI's system log.
// There is exactly one processing goroutine; retries are bounded and persisted.
type Worker struct {
	store  CallerStore
	client IdentityLookup
	logger *slog.Logger
	queue  chan string

	scanInterval time.Duration
	now          func() time.Time

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup
}

// NewWorker constructs the optional caller-identification worker.
func NewWorker(store CallerStore, client IdentityLookup, logger *slog.Logger) (*Worker, error) {
	if store == nil || client == nil {
		return nil, errors.New("newapi caller worker: nil dependency")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		store: store, client: client, logger: logger,
		queue:        make(chan string, callerQueueCapacity),
		scanInterval: defaultScanInterval,
		now:          time.Now,
	}, nil
}

// Start scans persisted pending work and starts one worker goroutine.
func (worker *Worker) Start(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return errors.New("newapi caller worker: invalid start")
	}
	worker.mu.Lock()
	if worker.closed || worker.started {
		worker.mu.Unlock()
		return errors.New("newapi caller worker: unavailable")
	}
	runContext, cancel := context.WithCancel(ctx)
	worker.started = true
	worker.cancel = cancel
	worker.wait.Add(1)
	go worker.run(runContext)
	worker.mu.Unlock()
	worker.scan(runContext)
	return nil
}

// Notify wakes the worker without blocking request finalization. The ID is a
// hint only; due work is always rediscovered from SQLite.
func (worker *Worker) Notify(auditID string) bool {
	if worker == nil || strings.TrimSpace(auditID) == "" {
		return false
	}
	worker.mu.Lock()
	closed := worker.closed
	worker.mu.Unlock()
	if closed {
		return false
	}
	select {
	case worker.queue <- auditID:
		return true
	default:
		return false
	}
}

// QueueLength is exposed only for readiness diagnostics.
func (worker *Worker) QueueLength() int {
	if worker == nil {
		return 0
	}
	return len(worker.queue)
}

// Close stops scans and waits for the current bounded lookup.
func (worker *Worker) Close() {
	if worker == nil {
		return
	}
	worker.mu.Lock()
	if worker.closed {
		worker.mu.Unlock()
		return
	}
	worker.closed = true
	cancel := worker.cancel
	worker.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	worker.wait.Wait()
}

func (worker *Worker) run(ctx context.Context) {
	defer worker.wait.Done()
	ticker := time.NewTicker(worker.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-worker.queue:
			worker.scan(ctx)
		case <-ticker.C:
			worker.scan(ctx)
		}
	}
}

func (worker *Worker) scan(ctx context.Context) {
	for {
		items, err := worker.store.ListDueCallerLookups(ctx, worker.now().UnixNano(), callerScanLimit)
		if err != nil {
			if ctx.Err() == nil {
				worker.logger.Warn("NewAPI caller scan failed", "error_code", "caller_scan_failed")
			}
			return
		}
		if len(items) == 0 {
			return
		}
		for _, item := range items {
			if ctx.Err() != nil {
				return
			}
			worker.process(ctx, item)
		}
		if len(items) < callerScanLimit {
			return
		}
	}
}

func (worker *Worker) process(ctx context.Context, item sqlite.CallerLookup) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	identity, found, err := worker.client.LookupRequest(lookupCtx, item.RequestID)
	cancel()
	attempts := item.Attempts + 1
	now := worker.now()
	if err == nil && found {
		if saveErr := worker.store.UpsertTokenLink(context.WithoutCancel(ctx), sqlite.TokenLink{
			AuditID: item.AuditID, NewAPIRequestID: item.RequestID,
			NewAPIUserID: identity.UserID, Username: identity.Username,
			NewAPITokenID: identity.TokenID, TokenName: identity.TokenName,
			LinkedAtNS: now.UnixNano(), Attempts: attempts,
		}); saveErr != nil && ctx.Err() == nil {
			worker.logger.Warn("NewAPI caller identity save failed", "audit_id", item.AuditID, "error_code", "caller_save_failed")
		}
		return
	}

	var nextAt *int64
	if attempts < maxLookupAttempts {
		next := now.Add(retryDelays[attempts-1]).UnixNano()
		nextAt = &next
	}
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer writeCancel()
	if retryErr := worker.store.RetryCallerLookup(writeCtx, sqlite.CallerRetry{
		AuditID: item.AuditID, RequestID: item.RequestID, Attempts: attempts,
		NextAttemptAtNS: nextAt, UpdatedAtNS: now.UnixNano(),
	}); retryErr != nil {
		if ctx.Err() == nil {
			worker.logger.Warn("NewAPI caller retry state failed", "audit_id", item.AuditID, "error_code", "caller_retry_failed")
		}
		return
	}
	if nextAt == nil {
		category := "caller_not_found"
		if err != nil {
			category = "caller_lookup_failed"
		}
		worker.logger.Warn("NewAPI caller remained unresolved", "audit_id", item.AuditID, "error_code", category)
	}
}
