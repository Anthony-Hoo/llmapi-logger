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

	// Historical billing backfill (doc/features/21-newapi-billing.md §4): one
	// link at a time, at least backfillInterval apart, pausing for
	// backfillPause once backfillPauseAfter attempts in a row have failed.
	backfillInterval   = 500 * time.Millisecond
	backfillPause      = time.Minute
	backfillPauseAfter = 2
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
	NextBillingBackfill(context.Context) (sqlite.BillingBackfillItem, bool, error)
	UpdateTokenLinkBilling(context.Context, sqlite.BillingUpdate) error
}

// LogLookup is implemented by Client and kept injectable for tests.
type LogLookup interface {
	LookupRequest(context.Context, string) (RequestLog, bool, error)
	EnsureQuotaPerUnit(context.Context) (float64, bool)
}

// Worker resolves completed audit request IDs through NewAPI's system log and
// records NewAPI's actual billing with the caller identity. There is exactly
// one processing goroutine; retries are bounded and persisted. Between caller
// lookups the same goroutine backfills billing for links written before
// billing existed.
type Worker struct {
	store  CallerStore
	client LogLookup
	logger *slog.Logger
	queue  chan string

	scanInterval time.Duration
	now          func() time.Time
	after        func(time.Duration) <-chan time.Time

	// backfillFailures counts consecutive failed backfill attempts. Only the
	// worker goroutine touches it.
	backfillFailures int

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup
}

// NewWorker constructs the optional caller-identification worker.
func NewWorker(store CallerStore, client LogLookup, logger *slog.Logger) (*Worker, error) {
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
		after:        time.After,
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
	backfill := worker.after(backfillInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-worker.queue:
			worker.scan(ctx)
		case <-ticker.C:
			worker.scan(ctx)
		case <-backfill:
			// Due caller lookups always go first; the backfill only gets
			// the gaps between them.
			worker.scan(ctx)
			if ctx.Err() != nil {
				return
			}
			delay, more := worker.backfillStep(ctx)
			backfill = nil
			if more {
				backfill = worker.after(delay)
			}
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
	record, found, err := worker.client.LookupRequest(lookupCtx, item.RequestID)
	cancel()
	attempts := item.Attempts + 1
	final := attempts > len(retryDelays)
	if err == nil && found {
		quotaPerUnit, haveRate := worker.client.EnsureQuotaPerUnit(ctx)
		switch {
		case record.Billed() && !haveRate && !final:
			// Never store a billing row without its conversion factor.
			worker.retry(ctx, item, attempts, "billing_rate_missing")
			return
		case !record.Billed() && record.ConsumeRows == 0 && record.Complete && successStatus(item.StatusCode) && !final:
			// A 2xx response with only error rows: the consume row may
			// not have been written yet.
			worker.retry(ctx, item, attempts, "billing_not_found")
			return
		}
		link := sqlite.TokenLink{
			AuditID: item.AuditID, NewAPIRequestID: item.RequestID,
			NewAPIUserID: record.UserID, Username: record.Username,
			NewAPITokenID: record.TokenID, TokenName: record.TokenName,
			LinkedAtNS: worker.now().UnixNano(), Attempts: attempts,
			BillingState: sqlite.BillingUnbilled,
		}
		if record.Billed() && haveRate {
			setBilled(&link.BillingState, &link.Quota, &link.QuotaPerUnit, &link.BilledPromptTokens, &link.BilledCompletionTokens, record, quotaPerUnit)
		} else if record.Billed() {
			worker.logger.Warn("NewAPI billing stored as unbilled", "audit_id", item.AuditID, "error_code", "billing_rate_missing")
		}
		if saveErr := worker.store.UpsertTokenLink(context.WithoutCancel(ctx), link); saveErr != nil && ctx.Err() == nil {
			worker.logger.Warn("NewAPI caller identity save failed", "audit_id", item.AuditID, "error_code", "caller_save_failed")
		}
		return
	}
	category := "caller_not_found"
	if err != nil {
		category = "caller_lookup_failed"
	}
	worker.retry(ctx, item, attempts, category)
}

// retry persists one unsuccessful attempt: rescheduled while attempts remain,
// terminally unresolved afterwards.
func (worker *Worker) retry(ctx context.Context, item sqlite.CallerLookup, attempts int, category string) {
	now := worker.now()
	var nextAt *int64
	if attempts <= len(retryDelays) {
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
		worker.logger.Warn("NewAPI caller remained unresolved", "audit_id", item.AuditID, "error_code", category)
	}
}

// backfillStep looks up the billing of the newest unchecked link. It returns
// the delay before the next step, and false once no unchecked link is left.
// It only ever writes billing columns: the caller identity and caller_status
// stay as they are, whatever the lookup returns.
func (worker *Worker) backfillStep(ctx context.Context) (time.Duration, bool) {
	item, ok, err := worker.store.NextBillingBackfill(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false
		}
		worker.logger.Warn("NewAPI billing backfill scan failed", "error_code", "billing_backfill_scan_failed")
		return backfillPause, true
	}
	if !ok {
		worker.logger.Info("NewAPI billing backfill finished")
		return 0, false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	record, found, lookupErr := worker.client.LookupRequest(lookupCtx, item.RequestID)
	cancel()
	if ctx.Err() != nil {
		return 0, false
	}
	quotaPerUnit, haveRate := worker.client.EnsureQuotaPerUnit(ctx)
	update := sqlite.BillingUpdate{AuditID: item.AuditID, Attempts: item.Attempts + 1, State: sqlite.BillingUnbilled}
	failed := lookupErr != nil || (found && record.Billed() && !haveRate)
	switch {
	case failed:
		if update.Attempts < sqlite.MaxBillingAttempts {
			update.State = sqlite.BillingUnchecked
		}
	case found && record.Billed():
		setBilled(&update.State, &update.Quota, &update.QuotaPerUnit, &update.BilledPromptTokens, &update.BilledCompletionTokens, record, quotaPerUnit)
	}
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	saveErr := worker.store.UpdateTokenLinkBilling(writeCtx, update)
	writeCancel()
	if saveErr != nil {
		worker.logger.Warn("NewAPI billing backfill save failed", "audit_id", item.AuditID, "error_code", "billing_backfill_save_failed")
		failed = true
	}
	if !failed {
		worker.backfillFailures = 0
		return backfillInterval, true
	}
	worker.backfillFailures++
	if worker.backfillFailures >= backfillPauseAfter {
		return backfillPause, true
	}
	return backfillInterval, true
}

func setBilled(state *string, quota **int64, quotaPerUnit **float64, prompt, completion **int64, record RequestLog, rate float64) {
	*state = sqlite.BillingBilled
	quotaValue, promptValue, completionValue, rateValue := record.Quota, record.PromptTokens, record.CompletionTokens, rate
	*quota, *quotaPerUnit, *prompt, *completion = &quotaValue, &rateValue, &promptValue, &completionValue
}

func successStatus(status *int) bool {
	return status != nil && *status >= 200 && *status <= 299
}
