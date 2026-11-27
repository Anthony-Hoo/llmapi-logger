package parser

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

const (
	// projectBackfillBatch bounds the audits given an identity per scan tick.
	// Header-only audits are cheap, so it is larger than backfillBatch.
	projectBackfillBatch = 50
	// projectBackfillRescanInterval pauses after the candidate list is empty.
	projectBackfillRescanInterval = 10 * time.Minute
)

// ProjectAnalyzer stores the project identity of one audit
// (doc/features/23-org-project-reports.md section 5.1). It is installed only
// when organisation reports are enabled and never touches audit_analysis.
type ProjectAnalyzer interface {
	AuditAnalyzer
	// Save stores the identity of input; bodyScanned tells whether the
	// request body was available.
	Save(ctx context.Context, input insights.Input, bodyScanned bool) error
	// Strong reports whether the headers alone already carry a remote,
	// project hash or declared name, so the body need not be read.
	Strong(input insights.Input) bool
}

// ProjectBackfillStore lists analysed audits without a current identity,
// newest first, after a lower bound (nil: none) and before a cursor.
type ProjectBackfillStore interface {
	ListProjectIdentityBackfillCandidates(ctx context.Context, version int, after, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error)
}

// ProjectBackfillHorizonStore reports the newest analysed audit position,
// which bounds the steady-state identity backfill. Without it every pass
// lists from the newest audit down to the oldest.
type ProjectBackfillHorizonStore interface {
	ProjectBackfillHorizon(ctx context.Context) (storage.ProjectBackfillCursor, bool, error)
}

// SetProjectAnalyzer installs the optional project identity hook. Call it
// before Start.
func (worker *Worker) SetProjectAnalyzer(analyzer ProjectAnalyzer) {
	if worker == nil {
		return
	}
	worker.mu.Lock()
	worker.projectAnalyzer = analyzer
	worker.mu.Unlock()
}

func (worker *Worker) currentProjectAnalyzer() ProjectAnalyzer {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.projectAnalyzer
}

// analyzeProject runs the project hook for the same audits the insights
// analyzer sees. A failure is logged and handed to the identity backfill:
// the audit_analysis row written next makes the audit a candidate there.
func (worker *Worker) analyzeProject(ctx context.Context, audit storage.ParserAudit, input Input, result Result) {
	analyzer := worker.currentProjectAnalyzer()
	if analyzer == nil {
		return
	}
	err := runAnalyzer(ctx, analyzer, audit, input, result)
	if err == nil || ctx.Err() != nil {
		return
	}
	if worker.projectBackfillEnabled() {
		if retryableFailure(err) {
			recordRetry(&worker.projectRetry, &worker.projectMark, audit.AuditID, nil, worker.now())
		} else {
			// The backfill would fail the same way on the same evidence.
			rememberSkip(&worker.projectSkipped, &worker.projectMark, audit.AuditID, nil)
		}
	}
	if canceled(err) {
		return
	}
	code := insights.ErrorCode(err)
	if errors.Is(err, errAnalyzerPanic) {
		code = "project_identity_panic"
	}
	worker.logger.Warn("project identity failed", "audit_id", audit.AuditID, "error_code", code, "storage_error", storage.ErrorClass(err))
}

// projectBackfillEnabled reports whether the identity backfill runs at all.
func (worker *Worker) projectBackfillEnabled() bool {
	_, listable := worker.store.(ProjectBackfillStore)
	return listable && worker.currentProjectAnalyzer() != nil
}

// projectBackfillLater records an audit the insights backfill just analysed:
// it may have no current identity, wherever it lies relative to the identity
// backfill's watermark. position is nil when it is unknown. It is due at
// once.
func (worker *Worker) projectBackfillLater(auditID string, position *keyset) {
	if !worker.projectBackfillEnabled() {
		return
	}
	if _, skipped := worker.projectSkipped[auditID]; skipped {
		return
	}
	if retry, waiting := worker.projectRetry[auditID]; waiting {
		if position != nil {
			retry.position = position
		}
		return
	}
	if len(worker.projectRetry) >= backfillRetryCap {
		worker.projectMark.lower(position)
		return
	}
	if worker.projectRetry == nil {
		worker.projectRetry = make(map[string]*backfillRetry)
	}
	worker.projectRetry[auditID] = &backfillRetry{position: position}
}

// projectBackfill gives up to projectBackfillBatch analysed audits their
// identity, newest first so the current and previous report weeks fill in
// before older history. Headers are read first; the request body only when
// the headers carry no strong signal, from raw chunks while they are retained
// or from the verified turn graph for OpenAI audits. Released Anthropic and
// Gemini bodies are skipped and keep a header-only identity.
//
// Invariant: every audit_analysis row at or below projectMark.covered has a
// current identity, or was attempted in this process (by the backfill or the
// live path) and skipped for good, or is in projectRetry. A pass lists every
// candidate after the watermark, and covered only advances, when a pass
// completes, to the newest analysis row present when it began. An analysis
// row appears later, whatever its position, only from this goroutine: the
// live path runs analyzeProject before the insights analyzer writes the row
// and records a failed identity as a retry or a skip, and an insights
// backfill that writes a row reports it to projectBackfillLater. A retry set
// that is full lowers the
// watermark instead. Nothing else deletes an identity row without its audit
// or lowers identity_version; the first pass after a restart covers nothing,
// which also handles a new ProjectIdentityVersion.
func (worker *Worker) projectBackfill(ctx context.Context) int {
	analyzer := worker.currentProjectAnalyzer()
	store, listable := worker.store.(ProjectBackfillStore)
	if analyzer == nil || !listable || ctx.Err() != nil || len(worker.queue) > 0 {
		return 0
	}
	mark := &worker.projectMark
	if !mark.open {
		if worker.now().Before(worker.projectNextScan) {
			return 0
		}
		horizon, err := worker.projectHorizon(ctx)
		if err != nil {
			if ctx.Err() == nil {
				worker.logger.Warn("project identity backfill failed", "error_code", "project_backfill_failed", "reason", "horizon_failed", "storage_error", storage.ErrorClass(err))
			}
			return 0
		}
		mark.begin(horizon)
		worker.projectPass++
		worker.projectCursor = nil
		worker.projectRetryQueue = dueRetries(worker.projectRetry, mark.passAfter, worker.now())
	}

	attempted := 0
	for len(worker.projectRetryQueue) > 0 {
		if ctx.Err() != nil || len(worker.queue) > 0 || attempted >= projectBackfillBatch {
			return attempted
		}
		auditID := worker.projectRetryQueue[0]
		worker.projectRetryQueue = worker.projectRetryQueue[1:]
		if retry, waiting := worker.projectRetry[auditID]; waiting && retry.pass != worker.projectPass {
			worker.attemptProject(ctx, analyzer, auditID, retry.position)
			attempted++
		}
	}
	if attempted >= projectBackfillBatch {
		return attempted
	}

	var after *storage.ProjectBackfillCursor
	if mark.passAfter != nil {
		bound := storage.ProjectBackfillCursor(*mark.passAfter)
		after = &bound
	}
	candidates, err := store.ListProjectIdentityBackfillCandidates(ctx, insights.ProjectIdentityVersion, after, worker.projectCursor, projectBackfillBatch)
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.Warn("project identity backfill failed", "error_code", "project_backfill_failed", "reason", "list_failed", "storage_error", storage.ErrorClass(err))
		}
		return attempted
	}
	if len(candidates) == 0 {
		mark.complete()
		worker.projectCursor = nil
		worker.projectNextScan = worker.now().Add(projectBackfillRescanInterval)
		return attempted
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil || len(worker.queue) > 0 {
			return attempted
		}
		position := keyset{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
		retry, waiting := worker.projectRetry[candidate.AuditID]
		if waiting {
			retry.position = keysetPointer(position)
		}
		at, skipped := worker.projectSkipped[candidate.AuditID]
		if skipped && at == nil {
			worker.projectSkipped[candidate.AuditID] = keysetPointer(position)
		}
		if !skipped && (!waiting || (retry.pass != worker.projectPass && retry.due(worker.now()))) {
			worker.attemptProject(ctx, analyzer, candidate.AuditID, &position)
			attempted++
		}
		worker.projectCursor = &storage.ProjectBackfillCursor{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
	}
	return attempted
}

// projectHorizon reads the newest analysed audit position; nil when the store
// cannot tell or holds no analysis.
func (worker *Worker) projectHorizon(ctx context.Context) (*keyset, error) {
	store, bounded := worker.store.(ProjectBackfillHorizonStore)
	if !bounded {
		return nil, nil
	}
	horizon, found, err := store.ProjectBackfillHorizon(ctx)
	if err != nil || !found {
		return nil, err
	}
	position := keyset(horizon)
	return &position, nil
}

// attemptProject runs projectBackfillOne and marks a remaining retry as tried
// by this pass.
func (worker *Worker) attemptProject(ctx context.Context, analyzer ProjectAnalyzer, auditID string, position *keyset) {
	worker.projectBackfillOne(ctx, analyzer, auditID, position)
	if retry, waiting := worker.projectRetry[auditID]; waiting {
		retry.pass = worker.projectPass
	}
}

// projectBackfillFail records a failed attempt with the same policy as
// backfillFail: a retryable failure backs off and is never given up, any
// other skips the audit for this process.
func (worker *Worker) projectBackfillFail(auditID, reason string, err error, position *keyset, retryable bool) {
	worker.logger.Warn("project identity backfill failed", "audit_id", auditID, "error_code", "project_backfill_failed", "reason", reason, "storage_error", storage.ErrorClass(err), "retry", retryable)
	if retryable {
		recordRetry(&worker.projectRetry, &worker.projectMark, auditID, position, worker.now())
		return
	}
	delete(worker.projectRetry, auditID)
	rememberSkip(&worker.projectSkipped, &worker.projectMark, auditID, position)
	worker.logger.Info("project identity backfill skipped", "audit_id", auditID, "error_code", "project_backfill_skipped", "reason", backfillSkipFailed)
}

func (worker *Worker) projectBackfillOne(ctx context.Context, analyzer ProjectAnalyzer, auditID string, position *keyset) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		delete(worker.projectRetry, auditID)
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			worker.projectBackfillFail(auditID, "audit_load_failed", err, position, true)
		}
		return
	}
	headers, err := worker.loadRequestHeaders(ctx, auditID, worker.headerNames())
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		headers = nil
	}
	endpoint := audit.ParserName
	if _, suffix, found := strings.Cut(endpoint, "."); found {
		endpoint = suffix
	}
	input := insights.Input{AuditID: auditID, Protocol: audit.Protocol, Endpoint: endpoint, Headers: headers}
	bodyScanned := false
	if !analyzer.Strong(input) {
		body, ok := worker.projectRequestBody(ctx, audit)
		if ctx.Err() != nil {
			return
		}
		if ok {
			input.Request, input.RequestComplete, bodyScanned = body, true, true
		}
	}
	if err := saveProjectSafely(ctx, analyzer, input, bodyScanned); err != nil {
		if ctx.Err() == nil {
			reason := insights.ErrorCode(err)
			if errors.Is(err, errAnalyzerPanic) {
				reason = "project_identity_panic"
			}
			worker.projectBackfillFail(auditID, reason, err, position, retryableFailure(err))
		}
		return
	}
	delete(worker.projectRetry, auditID)
}

func saveProjectSafely(ctx context.Context, analyzer ProjectAnalyzer, input insights.Input, bodyScanned bool) (err error) {
	defer func() {
		if recover() != nil {
			err = errAnalyzerPanic
		}
	}()
	return analyzer.Save(ctx, input, bodyScanned)
}

// projectRequestBody returns the decoded request body when it can be had
// cheaply and verifiably.
func (worker *Worker) projectRequestBody(ctx context.Context, audit storage.ParserAudit) ([]byte, bool) {
	stage, err := worker.store.LoadParserStage(ctx, audit.AuditID, storage.StageRequestReceived)
	if err != nil || stage.Body == nil {
		return nil, false
	}
	if stage.Body.RetentionState != storage.RetentionMetadata {
		source, _, err := worker.loadBody(ctx, audit.AuditID, storage.StageRequestReceived)
		if err != nil || !source.Present || len(source.Data) == 0 {
			return nil, false
		}
		return source.Data, true
	}
	reconstructor := worker.bodyReconstructor()
	if reconstructor == nil || audit.Protocol != "openai" {
		return nil, false
	}
	reconstruction, err := reconstructor.ReconstructBodies(ctx, audit.AuditID)
	if err != nil || len(reconstruction.Request) == 0 {
		return nil, false
	}
	return reconstruction.Request, true
}
