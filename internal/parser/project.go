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

// ProjectBackfillStore lists analysed audits without a current identity.
type ProjectBackfillStore interface {
	ListProjectIdentityBackfillCandidates(ctx context.Context, version int, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error)
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
// analyzer sees. Failures are logged and left to the backfill.
func (worker *Worker) analyzeProject(ctx context.Context, audit storage.ParserAudit, input Input, result Result) {
	analyzer := worker.currentProjectAnalyzer()
	if analyzer == nil {
		return
	}
	err := runAnalyzer(ctx, analyzer, audit, input, result)
	if err == nil || canceled(err) {
		return
	}
	code := insights.ErrorCode(err)
	if errors.Is(err, errAnalyzerPanic) {
		code = "project_identity_panic"
	}
	worker.logger.Warn("project identity failed", "audit_id", audit.AuditID, "error_code", code, "storage_error", storage.ErrorClass(err))
}

// projectBackfill gives up to projectBackfillBatch analysed audits their
// identity, newest first so the current and previous report weeks fill in
// before older history. Headers are read first; the request body only when
// the headers carry no strong signal, from raw chunks while they are retained
// or from the verified turn graph for OpenAI audits. Released Anthropic and
// Gemini bodies are skipped and keep a header-only identity.
func (worker *Worker) projectBackfill(ctx context.Context) int {
	analyzer := worker.currentProjectAnalyzer()
	store, listable := worker.store.(ProjectBackfillStore)
	if analyzer == nil || !listable || ctx.Err() != nil || len(worker.queue) > 0 || worker.now().Before(worker.projectNextScan) {
		return 0
	}
	candidates, err := store.ListProjectIdentityBackfillCandidates(ctx, insights.ProjectIdentityVersion, worker.projectCursor, projectBackfillBatch)
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.Warn("project identity backfill failed", "error_code", "project_backfill_failed", "reason", "list_failed", "storage_error", storage.ErrorClass(err))
		}
		return 0
	}
	if len(candidates) == 0 {
		worker.projectCursor = nil
		worker.projectNextScan = worker.now().Add(projectBackfillRescanInterval)
		return 0
	}
	attempted := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || len(worker.queue) > 0 {
			return attempted
		}
		worker.projectBackfillOne(ctx, analyzer, candidate.AuditID)
		attempted++
		worker.projectCursor = &storage.ProjectBackfillCursor{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
	}
	return attempted
}

func (worker *Worker) projectBackfillOne(ctx context.Context, analyzer ProjectAnalyzer, auditID string) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) || (err != nil && canceled(err)) {
		return
	}
	if err != nil {
		worker.logger.Warn("project identity backfill failed", "audit_id", auditID, "error_code", "project_backfill_failed", "reason", "audit_load_failed", "storage_error", storage.ErrorClass(err))
		return
	}
	headers, err := worker.loadRequestHeaders(ctx, auditID, worker.headerNames())
	if err != nil {
		if canceled(err) {
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
	if err := saveProjectSafely(ctx, analyzer, input, bodyScanned); err != nil && !canceled(err) {
		worker.logger.Warn("project identity backfill failed", "audit_id", auditID, "error_code", "project_backfill_failed", "reason", insights.ErrorCode(err), "storage_error", storage.ErrorClass(err))
	}
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
