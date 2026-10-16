package parser

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	// backfillBatch bounds the audits analysed per scan tick.
	backfillBatch = 20
	// backfillSkipCap bounds the in-memory set of audits that cannot be
	// analysed, so a permanently unusable audit is not retried in a tight loop.
	backfillSkipCap = 4096
	// backfillRescanInterval is the pause after the candidate list is
	// exhausted, before the next pass starts again from the newest audit.
	backfillRescanInterval = 10 * time.Minute
)

// Stable reasons logged with error_code analysis_backfill_skipped.
const (
	backfillSkipAuditMissing  = "audit_missing"
	backfillSkipNoParser      = "parser_not_registered"
	backfillSkipNoBody        = "no_body"
	backfillSkipRawReleased   = "raw_unavailable"
	backfillSkipNoTurnGraph   = "no_turn_graph"
	backfillSkipNotUsable     = "parse_not_usable"
	backfillSkipNoRequestBody = "no_request_body"
)

// ErrReconstructionUnavailable reports that an audit has no verified turn
// graph to rebuild bodies from.
var ErrReconstructionUnavailable = errors.New("parser: reconstruction unavailable")

// Reconstruction is the exact provider request/response rebuilt from the
// content-addressed turn graph of a metadata-retention audit. Response is the
// JSON body of a non-stream response. A stream response cannot be rebuilt as
// SSE, so ResponseIsStream is set, Response stays empty and the usage summary
// and the full conversation DTO stand in for it.
type Reconstruction struct {
	Request          []byte
	Response         []byte
	ResponseIsStream bool
	StreamUsage      Usage
	Conversation     *conversation.Conversation
}

// Reconstructor rebuilds bodies whose raw chunks were released after verified
// reconstruction. It is implemented by the query service.
type Reconstructor interface {
	ReconstructBodies(ctx context.Context, auditID string) (Reconstruction, error)
}

// BackfillStore lists audits that need (re)analysis. The sqlite store
// implements it; stores without it simply never backfill.
type BackfillStore interface {
	ListAnalysisBackfillCandidates(ctx context.Context, version int, after *sqlite.AnalysisBackfillCursor, limit int) ([]sqlite.AnalysisBackfillCandidate, error)
}

// SetReconstructor installs the optional body source for metadata-retention
// OpenAI audits; nil, the default, skips them during backfill. Call it before
// Start.
func (worker *Worker) SetReconstructor(reconstructor Reconstructor) {
	if worker == nil {
		return
	}
	worker.mu.Lock()
	worker.reconstructor = reconstructor
	worker.mu.Unlock()
}

func (worker *Worker) bodyReconstructor() Reconstructor {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.reconstructor
}

// backfill analyses up to backfillBatch parsed audits that have no current
// audit_analysis row (doc/features/20-context-insights.md section 9). It runs
// on the parser goroutine, only while the live queue is empty, and stops as
// soon as live work arrives, so it never delays live parsing. It writes
// nothing but audit_analysis rows. It returns the number of audits it tried.
func (worker *Worker) backfill(ctx context.Context) int {
	analyzer := worker.auditAnalyzer()
	store, listable := worker.store.(BackfillStore)
	if analyzer == nil || !listable || ctx.Err() != nil || len(worker.queue) > 0 || worker.now().Before(worker.backfillNextScan) {
		return 0
	}
	candidates, err := store.ListAnalysisBackfillCandidates(ctx, insights.AnalysisVersion, worker.backfillCursor, backfillBatch)
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.Warn("insights backfill failed", "error_code", "analysis_backfill_failed", "reason", "list_failed", "storage_error", sqlite.ErrorClass(err))
		}
		return 0
	}
	if len(candidates) == 0 {
		worker.backfillCursor = nil
		worker.backfillNextScan = worker.now().Add(backfillRescanInterval)
		return 0
	}
	attempted := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || len(worker.queue) > 0 {
			return attempted
		}
		if _, skipped := worker.backfillSkipped[candidate.AuditID]; !skipped {
			worker.backfillOne(ctx, analyzer, store, candidate.AuditID)
			attempted++
		}
		worker.backfillCursor = &sqlite.AnalysisBackfillCursor{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
	}
	return attempted
}

func (worker *Worker) backfillSkip(auditID, reason string) {
	worker.rememberBackfillSkip(auditID)
	worker.logger.Info("insights backfill skipped", "audit_id", auditID, "error_code", "analysis_backfill_skipped", "reason", reason)
}

func (worker *Worker) backfillFail(auditID, reason string, err error) {
	worker.rememberBackfillSkip(auditID)
	worker.logger.Warn("insights backfill failed", "audit_id", auditID, "error_code", "analysis_backfill_failed", "reason", reason, "storage_error", sqlite.ErrorClass(err))
}

func (worker *Worker) rememberBackfillSkip(auditID string) {
	if worker.backfillSkipped == nil || len(worker.backfillSkipped) >= backfillSkipCap {
		worker.backfillSkipped = make(map[string]struct{})
	}
	worker.backfillSkipped[auditID] = struct{}{}
}

func canceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (worker *Worker) backfillOne(ctx context.Context, analyzer AuditAnalyzer, _ BackfillStore, auditID string) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		worker.backfillSkip(auditID, backfillSkipAuditMissing)
		return
	}
	if err != nil {
		if !canceled(err) {
			worker.backfillFail(auditID, "audit_load_failed", err)
		}
		return
	}
	if audit.ParseStatus != StatusOK && audit.ParseStatus != StatusPartial {
		return
	}
	implementation := worker.parsers[audit.ParserName]
	if implementation == nil {
		worker.backfillSkip(auditID, backfillSkipNoParser)
		return
	}

	input, evidenceErr, reconstruction, reason, err := worker.backfillInput(ctx, audit)
	if err != nil {
		if !canceled(err) {
			worker.backfillFail(auditID, reason, err)
		}
		return
	}
	if reason != "" {
		worker.backfillSkip(auditID, reason)
		return
	}

	// The parse result is recomputed in memory only; parsed_results is never
	// rewritten.
	result := parseSafely(ctx, implementation, input)
	if reconstruction != nil && reconstruction.ResponseIsStream {
		applyStreamReconstruction(&result, *reconstruction)
	}
	worker.normalizeResult(&result, input, evidenceErr)
	if result.Status != StatusOK && result.Status != StatusPartial {
		worker.backfillSkip(auditID, backfillSkipNotUsable)
		return
	}
	if !input.Request.Present || len(input.Request.Data) == 0 {
		worker.backfillSkip(auditID, backfillSkipNoRequestBody)
		return
	}
	if err := runAnalyzer(ctx, analyzer, audit, input, result); err != nil && !canceled(err) {
		reason := insights.ErrorCode(err)
		if errors.Is(err, errAnalyzerPanic) {
			reason = "analysis_panic"
		}
		worker.backfillFail(auditID, reason, err)
	}
}

// backfillInput loads the evidence of one audit. A non-empty reason means the
// audit is skipped; a non-nil error means the load failed.
func (worker *Worker) backfillInput(ctx context.Context, audit sqlite.ParserAudit) (Input, error, *Reconstruction, string, error) {
	stage, err := worker.store.LoadParserStage(ctx, audit.AuditID, sqlite.StageRequestReceived)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && stage.Body == nil) {
		return Input{}, nil, nil, backfillSkipNoBody, nil
	}
	if err != nil {
		return Input{}, nil, nil, "evidence_read_failed", err
	}
	if stage.Body.RetentionState != sqlite.RetentionMetadata {
		input, evidenceErr := worker.loadInput(ctx, audit)
		return input, evidenceErr, nil, "", nil
	}

	reconstructor := worker.bodyReconstructor()
	if reconstructor == nil || audit.Protocol != "openai" {
		return Input{}, nil, nil, backfillSkipRawReleased, nil
	}
	reconstruction, err := reconstructor.ReconstructBodies(ctx, audit.AuditID)
	if errors.Is(err, ErrReconstructionUnavailable) {
		return Input{}, nil, nil, backfillSkipNoTurnGraph, nil
	}
	if err != nil {
		return Input{}, nil, nil, "reconstruction_failed", err
	}
	headers, headersErr := worker.loadRequestHeaders(ctx, audit.AuditID, worker.headerNames())
	if headersErr != nil {
		worker.logger.Warn("parser request headers load failed", "audit_id", audit.AuditID, "error_code", "request_headers_load_failed")
		headers = http.Header(nil)
	}
	input := Input{
		AuditID:  audit.AuditID,
		Protocol: audit.Protocol,
		Endpoint: audit.Path,
		Request:  BodySource{Present: true, Complete: true, ContentType: "application/json", Data: reconstruction.Request},
		Headers:  headers,
	}
	if len(reconstruction.Response) > 0 {
		input.Response = BodySource{Present: true, Complete: true, ContentType: "application/json", Data: reconstruction.Response}
	}
	return input, nil, &reconstruction, "", nil
}

// applyStreamReconstruction fills the response-derived fields of a stream
// whose SSE bytes are gone: the usage summary kept in the response envelope
// and the conversation DTO rebuilt from the content graph. Cache buckets are
// not recoverable and stay unreported.
func applyStreamReconstruction(result *Result, reconstruction Reconstruction) {
	observed := true
	result.ObservedStream = &observed
	result.Usage = reconstruction.StreamUsage
	result.Normalized = insights.Usage{
		UncachedInput: cloneInt64(reconstruction.StreamUsage.Input),
		Output:        cloneInt64(reconstruction.StreamUsage.Output),
	}
	if reconstruction.Conversation != nil {
		result.Conversation = reconstruction.Conversation
	}
}
