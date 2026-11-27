package parser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const defaultScanInterval = 30 * time.Second

// Worker owns one bounded queue and one parser goroutine. Queue saturation is
// intentionally non-blocking; pending rows are picked up by later scans.
//
// The queue is one FIFO for both inputs: audits Notify enqueues (at most
// QueueCapacity waiting) and jobs Submit enqueues (at most
// FinalizeQueueCapacity waiting), so audits are parsed in the order they were
// handed over. Enqueueing happens under mu, as Close's drain does, so every
// job's plaintext is released exactly once.
type Worker struct {
	store   Store
	cipher  security.Cipher
	parsers map[string]Parser
	logger  *slog.Logger
	queue   chan FinalizeJob
	// Only the parser goroutine accesses this bounded recovery backlog.
	// A failed release must be retried before the same audit can be claimed.
	pendingReleases map[string]struct{}

	scanInterval time.Duration
	now          func() time.Time

	// Guarded by mu; read once per audit by the parser goroutine.
	headerAllowlist []string
	analyzer        AuditAnalyzer
	reconstructor   Reconstructor
	idleTasks       []IdleTask
	projectAnalyzer ProjectAnalyzer

	// Only the parser goroutine accesses the insights backfill state
	// (backfill.go): the watermark, the open pass's cursor and number, the
	// audits skipped for good, the audits to retry and the retries the open
	// pass still has to try first.
	backfillMark       watermark
	backfillCursor     *storage.AnalysisBackfillCursor
	backfillPass       uint64
	backfillSkipped    map[string]*keyset
	backfillRetry      map[string]*backfillRetry
	backfillRetryQueue []string
	backfillNextScan   time.Time
	// backfillProgress is readable from any goroutine.
	backfillProgress backfillProgress
	// Project identity backfill state, parser goroutine only (project.go).
	projectMark       watermark
	projectCursor     *storage.ProjectBackfillCursor
	projectPass       uint64
	projectSkipped    map[string]*keyset
	projectRetry      map[string]*backfillRetry
	projectRetryQueue []string
	projectNextScan   time.Time

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup
}

// NewWorker validates and indexes the configured protocol parsers.
func NewWorker(store Store, cipher security.Cipher, parsers []Parser, logger *slog.Logger) (*Worker, error) {
	if store == nil {
		return nil, errors.New("parser: nil store")
	}
	if cipher == nil {
		return nil, errors.New("parser: nil cipher")
	}
	if logger == nil {
		logger = slog.Default()
	}
	indexed := make(map[string]Parser, len(parsers))
	for _, implementation := range parsers {
		if implementation == nil || strings.TrimSpace(implementation.Name()) == "" || strings.TrimSpace(implementation.Version()) == "" {
			return nil, errors.New("parser: invalid parser registration")
		}
		if _, exists := indexed[implementation.Name()]; exists {
			return nil, fmt.Errorf("parser: duplicate parser %q", implementation.Name())
		}
		indexed[implementation.Name()] = implementation
	}
	return &Worker{
		store:           store,
		cipher:          cipher,
		parsers:         indexed,
		logger:          logger,
		queue:           make(chan FinalizeJob, FinalizeQueueCapacity),
		pendingReleases: make(map[string]struct{}),
		scanInterval:    defaultScanInterval,
		now:             time.Now,
	}, nil
}

// SetHeaderAllowlist names the inbound request headers decrypted into
// Input.Headers. Matching is case-insensitive; an empty list, the default,
// loads no headers. Call it before Start.
func (worker *Worker) SetHeaderAllowlist(names []string) {
	if worker == nil {
		return
	}
	seen := make(map[string]struct{}, len(names))
	allowlist := make([]string, 0, len(names))
	for _, name := range names {
		lowered := strings.ToLower(strings.TrimSpace(name))
		if lowered == "" {
			continue
		}
		if _, duplicate := seen[lowered]; duplicate {
			continue
		}
		seen[lowered] = struct{}{}
		allowlist = append(allowlist, lowered)
	}
	worker.mu.Lock()
	worker.headerAllowlist = allowlist
	worker.mu.Unlock()
}

func (worker *Worker) headerNames() []string {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.headerAllowlist
}

// AuditAnalyzer derives insights from one successfully parsed audit. It runs
// on the parser goroutine after the parse result is saved and can never
// change that result.
type AuditAnalyzer interface {
	AnalyzeAudit(context.Context, insights.Input) error
}

// SetAnalyzer installs the optional insights analyzer; nil, the default,
// disables analysis. Call it before Start.
func (worker *Worker) SetAnalyzer(analyzer AuditAnalyzer) {
	if worker == nil {
		return
	}
	worker.mu.Lock()
	worker.analyzer = analyzer
	worker.mu.Unlock()
}

func (worker *Worker) auditAnalyzer() AuditAnalyzer {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.analyzer
}

// Start resets interrupted processing rows, performs the startup pending scan,
// and starts exactly one worker goroutine.
func (worker *Worker) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("parser: nil context")
	}
	if worker == nil {
		return errors.New("parser: nil worker")
	}

	worker.mu.Lock()
	if worker.closed {
		worker.mu.Unlock()
		return errors.New("parser: worker is closed")
	}
	if worker.started {
		worker.mu.Unlock()
		return errors.New("parser: worker already started")
	}
	if err := worker.store.ResetProcessingParses(ctx); err != nil {
		worker.mu.Unlock()
		return fmt.Errorf("parser: reset interrupted work: %w", err)
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

// Notify tries to enqueue a completed audit without waiting. False means the
// queue is full or the worker has been closed; the DB row remains pending.
func (worker *Worker) Notify(auditID string) bool {
	if worker == nil || strings.TrimSpace(auditID) == "" {
		return false
	}
	return worker.enqueue(FinalizeJob{Audit: storage.ParserAudit{AuditID: auditID}}, QueueCapacity)
}

// Submit hands a committed audit to the parser goroutine without waiting
// (design G.1). A job with evidence is parsed from that evidence instead of
// the stored rows; an id-only job is parsed like a notified audit. Submit
// takes the job's plaintext: its Release runs exactly once, when the job is
// refused, after it is processed, or when the worker stops before reaching
// it. False means the queue is full or the worker is closed; the row then
// stays pending for the scan, as after a refused Notify.
func (worker *Worker) Submit(job FinalizeJob) bool {
	if worker == nil || strings.TrimSpace(job.Audit.AuditID) == "" {
		releaseJob(job)
		return false
	}
	if !worker.enqueue(job, FinalizeQueueCapacity) {
		releaseJob(job)
		return false
	}
	return true
}

// enqueue adds a job unless the worker is closed or limit jobs are already
// waiting.
func (worker *Worker) enqueue(job FinalizeJob, limit int) bool {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.closed || len(worker.queue) >= limit {
		return false
	}
	select {
	case worker.queue <- job:
		return true
	default:
		return false
	}
}

func releaseJob(job FinalizeJob) {
	if job.Release != nil {
		job.Release()
	}
}

// QueueLength returns the current in-memory backlog for readiness reporting.
func (worker *Worker) QueueLength() int {
	if worker == nil {
		return 0
	}
	return len(worker.queue)
}

// Close stops background scans and waits for the current parse operation. It
// is safe before Start and safe to call more than once.
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
	// No job can be enqueued any more (closed is set); release the plaintext
	// of those the goroutine did not reach. Their rows stay pending.
	for {
		select {
		case job := <-worker.queue:
			releaseJob(job)
		default:
			return
		}
	}
}

func (worker *Worker) run(ctx context.Context) {
	defer worker.wait.Done()
	ticker := time.NewTicker(worker.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-worker.queue:
			worker.serve(ctx, job)
		case <-ticker.C:
			worker.retryProcessingReleases(ctx)
			worker.scan(ctx)
			worker.backfill(ctx)
			worker.projectBackfill(ctx)
			worker.runIdleTasks(ctx)
		}
	}
}

func (worker *Worker) scan(ctx context.Context) {
	ids, err := worker.store.ListPendingParseIDs(ctx, QueueCapacity)
	if err != nil {
		worker.logger.Warn("parser pending scan failed", "error_code", "pending_scan_failed")
		return
	}
	for _, auditID := range ids {
		if !worker.Notify(auditID) {
			return
		}
	}
}

// serve processes one queued job and then releases its plaintext.
func (worker *Worker) serve(ctx context.Context, job FinalizeJob) {
	defer releaseJob(job)
	if job.Evidence == nil {
		worker.process(ctx, job.Audit.AuditID)
		return
	}
	worker.finalize(ctx, job.Audit, job.Evidence)
}

// process parses an audit from its stored evidence.
func (worker *Worker) process(ctx context.Context, auditID string) {
	if !worker.mayClaim(auditID) {
		return
	}
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if err != nil {
		worker.logger.Warn("parser audit load failed", "audit_id", auditID, "error_code", "audit_load_failed")
		return
	}
	if !worker.claim(ctx, auditID) {
		return
	}
	input, evidenceErr := worker.loadInput(ctx, audit)
	worker.parseClaimed(ctx, audit, input, evidenceErr)
}

// mayClaim reports whether the worker may claim the audit now.
func (worker *Worker) mayClaim(auditID string) bool {
	// Pending rows remain discoverable after storage recovers. Do not claim
	// more work than this worker can remember to release safely.
	_, waiting := worker.pendingReleases[auditID]
	return !waiting && len(worker.pendingReleases) < QueueCapacity
}

func (worker *Worker) claim(ctx context.Context, auditID string) bool {
	claimed, err := worker.store.ClaimPendingParse(ctx, auditID)
	if err != nil {
		worker.logger.Warn("parser claim failed", "audit_id", auditID, "error_code", "parse_claim_failed")
		return false
	}
	return claimed
}

// parseClaimed parses, normalizes, prepares, saves and analyzes a claimed
// audit; every path into the parser ends here.
func (worker *Worker) parseClaimed(ctx context.Context, audit storage.ParserAudit, input Input, evidenceErr error) {
	implementation := worker.parsers[audit.ParserName]
	result := Result{}
	if implementation == nil {
		result.Status = StatusSkipped
		result.ErrorCode = "parser_not_registered"
	} else if !input.Request.Present && !input.Response.Present && evidenceErr == nil {
		result.Status = StatusSkipped
		result.ErrorCode = "no_body"
	} else {
		result = parseSafely(ctx, implementation, input)
	}
	worker.normalizeResult(&result, input, evidenceErr)
	prepared := worker.prepareTurn(ctx, audit, implementation, input, &result)
	savedStatus, err := worker.persistResult(ctx, audit, implementation, result, prepared)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// A canceled save may not have been attempted, or may still commit
			// after submitSync stops waiting. Leave processing for startup
			// recovery instead of spending the persistence-failure budget.
			if ctx.Err() == nil {
				worker.backfillUnsure(audit.AuditID)
			}
			return
		}
		worker.logger.Warn("parser result save failed", "audit_id", audit.AuditID, "error_code", "parsed_result_save_failed", "storage_error", storage.ErrorClass(err))
		worker.releaseProcessing(ctx, audit.AuditID)
		// The error may have come back after the save committed; the release
		// is then a no-op and the audit is ok or partial without an analysis.
		worker.backfillUnsure(audit.AuditID)
		return
	}
	worker.analyze(ctx, audit, input, result, savedStatus)
}

// analyze runs the optional insights analyzer for a saved ok or partial
// parse with a request body. savedStatus is the status actually committed,
// which persistResult may have downgraded. Failures and panics are logged
// with a stable code and dropped: the parse status is already committed, and
// the insights backfill recomputes missing rows later instead of retrying
// here. Every saved ok or partial audit left without an analysis, unless the
// worker is stopping, is reported to backfillLater: the backfill's watermark
// may already cover it.
func (worker *Worker) analyze(ctx context.Context, audit storage.ParserAudit, input Input, result Result, savedStatus string) {
	analyzer := worker.auditAnalyzer()
	if analyzer == nil || (savedStatus != StatusOK && savedStatus != StatusPartial) {
		return
	}
	if !input.Request.Present || len(input.Request.Data) == 0 {
		worker.backfillLater(audit.AuditID, input, nil)
		return
	}
	// The optional project identity hook is independent of the insights
	// result; it runs first so an analysis failure cannot skip it.
	worker.analyzeProject(ctx, audit, input, result)
	err := runAnalyzer(ctx, analyzer, audit, input, result)
	if err == nil || ctx.Err() != nil {
		return
	}
	worker.backfillLater(audit.AuditID, input, err)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	if errors.Is(err, errAnalyzerPanic) {
		worker.logger.Warn("insights analysis failed", "audit_id", audit.AuditID, "error_code", "analysis_panic")
		return
	}
	worker.logger.Warn("insights analysis failed", "audit_id", audit.AuditID, "error_code", insights.ErrorCode(err), "storage_error", storage.ErrorClass(err))
}

var errAnalyzerPanic = errors.New("parser: analyzer panic")

// runAnalyzer invokes the analyzer hook shared by live parsing and the
// insights backfill, converting a panic into errAnalyzerPanic.
func runAnalyzer(ctx context.Context, analyzer AuditAnalyzer, audit storage.ParserAudit, input Input, result Result) (err error) {
	defer func() {
		if recover() != nil {
			err = errAnalyzerPanic
		}
	}()
	endpoint := audit.ParserName
	if _, suffix, found := strings.Cut(endpoint, "."); found {
		endpoint = suffix
	}
	return analyzer.AnalyzeAudit(ctx, insights.Input{
		AuditID:          audit.AuditID,
		Protocol:         audit.Protocol,
		Endpoint:         endpoint,
		Request:          input.Request.Data,
		RequestComplete:  input.Request.Complete,
		Response:         input.Response.Data,
		ResponseComplete: input.Response.Complete,
		ResponseIsStream: result.ObservedStream != nil && *result.ObservedStream,
		StopReason:       result.StopReason,
		Headers:          input.Headers,
		RequestModel:     result.RequestModel,
		ResponseModel:    result.ResponseModel,
		Usage:            result.Normalized,
		Conversation:     result.Conversation,
	})
}

func (worker *Worker) releaseProcessing(ctx context.Context, auditID string) bool {
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := worker.store.ReleaseProcessingParse(releaseContext, auditID); err != nil {
		worker.pendingReleases[auditID] = struct{}{}
		worker.logger.Warn("parser retry release failed", "audit_id", auditID, "error_code", "parse_release_failed", "storage_error", storage.ErrorClass(err))
		return false
	}
	delete(worker.pendingReleases, auditID)
	return true
}

func (worker *Worker) retryProcessingReleases(ctx context.Context) {
	for auditID := range worker.pendingReleases {
		if ctx.Err() != nil || !worker.releaseProcessing(ctx, auditID) {
			// A storage outage should not cause a tight retry loop or spend
			// five seconds on every outstanding audit during this scan.
			return
		}
	}
}

// prepareTurn prepares the turn of a parsed audit. A full turn, carrying the
// request and the response, needs an ok parse of complete bodies. When that
// cannot be had because of the response alone, a request-only turn is
// prepared instead (prepareRequestOnlyTurn): its response layout is none, and
// the response raw stays as the only evidence of the response.
func (worker *Worker) prepareTurn(ctx context.Context, audit storage.ParserAudit, implementation Parser, input Input, result *Result) *auditmodel.PreparedTurn {
	if implementation == nil || result == nil || !input.Request.Complete {
		return nil
	}
	normalizer, ok := implementation.(AuditNormalizer)
	if !ok {
		return nil
	}
	if result.Status != StatusOK || (input.Response.Present && !input.Response.Complete) {
		return worker.prepareRequestOnlyTurn(ctx, audit, implementation, normalizer, input, result)
	}
	turn, err := normalizer.NormalizeAudit(ctx, input, *result)
	if errors.Is(err, ErrStreamResidueTooLarge) {
		// The response is complete and was parsed; its stream only carries
		// more than the envelope may hold. The parse stays ok, the response
		// raw stays, and the request can still be released.
		prepared := worker.prepareRequestOnlyTurn(ctx, audit, implementation, normalizer, input, result)
		if prepared != nil {
			if result.ErrorCode == "" {
				result.ErrorCode = ErrorCodeResponseNotNormalized
			}
			return prepared
		}
	}
	if err != nil {
		result.Status = StatusPartial
		result.ErrorCode = "normalization_failed"
		result.ParsedJSON = nil
		return nil
	}
	return worker.prepareNormalizedTurn(ctx, audit, turn, result)
}

// prepareRequestOnlyTurn prepares a turn from the request alone for an audit
// whose response was captured but cannot be carried by the turn: it is
// incomplete, the parse is partial because of it, or the normalizer declined
// it. The request must be one a full turn would accept: a complete body, which
// the parser reads without fault on its own (so a partial parse is partial
// because of the response), and which normalizes and verifies against its
// decoded bytes. Whatever fails, it returns nil and leaves the result as it
// is: the audit then keeps all of its raw, as it did before.
//
// The normalizer is called with the response removed from the input, which
// every normalizer answers with response layout none; no protocol needs its
// own request-only path.
func (worker *Worker) prepareRequestOnlyTurn(ctx context.Context, audit storage.ParserAudit, implementation Parser, normalizer AuditNormalizer, input Input, result *Result) *auditmodel.PreparedTurn {
	if result.Status != StatusOK && result.Status != StatusPartial {
		return nil
	}
	if !input.Request.Present || !input.Request.Complete || input.Request.ErrorCode != "" || !input.Response.Present ||
		input.Response.ErrorCode == "evidence_read_error" || input.Response.ErrorCode == "capture_integrity_error" {
		// No response, so nothing to leave out; or the response could not be
		// read as it was stored, so what the parser saw is not the evidence.
		return nil
	}
	requestOnly := input
	requestOnly.Response = BodySource{}
	requestOnly.StatusCode = nil
	if parsed := parseSafely(ctx, implementation, requestOnly); parsed.Status != StatusOK {
		return nil
	}
	turn, err := normalizer.NormalizeAudit(ctx, requestOnly, *result)
	if err != nil || turn.RequestLayout == auditmodel.LayoutNone || turn.ResponseLayout != auditmodel.LayoutNone {
		return nil
	}
	turn.ResponseItems, turn.ResponseEnvelope, turn.ResponseOriginal = nil, nil, nil
	// A failed check must not relabel the parse: the audit then stays as it
	// was before request-only turns existed.
	probe := *result
	return worker.prepareNormalizedTurn(ctx, audit, turn, &probe)
}

// ErrorCodeResponseNotNormalized is the parse error code of an ok parse whose
// complete response the normalizer declined (ErrStreamResidueTooLarge): the
// audit has a request-only turn and keeps its response raw.
const ErrorCodeResponseNotNormalized = "response_not_normalized"

// responseMessages returns the response-phase messages of a parsed
// conversation, which a request-only turn does not rebuild.
func responseMessages(value *conversation.Conversation) []conversation.Message {
	messages := make([]conversation.Message, 0)
	for _, message := range value.Messages {
		if message.Phase == conversation.PhaseResponse {
			messages = append(messages, message)
		}
	}
	return messages
}

// prepareNormalizedTurn fills the audit fields of a normalized turn and
// prepares it with the reconstruction check. A failed check marks the parse
// partial with reconstruction_failed.
func (worker *Worker) prepareNormalizedTurn(ctx context.Context, audit storage.ParserAudit, turn auditmodel.Turn, result *Result) *auditmodel.PreparedTurn {
	turn.AuditID = audit.AuditID
	turn.Protocol = audit.Protocol
	turn.ParserName = audit.ParserName
	turn.ResponseID = result.ResponseID
	turn.CreatedAtNS = worker.now().UnixNano()
	var lookup auditmodel.ObjectLookup
	if existing, ok := worker.store.(interface {
		LookupAuditObjects(context.Context, [][]byte, [][]byte) ([]auditmodel.StoredContent, []auditmodel.StoredBinary, error)
	}); ok {
		lookup = func(contentHashes, binaryHashes [][]byte) ([]auditmodel.StoredContent, []auditmodel.StoredBinary, error) {
			return existing.LookupAuditObjects(ctx, contentHashes, binaryHashes)
		}
	}
	prepared, err := auditmodel.PrepareWithLookup(turn, worker.cipher, lookup)
	if err != nil {
		result.Status = StatusPartial
		result.ErrorCode = "reconstruction_failed"
		result.ParsedJSON = nil
		return nil
	}
	return &prepared
}

func parseSafely(ctx context.Context, implementation Parser, input Input) (result Result) {
	defer func() {
		if recover() != nil {
			result = Result{Status: StatusError, ErrorCode: "parser_panic"}
		}
	}()
	return implementation.Parse(ctx, input)
}

func (worker *Worker) normalizeResult(result *Result, input Input, evidenceErr error) {
	if result.Status == "" {
		if result.IsUsable() {
			result.Status = StatusOK
		} else {
			result.Status = StatusError
			result.ErrorCode = "empty_parser_result"
		}
	} else if result.Status != StatusOK && result.Status != StatusPartial && result.Status != StatusError && result.Status != StatusSkipped {
		result.Status = StatusError
		result.ErrorCode = "invalid_parser_status"
	}

	evidenceCode := selectEvidenceCode(input.Request.ErrorCode, input.Response.ErrorCode)
	evidenceProblem := evidenceErr != nil || (!input.Request.Complete && input.Request.Present) || (!input.Response.Complete && input.Response.Present)
	if evidenceProblem && !(result.Status == StatusSkipped && result.ErrorCode == "parser_not_registered") {
		if onlyUnsupportedEncoding(input) {
			result.Status = StatusSkipped
		} else if result.Status == StatusOK {
			if result.IsUsable() {
				result.Status = StatusPartial
			} else {
				result.Status = StatusError
			}
		}
		if !preserveParserFailure(result.ErrorCode) {
			result.ErrorCode = firstNonEmpty(evidenceCode, "evidence_error")
		}
	}
	if result.Status == StatusError && result.ErrorCode == "" {
		result.ErrorCode = "parse_error"
	}
	if len(result.ParsedJSON) == 0 {
		result.ParsedJSON, _ = json.Marshal(compactResultJSON(*result))
	}
}

// persistResult saves the parse and returns the status it actually stored,
// which encryption failures downgrade to error.
func (worker *Worker) persistResult(ctx context.Context, audit storage.ParserAudit, implementation Parser, result Result, prepared *auditmodel.PreparedTurn) (string, error) {
	parserVersion := "1"
	if implementation != nil {
		parserVersion = implementation.Version()
	}
	plaintext, generatedPlaintext := parsedResultPlaintext(result, prepared)
	// Large results, chiefly the fallback conversation, are compressed inside
	// the encrypted payload; see auditmodel.SealParsedResult.
	encrypted, err := auditmodel.SealParsedResult(worker.cipher, audit.AuditID, audit.ParserName, plaintext)
	if errors.Is(err, auditmodel.ErrParsedResultAAD) {
		worker.logger.Warn("parser result AAD failed", "audit_id", audit.AuditID, "error_code", "parsed_json_aad_failed")
		result.Status = StatusError
		result.ErrorCode = "parsed_json_aad_failed"
	} else if err != nil {
		worker.logger.Warn("parser result encryption failed", "audit_id", audit.AuditID, "error_code", "parsed_json_encryption_failed")
		result.Status = StatusError
		result.ErrorCode = "parsed_json_encryption_failed"
	}
	if generatedPlaintext {
		clear(plaintext)
	}
	storageResult := storage.ParsedResult{
		AuditID:            audit.AuditID,
		ParserName:         audit.ParserName,
		ParserVersion:      parserVersion,
		Status:             result.Status,
		RequestModel:       optionalString(result.RequestModel),
		ResponseModel:      optionalString(result.ResponseModel),
		RequestedStream:    cloneBool(result.RequestedStream),
		ObservedStream:     cloneBool(result.ObservedStream),
		ResponseID:         optionalString(result.ResponseID),
		UsageInput:         cloneInt64(result.Usage.Input),
		UsageOutput:        cloneInt64(result.Usage.Output),
		UsageTotal:         cloneInt64(result.Usage.Total),
		ErrorType:          optionalString(result.ErrorType),
		ErrorCode:          optionalString(result.ErrorCode),
		UpstreamErrorClass: optionalString(result.UpstreamErrorClass),
		MessageCount:       cloneInt(result.MessageCount),
		ToolCallCount:      cloneInt(result.ToolCallCount),
		HasToolCall:        cloneBool(result.HasToolCall),
		ParsedJSONEnc:      encrypted,
		ParsedAtNS:         worker.now().UnixNano(),
	}
	return result.Status, worker.store.SaveParsedAudit(ctx, storage.ParsedAudit{Result: storageResult, Turn: prepared})
}

// PartialResponseMessagesKey is the parsed_json_enc key under which an audit
// with a request-only turn keeps the response-phase messages of its parsed
// conversation. The turn rebuilds only the request messages; readers append
// these after them (doc/features/18 section 6).
const PartialResponseMessagesKey = "partial_response_messages"

// parsedResultPlaintext is the plaintext of parsed_json_enc. Without a turn
// it holds the whole parsed conversation as the fallback copy. With a turn
// the conversation is rebuilt from the turn and not stored again, except for
// what a turn without a response (response layout none) cannot rebuild: the
// response-phase messages of the conversation, kept on their own under
// PartialResponseMessagesKey. A turn with no captured response has none, and
// stores nothing more.
func parsedResultPlaintext(result Result, prepared *auditmodel.PreparedTurn) ([]byte, bool) {
	plaintext := result.ParsedJSON
	generated := false
	if len(plaintext) == 0 {
		plaintext, _ = json.Marshal(compactResultJSON(result))
		generated = true
	}
	if result.Conversation == nil {
		return plaintext, generated
	}
	key, value := "conversation", any(result.Conversation)
	if prepared != nil {
		if prepared.ResponseLayout != auditmodel.LayoutNone {
			return plaintext, generated
		}
		messages := responseMessages(result.Conversation)
		if len(messages) == 0 {
			return plaintext, generated
		}
		key, value = PartialResponseMessagesKey, messages
	}
	var envelope map[string]any
	if err := json.Unmarshal(plaintext, &envelope); err != nil || envelope == nil {
		envelope = make(map[string]any)
	}
	envelope[key] = value
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return plaintext, generated
	}
	if generated {
		clear(plaintext)
	}
	return encoded, true
}

func onlyUnsupportedEncoding(input Input) bool {
	found := false
	for _, source := range []BodySource{input.Request, input.Response} {
		if !source.Present {
			continue
		}
		if source.ErrorCode != "unsupported_content_encoding" || len(source.Data) != 0 {
			return false
		}
		found = true
	}
	return found
}

func preserveParserFailure(errorCode string) bool {
	switch errorCode {
	case "parser_not_registered", "parser_panic", "empty_parser_result", "invalid_parser_status":
		return true
	default:
		return false
	}
}

func selectEvidenceCode(values ...string) string {
	for _, preferred := range []string{
		"capture_integrity_error",
		"evidence_read_error",
		"body_encryption_failed",
		"add_chunk_failed",
		"body_too_large",
		"gzip_ratio_exceeded",
		"gzip_invalid",
		"unsupported_content_encoding",
		"body_read_error",
		"body_write_error",
		"capture_partial",
	} {
		for _, value := range values {
			if value == preferred {
				return value
			}
		}
	}
	return firstNonEmpty(values...)
}

func compactResultJSON(result Result) map[string]any {
	return map[string]any{
		"status":               result.Status,
		"request_model":        result.RequestModel,
		"response_model":       result.ResponseModel,
		"requested_stream":     result.RequestedStream,
		"observed_stream":      result.ObservedStream,
		"response_id":          result.ResponseID,
		"usage":                result.Usage,
		"error_type":           result.ErrorType,
		"error_code":           result.ErrorCode,
		"upstream_error_class": result.UpstreamErrorClass,
		"message_count":        result.MessageCount,
		"tool_call_count":      result.ToolCallCount,
		"has_tool_call":        result.HasToolCall,
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	cloned := value
	return &cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
