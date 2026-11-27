package parser

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

const (
	// backfillBatch bounds the audits analysed per scan tick.
	backfillBatch = 20
	// backfillSkipCap bounds each in-memory set of audits skipped for good.
	// A full set first forgets the covered audits, which no pass lists again;
	// an audit that still does not fit is attempted again by the next pass
	// that lists it.
	backfillSkipCap = 1 << 16
	// backfillRetryCap bounds each in-memory set of audits waiting for a
	// retry. An audit that does not fit lowers the watermark instead, so the
	// next pass lists it again.
	backfillRetryCap = 1 << 16
	// backfillRescanInterval is the pause after the candidate list is
	// exhausted, before the next pass starts again from the watermark. It is
	// also the first retry delay.
	backfillRescanInterval = 10 * time.Minute
	// backfillRetryDoublings caps the retry backoff at
	// backfillRescanInterval << backfillRetryDoublings (80 minutes).
	backfillRetryDoublings = 3
)

// Stable reason logged with error_code analysis_backfill_skipped and
// project_backfill_skipped when a failure that cannot clear by waiting ends
// the attempts on an audit for this process.
const backfillSkipFailed = "failed"

// retryableFailure reports whether err may clear without any change to the
// audit: the storage was busy, unreachable, full, read-only or shut, or an
// operation timed out. Anything else, an analysis that rejects the evidence
// or a panic, fails the same way on the same evidence, so the audit is not
// loaded again in this process; a restart tries it once more.
func retryableFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, storage.ErrClosed) || errors.Is(err, storage.ErrQueueFull) || errors.Is(err, storage.ErrRecoveryOverflow) {
		return true
	}
	var network net.Error
	if errors.As(err, &network) {
		return true
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) && len(state.SQLState()) >= 2 {
		// Connection, transaction rollback (serialization, deadlock),
		// insufficient resources, object in use (lock timeout), operator
		// intervention (shutdown, cancel) and system errors.
		switch state.SQLState()[:2] {
		case "08", "40", "53", "55", "57", "58":
			return true
		}
		return false
	}
	switch storage.ErrorClass(err) {
	case "sqlite_busy", "sqlite_full", "sqlite_io_error", "sqlite_read_only":
		return true
	}
	return false
}

// retryDelay is the wait before attempt number attempts+1.
func retryDelay(attempts int) time.Duration {
	return backfillRescanInterval << min(max(attempts-1, 0), backfillRetryDoublings)
}

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

// BackfillStore lists audits that need (re)analysis. Stores without it simply
// never backfill.
type BackfillStore interface {
	ListAnalysisBackfillCandidates(ctx context.Context, version int, after *storage.AnalysisBackfillCursor, limit int) ([]storage.AnalysisBackfillCandidate, error)
}

// BackfillHorizonStore reports the newest audit position, which bounds the
// steady-state insights backfill (see backfillMark). A store without it, the
// legacy SQLite one, runs every pass from the oldest audit.
type BackfillHorizonStore interface {
	AnalysisBackfillHorizon(ctx context.Context) (storage.AnalysisBackfillCursor, bool, error)
}

// keyset is a (started_at_ns, audit_id) position: both backfills list their
// candidates in this order. The project cursor type has the same fields.
type keyset = storage.AnalysisBackfillCursor

func keysetBefore(a, b keyset) bool {
	return a.StartedAtNS < b.StartedAtNS || (a.StartedAtNS == b.StartedAtNS && a.AuditID < b.AuditID)
}

// lowerCovered returns the lower of two covered bounds; nil covers nothing
// and is the lowest.
func lowerCovered(a, b *keyset) *keyset {
	if a == nil || b == nil {
		return nil
	}
	if keysetBefore(*b, *a) {
		return b
	}
	return a
}

// uncovering returns the highest covered bound that leaves position
// uncovered: the empty audit id sorts below every real one at that time. A
// nil position (unknown) uncovers everything.
func uncovering(position *keyset) *keyset {
	if position == nil {
		return nil
	}
	return &keyset{StartedAtNS: position.StartedAtNS}
}

// watermark keeps one backfill from rescanning what it has already proved
// empty. covered is the watermark: every pass lists only candidates after it,
// so in the steady state a pass reads the few rows written since the last
// one instead of the whole table. It is kept in memory only, so the first
// pass after a restart covers everything, which also handles a version bump.
//
// Each backfill states its own invariant for the covered side (backfill and
// projectBackfill). A code path that may break it calls lower, which uncovers
// a position for the next pass, or records the audit in the backfill's retry
// set. When a pass completes, covered becomes the horizon read as the pass
// began, lowered by everything recorded while the pass was open.
type watermark struct {
	covered *keyset
	// open is set from the first tick of a pass until its list runs empty.
	open bool
	// passAfter is the bound the open pass lists after; horizon the newest
	// row when it began (nil: none, or the store cannot tell).
	passAfter *keyset
	horizon   *keyset
	// lowered/lowerTo accumulate lower calls until they are applied.
	lowered bool
	lowerTo *keyset
}

// lower uncovers position (nil: everything) for the next pass.
func (mark *watermark) lower(position *keyset) {
	mark.lowerBound(uncovering(position))
}

// lowerBound makes the next pass list everything after bound.
func (mark *watermark) lowerBound(bound *keyset) {
	if !mark.lowered {
		mark.lowered, mark.lowerTo = true, bound
		return
	}
	mark.lowerTo = lowerCovered(mark.lowerTo, bound)
}

func (mark *watermark) takeLowered(bound *keyset) *keyset {
	if mark.lowered {
		bound = lowerCovered(bound, mark.lowerTo)
	}
	mark.lowered, mark.lowerTo = false, nil
	return bound
}

// begin opens a pass that lists after the watermark.
func (mark *watermark) begin(horizon *keyset) {
	mark.open = true
	mark.passAfter = mark.takeLowered(mark.covered)
	mark.horizon = horizon
}

// complete closes the open pass: everything up to its horizon was listed.
func (mark *watermark) complete() {
	mark.covered = mark.takeLowered(mark.horizon)
	mark.open, mark.passAfter, mark.horizon = false, nil, nil
}

// abandon closes the open pass without moving the watermark: the next pass
// lists again from where this one began.
func (mark *watermark) abandon() {
	if mark.open {
		mark.lowerBound(mark.passAfter)
	}
	mark.open, mark.passAfter, mark.horizon = false, nil, nil
}

func keysetPointer(value keyset) *keyset { return &value }

// backfillRetry is one audit a backfill must try again after a failure that
// may clear by waiting. position is nil while it is unknown (the audit came
// from the live path); pass is the pass that last attempted it, so a pass
// tries it once; attempts counts the failures and nextAt is when it is due.
type backfillRetry struct {
	position *keyset
	pass     uint64
	attempts int
	nextAt   time.Time
}

func (retry *backfillRetry) due(now time.Time) bool { return !now.Before(retry.nextAt) }

// recordRetry records one more retryable failure of auditID in a retry set
// and backs its next attempt off. When the set is full the audit's position
// is uncovered instead, so the next pass lists it again.
func recordRetry(retries *map[string]*backfillRetry, mark *watermark, auditID string, position *keyset, now time.Time) {
	retry, waiting := (*retries)[auditID]
	if !waiting {
		if len(*retries) >= backfillRetryCap {
			mark.lower(position)
			return
		}
		if *retries == nil {
			*retries = make(map[string]*backfillRetry)
		}
		retry = &backfillRetry{}
		(*retries)[auditID] = retry
	}
	if position != nil {
		retry.position = position
	}
	retry.attempts++
	retry.nextAt = now.Add(retryDelay(retry.attempts))
}

// rememberSkip records that auditID is skipped for good in a skip set; the
// value is its position, nil while unknown. A full set first forgets the
// audits the watermark covers: no pass lists them again unless the watermark
// is lowered. If it is still full the audit is not remembered, and the next
// pass that lists it attempts it again.
func rememberSkip(skipped *map[string]*keyset, mark *watermark, auditID string, position *keyset) {
	if *skipped == nil {
		*skipped = make(map[string]*keyset)
	}
	if _, known := (*skipped)[auditID]; !known && len(*skipped) >= backfillSkipCap {
		for id, at := range *skipped {
			if at != nil && mark.covered != nil && !keysetBefore(*mark.covered, *at) {
				delete(*skipped, id)
			}
		}
		if len(*skipped) >= backfillSkipCap {
			return
		}
	}
	if previous := (*skipped)[auditID]; position == nil && previous != nil {
		position = previous
	}
	(*skipped)[auditID] = position
}

// dueRetries lists the retries due at now that a pass listing after bound
// cannot list itself: their position is unknown or covered.
func dueRetries(retries map[string]*backfillRetry, after *keyset, now time.Time) []string {
	var due []string
	for auditID, retry := range retries {
		if retry.due(now) && (retry.position == nil || (after != nil && !keysetBefore(*after, *retry.position))) {
			due = append(due, auditID)
		}
	}
	sort.Strings(due)
	return due
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
//
// Invariant: every audit at or below backfillMark.covered has a current
// analysis, or is not a candidate (not ended, or parse status not ok or
// partial), or was attempted in this process (by the backfill or the live
// analysis) and skipped for good, or is in backfillRetry. It holds because:
//   - covered only advances, at the end of a pass, to the horizon read when
//     the pass began, and the pass listed every candidate after its start;
//   - an audit becomes a candidate later only through a live parse in
//     process, which runs on this goroutine. Every exit of process that saves
//     ok or partial reaches analyze, and analyze reports each audit it leaves
//     without an analysis to backfillLater, however old the audit is: a long
//     request, a parse retried after a save failure, a pending row picked up
//     by a later scan or an audit closed by startup recovery all end there;
//   - a failure recorded while the retry set is full lowers the watermark;
//   - nothing else writes parse_status ok or partial, deletes an
//     audit_analysis row without its audit, or lowers analysis_version, and
//     retention only removes audits.
//
// The first pass after a restart covers nothing, so a new AnalysisVersion,
// audits imported offline and a parse whose save was cancelled at shutdown
// but committed are all listed. A store without BackfillHorizonStore never
// covers anything and every pass lists from the oldest audit.
func (worker *Worker) backfill(ctx context.Context) int {
	analyzer := worker.auditAnalyzer()
	store, listable := worker.store.(BackfillStore)
	if analyzer == nil || !listable || ctx.Err() != nil || len(worker.queue) > 0 {
		return 0
	}
	mark := &worker.backfillMark
	if !mark.open {
		if worker.now().Before(worker.backfillNextScan) {
			return 0
		}
		horizon, err := worker.backfillHorizon(ctx)
		if err != nil {
			if ctx.Err() == nil {
				worker.logger.Warn("insights backfill failed", "error_code", "analysis_backfill_failed", "reason", "horizon_failed", "storage_error", storage.ErrorClass(err))
			}
			return 0
		}
		mark.begin(horizon)
		worker.backfillPass++
		worker.backfillCursor = mark.passAfter
		worker.backfillRetryQueue = dueRetries(worker.backfillRetry, mark.passAfter, worker.now())
		worker.backfillProgress.begin(worker.now().UnixNano())
	}

	attempted := 0
	// Retries the list cannot return come first: their audits lie on the
	// covered side, or their position is unknown.
	for len(worker.backfillRetryQueue) > 0 {
		if ctx.Err() != nil || len(worker.queue) > 0 || attempted >= backfillBatch {
			return attempted
		}
		auditID := worker.backfillRetryQueue[0]
		worker.backfillRetryQueue = worker.backfillRetryQueue[1:]
		if retry, waiting := worker.backfillRetry[auditID]; waiting && retry.pass != worker.backfillPass {
			worker.attemptBackfill(ctx, analyzer, auditID, retry.position)
			attempted++
		}
	}
	if mark.passAfter != nil {
		// Everything at or below the watermark is analysed, was attempted and
		// skipped or failed, or was retried just now if its retry was due.
		worker.backfillProgress.advance(mark.passAfter.StartedAtNS)
	}
	if attempted >= backfillBatch {
		return attempted
	}

	candidates, err := store.ListAnalysisBackfillCandidates(ctx, insights.AnalysisVersion, worker.backfillCursor, backfillBatch)
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.Warn("insights backfill failed", "error_code", "analysis_backfill_failed", "reason", "list_failed", "storage_error", storage.ErrorClass(err))
		}
		return attempted
	}
	if len(candidates) == 0 {
		mark.complete()
		worker.backfillCursor = nil
		worker.backfillNextScan = worker.now().Add(backfillRescanInterval)
		worker.backfillProgress.complete()
		return attempted
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil || len(worker.queue) > 0 {
			return attempted
		}
		position := keyset{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
		retry, waiting := worker.backfillRetry[candidate.AuditID]
		if waiting {
			retry.position = keysetPointer(position)
		}
		at, skipped := worker.backfillSkipped[candidate.AuditID]
		if skipped && at == nil {
			worker.backfillSkipped[candidate.AuditID] = keysetPointer(position)
		}
		if !skipped && (!waiting || (retry.pass != worker.backfillPass && retry.due(worker.now()))) {
			worker.attemptBackfill(ctx, analyzer, candidate.AuditID, &position)
			attempted++
		}
		worker.backfillCursor = &storage.AnalysisBackfillCursor{StartedAtNS: candidate.StartedAtNS, AuditID: candidate.AuditID}
		worker.backfillProgress.advance(candidate.StartedAtNS)
	}
	return attempted
}

// backfillHorizon reads the newest audit position; nil when the store cannot
// tell or holds no audit.
func (worker *Worker) backfillHorizon(ctx context.Context) (*keyset, error) {
	store, bounded := worker.store.(BackfillHorizonStore)
	if !bounded {
		return nil, nil
	}
	horizon, found, err := store.AnalysisBackfillHorizon(ctx)
	if err != nil || !found {
		return nil, err
	}
	return &horizon, nil
}

// attemptBackfill runs backfillOne and marks a remaining retry as tried by
// this pass.
func (worker *Worker) attemptBackfill(ctx context.Context, analyzer AuditAnalyzer, auditID string, position *keyset) {
	worker.backfillOne(ctx, analyzer, auditID, position)
	if retry, waiting := worker.backfillRetry[auditID]; waiting {
		retry.pass = worker.backfillPass
	}
}

// backfillEnabled reports whether the insights backfill runs at all.
func (worker *Worker) backfillEnabled() bool {
	_, listable := worker.store.(BackfillStore)
	return listable && worker.auditAnalyzer() != nil
}

// backfillLater records an audit the live path left without an analysis,
// whichever side of the watermark it lies on. err is the analysis failure;
// nil means the request body was missing or empty. A failure that may clear
// by waiting is retried later; anything else would fail the same way on the
// same evidence, so the audit is skipped without loading it again.
func (worker *Worker) backfillLater(auditID string, input Input, err error) {
	if !worker.backfillEnabled() {
		return
	}
	if (err == nil && input.Request.ErrorCode == "evidence_read_error") || (err != nil && retryableFailure(err)) {
		recordRetry(&worker.backfillRetry, &worker.backfillMark, auditID, nil, worker.now())
		return
	}
	rememberSkip(&worker.backfillSkipped, &worker.backfillMark, auditID, nil)
}

func (worker *Worker) backfillSkip(auditID, reason string, position *keyset) {
	delete(worker.backfillRetry, auditID)
	rememberSkip(&worker.backfillSkipped, &worker.backfillMark, auditID, position)
	worker.logger.Info("insights backfill skipped", "audit_id", auditID, "error_code", "analysis_backfill_skipped", "reason", reason)
}

// backfillFail records a failed attempt. A retryable failure waits for its
// backoff and is never given up, so a storage outage is retried once it
// ends; any other failure skips the audit for this process: the evidence was
// already loaded once and would fail the same way.
func (worker *Worker) backfillFail(auditID, reason string, err error, position *keyset, retryable bool) {
	worker.logger.Warn("insights backfill failed", "audit_id", auditID, "error_code", "analysis_backfill_failed", "reason", reason, "storage_error", storage.ErrorClass(err), "retry", retryable)
	if retryable {
		recordRetry(&worker.backfillRetry, &worker.backfillMark, auditID, position, worker.now())
		return
	}
	worker.backfillSkip(auditID, backfillSkipFailed, position)
}

func canceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// backfillOne analyses one audit; position is nil when it is unknown. A
// failure before any body is read is always retried: it costs nothing to try
// again.
func (worker *Worker) backfillOne(ctx context.Context, analyzer AuditAnalyzer, auditID string, position *keyset) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		worker.backfillSkip(auditID, backfillSkipAuditMissing, position)
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			worker.backfillFail(auditID, "audit_load_failed", err, position, true)
		}
		return
	}
	if audit.ParseStatus != StatusOK && audit.ParseStatus != StatusPartial {
		delete(worker.backfillRetry, auditID)
		return
	}
	implementation := worker.parsers[audit.ParserName]
	if implementation == nil {
		worker.backfillSkip(auditID, backfillSkipNoParser, position)
		return
	}

	input, evidenceErr, reconstruction, reason, err := worker.backfillInput(ctx, audit)
	if err != nil {
		if ctx.Err() == nil {
			worker.backfillFail(auditID, reason, err, position, reason == "evidence_read_failed" || retryableFailure(err))
		}
		return
	}
	if reason != "" {
		worker.backfillSkip(auditID, reason, position)
		return
	}
	if input.Request.ErrorCode == "evidence_read_error" || input.Response.ErrorCode == "evidence_read_error" {
		// The store failed while the body was read: what was read is not the
		// evidence, so parsing it could skip the audit for good.
		if ctx.Err() == nil {
			worker.backfillFail(auditID, "evidence_read_failed", evidenceErr, position, true)
		}
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
		worker.backfillSkip(auditID, backfillSkipNotUsable, position)
		return
	}
	if !input.Request.Present || len(input.Request.Data) == 0 {
		worker.backfillSkip(auditID, backfillSkipNoRequestBody, position)
		return
	}
	if err := runAnalyzer(ctx, analyzer, audit, input, result); err != nil {
		if ctx.Err() == nil {
			reason := insights.ErrorCode(err)
			if errors.Is(err, errAnalyzerPanic) {
				reason = "analysis_panic"
			}
			worker.backfillFail(auditID, reason, err, position, retryableFailure(err))
		}
		return
	}
	delete(worker.backfillRetry, auditID)
	// The new audit_analysis row makes the audit a project identity
	// candidate, wherever it lies relative to that backfill's watermark.
	worker.projectBackfillLater(auditID, position)
}

// backfillInput loads the evidence of one audit. A non-empty reason means the
// audit is skipped; a non-nil error means the load failed.
func (worker *Worker) backfillInput(ctx context.Context, audit storage.ParserAudit) (Input, error, *Reconstruction, string, error) {
	stage, err := worker.store.LoadParserStage(ctx, audit.AuditID, storage.StageRequestReceived)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && stage.Body == nil) {
		return Input{}, nil, nil, backfillSkipNoBody, nil
	}
	if err != nil {
		return Input{}, nil, nil, "evidence_read_failed", err
	}
	if stage.Body.RetentionState != storage.RetentionMetadata {
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
