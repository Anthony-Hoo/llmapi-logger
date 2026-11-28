package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"

	"github.com/jackc/pgx/v5/pgconn"
)

type writeKind uint8

const (
	writeBeginAudit writeKind = iota + 1
	writeStartStage
	writeStartBody
	writeAddHeaders
	writeAddChunk
	writeFinishStage
	writeFinishAudit
	writeResetProcessingParses
	writeClaimPendingParse
	writeReleaseProcessingParse
	writeSaveParsedResult
	writeSaveParsedAudit
	writeRecoverInterruptedAudits
	writeInsertAuditGaps
	writeDeleteExpired
	writeUpsertTokenLink
	writeRetryCallerLookup
	writeCreateUserAgentRule
	writeUpdateUserAgentRule
	writeDeleteUserAgentRule
	writeSaveAnalysis
	writeUpdateTokenLinkBilling
	writeCreateContentPolicyRule
	writeUpdateContentPolicyRule
	writeDeleteContentPolicyRule
	// writeOrg carries one organisation-report write (org_writes.go). Its data
	// is an orgWrite closure so that the feature adds a single writer case.
	writeOrg
	writeDerived
	// writeCheckpoint and writeCommitAudit are the staged write path's
	// in-flight write and final write (checkpoint_writer.go, commit_writer.go).
	writeCheckpoint
	writeCommitAudit
	// writeRestoreStagedChunks is the start-up import of local staging
	// (staged_restore.go).
	writeRestoreStagedChunks
	// writeArchive carries one cold archive catalog write (archive_catalog.go)
	// as an archiveWrite closure. Each one is alone in its transaction.
	writeArchive
)

type writeRequest struct {
	kind     writeKind
	data     any
	ack      chan error
	sequence uint64
	policy   *policyWrite
	// payloadBytes is the ciphertext a checkpoint or commit carries. Legacy
	// operations leave it zero, so their batching is unchanged.
	payloadBytes int64
	// inboundLost is set by a BeginAudit whose start row was written but whose
	// inbound stage row was rejected on its own. The operation itself
	// succeeds, so its savepoint is released; the flag only counts once the
	// batch commits.
	inboundLost *bool
}

const (
	// A checkpoint or commit above this size gets a transaction of its own.
	aloneWritePayloadBytes = 16 << 20
	// A batch stops collecting once its checkpoints and commits reach this.
	batchPayloadBytes = 32 << 20
)

// alone reports whether the request gets a transaction of its own. A policy
// write has its own deadline. A retention batch is a write whose cost grows
// with the stored data, and a storage error fails a whole batch, so it must
// not share its fate with audit writes that happened to queue beside it. A
// large checkpoint or commit is alone for the same reason. An archive catalog
// write is alone so that its outcome (an intent registered, a segment sealed)
// is never rolled back by an unrelated failure in the same batch (design I).
func (request writeRequest) alone() bool {
	return request.policy != nil || request.kind == writeDeleteExpired || request.kind == writeArchive ||
		request.payloadBytes > aloneWritePayloadBytes
}

// BeginAudit enqueues a parent audit row and waits until its batch commits.
// Under the staged write path the record carries its inbound stage, which is
// written in the same operation (K item 1).
func (store *Store) BeginAudit(ctx context.Context, record AuditRecord) error {
	record.Defaults()
	if record.Inbound != nil {
		inbound := *record.Inbound
		inbound.Stage.Defaults()
		record.Inbound = &inbound
	}
	if err := validateAuditRecord(record); err != nil {
		return err
	}
	if err := storage.ValidateAuditRecordCapture(record); err != nil {
		return err
	}
	if err := requireCaptureVersion(record.CaptureVersion); err != nil {
		return err
	}
	owned := cloneAuditRecord(record)
	if record.Inbound != nil {
		inbound := cloneInboundStage(*record.Inbound)
		owned.Inbound = &inbound
	}
	inboundLost := new(bool)
	if err := store.submitSync(ctx, writeRequest{kind: writeBeginAudit, data: owned, inboundLost: inboundLost}); err != nil {
		return err
	}
	if *inboundLost {
		// The start row and its failure marks are committed: admitted, but
		// the session must not merge the request pair into a stage that has
		// no row (storage.ErrInboundStageNotStored).
		return fmt.Errorf("postgres: %w", storage.ErrInboundStageNotStored)
	}
	return nil
}

// StartStage non-blockingly appends an observed HTTP stage to the writer
// queue. A nil error means accepted by the queue, not yet committed.
func (store *Store) StartStage(ctx context.Context, stage HTTPStage) error {
	stage.Defaults()
	if err := validateStage(stage); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeStartStage, data: cloneHTTPStage(stage)})
}

// StartBody non-blockingly appends a lazily created body stream.
func (store *Store) StartBody(ctx context.Context, body BodyStream) error {
	body.Defaults()
	if err := validateBodyStream(body); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeStartBody, data: cloneBodyStream(body)})
}

// AddHeaders non-blockingly appends a group of encrypted Header or Trailer
// values as one ordered write operation.
func (store *Store) AddHeaders(ctx context.Context, headers []HTTPHeader) error {
	if len(headers) == 0 {
		return nil
	}
	owned := make([]HTTPHeader, len(headers))
	for index, header := range headers {
		if err := validateHeader(header); err != nil {
			return fmt.Errorf("header %d: %w", index, err)
		}
		owned[index] = cloneHTTPHeader(header)
	}
	return store.submitAsync(ctx, writeRequest{kind: writeAddHeaders, data: owned})
}

// AddChunk non-blockingly appends one encrypted owning body chunk.
func (store *Store) AddChunk(ctx context.Context, chunk BodyChunk) error {
	chunk.Defaults()
	if err := validateChunk(chunk); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeAddChunk, data: cloneBodyChunk(chunk)})
}

// FinishStage non-blockingly appends a stage and optional body finalization.
func (store *Store) FinishStage(ctx context.Context, finish StageFinish) error {
	finish.Defaults()
	if err := validateStageFinish(finish); err != nil {
		return err
	}
	return store.submitAsync(ctx, writeRequest{kind: writeFinishStage, data: cloneStageFinish(finish)})
}

// FinishAudit appends the terminal audit outcome and waits for its batch to
// commit. Since the writer is ordered, this is also a barrier for all earlier
// accepted operations.
func (store *Store) FinishAudit(ctx context.Context, finish AuditFinish) error {
	_, err := store.FinishAuditWithResult(ctx, finish)
	return err
}

// FinishAuditWithResult returns the effective terminal outcome only after the
// outer transaction commits. In particular, asynchronous capture failures may
// downgrade the submitted status. No outcome is returned on a failed or
// canceled acknowledgement, even if an accepted write later commits.
func (store *Store) FinishAuditWithResult(ctx context.Context, finish AuditFinish) (AuditFinish, error) {
	finish.Defaults()
	if err := validateAuditFinish(finish); err != nil {
		return AuditFinish{}, err
	}
	owned := cloneAuditFinish(finish)
	if err := store.submitSync(ctx, writeRequest{kind: writeFinishAudit, data: &owned}); err != nil {
		return AuditFinish{}, err
	}
	return owned, nil
}

func (store *Store) submitAsync(ctx context.Context, request writeRequest) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return ErrClosed
	}

	store.submitMu.Lock()
	defer store.submitMu.Unlock()
	if store.closed {
		return ErrClosed
	}
	request.sequence = store.submittedSequence + 1
	select {
	case store.queue <- request:
		store.submittedSequence = request.sequence
		return nil
	default:
		if request.kind == writeFinishAudit {
			// Replaying must wait for every earlier accepted stage write.
			store.rememberFailedWrite(request, store.submittedSequence)
		}
		if commit, ok := request.data.(*commitWrite); ok && request.kind == writeCommitAudit && commit.FinalAttempt {
			// Only the last attempt hands the outcome to recovery; an earlier
			// one leaves the audit open for the session's retry (B.8).
			store.rememberFailedWrite(commit.finishRequest(request.sequence), store.submittedSequence)
			store.holdStaged(commit.Finish.AuditID, commit.Chunks)
		}
		return ErrQueueFull
	}
}

func (store *Store) submitSync(ctx context.Context, request writeRequest) error {
	request.ack = make(chan error, 1)
	if err := store.submitAsync(ctx, request); err != nil {
		return err
	}
	select {
	case err := <-request.ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (store *Store) runWriter() {
	defer close(store.done)
	ticker := time.NewTicker(captureRecoveryInterval)
	defer ticker.Stop()
	var pending *writeRequest
	for {
		var first writeRequest
		var open bool
		if pending != nil {
			first, open = *pending, true
			pending = nil
		} else {
			select {
			case first, open = <-store.queue:
			case <-ticker.C:
				store.recoverCaptureWrites()
				continue
			case <-store.recoveryWake:
				store.recoverCaptureWrites()
				continue
			}
		}
		if !open {
			store.recoverCaptureWrites()
			return
		}

		batch := make([]writeRequest, 0, writerBatchSize)
		batch = append(batch, first)
		timer := time.NewTimer(writerBatchDelay)
		queueClosed := false
		payloadBytes := first.payloadBytes

	collect:
		for !first.alone() && len(batch) < writerBatchSize && payloadBytes < batchPayloadBytes {
			select {
			case request, open := <-store.queue:
				if !open {
					queueClosed = true
					break collect
				}
				if request.alone() {
					pending = &request
					break collect
				}
				batch = append(batch, request)
				payloadBytes += request.payloadBytes
			case <-timer.C:
				break collect
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		results, wrote, err := store.commitBatch(batch)
		if err != nil {
			store.healthy.Store(false)
			if store.logger != nil {
				store.logger.Warn("audit writer batch failed", "error_category", "writer_batch_failed",
					"storage_error", ErrorClass(err), "write_count", len(batch))
			}
			for _, request := range batch {
				if commit, ok := request.data.(*commitWrite); ok && request.kind == writeCommitAudit && !commit.FinalAttempt {
					// The session retries; recovery must not finalize first.
					continue
				}
				store.rememberFailedWrite(request, request.sequence)
			}
		} else if wrote {
			store.healthy.Store(true)
		}
		if err == nil {
			for index, request := range batch {
				switch request.kind {
				case writeFinishAudit:
					if results[index] != nil && !errors.Is(results[index], sql.ErrNoRows) {
						store.rememberFailedWrite(request, request.sequence)
					} else if results[index] == nil {
						store.forgetFinishedRecovery(request.data.(*AuditFinish).AuditID)
					}
				case writeCommitAudit:
					// An operation-level failure is never retried, so the
					// outcome goes to recovery whatever the attempt (B.8).
					commit := request.data.(*commitWrite)
					if results[index] != nil && !errors.Is(results[index], sql.ErrNoRows) {
						store.rememberFailedWrite(commit.finishRequest(request.sequence), request.sequence)
						store.holdStaged(commit.Finish.AuditID, commit.Chunks)
					} else if results[index] == nil {
						store.forgetFinishedRecovery(commit.Finish.AuditID)
					}
				}
			}
		}
		for _, request := range batch {
			store.processedSequence = max(store.processedSequence, request.sequence)
		}
		for index, request := range batch {
			if request.ack != nil {
				if err != nil && request.kind == writeCommitAudit {
					// The caller may retry a batch-level failure (B.8).
					request.ack <- fmt.Errorf("%w: %w", ErrWriteBatchFailed, err)
				} else if err != nil {
					request.ack <- err
				} else {
					request.ack <- results[index]
				}
			}
		}
		if queueClosed {
			store.recoverCaptureWrites()
			return
		}
	}
}

// Known local errors can be isolated. Storage errors fail the whole batch even
// when PostgreSQL could otherwise recover the transaction with a savepoint.
func (store *Store) commitBatch(batch []writeRequest) ([]error, bool, error) {
	ctx := context.Background()
	if len(batch) == 1 && batch[0].policy != nil {
		operation := batch[0].policy
		if !operation.state.CompareAndSwap(0, 1) {
			return []error{operation.ctx.Err()}, false, nil
		}
		ctx = operation.ctx
	}
	transaction, err := store.beginWrite(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("postgres writer: begin batch: %w", err)
	}
	defer transaction.Rollback()
	results := make([]error, len(batch))
	wrote := false
	for index, request := range batch {
		if _, err := transaction.Exec("SAVEPOINT writer_operation"); err != nil {
			return nil, false, fmt.Errorf("postgres writer: savepoint: %w", err)
		}
		before := transaction.mutations
		results[index] = store.applyWrite(transaction, request)
		if results[index] != nil && ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if results[index] != nil {
			var integrityFailure storedObjectIntegrityError
			if errors.As(results[index], &integrityFailure) {
				// Detection remains valid even if this operation rolls back.
				// Isolate its write failure, but latch readiness unhealthy.
				store.payloadState.Store(integrityPayloadsFailed)
			}
			if !canIsolateWriteError(results[index]) {
				return nil, false, results[index]
			}
			if _, err := transaction.Exec("ROLLBACK TO writer_operation"); err != nil {
				return nil, false, fmt.Errorf("postgres writer: rollback operation: %w", err)
			}
			transaction.mutations = before
			if err := markCaptureWriteFailed(transaction, request); err != nil {
				return nil, false, err
			}
		}
		wrote = wrote || transaction.mutations > before
		if _, err := transaction.Exec("RELEASE writer_operation"); err != nil {
			return nil, false, fmt.Errorf("postgres writer: release operation: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := transaction.Commit(); err != nil {
		return nil, false, fmt.Errorf("postgres writer: commit batch: %w", err)
	}
	return results, wrote, nil
}

type localWriteError string

func (err localWriteError) Error() string             { return string(err) }
func (err localWriteError) StorageErrorClass() string { return "invalid_write" }

type storedObjectIntegrityError string

func (err storedObjectIntegrityError) Error() string             { return string(err) }
func (err storedObjectIntegrityError) StorageErrorClass() string { return "object_integrity" }

// This controls rollback scope, not health: object integrity faults are
// isolated but also latch payloadState failed. Unclassified errors and storage
// failures must abort the outer transaction.
func canIsolateWriteError(err error) bool {
	var coded *pgconn.PgError
	if errors.As(err, &coded) {
		return len(coded.Code) >= 2 && coded.Code[:2] == "23"
	}
	var local localWriteError
	var integrityFailure storedObjectIntegrityError
	return errors.As(err, &local) || errors.As(err, &integrityFailure) || errors.Is(err, ErrRecoveryOverflow) || errors.Is(err, auditmodel.ErrReconstruction) ||
		errors.Is(err, sql.ErrNoRows) || errors.Is(err, uaguard.ErrNotFound) || errors.Is(err, contentpolicy.ErrNotFound) ||
		errors.Is(err, orgreport.ErrNotFound)
}

// Async capture has no acknowledgement. Persist the failure on its audit so
// finalization in this or any later batch cannot claim complete evidence.
// A parser or management operation must never taint unrelated capture.
func markCaptureWriteFailed(transaction dbTransaction, request writeRequest) error {
	var auditIDs []string
	headerStages := make(map[[2]string]struct{})
	switch request.kind {
	case writeStartStage:
		auditIDs = []string{request.data.(HTTPStage).AuditID}
	case writeStartBody:
		auditIDs = []string{request.data.(BodyStream).AuditID}
	case writeAddHeaders:
		seen := make(map[string]bool)
		for _, header := range request.data.([]HTTPHeader) {
			headerStages[[2]string{header.AuditID, header.Stage}] = struct{}{}
			if !seen[header.AuditID] {
				seen[header.AuditID] = true
				auditIDs = append(auditIDs, header.AuditID)
			}
		}
	case writeAddChunk:
		auditIDs = []string{request.data.(BodyChunk).AuditID}
	case writeFinishStage:
		auditIDs = []string{request.data.(StageFinish).AuditID}
	case writeCheckpoint:
		// The checkpoint replaces StartStage, AddHeaders, StartBody and
		// AddChunk: record what their failures would have recorded. The
		// rows this checkpoint inserted are rolled back, so the stage and body
		// markers only land on rows an earlier write left (B.8).
		checkpoint := request.data.(*checkpointWrite)
		auditIDs = []string{checkpoint.AuditID}
		for _, header := range checkpoint.Headers {
			headerStages[[2]string{header.AuditID, header.Stage}] = struct{}{}
		}
	case writeCommitAudit:
		auditIDs = []string{request.data.(*commitWrite).Finish.AuditID}
	}
	for _, auditID := range auditIDs {
		if _, err := transaction.Exec(`
UPDATE audit_records SET capture_status = 'failed', error_code = 'capture_write_failed'
WHERE audit_id = $1 AND ended_at_ns IS NULL`, auditID); err != nil {
			return fmt.Errorf("postgres writer: record capture failure: %w", err)
		}
	}
	for identity := range headerStages {
		if _, err := transaction.Exec(`
UPDATE http_stages SET state = 'partial', error_code = 'capture_headers_failed'
WHERE audit_id = $1 AND stage = $2
  AND EXISTS (SELECT 1 FROM audit_records a WHERE a.audit_id = http_stages.audit_id AND a.ended_at_ns IS NULL)`,
			identity[0], identity[1]); err != nil {
			return fmt.Errorf("postgres writer: record header stage failure: %w", err)
		}
	}
	if request.kind == writeAddChunk {
		chunk := request.data.(BodyChunk)
		if err := markMissingChunk(transaction, chunk.AuditID, chunk.Stage, chunk.Offset+int64(chunk.PlaintextLength)); err != nil {
			return err
		}
	}
	if request.kind == writeCheckpoint {
		checkpoint := request.data.(*checkpointWrite)
		bounds := checkpoint.chunkBounds()
		for index, stage := range captureStageNames {
			if bounds[index] < 0 {
				continue
			}
			if err := markMissingChunk(transaction, checkpoint.AuditID, stage, bounds[index]); err != nil {
				return err
			}
		}
	}
	return nil
}

func markMissingChunk(transaction dbTransaction, auditID, stage string, observed int64) error {
	if _, err := transaction.Exec(`
UPDATE body_streams SET observed_length = GREATEST(observed_length, $1), error_code = $2
WHERE audit_id = $3 AND stage = $4 AND state = 'streaming'
  AND EXISTS (SELECT 1 FROM audit_records a WHERE a.audit_id = body_streams.audit_id AND a.ended_at_ns IS NULL)`,
		observed, CaptureChunkMissing, auditID, stage); err != nil {
		return fmt.Errorf("postgres writer: record missing chunk: %w", err)
	}
	return nil
}

func (store *Store) applyWrite(transaction dbTransaction, request writeRequest) error {
	signer := store.integrity.Load()
	switch request.kind {
	case writeBeginAudit:
		if store.recoveryOverflow.Load() {
			return ErrRecoveryOverflow
		}
		record := request.data.(AuditRecord)
		if err := insertAudit(transaction, record); err != nil {
			return err
		}
		if record.Inbound == nil {
			return nil
		}
		stored, err := insertInboundStage(transaction, *record.Inbound)
		if err == nil && !stored && request.inboundLost != nil {
			*request.inboundLost = true
		}
		return err
	case writeStartStage:
		return insertStage(transaction, request.data.(HTTPStage))
	case writeStartBody:
		return insertBody(transaction, request.data.(BodyStream))
	case writeAddHeaders:
		return insertHeaders(transaction, request.data.([]HTTPHeader))
	case writeAddChunk:
		return insertChunk(transaction, request.data.(BodyChunk))
	case writeFinishStage:
		return finishStage(transaction, request.data.(StageFinish))
	case writeFinishAudit:
		if err := store.prepareFinalization(transaction, request.data.(*AuditFinish).AuditID); err != nil {
			return err
		}
		return finishAudit(transaction, request.data.(*AuditFinish), signer, legacyDedup)
	case writeCheckpoint:
		return applyCheckpoint(transaction, request.data.(*checkpointWrite))
	case writeCommitAudit:
		commit := request.data.(*commitWrite)
		if err := store.prepareFinalization(transaction, commit.Finish.AuditID); err != nil {
			return err
		}
		return applyCommit(transaction, commit, signer)
	case writeRestoreStagedChunks:
		return restoreStagedChunks(transaction, request.data.(*stagedRestoreWrite))
	case writeResetProcessingParses:
		return resetProcessingParses(transaction)
	case writeClaimPendingParse:
		return claimPendingParse(transaction, request.data.(*parseClaim))
	case writeReleaseProcessingParse:
		return releaseProcessingParse(transaction, request.data.(string), signer, time.Now())
	case writeSaveParsedResult:
		return saveParsedResult(transaction, request.data.(ParsedResult), signer)
	case writeSaveParsedAudit:
		return saveParsedAudit(transaction, request.data.(ParsedAudit), signer)
	case writeRecoverInterruptedAudits:
		return recoverInterruptedAudits(transaction, request.data.(*recoveryRequest), signer)
	case writeInsertAuditGaps:
		return insertAuditGaps(transaction, request.data.([]AuditGap))
	case writeDeleteExpired:
		return deleteExpired(transaction, request.data.(*retentionRequest))
	case writeUpsertTokenLink:
		return upsertTokenLink(transaction, request.data.(TokenLink))
	case writeRetryCallerLookup:
		return retryCallerLookup(transaction, request.data.(CallerRetry))
	case writeUpdateTokenLinkBilling:
		return updateTokenLinkBilling(transaction, request.data.(BillingUpdate))
	case writeCreateUserAgentRule:
		return createUserAgentRule(transaction, request.data.(uaguard.Rule))
	case writeUpdateUserAgentRule:
		return updateUserAgentRule(transaction, request.data.(uaguard.Rule))
	case writeDeleteUserAgentRule:
		return deleteUserAgentRule(transaction, request.data.(int64))
	case writeCreateContentPolicyRule:
		return createContentPolicyRule(transaction, request.data.(*contentpolicy.Rule))
	case writeUpdateContentPolicyRule:
		return updateContentPolicyRule(transaction, request.data.(contentpolicy.Rule))
	case writeDeleteContentPolicyRule:
		return deleteContentPolicyRule(transaction, request.data.(int64))
	case writeSaveAnalysis:
		return saveAnalysis(transaction, request.data.(AnalysisRow))
	case writeOrg:
		return request.data.(orgWrite)(transaction)
	case writeDerived:
		return request.data.(derivedWrite)(transaction)
	case writeArchive:
		return request.data.(archiveWrite)(transaction)
	default:
		return fmt.Errorf("postgres writer: unknown operation %d", request.kind)
	}
}

// prepareFinalization runs before a FinishAudit or CommitAudit finalizes an
// audit: a failed recovery attempt and this batch use separate transactions,
// so the finish must not outrun its failure marker, and an overflowed
// recovery table forbids claiming any capture complete.
func (store *Store) prepareFinalization(transaction dbTransaction, auditID string) error {
	store.recoveryMu.Lock()
	entry, pending := store.recoveries[auditID]
	store.recoveryMu.Unlock()
	if pending && !entry.marked {
		entry.finish = nil
		if _, err := store.recoverCaptureEntry(transaction, auditID, entry); err != nil {
			return err
		}
	}
	if store.recoveryOverflow.Load() {
		if _, err := transaction.Exec(`UPDATE audit_records
SET capture_status='failed', error_code='capture_recovery_overflow'
WHERE audit_id=$1 AND ended_at_ns IS NULL`, auditID); err != nil {
			return err
		}
	}
	return nil
}

// insertInboundStage writes the rows the legacy StartStage and AddHeaders
// write for request_received, each in a nested savepoint. Admission must not
// depend on them: when one is rejected with an isolatable error, only that
// part is rolled back, the start row stays, and the audit is marked as
// legacy marks it when that operation fails. Any other error fails the
// whole operation, as it fails BeginAudit today. stageStored reports whether
// the request_received row was kept; a rejected header insert keeps it.
func insertInboundStage(transaction dbTransaction, inbound InboundStage) (stageStored bool, err error) {
	part := func(write func() error, failed writeRequest) (bool, error) {
		if _, err := transaction.Exec("SAVEPOINT begin_inbound"); err != nil {
			return false, fmt.Errorf("postgres writer: inbound savepoint: %w", err)
		}
		err := write()
		if err != nil {
			if !canIsolateWriteError(err) {
				return false, err
			}
			if _, rollbackErr := transaction.Exec("ROLLBACK TO begin_inbound"); rollbackErr != nil {
				return false, fmt.Errorf("postgres writer: rollback inbound stage: %w", rollbackErr)
			}
			if markErr := markCaptureWriteFailed(transaction, failed); markErr != nil {
				return false, markErr
			}
		}
		if _, releaseErr := transaction.Exec("RELEASE begin_inbound"); releaseErr != nil {
			return false, fmt.Errorf("postgres writer: release inbound savepoint: %w", releaseErr)
		}
		return err == nil, nil
	}
	content := map[string]StageContent{inbound.Stage.Stage: {Stage: inbound.Stage.Stage, ContentType: inbound.ContentType, ContentEncoding: inbound.ContentEncoding}}
	written, err := part(func() error { return insertStageRows(transaction, []HTTPStage{inbound.Stage}, content) },
		writeRequest{kind: writeStartStage, data: inbound.Stage})
	if err != nil || !written {
		// Without the stage row legacy's AddHeaders fails on its parent and
		// adds no mark beyond the audit's.
		return written, err
	}
	if inbound.HeaderBlock != nil {
		// Version 2: a block with only this stage. A rejected block is marked
		// as a rejected AddHeaders of the stage. The session is not told: a
		// later write that inserts a stage row or adds trailers writes the
		// whole block again, but an audit without one (an interceptor
		// rejection, a crash before checkpoint 1) keeps a stage row without
		// a block. The audit is marked failed, so headerblock.Expand reads
		// it with that stage's Headers absent, as legacy does.
		marker := []HTTPHeader{{AuditID: inbound.Stage.AuditID, Stage: inbound.Stage.Stage}}
		_, err = part(func() error { return upsertHeaderBlock(transaction, inbound.Stage.AuditID, inbound.HeaderBlock) },
			writeRequest{kind: writeAddHeaders, data: marker})
		return err == nil, err
	}
	if len(inbound.Headers) == 0 {
		return true, nil
	}
	_, err = part(func() error { return insertHeaderRows(transaction, inbound.Headers) },
		writeRequest{kind: writeAddHeaders, data: inbound.Headers})
	return err == nil, err
}

func insertAudit(transaction dbTransaction, record AuditRecord) error {
	_, err := transaction.Exec(`
INSERT INTO audit_records (
    audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
    method, path, request_uri_enc, mode, status_code, ttft_ns, forward_status,
    capture_status, parse_status, blocked_by, block_code, error_code,
    newapi_request_id, caller_status, caller_attempts, caller_next_at_ns,
    caller_updated_at_ns, api_key_fpr, capture_version, user_agent_enc
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		record.AuditID,
		record.StartedAtNS,
		record.EndedAtNS,
		record.RouteID,
		record.Protocol,
		record.ParserName,
		record.Method,
		record.Path,
		record.RequestURIEnc,
		record.Mode,
		record.StatusCode,
		record.TTFTNS,
		record.ForwardStatus,
		record.CaptureStatus,
		record.ParseStatus,
		record.BlockedBy,
		record.BlockCode,
		record.ErrorCode,
		record.NewAPIRequestID,
		record.CallerStatus,
		record.CallerAttempts,
		record.CallerNextAtNS,
		record.CallerUpdatedAtNS,
		nullableBytes(record.APIKeyFPR),
		storage.EffectiveCaptureVersion(record.CaptureVersion),
		nullableBytes(record.UserAgentEnc),
	)
	if err != nil {
		return fmt.Errorf("postgres writer: begin audit: %w", err)
	}
	return nil
}

func insertStage(transaction dbTransaction, stage HTTPStage) error {
	_, err := transaction.Exec(`
INSERT INTO http_stages (
    audit_id, stage, state, proto, method, host, status_code,
    content_length, started_at_ns, ended_at_ns, error_code
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		stage.AuditID,
		stage.Stage,
		stage.State,
		stage.Proto,
		stage.Method,
		stage.Host,
		stage.StatusCode,
		stage.ContentLength,
		stage.StartedAtNS,
		stage.EndedAtNS,
		stage.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: start stage: %w", err)
	}
	return nil
}

func insertBody(transaction dbTransaction, body BodyStream) error {
	_, err := transaction.Exec(`
INSERT INTO body_streams (
    audit_id, stage, source_stage, observed_length, stored_length, sha256,
    hash_complete, eof_seen, state, retention_state,
    first_observed_at_ns, last_observed_at_ns, chunk_count,
    stream_event_count, stream_timeline_complete, error_code
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		body.AuditID,
		body.Stage,
		body.SourceStage,
		body.ObservedLength,
		body.StoredLength,
		nullableBytes(body.SHA256),
		boolInteger(body.HashComplete),
		boolInteger(body.EOFSeen),
		body.State,
		body.RetentionState,
		body.FirstObservedAtNS,
		body.LastObservedAtNS,
		body.ChunkCount,
		body.StreamEventCount,
		boolInteger(body.StreamTimelineComplete),
		body.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: start body: %w", err)
	}
	return nil
}

func insertHeaders(transaction dbTransaction, headers []HTTPHeader) error {
	for _, header := range headers {
		_, err := transaction.Exec(`
INSERT INTO http_headers (
    audit_id, stage, kind, name, value_index, value_length, value_enc
) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			header.AuditID,
			header.Stage,
			header.Kind,
			header.Name,
			header.ValueIndex,
			header.ValueLength,
			header.ValueEnc,
		)
		if err != nil {
			return fmt.Errorf("postgres writer: add header: %w", err)
		}
	}
	return nil
}

func insertChunk(transaction dbTransaction, chunk BodyChunk) error {
	_, err := transaction.Exec(`
INSERT INTO body_chunks (
    audit_id, stage, seq, "offset", plaintext_length, encoded_length,
    observed_at_ns, compression, data_enc
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		chunk.AuditID,
		chunk.Stage,
		chunk.Seq,
		chunk.Offset,
		chunk.PlaintextLength,
		chunk.EncodedLength,
		chunk.ObservedAtNS,
		chunk.Compression,
		chunk.DataEnc,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: add chunk: %w", err)
	}
	return nil
}

func finishStage(transaction dbTransaction, finish StageFinish) error {
	result, err := transaction.Exec(`
UPDATE http_stages
SET state = CASE WHEN error_code IN ('capture_headers_failed','capture_storage_failed') THEN 'partial' ELSE $1 END,
    status_code = $2, content_length = $3, ended_at_ns = $4,
    error_code = CASE WHEN error_code IN ('capture_headers_failed','capture_storage_failed') THEN error_code ELSE $5 END
WHERE audit_id = $6 AND stage = $7`,
		finish.State,
		finish.StatusCode,
		finish.ContentLength,
		finish.EndedAtNS,
		finish.ErrorCode,
		finish.AuditID,
		finish.Stage,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: finish stage: %w", err)
	}
	if err := requireOneRow(result, "finish stage"); err != nil {
		return err
	}
	if finish.Body == nil {
		return nil
	}

	result, err = transaction.Exec(`
UPDATE body_streams
SET observed_length = $1, stored_length = $2, sha256 = $3, hash_complete = $4,
    eof_seen = $5, state = $6, retention_state = $7,
    first_observed_at_ns = $8, last_observed_at_ns = $9, chunk_count = $10,
    stream_event_count = $11, stream_timeline_complete = $12, error_code = $13
WHERE audit_id = $14 AND stage = $15`,
		finish.Body.ObservedLength,
		finish.Body.StoredLength,
		nullableBytes(finish.Body.SHA256),
		boolInteger(finish.Body.HashComplete),
		boolInteger(finish.Body.EOFSeen),
		finish.Body.State,
		finish.Body.RetentionState,
		finish.Body.FirstObservedAtNS,
		finish.Body.LastObservedAtNS,
		finish.Body.ChunkCount,
		finish.Body.StreamEventCount,
		boolInteger(finish.Body.StreamTimelineComplete),
		finish.Body.ErrorCode,
		finish.AuditID,
		finish.Stage,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: finish body: %w", err)
	}
	if err := requireOneRow(result, "finish body"); err != nil {
		return err
	}
	return saveStreamTimeline(transaction, finish.AuditID, finish.Stage, finish.Body.Timeline)
}

func saveStreamTimeline(transaction dbTransaction, auditID, stage string, timeline *StreamTimeline) error {
	if timeline != nil {
		if _, err := transaction.Exec(`
INSERT INTO stream_timelines (
    audit_id, stage, event_count, first_event_at_ns, last_event_at_ns,
    timeline_complete, compression, plaintext_length, timeline_enc
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT(audit_id, stage) DO UPDATE SET
    event_count = excluded.event_count,
    first_event_at_ns = excluded.first_event_at_ns,
    last_event_at_ns = excluded.last_event_at_ns,
    timeline_complete = excluded.timeline_complete,
    compression = excluded.compression,
    plaintext_length = excluded.plaintext_length,
    timeline_enc = excluded.timeline_enc`,
			auditID, stage, timeline.EventCount,
			timeline.FirstEventAtNS, timeline.LastEventAtNS,
			boolInteger(timeline.Complete), timeline.Compression,
			timeline.PlaintextLength, timeline.DataEnc,
		); err != nil {
			return fmt.Errorf("postgres writer: save stream timeline: %w", err)
		}
	}
	return nil
}

// legacyDedup merges both stage pairs in the database, as the legacy write
// path and every recovery do.
var legacyDedup = [2]bool{true, true}

// finishAudit finalizes one audit. dedupInDB selects the stage pairs
// (request, response) whose equivalent bodies are merged here; CommitAudit
// clears a pair it already decided in memory.
func finishAudit(transaction dbTransaction, finish *AuditFinish, signer *security.IntegritySigner, dedupInDB [2]bool) error {
	// Recovery and a caller retry may meet after an uncertain Ack. A second
	// finalization must not overwrite parsing/caller state or sign a new event.
	var ended sql.NullInt64
	if err := transaction.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id=$1", finish.AuditID).Scan(&ended); err != nil {
		return fmt.Errorf("postgres writer: read finalization state: %w", err)
	}
	if ended.Valid {
		return loadFinishedOutcome(transaction, finish)
	}
	var storedCaptureStatus string
	var storedErrorCode sql.NullString
	if err := transaction.QueryRow("SELECT capture_status, error_code FROM audit_records WHERE audit_id = $1", finish.AuditID).Scan(&storedCaptureStatus, &storedErrorCode); err != nil {
		return fmt.Errorf("postgres writer: read capture status: %w", err)
	}
	if storedCaptureStatus == CaptureFailed {
		finish.CaptureStatus = CaptureFailed
		code := "capture_write_failed"
		if storedErrorCode.Valid {
			code = storedErrorCode.String
		}
		finish.ErrorCode = &code
	} else {
		if err := deduplicateEquivalentBodyStages(transaction, finish.AuditID, dedupInDB); err != nil {
			return err
		}
	}
	if finish.CaptureStatus != CaptureComplete {
		if err := finalizeIncompleteCapture(transaction, finish.AuditID, finish.EndedAtNS); err != nil {
			return err
		}
	}
	result, err := transaction.Exec(`
UPDATE audit_records
SET ended_at_ns = $1, status_code = $2, ttft_ns = $3, forward_status = $4, capture_status = $5,
    parse_status = $6, blocked_by = $7, block_code = $8, error_code = $9,
    newapi_request_id = $10,
    caller_status = CASE WHEN $11::text IS NULL THEN 'none' ELSE 'pending' END,
    caller_attempts = 0,
    caller_next_at_ns = CASE WHEN $12::text IS NULL THEN NULL ELSE $13::bigint END,
    caller_updated_at_ns = CASE WHEN $14::text IS NULL THEN NULL ELSE $15::bigint END
WHERE audit_id = $16`,
		finish.EndedAtNS,
		finish.StatusCode,
		finish.TTFTNS,
		finish.ForwardStatus,
		finish.CaptureStatus,
		finish.ParseStatus,
		finish.BlockedBy,
		finish.BlockCode,
		finish.ErrorCode,
		finish.NewAPIRequestID,
		finish.NewAPIRequestID,
		finish.NewAPIRequestID,
		finish.EndedAtNS,
		finish.NewAPIRequestID,
		finish.EndedAtNS,
		finish.AuditID,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: finish audit: %w", err)
	}
	if err := requireOneRow(result, "finish audit"); err != nil {
		return err
	}
	if finish.ForwardStatus != ForwardCompleted || finish.CaptureStatus != CaptureComplete ||
		finish.StatusCode == nil || *finish.StatusCode < 200 || *finish.StatusCode >= 400 ||
		finish.ParseStatus == ParseSkipped {
		if _, err := transaction.Exec(`
UPDATE body_streams
SET retention_state = 'full'
WHERE audit_id = $1`, finish.AuditID); err != nil {
			return fmt.Errorf("postgres writer: retain terminal raw evidence: %w", err)
		}
	}
	payloadDigest, err := capturePayloadDigestFor(context.Background(), transaction, finish.AuditID, schemaLive)
	if err != nil {
		return err
	}
	if err := appendIntegrityEvent(transaction, signer, finish.AuditID, integrityCaptureFinalized, payloadDigest, finish.EndedAtNS); err != nil {
		return err
	}
	return nil
}

func loadFinishedOutcome(transaction dbTransaction, finish *AuditFinish) error {
	var status, ttft sql.NullInt64
	var blocked, blockCode, errorCode, requestID sql.NullString
	err := transaction.QueryRow(`SELECT ended_at_ns, status_code, ttft_ns, forward_status,
capture_status, parse_status, blocked_by, block_code, error_code, newapi_request_id
FROM audit_records WHERE audit_id=$1`, finish.AuditID).Scan(
		&finish.EndedAtNS, &status, &ttft, &finish.ForwardStatus, &finish.CaptureStatus,
		&finish.ParseStatus, &blocked, &blockCode, &errorCode, &requestID)
	if err != nil {
		return fmt.Errorf("postgres writer: read committed outcome: %w", err)
	}
	finish.StatusCode = nullIntPointer(status)
	finish.TTFTNS = nullInt64Pointer(ttft)
	finish.BlockedBy, finish.BlockCode = nullStringPointer(blocked), nullStringPointer(blockCode)
	finish.ErrorCode, finish.NewAPIRequestID = nullStringPointer(errorCode), nullStringPointer(requestID)
	return nil
}

// Reconcile every damaged body, including a successful FinishStage whose
// in-memory totals include chunks that never committed. Keep the observed
// length, but describe only the actual stored bytes as retained evidence.
// A sealed timeline and a collector stage code describe what was observed, so
// both survive. A finished body without a sealed timeline already reports it
// incomplete; only a body that never finished still needs the flag cleared.
func finalizeIncompleteCapture(transaction dbTransaction, auditID string, endedAtNS int64) error {
	if _, err := transaction.Exec(`
WITH chunk_lengths AS (
    SELECT stage, SUM(plaintext_length) AS stored_length,
           MAX("offset" + plaintext_length) AS observed_length, COUNT(*) AS chunk_count,
           MAX(seq) + 1 AS sequence_count
    FROM body_chunks WHERE audit_id = $1 GROUP BY stage
)
UPDATE body_streams
SET stored_length = COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0),
    observed_length = GREATEST(observed_length, COALESCE((SELECT observed_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)),
    chunk_count = COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0),
    sha256 = NULL, hash_complete = 0, eof_seen = 0,
    state = 'partial', retention_state = 'full',
    stream_timeline_complete = CASE WHEN state = 'streaming' THEN 0 ELSE stream_timeline_complete END,
    error_code = CASE WHEN error_code = 'capture_chunk_missing'
        OR (state <> 'streaming' AND (
            stored_length > COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
            OR chunk_count > COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)))
        OR EXISTS (SELECT 1 FROM chunk_lengths WHERE stage = body_streams.source_stage
            AND (sequence_count <> chunk_count OR observed_length <> stored_length))
        THEN 'capture_chunk_missing' ELSE 'capture_write_failed' END
WHERE audit_id = $2 AND (
    state = 'streaming' OR error_code = 'capture_chunk_missing'
    OR stored_length <> COALESCE((SELECT stored_length FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
    OR chunk_count <> COALESCE((SELECT chunk_count FROM chunk_lengths WHERE stage = body_streams.source_stage), 0)
    OR EXISTS (SELECT 1 FROM chunk_lengths WHERE stage = body_streams.source_stage
        AND (sequence_count <> chunk_count OR observed_length <> stored_length))
)`, auditID, auditID); err != nil {
		return fmt.Errorf("postgres writer: finalize incomplete body: %w", err)
	}
	if _, err := transaction.Exec(`
UPDATE http_stages
SET state = 'partial', ended_at_ns = COALESCE(ended_at_ns, $1),
    error_code = COALESCE(error_code, 'capture_write_failed')
WHERE audit_id = $2 AND (state = 'streaming' OR error_code IN ('capture_headers_failed', 'capture_storage_failed') OR EXISTS (
    SELECT 1 FROM body_streams b WHERE b.audit_id = http_stages.audit_id AND b.stage = http_stages.stage
      AND b.state = 'partial' AND b.error_code IN ('capture_write_failed', 'capture_chunk_missing')
))`, endedAtNS, auditID); err != nil {
		return fmt.Errorf("postgres writer: finalize incomplete stage: %w", err)
	}
	return nil
}

type bodyDedupState struct {
	SourceStage      string
	ObservedLength   int64
	StoredLength     int64
	Digest           []byte
	HashComplete     int
	EOFSeen          int
	State            string
	ChunkCount       int64
	StreamEventCount int64
	TimelineComplete int
}

func deduplicateEquivalentBodyStages(transaction dbTransaction, auditID string, pairs [2]bool) error {
	for index, pair := range [][2]string{
		{StageRequestReceived, StageRequestSent},
		{StageResponseReceived, StageResponseSent},
	} {
		if !pairs[index] {
			continue
		}
		if err := deduplicateEquivalentBodyPair(transaction, auditID, pair[0], pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func deduplicateEquivalentBodyPair(transaction dbTransaction, auditID, sourceStage, duplicateStage string) error {
	source, found, err := readBodyDedupState(transaction, auditID, sourceStage)
	if err != nil || !found {
		return err
	}
	duplicate, found, err := readBodyDedupState(transaction, auditID, duplicateStage)
	if err != nil || !found {
		return err
	}
	if source.SourceStage != sourceStage || duplicate.SourceStage != duplicateStage ||
		source.State != StageStateComplete || duplicate.State != StageStateComplete ||
		source.HashComplete == 0 || duplicate.HashComplete == 0 || source.EOFSeen == 0 || duplicate.EOFSeen == 0 ||
		source.StoredLength != source.ObservedLength || duplicate.StoredLength != duplicate.ObservedLength ||
		source.ObservedLength != duplicate.ObservedLength || len(source.Digest) != 32 || !bytes.Equal(source.Digest, duplicate.Digest) {
		return nil
	}
	sourceChunkCount, sourceChunkLength, err := bodyChunkAggregate(transaction, auditID, sourceStage)
	if err != nil {
		return err
	}
	duplicateChunkCount, duplicateChunkLength, err := bodyChunkAggregate(transaction, auditID, duplicateStage)
	if err != nil {
		return err
	}
	if sourceChunkCount != source.ChunkCount || sourceChunkLength != source.StoredLength ||
		duplicateChunkCount != duplicate.ChunkCount || duplicateChunkLength != duplicate.StoredLength {
		return nil
	}
	if _, err := transaction.Exec(`DELETE FROM body_chunks WHERE audit_id = $1 AND stage = $2`, auditID, duplicateStage); err != nil {
		return fmt.Errorf("postgres writer: delete duplicate body chunks: %w", err)
	}
	result, err := transaction.Exec(`
UPDATE body_streams
SET source_stage = $1, stored_length = $2, chunk_count = $3,
    stream_event_count = $4, stream_timeline_complete = $5
WHERE audit_id = $6 AND stage = $7 AND source_stage = $8`,
		sourceStage, source.StoredLength, source.ChunkCount,
		source.StreamEventCount, source.TimelineComplete,
		auditID, duplicateStage, duplicateStage,
	)
	if err != nil {
		return fmt.Errorf("postgres writer: link duplicate body stream: %w", err)
	}
	return requireOneRow(result, "link duplicate body stream")
}

func readBodyDedupState(transaction dbTransaction, auditID, stage string) (bodyDedupState, bool, error) {
	var result bodyDedupState
	err := transaction.QueryRow(`
SELECT source_stage, observed_length, stored_length, sha256,
       hash_complete, eof_seen, state, chunk_count,
       stream_event_count, stream_timeline_complete
FROM body_streams
WHERE audit_id = $1 AND stage = $2`, auditID, stage).Scan(
		&result.SourceStage,
		&result.ObservedLength,
		&result.StoredLength,
		&result.Digest,
		&result.HashComplete,
		&result.EOFSeen,
		&result.State,
		&result.ChunkCount,
		&result.StreamEventCount,
		&result.TimelineComplete,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return bodyDedupState{}, false, nil
	}
	if err != nil {
		return bodyDedupState{}, false, fmt.Errorf("postgres writer: read body dedup state: %w", err)
	}
	return result, true, nil
}

func bodyChunkAggregate(transaction dbTransaction, auditID, stage string) (int64, int64, error) {
	var count, length int64
	if err := transaction.QueryRow(`
SELECT COUNT(*), COALESCE(SUM(plaintext_length), 0)
FROM body_chunks
WHERE audit_id = $1 AND stage = $2`, auditID, stage).Scan(&count, &length); err != nil {
		return 0, 0, fmt.Errorf("postgres writer: read body chunk aggregate: %w", err)
	}
	return count, length, nil
}

func requireOneRow(result sql.Result, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres writer: %s rows affected: %w", operation, err)
	}
	if rows != 1 {
		if rows == 0 {
			return localWriteError(fmt.Sprintf("postgres writer: %s affected no rows", operation))
		}
		return fmt.Errorf("postgres writer: %s affected %d rows", operation, rows)
	}
	return nil
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func cloneAuditRecord(record AuditRecord) AuditRecord {
	record.RequestURIEnc = cloneBytes(record.RequestURIEnc)
	record.EndedAtNS = cloneInt64(record.EndedAtNS)
	record.StatusCode = cloneInt(record.StatusCode)
	record.TTFTNS = cloneInt64(record.TTFTNS)
	record.BlockedBy = cloneString(record.BlockedBy)
	record.BlockCode = cloneString(record.BlockCode)
	record.ErrorCode = cloneString(record.ErrorCode)
	record.NewAPIRequestID = cloneString(record.NewAPIRequestID)
	record.CallerNextAtNS = cloneInt64(record.CallerNextAtNS)
	record.CallerUpdatedAtNS = cloneInt64(record.CallerUpdatedAtNS)
	record.APIKeyFPR = cloneBytes(record.APIKeyFPR)
	record.UserAgentEnc = cloneBytes(record.UserAgentEnc)
	record.Inbound = nil
	return record
}

func cloneHTTPStage(stage HTTPStage) HTTPStage {
	stage.StatusCode = cloneInt(stage.StatusCode)
	stage.ContentLength = cloneInt64(stage.ContentLength)
	stage.EndedAtNS = cloneInt64(stage.EndedAtNS)
	stage.ErrorCode = cloneString(stage.ErrorCode)
	return stage
}

func cloneHTTPHeader(header HTTPHeader) HTTPHeader {
	header.ValueEnc = cloneBytes(header.ValueEnc)
	return header
}

func cloneBodyStream(body BodyStream) BodyStream {
	body.SHA256 = cloneBytes(body.SHA256)
	body.FirstObservedAtNS = cloneInt64(body.FirstObservedAtNS)
	body.LastObservedAtNS = cloneInt64(body.LastObservedAtNS)
	body.ErrorCode = cloneString(body.ErrorCode)
	return body
}

func cloneBodyChunk(chunk BodyChunk) BodyChunk {
	chunk.DataEnc = cloneBytes(chunk.DataEnc)
	return chunk
}

func cloneStageFinish(finish StageFinish) StageFinish {
	finish.StatusCode = cloneInt(finish.StatusCode)
	finish.ContentLength = cloneInt64(finish.ContentLength)
	finish.ErrorCode = cloneString(finish.ErrorCode)
	if finish.Body != nil {
		body := *finish.Body
		body.SHA256 = cloneBytes(body.SHA256)
		body.FirstObservedAtNS = cloneInt64(body.FirstObservedAtNS)
		body.LastObservedAtNS = cloneInt64(body.LastObservedAtNS)
		if body.Timeline != nil {
			timeline := *body.Timeline
			timeline.FirstEventAtNS = cloneInt64(timeline.FirstEventAtNS)
			timeline.LastEventAtNS = cloneInt64(timeline.LastEventAtNS)
			timeline.DataEnc = cloneBytes(timeline.DataEnc)
			body.Timeline = &timeline
		}
		body.ErrorCode = cloneString(body.ErrorCode)
		finish.Body = &body
	}
	return finish
}

func cloneAuditFinish(finish AuditFinish) AuditFinish {
	finish.StatusCode = cloneInt(finish.StatusCode)
	finish.TTFTNS = cloneInt64(finish.TTFTNS)
	finish.BlockedBy = cloneString(finish.BlockedBy)
	finish.BlockCode = cloneString(finish.BlockCode)
	finish.ErrorCode = cloneString(finish.ErrorCode)
	finish.NewAPIRequestID = cloneString(finish.NewAPIRequestID)
	return finish
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneInt(value *int) *int {
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

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
