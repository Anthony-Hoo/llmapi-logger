package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// The export snapshot of the cold archive (design H.2 step 1 to 2.4). One
// read-only REPEATABLE READ transaction on the reader pool serves a whole
// pass: the selection (B.1), the records, the change stamps and, through
// bundle.Payloads, the content objects, binary objects and raw chunk
// plaintext the bundle writer asks for. It never uses the writer.
//
// The transaction holds one connection, so every query drains its rows
// before the next one starts, and nothing is handed to the caller while rows
// are open.

// Reasons an audit is excluded from an export (ArchiveMemberError.Reason).
// Each is a stable code for logs and counters.
const (
	// ArchiveReasonNotFound: the audit has no audit_records row in the
	// snapshot. Not an integrity failure.
	ArchiveReasonNotFound = "not_found"
	// ArchiveReasonOpen: the audit has not ended; only ended audits are
	// archived (B.1 item 1). Not an integrity failure.
	ArchiveReasonOpen = "open"
	// ArchiveReasonEventMissing: no capture_finalized event, or a turn
	// without a semantic_compacted event (H.3 item 1).
	ArchiveReasonEventMissing = "event_missing"
	// ArchiveReasonEventPayload: an event's payload digest does not re-derive
	// from the stored rows (H.3 item 2).
	ArchiveReasonEventPayload = "event_payload"
	// ArchiveReasonEventMAC: an event's MAC does not verify.
	ArchiveReasonEventMAC = "event_mac"
	// ArchiveReasonDecrypt: a ciphertext column does not authenticate or
	// decode under its AAD (H.2 step 2.3).
	ArchiveReasonDecrypt = "decrypt"
	// ArchiveReasonContentHash: decrypted content does not match its hash:
	// a content or binary object its address or semantic hash, a complete
	// body the SHA-256 body_streams records.
	ArchiveReasonContentHash = "content_hash"
	// ArchiveReasonTurnGraph: the turn's request refs do not rebuild, its
	// sequence hashes or counts differ, or a referenced object is missing.
	ArchiveReasonTurnGraph = "turn_graph"
	// ArchiveReasonTimeline: a decrypted timeline fails the bounds checks of
	// query.Timeline. Not latched as a payload failure.
	ArchiveReasonTimeline = "timeline"
	// ArchiveReasonRawUnservable: body chunks the record cannot carry the
	// way the reader serves them: a chunk of a stage no full body is served
	// from, or chunks that do not run on in seq and offset or disagree with
	// chunk_count or stored_length. Not latched as a payload failure.
	ArchiveReasonRawUnservable = "raw_unservable"
	// ArchiveReasonRecordFormat: the record fails the format's canonical
	// checks. This is a defect, not damage. Not latched.
	ArchiveReasonRecordFormat = "record_format"
)

// ArchiveMemberError excludes one audit from an export. The export of the
// other audits continues (H.4).
type ArchiveMemberError struct {
	AuditID string
	Reason  string
}

func (err *ArchiveMemberError) Error() string {
	return "postgres archive: audit excluded from export: " + err.Reason
}

// Integrity reports whether the exclusion is an integrity failure in the
// sense of H.4 (archive_integrity_failed): the stored evidence does not
// verify. The store's payload state is then failed, as when the background
// payload verification finds a mismatch (P item 4).
func (err *ArchiveMemberError) Integrity() bool {
	switch err.Reason {
	case ArchiveReasonEventMissing, ArchiveReasonEventPayload, ArchiveReasonEventMAC,
		ArchiveReasonDecrypt, ArchiveReasonContentHash, ArchiveReasonTurnGraph:
		return true
	}
	return false
}

// ArchiveSnapshotOptions are what an export needs besides the store: the
// audit cipher and the credential fingerprinter of the projection (D.4),
// security.ArchiveKeys.
type ArchiveSnapshotOptions struct {
	Cipher        security.Cipher
	Fingerprinter archive.CredentialFingerprinter
}

// ArchiveSnapshot is one export snapshot. It is not safe for concurrent use.
type ArchiveSnapshot struct {
	store         *Store
	ctx           context.Context
	tx            *sql.Tx
	cipher        security.Cipher
	fingerprinter archive.CredentialFingerprinter
	signer        *security.IntegritySigner

	// Per conversation, as in the background payload verification: the
	// event digest cache and the request refs memo (H.7).
	conversation string
	cache        *integrityGraphCache
	refs         map[string][]auditmodel.ObjectRef
	// Objects and binaries already decrypted and checked in this snapshot,
	// by hash only; their plaintext is not kept.
	verifiedObjects  map[string]struct{}
	verifiedBinaries map[string]struct{}
	// The audit row's two ciphertext columns between readAuditRow and
	// openAuditColumns.
	pendingURI       []byte
	pendingUserAgent []byte
	closed           bool
}

// archiveVerifiedLimit bounds the verified-object sets; past it they are
// cleared and objects are checked again.
const archiveVerifiedLimit = 1 << 20

// OpenArchiveSnapshot begins an export snapshot. It needs EnableIntegrity to
// have run: every export re-verifies the audit's events. ctx bounds the whole
// snapshot, including the Payloads calls of the bundle writer. Close ends it.
func (store *Store) OpenArchiveSnapshot(ctx context.Context, options ArchiveSnapshotOptions) (*ArchiveSnapshot, error) {
	if err := store.archiveReadable(ctx); err != nil {
		return nil, err
	}
	if options.Cipher == nil || options.Fingerprinter == nil {
		return nil, errors.New("postgres archive: snapshot needs a cipher and a fingerprinter")
	}
	signer := store.integrity.Load()
	if signer == nil {
		return nil, errors.New("postgres archive: integrity is not enabled")
	}
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("postgres archive: begin snapshot: %w", err)
	}
	return &ArchiveSnapshot{
		store: store, ctx: ctx, tx: transaction, cipher: options.Cipher, fingerprinter: options.Fingerprinter, signer: signer,
		cache: newIntegrityGraphCache(), refs: map[string][]auditmodel.ObjectRef{},
		verifiedObjects: map[string]struct{}{}, verifiedBinaries: map[string]struct{}{},
	}, nil
}

// Close ends the snapshot. It is safe to call more than once.
func (snapshot *ArchiveSnapshot) Close() error {
	if snapshot == nil || snapshot.closed {
		return nil
	}
	snapshot.closed = true
	err := snapshot.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return err
}

func (snapshot *ArchiveSnapshot) usable() error {
	if snapshot == nil || snapshot.closed {
		return errors.New("postgres archive: snapshot is closed")
	}
	return snapshot.ctx.Err()
}

// memberFailure turns a failure while exporting auditID into an
// ArchiveMemberError, unless it is a failure of the snapshot itself: a
// cancelled context, a closed store, or a transaction that no longer answers.
// Those end the pass and are returned as they are, so a shutdown is never
// taken for damage. An integrity exclusion latches the payload state failed.
func (snapshot *ArchiveSnapshot) memberFailure(auditID, reason string, cause error) error {
	if cause != nil {
		if err := snapshot.ctx.Err(); err != nil {
			return err
		}
		if snapshot.store.isClosed() {
			return ErrClosed
		}
		var probe int
		if err := snapshot.tx.QueryRowContext(snapshot.ctx, `SELECT 1`).Scan(&probe); err != nil {
			return fmt.Errorf("postgres archive: snapshot failed: %w", cause)
		}
	}
	failure := &ArchiveMemberError{AuditID: auditID, Reason: reason}
	if failure.Integrity() {
		snapshot.store.payloadState.Store(integrityPayloadsFailed)
	}
	return failure
}

// --- Selection (B.1) ---

const archiveCandidateColumns = `
SELECT a.audit_id, a.started_at_ns, a.protocol, t.conversation_id, t.created_at_ns,
       CASE WHEN a.ended_at_ns IS NULL THEN 'open'
            WHEN a.parse_status IN ('pending', 'processing') THEN 'parse_pending'
            WHEN a.caller_status = 'pending' THEN 'caller_pending'
            ELSE '' END,
       EXISTS (SELECT 1 FROM archive_members AS m JOIN archive_segments AS s ON s.segment_id = m.segment_id
               WHERE m.audit_id = a.audit_id AND m.state <> 'stale' AND s.format_version = $1),
       COALESCE((SELECT MAX(m.revision) FROM archive_members AS m WHERE m.audit_id = a.audit_id), 0) + 1
FROM audit_records AS a
LEFT JOIN turns AS t ON t.audit_id = a.audit_id`

func (snapshot *ArchiveSnapshot) queryCandidates(statement string, arguments ...any) ([]ArchiveCandidate, error) {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: select candidates: %w", err)
	}
	var candidates []ArchiveCandidate
	for rows.Next() {
		var candidate ArchiveCandidate
		var conversation sql.NullString
		var created sql.NullInt64
		if err := rows.Scan(&candidate.AuditID, &candidate.StartedAtNS, &candidate.Protocol, &conversation, &created,
			&candidate.Deferral, &candidate.Current, &candidate.NextRevision); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan candidate: %w", err)
		}
		candidate.ConversationID = nullStringPointer(conversation)
		candidate.TurnCreatedAtNS = nullInt64Pointer(created)
		candidates = append(candidates, candidate)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: select candidates: %w", err)
	}
	return candidates, nil
}

// Due pages the audits started before cutoffNS after the watermark (nil:
// from the beginning) in (started_at_ns, audit_id) order along
// audit_records_started_idx, at most limit. Every audit looked at is in the
// page, due or not (B.1: the last one is the new watermark whatever became
// of it). formatVersion is the current archive format version, which decides
// what a current member is (B.1 item 4).
func (snapshot *ArchiveSnapshot) Due(after *ArchivePosition, cutoffNS, formatVersion int64, limit int) (ArchiveDuePage, error) {
	if err := snapshot.usable(); err != nil {
		return ArchiveDuePage{}, err
	}
	if !validArchiveLimit(limit) || formatVersion < 0 {
		return ArchiveDuePage{}, errors.New("postgres archive: invalid selection")
	}
	afterStarted, afterAudit := int64(-1<<63), ""
	if after != nil {
		afterStarted, afterAudit = after.StartedAtNS, after.AuditID
	}
	candidates, err := snapshot.queryCandidates(archiveCandidateColumns+`
WHERE (a.started_at_ns, a.audit_id) > ($2, $3) AND a.started_at_ns < $4
ORDER BY a.started_at_ns, a.audit_id
LIMIT $5`, formatVersion, afterStarted, afterAudit, cutoffNS, limit+1)
	if err != nil {
		return ArchiveDuePage{}, err
	}
	page := ArchiveDuePage{Candidates: candidates}
	if len(candidates) > limit {
		page.Candidates, page.More = candidates[:limit], true
	}
	if count := len(page.Candidates); count > 0 {
		last := page.Candidates[count-1]
		page.Last = &ArchivePosition{StartedAtNS: last.StartedAtNS, AuditID: last.AuditID}
	}
	return page, nil
}

// Candidates looks at the given audits again: the deferred ones, or members
// to re-include. An audit that is no longer in the hot store is left out of
// the result.
func (snapshot *ArchiveSnapshot) Candidates(auditIDs []string, formatVersion int64) ([]ArchiveCandidate, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	var result []ArchiveCandidate
	for start := 0; start < len(auditIDs); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(auditIDs))
		arguments := append([]any{formatVersion}, stringsToAny(auditIDs[start:end])...)
		candidates, err := snapshot.queryCandidates(archiveCandidateColumns+`
WHERE a.audit_id IN (`+placeholders(end-start, 1)+`)
ORDER BY a.started_at_ns, a.audit_id`, arguments...)
		if err != nil {
			return nil, err
		}
		result = append(result, candidates...)
	}
	return result, nil
}

// ConversationCandidates returns every audit started before cutoffNS whose
// turn belongs to one of the conversations, in (conversation_id,
// turns.created_at_ns, audit_id) order, so that a pass can complete the
// conversations it touches (B.2). The watermark does not limit it.
func (snapshot *ArchiveSnapshot) ConversationCandidates(conversationIDs []string, cutoffNS, formatVersion int64) ([]ArchiveCandidate, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	var result []ArchiveCandidate
	for start := 0; start < len(conversationIDs); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(conversationIDs))
		arguments := append([]any{formatVersion, cutoffNS}, stringsToAny(conversationIDs[start:end])...)
		candidates, err := snapshot.queryCandidates(archiveCandidateColumns+`
WHERE t.conversation_id IN (`+placeholders(end-start, 2)+`) AND a.started_at_ns < $2
ORDER BY t.conversation_id, t.created_at_ns, a.audit_id`, arguments...)
		if err != nil {
			return nil, err
		}
		result = append(result, candidates...)
	}
	return result, nil
}

// StaleCandidates returns the audits that have a stale member, are still in
// the hot store, started before cutoffNS and have no current member (B.1,
// the part a run looks back at), in audit_id order after after, at most limit.
func (snapshot *ArchiveSnapshot) StaleCandidates(cutoffNS, formatVersion int64, after string, limit int) ([]ArchiveCandidate, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	if !validArchiveLimit(limit) {
		return nil, errors.New("postgres archive: invalid selection")
	}
	return snapshot.queryCandidates(archiveCandidateColumns+`
WHERE a.audit_id IN (SELECT DISTINCT audit_id FROM archive_members WHERE state = 'stale')
  AND NOT EXISTS (SELECT 1 FROM archive_members AS c JOIN archive_segments AS s ON s.segment_id = c.segment_id
                  WHERE c.audit_id = a.audit_id AND c.state <> 'stale' AND s.format_version = $1)
  AND a.started_at_ns < $2 AND a.audit_id > $3
ORDER BY a.audit_id
LIMIT $4`, formatVersion, cutoffNS, after, limit)
}

// --- Export ---

// ArchiveExport is one exported audit: the canonical, materialised record
// (bundle.SegmentWriter.Add takes it as it is), its record digest, the change
// stamp of M.1 computed in the same snapshot and turns.created_at_ns, nil for
// an audit without a turn.
type ArchiveExport struct {
	Record          *archive.Record
	Digest          [32]byte
	ChangeStamp     [32]byte
	TurnCreatedAtNS *int64
}

// Export reads one audit into an archive record with the given revision.
// It re-verifies the audit's integrity events (H.3), decrypts and checks
// every ciphertext the record and its payloads need (H.2 step 2.3), and
// computes the change stamp. A failure that concerns this audit alone is an
// *ArchiveMemberError and the snapshot stays usable; any other error is a
// failure of the snapshot.
//
// The caller exports a pass's audits in segment order (B.3): the event
// cache and request refs memo are kept per conversation and reset when the
// conversation changes.
func (snapshot *ArchiveSnapshot) Export(auditID string, revision int64) (*ArchiveExport, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	if auditID == "" || revision < 1 {
		return nil, errors.New("postgres archive: invalid export")
	}
	record := &archive.Record{Revision: revision}
	found, ended, err := snapshot.readAuditRow(auditID, record)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonNotFound, nil)
	}
	if !ended {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonOpen, nil)
	}
	turnRow, err := snapshot.readTurnRow(auditID)
	if err != nil {
		return nil, err
	}
	conversation := ""
	if turnRow != nil {
		conversation = turnRow.ConversationID
	}
	if conversation != snapshot.conversation || conversation == "" {
		snapshot.conversation = conversation
		snapshot.cache.reset()
		clear(snapshot.refs)
	}
	if record.IntegrityEvents, err = snapshot.reverifyArchiveEvents(auditID, turnRow != nil); err != nil {
		return nil, err
	}
	if err := snapshot.openAuditColumns(auditID, record); err != nil {
		return nil, err
	}
	if err := snapshot.readStages(auditID, record); err != nil {
		return nil, err
	}
	if err := snapshot.readHeaders(auditID, record); err != nil {
		return nil, err
	}
	if record.Bodies, err = readBodies(snapshot.ctx, snapshot.tx, auditID); err != nil {
		return nil, err
	}
	if err := snapshot.readRawChunks(auditID, record); err != nil {
		return nil, err
	}
	if err := snapshot.readTimelines(auditID, record); err != nil {
		return nil, err
	}
	if err := snapshot.readParsedResult(auditID, record); err != nil {
		return nil, err
	}
	if err := snapshot.readTokenLink(auditID, record); err != nil {
		return nil, err
	}
	if turnRow != nil {
		if err := snapshot.readTurn(auditID, *turnRow, record); err != nil {
			return nil, err
		}
		if err := snapshot.readConversation(auditID, turnRow.ConversationID, record); err != nil {
			return nil, err
		}
	}
	if err := snapshot.readProjectIdentity(auditID, record); err != nil {
		return nil, err
	}
	if err := record.Canonicalize(); err != nil {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonRecordFormat, nil)
	}
	if err := checkArchiveRawLayout(record); err != nil {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonRawUnservable, nil)
	}
	if err := checkArchiveTimelines(record); err != nil {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonTimeline, nil)
	}
	digest, err := archive.Digest(record)
	if err != nil {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonRecordFormat, nil)
	}
	stamp, exists, err := archiveChangeStamp(snapshot.ctx, snapshot.tx, auditID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("postgres archive: audit vanished inside the snapshot")
	}
	export := &ArchiveExport{Record: record, Digest: digest, ChangeStamp: stamp}
	if turnRow != nil {
		created := turnRow.CreatedAtNS
		export.TurnCreatedAtNS = &created
	}
	return export, nil
}

// readAuditRow reads every audit_records column. The two ciphertext columns
// are kept on the side for openAuditColumns.
func (snapshot *ArchiveSnapshot) readAuditRow(auditID string, record *archive.Record) (found, ended bool, err error) {
	audit := &record.Audit
	var endedAt, statusCode, ttft, callerNext, callerUpdated, parseNext sql.NullInt64
	var blockedBy, blockCode, errorCode, requestID sql.NullString
	err = snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT audit_id, schema_generation, started_at_ns, ended_at_ns, route_id, protocol, parser_name,
       method, path, request_uri_enc, mode, status_code, ttft_ns, forward_status, capture_status,
       parse_status, blocked_by, block_code, error_code, newapi_request_id, caller_status,
       caller_attempts, caller_next_at_ns, caller_updated_at_ns, api_key_fpr, parse_save_failures,
       parse_next_at_ns, capture_version, user_agent_enc
FROM audit_records WHERE audit_id = $1`, auditID).Scan(
		&audit.AuditID, &audit.SchemaGeneration, &audit.StartedAtNS, &endedAt, &audit.RouteID, &audit.Protocol,
		&audit.ParserName, &audit.Method, &audit.Path, &snapshot.pendingURI, &audit.Mode, &statusCode, &ttft,
		&audit.ForwardStatus, &audit.CaptureStatus, &audit.ParseStatus, &blockedBy, &blockCode, &errorCode,
		&requestID, &audit.CallerStatus, &audit.CallerAttempts, &callerNext, &callerUpdated, &audit.APIKeyFPR,
		&audit.ParseSaveFailures, &parseNext, &audit.CaptureVersion, &snapshot.pendingUserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("postgres archive: read audit: %w", err)
	}
	audit.APIKeyFPR = cloneBytes(audit.APIKeyFPR)
	snapshot.pendingURI = cloneBytes(snapshot.pendingURI)
	snapshot.pendingUserAgent = cloneBytes(snapshot.pendingUserAgent)
	if !endedAt.Valid {
		return true, false, nil
	}
	audit.EndedAtNS = endedAt.Int64
	audit.StatusCode, audit.TTFTNS = nullInt64Pointer(statusCode), nullInt64Pointer(ttft)
	audit.BlockedBy, audit.BlockCode = nullStringPointer(blockedBy), nullStringPointer(blockCode)
	audit.ErrorCode, audit.NewAPIRequestID = nullStringPointer(errorCode), nullStringPointer(requestID)
	audit.CallerNextAtNS, audit.CallerUpdatedAtNS = nullInt64Pointer(callerNext), nullInt64Pointer(callerUpdated)
	audit.ParseNextAtNS = nullInt64Pointer(parseNext)
	return true, true, nil
}

// openAuditColumns opens request_uri_enc and user_agent_enc and projects
// them (D.3). The plaintext is cleared once projected.
func (snapshot *ArchiveSnapshot) openAuditColumns(auditID string, record *archive.Record) error {
	uriEnc, userAgentEnc := snapshot.pendingURI, snapshot.pendingUserAgent
	snapshot.pendingURI, snapshot.pendingUserAgent = nil, nil
	aad, err := security.AAD(auditID, "request_uri")
	if err != nil {
		return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	uri, err := snapshot.cipher.Decrypt(aad, uriEnc)
	if err != nil {
		return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	record.Audit.RequestURI = archive.ProjectRequestURI(snapshot.fingerprinter, uri)
	clear(uri)
	if userAgentEnc == nil {
		return nil
	}
	values, err := headerblock.OpenUserAgent(snapshot.cipher, auditID, userAgentEnc)
	if err != nil {
		return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	if values == nil {
		values = []string{}
	}
	record.Audit.UserAgent = archive.ProjectUserAgent(snapshot.fingerprinter, values)
	return nil
}

func (snapshot *ArchiveSnapshot) readStages(auditID string, record *archive.Record) error {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT stage, state, proto, method, host, status_code, content_length, started_at_ns,
       ended_at_ns, error_code, content_type, content_encoding
FROM http_stages WHERE audit_id = $1 ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return fmt.Errorf("postgres archive: read stages: %w", err)
	}
	record.Stages = []archive.Stage{}
	for rows.Next() {
		stage := archive.Stage{HTTPStage: storage.HTTPStage{AuditID: auditID}}
		var statusCode, contentLength, endedAt sql.NullInt64
		var errorCode, contentType, contentEncoding sql.NullString
		if err := rows.Scan(&stage.Stage, &stage.State, &stage.Proto, &stage.Method, &stage.Host, &statusCode,
			&contentLength, &stage.StartedAtNS, &endedAt, &errorCode, &contentType, &contentEncoding); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres archive: scan stage: %w", err)
		}
		stage.StatusCode, stage.ContentLength = nullIntPointer(statusCode), nullInt64Pointer(contentLength)
		stage.EndedAtNS, stage.ErrorCode = nullInt64Pointer(endedAt), nullStringPointer(errorCode)
		stage.ContentType, stage.ContentEncoding = nullStringPointer(contentType), nullStringPointer(contentEncoding)
		record.Stages = append(record.Stages, stage)
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres archive: read stages: %w", err)
	}
	return nil
}

// readHeaders expands the saved Headers through headerblock.Expand, with the
// same HeaderSource the query service builds, and projects every value. For
// version 2 it also opens the block to list the stages that have a section.
func (snapshot *ArchiveSnapshot) readHeaders(auditID string, record *archive.Record) error {
	rows, err := readHeaderEvidence(snapshot.ctx, snapshot.tx, auditID)
	if err != nil {
		return err
	}
	block, err := readHeaderBlockEvidence(snapshot.ctx, snapshot.tx, auditID)
	if err != nil {
		return err
	}
	stageSet := make([]string, 0, len(record.Stages))
	for _, stage := range record.Stages {
		stageSet = append(stageSet, stage.Stage)
	}
	source := storage.HeaderSource{
		CaptureVersion: int(record.Audit.CaptureVersion), Rows: rows, Block: block, StageSet: stageSet,
		CaptureFailed: record.Audit.CaptureStatus == CaptureFailed, Interrupted: record.Audit.ForwardStatus == ForwardInterrupted,
	}
	values, err := headerblock.Expand(snapshot.cipher, auditID, source)
	if err != nil {
		return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	headers := archive.Headers{CaptureVersion: record.Audit.CaptureVersion, Values: archive.ProjectHeaders(snapshot.fingerprinter, values)}
	for _, value := range values {
		clear(value.Value)
	}
	if record.Audit.CaptureVersion == CaptureVersion2 && block != nil {
		stages, err := headerblock.OpenBlock(snapshot.cipher, auditID, *block)
		if err != nil {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		headers.BlockPresent = true
		headers.BlockStages = headerblock.StageNames(stages)
		for _, stage := range stages {
			for _, fields := range [2][]headerblock.Field{stage.Headers, stage.Trailers} {
				for _, field := range fields {
					for _, value := range field.Values {
						clear(value)
					}
				}
			}
		}
	}
	record.Headers = headers
	return nil
}

// chunkMeta is one body_chunks row without its ciphertext.
type chunkMeta struct {
	stage           string
	seq             int64
	offset          int64
	plaintextLength int64
	encodedLength   int64
	observedAtNS    int64
	compression     string
}

// readRawChunks lists the audit's chunks, then decrypts them one at a time
// to record each one's SHA-256, and checks the SHA-256 of every complete body
// with full retention against the chunks of its source stage. No chunk
// plaintext is kept: the bundle writer asks for it again (RawChunk).
func (snapshot *ArchiveSnapshot) readRawChunks(auditID string, record *archive.Record) error {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT stage, seq, "offset", plaintext_length, encoded_length, observed_at_ns, compression
FROM body_chunks WHERE audit_id = $1 ORDER BY `+stageOrderSQL+`, seq`, auditID)
	if err != nil {
		return fmt.Errorf("postgres archive: read chunks: %w", err)
	}
	var chunks []chunkMeta
	for rows.Next() {
		var chunk chunkMeta
		if err := rows.Scan(&chunk.stage, &chunk.seq, &chunk.offset, &chunk.plaintextLength, &chunk.encodedLength, &chunk.observedAtNS, &chunk.compression); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres archive: scan chunk: %w", err)
		}
		chunks = append(chunks, chunk)
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres archive: read chunks: %w", err)
	}
	streams := map[string]hash.Hash{}
	record.RawChunks = make([]archive.RawChunk, 0, len(chunks))
	for _, chunk := range chunks {
		plaintext, err := snapshot.openChunk(auditID, chunk)
		if err != nil {
			return err
		}
		stream := streams[chunk.stage]
		if stream == nil {
			stream = sha256.New()
			streams[chunk.stage] = stream
		}
		stream.Write(plaintext)
		record.RawChunks = append(record.RawChunks, archive.RawChunk{
			Stage: chunk.stage, Seq: chunk.seq, Offset: chunk.offset, PlaintextLength: chunk.plaintextLength,
			ObservedAtNS: chunk.observedAtNS, SHA256: sha256.Sum256(plaintext),
		})
		clear(plaintext)
	}
	for index := range record.Bodies {
		body := &record.Bodies[index]
		body.AuditID = auditID
		complete := body.State == StageStateComplete && body.HashComplete && body.EOFSeen && body.StoredLength == body.ObservedLength
		if body.RetentionState != RetentionFull || !complete {
			continue
		}
		digest := sha256.New().Sum(nil)
		if stream := streams[body.SourceStage]; stream != nil {
			digest = stream.Sum(nil)
		}
		if !bytes.Equal(digest, body.SHA256) {
			return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
		}
	}
	return nil
}

// openChunk fetches and opens one chunk as query.StreamRaw does: the
// body_chunk_v2 AAD, the legacy body_chunk AAD for an uncompressed chunk,
// the encoded length check, then decompression to the plaintext length.
func (snapshot *ArchiveSnapshot) openChunk(auditID string, chunk chunkMeta) ([]byte, error) {
	var dataEnc []byte
	if err := snapshot.tx.QueryRowContext(snapshot.ctx, `SELECT data_enc FROM body_chunks WHERE audit_id = $1 AND stage = $2 AND seq = $3`,
		auditID, chunk.stage, chunk.seq).Scan(&dataEnc); err != nil {
		return nil, fmt.Errorf("postgres archive: read chunk: %w", err)
	}
	compression := chunk.compression
	if compression == "" {
		compression = bodycodec.CompressionNone
	}
	sequence := strconv.FormatInt(chunk.seq, 10)
	aad, err := security.AAD(auditID, "body_chunk_v2", chunk.stage, sequence, compression)
	if err != nil {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	encoded, err := snapshot.cipher.Decrypt(aad, dataEnc)
	if err != nil && compression == bodycodec.CompressionNone {
		if legacy, legacyErr := security.AAD(auditID, "body_chunk", chunk.stage, sequence); legacyErr == nil {
			encoded, err = snapshot.cipher.Decrypt(legacy, dataEnc)
		}
	}
	if err != nil || chunk.encodedLength > 0 && int64(len(encoded)) != chunk.encodedLength {
		clear(encoded)
		return nil, snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	plaintext, err := bodycodec.Decode(encoded, compression, int(chunk.plaintextLength))
	clear(encoded)
	if err != nil || int64(len(plaintext)) != chunk.plaintextLength {
		clear(plaintext)
		return nil, snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
	}
	if plaintext == nil {
		plaintext = []byte{}
	}
	return plaintext, nil
}

func (snapshot *ArchiveSnapshot) readTimelines(auditID string, record *archive.Record) error {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT stage, event_count, first_event_at_ns, last_event_at_ns, timeline_complete, compression,
       plaintext_length, timeline_enc
FROM stream_timelines WHERE audit_id = $1 ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return fmt.Errorf("postgres archive: read timelines: %w", err)
	}
	type sealedTimeline struct {
		timeline    archive.Timeline
		compression string
		enc         []byte
	}
	var sealed []sealedTimeline
	for rows.Next() {
		var row sealedTimeline
		var first, last sql.NullInt64
		var complete int64
		if err := rows.Scan(&row.timeline.Stage, &row.timeline.EventCount, &first, &last, &complete, &row.compression,
			&row.timeline.PlaintextLength, &row.enc); err != nil {
			_ = rows.Close()
			return fmt.Errorf("postgres archive: scan timeline: %w", err)
		}
		row.timeline.FirstEventAtNS, row.timeline.LastEventAtNS = nullInt64Pointer(first), nullInt64Pointer(last)
		row.timeline.Complete = complete != 0
		row.enc = cloneBytes(row.enc)
		sealed = append(sealed, row)
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("postgres archive: read timelines: %w", err)
	}
	record.Timelines = make([]archive.Timeline, 0, len(sealed))
	for _, row := range sealed {
		timeline := row.timeline
		if row.enc != nil {
			aad, err := security.AAD(auditID, "stream_timeline_v1", timeline.Stage, row.compression)
			if err != nil {
				return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
			}
			encoded, err := snapshot.cipher.Decrypt(aad, row.enc)
			if err != nil {
				return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
			}
			plaintext, err := bodycodec.Decode(encoded, row.compression, int(timeline.PlaintextLength))
			clear(encoded)
			if err != nil || int64(len(plaintext)) != timeline.PlaintextLength {
				return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
			}
			if plaintext == nil {
				plaintext = []byte{}
			}
			timeline.Plaintext = plaintext
		}
		record.Timelines = append(record.Timelines, timeline)
	}
	return nil
}

func (snapshot *ArchiveSnapshot) readParsedResult(auditID string, record *archive.Record) error {
	var parsed archive.ParsedResult
	var requestModel, responseModel, responseID, errorType, errorCode, upstream sql.NullString
	var requestedStream, observedStream, hasToolCall, usageInput, usageOutput, usageTotal, messages, tools sql.NullInt64
	var enc []byte
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT parser_name, parser_version, status, request_model, response_model, requested_stream,
       observed_stream, response_id, usage_input, usage_output, usage_total, error_type, error_code,
       upstream_error_class, message_count, tool_call_count, has_tool_call, parsed_json_enc, parsed_at_ns
FROM parsed_results WHERE audit_id = $1`, auditID).Scan(
		&parsed.ParserName, &parsed.ParserVersion, &parsed.Status, &requestModel, &responseModel, &requestedStream,
		&observedStream, &responseID, &usageInput, &usageOutput, &usageTotal, &errorType, &errorCode,
		&upstream, &messages, &tools, &hasToolCall, &enc, &parsed.ParsedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres archive: read parsed result: %w", err)
	}
	parsed.RequestModel, parsed.ResponseModel, parsed.ResponseID = nullStringPointer(requestModel), nullStringPointer(responseModel), nullStringPointer(responseID)
	parsed.RequestedStream, parsed.ObservedStream, parsed.HasToolCall = nullBoolPointer(requestedStream), nullBoolPointer(observedStream), nullBoolPointer(hasToolCall)
	parsed.UsageInput, parsed.UsageOutput, parsed.UsageTotal = nullInt64Pointer(usageInput), nullInt64Pointer(usageOutput), nullInt64Pointer(usageTotal)
	parsed.ErrorType, parsed.ErrorCode, parsed.UpstreamErrorClass = nullStringPointer(errorType), nullStringPointer(errorCode), nullStringPointer(upstream)
	parsed.MessageCount, parsed.ToolCallCount = nullInt64Pointer(messages), nullInt64Pointer(tools)
	// An empty parsed_json_enc is exported as NULL (R.4 item 6): the query
	// layer treats a present but empty value as an integrity error.
	if len(enc) > 0 {
		plaintext, err := auditmodel.OpenParsedResult(snapshot.cipher, auditID, parsed.ParserName, enc)
		if err != nil {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		if plaintext == nil {
			plaintext = []byte{}
		}
		parsed.ParsedJSON = plaintext
	}
	record.ParsedResult = &parsed
	return nil
}

func (snapshot *ArchiveSnapshot) readTokenLink(auditID string, record *archive.Record) error {
	var link archive.TokenLink
	var quota, prompt, completion sql.NullInt64
	var quotaPerUnit sql.NullFloat64
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT newapi_user_id, username, newapi_token_id, token_name, linked_at_ns, billing_state, quota,
       quota_per_unit, billed_prompt_tokens, billed_completion_tokens, billing_attempts
FROM token_links WHERE audit_id = $1`, auditID).Scan(&link.NewAPIUserID, &link.Username, &link.NewAPITokenID,
		&link.TokenName, &link.LinkedAtNS, &link.BillingState, &quota, &quotaPerUnit, &prompt, &completion, &link.BillingAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres archive: read token link: %w", err)
	}
	link.Quota, link.BilledPromptTokens, link.BilledCompletionTokens = nullInt64Pointer(quota), nullInt64Pointer(prompt), nullInt64Pointer(completion)
	if quotaPerUnit.Valid {
		value := quotaPerUnit.Float64
		link.QuotaPerUnit = &value
	}
	record.TokenLink = &link
	return nil
}

func (snapshot *ArchiveSnapshot) readTurnRow(auditID string) (*archive.TurnRow, error) {
	var row archive.TurnRow
	var parent, previous, response sql.NullString
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT turn_id, conversation_id, parent_turn_id, parent_base, link_reason, link_confidence,
       request_layout, response_layout, request_envelope_hash, response_envelope_hash,
       request_item_count, response_item_count, request_sequence_hash, response_sequence_hash,
       request_reconstruction_hash, response_reconstruction_hash, reconstruction_status,
       previous_response_id, response_id, created_at_ns
FROM turns WHERE audit_id = $1`, auditID).Scan(&row.TurnID, &row.ConversationID, &parent, &row.ParentBase,
		&row.LinkReason, &row.LinkConfidence, &row.RequestLayout, &row.ResponseLayout, &row.RequestEnvelopeHash,
		&row.ResponseEnvelopeHash, &row.RequestItemCount, &row.ResponseItemCount, &row.RequestSequenceHash,
		&row.ResponseSequenceHash, &row.RequestReconstructionHash, &row.ResponseReconstructionHash,
		&row.ReconstructionStatus, &previous, &response, &row.CreatedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read turn: %w", err)
	}
	row.ParentTurnID, row.PreviousResponseID, row.ResponseID = nullStringPointer(parent), nullStringPointer(previous), nullStringPointer(response)
	for _, value := range []*[]byte{&row.RequestEnvelopeHash, &row.ResponseEnvelopeHash, &row.RequestSequenceHash,
		&row.ResponseSequenceHash, &row.RequestReconstructionHash, &row.ResponseReconstructionHash} {
		*value = cloneBytes(*value)
	}
	return &row, nil
}

// readTurn fills the turn: the stored context operations in delta form, the
// materialised request refs (loadRequestRefs, as readTurnGraph), the
// response items, and every object, binary and reference row the turn
// reaches, each object and binary decrypted and checked once per snapshot.
func (snapshot *ArchiveSnapshot) readTurn(auditID string, row archive.TurnRow, record *archive.Record) error {
	turn := &archive.Turn{Row: row, Context: archive.RequestContext{Form: archive.ContextDelta}}
	ops, err := snapshot.readContextOps(row.TurnID)
	if err != nil {
		return err
	}
	turn.Context.Ops = ops
	refs, err := loadRequestRefs(snapshot.tx, row.TurnID, snapshot.refs, make(map[string]bool))
	if err != nil {
		return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, err)
	}
	if refs == nil {
		refs = []auditmodel.ObjectRef{}
	}
	turn.RequestRefs = refs
	if turn.ResponseItems, err = snapshot.readResponseItems(row.TurnID); err != nil {
		return err
	}
	responseRefs := turn.ResponseRefs()
	if int64(len(refs)) != row.RequestItemCount || int64(len(responseRefs)) != row.ResponseItemCount ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(refs), row.RequestSequenceHash) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(responseRefs), row.ResponseSequenceHash) {
		return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, nil)
	}
	hashes := [][]byte{row.RequestEnvelopeHash, row.ResponseEnvelopeHash}
	for _, ref := range refs {
		hashes = append(hashes, ref.ObjectHash)
	}
	for _, ref := range responseRefs {
		hashes = append(hashes, ref.ObjectHash)
	}
	unique := uniqueHashes(hashes)
	if turn.Objects, err = snapshot.readObjectMetas(unique); err != nil {
		return err
	}
	if len(turn.Objects) != len(unique) {
		return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, nil)
	}
	semantic := make(map[string][]byte, len(turn.Objects))
	for _, object := range turn.Objects {
		semantic[string(object.Hash)] = object.SemanticHash
	}
	for _, ref := range append(append([]auditmodel.ObjectRef(nil), refs...), responseRefs...) {
		if !bytes.Equal(semantic[string(ref.ObjectHash)], ref.SemanticHash) {
			return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, nil)
		}
	}
	for _, object := range turn.Objects {
		if err := snapshot.verifyObject(auditID, object); err != nil {
			return err
		}
	}
	if turn.BinaryRefs, err = snapshot.readBinaryRefs(unique); err != nil {
		return err
	}
	if turn.ExternalRefs, err = snapshot.readExternalRefs(auditID, unique); err != nil {
		return err
	}
	binaryHashes := make([][]byte, 0, len(turn.BinaryRefs))
	for _, ref := range turn.BinaryRefs {
		binaryHashes = append(binaryHashes, ref.BinaryHash)
	}
	uniqueBinaries := uniqueHashes(binaryHashes)
	if turn.Binaries, err = snapshot.readBinaryMetas(uniqueBinaries); err != nil {
		return err
	}
	if len(turn.Binaries) != len(uniqueBinaries) {
		return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, nil)
	}
	for _, binary := range turn.Binaries {
		if err := snapshot.verifyBinary(auditID, binary); err != nil {
			return err
		}
	}
	record.Turn = turn
	return nil
}

func (snapshot *ArchiveSnapshot) readContextOps(turnID string) ([]archive.ContextOp, error) {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT op_index, operation, item_count, slot, object_hash, semantic_hash
FROM turn_context_ops WHERE turn_id = $1 ORDER BY op_index`, turnID)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read context operations: %w", err)
	}
	ops := []archive.ContextOp{}
	for rows.Next() {
		var op archive.ContextOp
		var slot sql.NullString
		if err := rows.Scan(&op.OpIndex, &op.Operation, &op.ItemCount, &slot, &op.ObjectHash, &op.SemanticHash); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan context operation: %w", err)
		}
		op.Slot, op.ObjectHash, op.SemanticHash = nullStringPointer(slot), cloneBytes(op.ObjectHash), cloneBytes(op.SemanticHash)
		ops = append(ops, op)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: read context operations: %w", err)
	}
	return ops, nil
}

func (snapshot *ArchiveSnapshot) readResponseItems(turnID string) ([]archive.ResponseItem, error) {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT ordinal, slot, object_hash, semantic_hash FROM turn_response_items WHERE turn_id = $1 ORDER BY ordinal`, turnID)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read response items: %w", err)
	}
	items := []archive.ResponseItem{}
	for rows.Next() {
		var item archive.ResponseItem
		if err := rows.Scan(&item.Ordinal, &item.Slot, &item.ObjectHash, &item.SemanticHash); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan response item: %w", err)
		}
		item.ObjectHash, item.SemanticHash = cloneBytes(item.ObjectHash), cloneBytes(item.SemanticHash)
		items = append(items, item)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: read response items: %w", err)
	}
	return items, nil
}

func (snapshot *ArchiveSnapshot) readObjectMetas(hashes [][]byte) ([]archive.ObjectMeta, error) {
	objects := []archive.ObjectMeta{}
	for start := 0; start < len(hashes); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(hashes))
		rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT object_hash, semantic_hash, kind, plaintext_length FROM content_objects
WHERE object_hash IN (`+placeholders(end-start)+`) ORDER BY object_hash`, bytesToAny(hashes[start:end])...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read content object metadata: %w", err)
		}
		for rows.Next() {
			var object archive.ObjectMeta
			if err := rows.Scan(&object.Hash, &object.SemanticHash, &object.Kind, &object.PlaintextLength); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan content object metadata: %w", err)
			}
			object.Hash, object.SemanticHash = cloneBytes(object.Hash), cloneBytes(object.SemanticHash)
			objects = append(objects, object)
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read content object metadata: %w", err)
		}
	}
	return objects, nil
}

func (snapshot *ArchiveSnapshot) readBinaryMetas(hashes [][]byte) ([]archive.BinaryMeta, error) {
	binaries := []archive.BinaryMeta{}
	for start := 0; start < len(hashes); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(hashes))
		rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT binary_hash, media_type, plaintext_length FROM binary_objects
WHERE binary_hash IN (`+placeholders(end-start)+`) ORDER BY binary_hash`, bytesToAny(hashes[start:end])...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read binary object metadata: %w", err)
		}
		for rows.Next() {
			var binary archive.BinaryMeta
			if err := rows.Scan(&binary.Hash, &binary.MediaType, &binary.PlaintextLength); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan binary object metadata: %w", err)
			}
			binary.Hash = cloneBytes(binary.Hash)
			binaries = append(binaries, binary)
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read binary object metadata: %w", err)
		}
	}
	return binaries, nil
}

func (snapshot *ArchiveSnapshot) readBinaryRefs(objectHashes [][]byte) ([]archive.BinaryRef, error) {
	refs := []archive.BinaryRef{}
	for start := 0; start < len(objectHashes); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(objectHashes))
		rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT object_hash, json_pointer, binary_hash, media_type, encoding FROM content_binary_refs
WHERE object_hash IN (`+placeholders(end-start)+`)`, bytesToAny(objectHashes[start:end])...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read binary refs: %w", err)
		}
		for rows.Next() {
			var ref archive.BinaryRef
			if err := rows.Scan(&ref.ObjectHash, &ref.JSONPointer, &ref.BinaryHash, &ref.MediaType, &ref.Encoding); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan binary ref: %w", err)
			}
			ref.ObjectHash, ref.BinaryHash = cloneBytes(ref.ObjectHash), cloneBytes(ref.BinaryHash)
			refs = append(refs, ref)
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read binary refs: %w", err)
		}
	}
	return refs, nil
}

func (snapshot *ArchiveSnapshot) readExternalRefs(auditID string, objectHashes [][]byte) ([]archive.ExternalRef, error) {
	type sealedRef struct {
		ref archive.ExternalRef
		enc []byte
	}
	var sealed []sealedRef
	for start := 0; start < len(objectHashes); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(objectHashes))
		rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT object_hash, json_pointer, ref_kind, value_hash, value_enc FROM content_external_refs
WHERE object_hash IN (`+placeholders(end-start)+`)`, bytesToAny(objectHashes[start:end])...)
		if err != nil {
			return nil, fmt.Errorf("postgres archive: read external refs: %w", err)
		}
		for rows.Next() {
			var row sealedRef
			if err := rows.Scan(&row.ref.ObjectHash, &row.ref.JSONPointer, &row.ref.RefKind, &row.ref.ValueHash, &row.enc); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres archive: scan external ref: %w", err)
			}
			row.ref.ObjectHash, row.ref.ValueHash, row.enc = cloneBytes(row.ref.ObjectHash), cloneBytes(row.ref.ValueHash), cloneBytes(row.enc)
			sealed = append(sealed, row)
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("postgres archive: read external refs: %w", err)
		}
	}
	refs := make([]archive.ExternalRef, 0, len(sealed))
	for _, row := range sealed {
		value, err := auditmodel.OpenExternalReference(snapshot.cipher, row.ref.ObjectHash, row.ref.JSONPointer, row.ref.RefKind, row.ref.ValueHash, row.enc)
		if err != nil {
			return nil, snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		row.ref.Value = value
		refs = append(refs, row.ref)
	}
	return refs, nil
}

// verifyObject decrypts one content object and checks it as the bundle
// reader will: address, length, schema version, kind and semantic hash.
func (snapshot *ArchiveSnapshot) verifyObject(auditID string, meta archive.ObjectMeta) error {
	key := string(meta.Hash)
	if _, ok := snapshot.verifiedObjects[key]; ok {
		return nil
	}
	object, err := snapshot.openContentObject(meta.Hash)
	if err != nil {
		if errors.Is(err, auditmodel.ErrIntegrity) {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		return err
	}
	defer clear(object.Data)
	if !bytes.Equal(object.SemanticHash, meta.SemanticHash) || object.Kind != meta.Kind || object.PlaintextLength != meta.PlaintextLength {
		return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
	}
	var decoded auditmodel.DecodedObject
	if err := auditmodel.DecodeJSON(object.Data, &decoded); err != nil || decoded.SchemaVersion != auditmodel.SchemaVersion || decoded.Kind != object.Kind {
		return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
	}
	semantic := object.Hash
	if decoded.Kind != "request_envelope" && decoded.Kind != "response_envelope" {
		if semantic, err = auditmodel.SemanticHash(decoded.Kind, decoded.Value); err != nil {
			return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
		}
	}
	if !auditmodel.EqualHash(semantic, object.SemanticHash) {
		return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
	}
	if len(snapshot.verifiedObjects) >= archiveVerifiedLimit {
		clear(snapshot.verifiedObjects)
	}
	snapshot.verifiedObjects[key] = struct{}{}
	return nil
}

func (snapshot *ArchiveSnapshot) verifyBinary(auditID string, meta archive.BinaryMeta) error {
	key := string(meta.Hash)
	if _, ok := snapshot.verifiedBinaries[key]; ok {
		return nil
	}
	binary, err := snapshot.openBinaryObject(meta.Hash)
	if err != nil {
		if errors.Is(err, auditmodel.ErrIntegrity) {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		return err
	}
	clear(binary.Data)
	if binary.MediaType != meta.MediaType || binary.PlaintextLength != meta.PlaintextLength {
		return snapshot.memberFailure(auditID, ArchiveReasonContentHash, nil)
	}
	if len(snapshot.verifiedBinaries) >= archiveVerifiedLimit {
		clear(snapshot.verifiedBinaries)
	}
	snapshot.verifiedBinaries[key] = struct{}{}
	return nil
}

func (snapshot *ArchiveSnapshot) readConversation(auditID, conversationID string, record *archive.Record) error {
	conversation := archive.Conversation{}
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT conversation_id, protocol, key_hash, created_at_ns FROM conversations WHERE conversation_id = $1`, conversationID).Scan(
		&conversation.ConversationID, &conversation.Protocol, &conversation.KeyHash, &conversation.CreatedAtNS)
	if errors.Is(err, sql.ErrNoRows) {
		// turns.conversation_id references conversations with RESTRICT.
		return snapshot.memberFailure(auditID, ArchiveReasonTurnGraph, nil)
	}
	if err != nil {
		return fmt.Errorf("postgres archive: read conversation: %w", err)
	}
	conversation.KeyHash = cloneBytes(conversation.KeyHash)
	record.Conversation = &conversation
	return nil
}

func (snapshot *ArchiveSnapshot) readProjectIdentity(auditID string, record *archive.Record) error {
	var identity archive.ProjectIdentity
	var bodyScanned int64
	var enc []byte
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT identity_version, extracted_at_ns, source, body_scanned, identity_fpr, remote_fpr,
       repo_root_fpr, cwd_fpr, identity_enc
FROM audit_project_identity WHERE audit_id = $1`, auditID).Scan(&identity.IdentityVersion, &identity.ExtractedAtNS,
		&identity.Source, &bodyScanned, &identity.IdentityFPR, &identity.RemoteFPR, &identity.RepoRootFPR, &identity.CwdFPR, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres archive: read project identity: %w", err)
	}
	identity.BodyScanned = bodyScanned != 0
	identity.IdentityFPR, identity.RemoteFPR = cloneBytes(identity.IdentityFPR), cloneBytes(identity.RemoteFPR)
	identity.RepoRootFPR, identity.CwdFPR = cloneBytes(identity.RepoRootFPR), cloneBytes(identity.CwdFPR)
	if enc != nil {
		aad, err := orgreport.IdentityAAD(auditID, int(identity.IdentityVersion))
		if err != nil {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		plaintext, err := snapshot.cipher.Decrypt(aad, enc)
		if err != nil {
			return snapshot.memberFailure(auditID, ArchiveReasonDecrypt, nil)
		}
		if plaintext == nil {
			plaintext = []byte{}
		}
		identity.Identity = plaintext
	}
	record.ProjectIdentity = &identity
	return nil
}

// checkArchiveRawLayout requires the chunks to be what the reader serves
// (query.StreamRaw, J.2 item 5): every chunk belongs to the source stage of a
// body with full retention that is not streaming, and for each such body the
// chunks of its source stage run on in seq and offset (a forward gap only for
// a partial body with capture_chunk_missing), their count is chunk_count and
// their bytes stored_length. A record that breaks this would be rejected by
// the bundle's re-read check and void its whole segment; it is excluded
// here instead.
func checkArchiveRawLayout(record *archive.Record) error {
	sources := map[string]bool{}
	for _, body := range record.Bodies {
		if body.RetentionState != RetentionFull || body.State == StageStateStreaming {
			continue
		}
		sources[body.SourceStage] = true
		missing := body.State == StageStatePartial && body.ErrorCode != nil && *body.ErrorCode == CaptureChunkMissing
		var sequence, offset, total, count int64
		for _, chunk := range record.OwningChunks(body) {
			if chunk.Seq != sequence || chunk.Offset != offset {
				if !missing || chunk.Seq <= sequence || chunk.Offset < offset {
					return errors.New("raw chunks do not run on")
				}
			}
			total += chunk.PlaintextLength
			count++
			sequence, offset = chunk.Seq+1, chunk.Offset+chunk.PlaintextLength
		}
		if total != body.StoredLength || count != body.ChunkCount {
			return errors.New("raw chunks differ from chunk_count or stored_length")
		}
	}
	for _, chunk := range record.RawChunks {
		if !sources[chunk.Stage] {
			return errors.New("raw chunk of a stage no full body is served from")
		}
	}
	return nil
}

// checkArchiveTimelines runs the bounds checks of query.Timeline on every
// timeline a body is served from (H.2 step 2.3).
func checkArchiveTimelines(record *archive.Record) error {
	for _, body := range record.Bodies {
		stored, plaintext, ok := record.StoredTimeline(body)
		if !ok || plaintext == nil {
			continue
		}
		if _, err := query.TimelineFromPlain(stored, plaintext); err != nil {
			return err
		}
	}
	return nil
}

// --- bundle.Payloads ---

func (snapshot *ArchiveSnapshot) openContentObject(hash []byte) (archive.ContentObject, error) {
	var stored auditmodel.StoredContent
	var created int64
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns
FROM content_objects WHERE object_hash = $1`, hash).Scan(&stored.Hash, &stored.SemanticHash, &stored.Kind,
		&stored.Compression, &stored.PlaintextLength, &stored.EncodedLength, &stored.DataEnc, &created)
	if err != nil {
		return archive.ContentObject{}, fmt.Errorf("postgres archive: read content object: %w", err)
	}
	data, err := auditmodel.OpenContent(snapshot.cipher, stored)
	if err != nil {
		return archive.ContentObject{}, auditmodel.ErrIntegrity
	}
	return archive.ContentObject{Hash: cloneBytes(stored.Hash), SemanticHash: cloneBytes(stored.SemanticHash), Kind: stored.Kind,
		PlaintextLength: stored.PlaintextLength, CreatedAtNS: created, Data: data}, nil
}

func (snapshot *ArchiveSnapshot) openBinaryObject(hash []byte) (archive.BinaryObject, error) {
	var stored auditmodel.StoredBinary
	var created int64
	err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT binary_hash, media_type, compression, plaintext_length, encoded_length, data_enc, created_at_ns
FROM binary_objects WHERE binary_hash = $1`, hash).Scan(&stored.Hash, &stored.MediaType, &stored.Compression,
		&stored.PlaintextLength, &stored.EncodedLength, &stored.DataEnc, &created)
	if err != nil {
		return archive.BinaryObject{}, fmt.Errorf("postgres archive: read binary object: %w", err)
	}
	data, err := auditmodel.OpenBinary(snapshot.cipher, stored)
	if err != nil {
		return archive.BinaryObject{}, auditmodel.ErrIntegrity
	}
	if data == nil {
		data = []byte{}
	}
	return archive.BinaryObject{Hash: cloneBytes(stored.Hash), MediaType: stored.MediaType, PlaintextLength: stored.PlaintextLength,
		CreatedAtNS: created, Data: data}, nil
}

// ContentObject implements bundle.Payloads: the content object with the
// given object_hash, opened in this snapshot.
func (snapshot *ArchiveSnapshot) ContentObject(hash []byte) (archive.ContentObject, error) {
	if err := snapshot.usable(); err != nil {
		return archive.ContentObject{}, err
	}
	return snapshot.openContentObject(hash)
}

// BinaryObject implements bundle.Payloads.
func (snapshot *ArchiveSnapshot) BinaryObject(hash []byte) (archive.BinaryObject, error) {
	if err := snapshot.usable(); err != nil {
		return archive.BinaryObject{}, err
	}
	return snapshot.openBinaryObject(hash)
}

// RawChunk implements bundle.Payloads: the plaintext of one raw chunk. Only
// that chunk is in memory.
func (snapshot *ArchiveSnapshot) RawChunk(auditID, stage string, seq int64) ([]byte, error) {
	if err := snapshot.usable(); err != nil {
		return nil, err
	}
	chunk := chunkMeta{stage: stage, seq: seq}
	if err := snapshot.tx.QueryRowContext(snapshot.ctx, `
SELECT plaintext_length, encoded_length, compression FROM body_chunks WHERE audit_id = $1 AND stage = $2 AND seq = $3`,
		auditID, stage, seq).Scan(&chunk.plaintextLength, &chunk.encodedLength, &chunk.compression); err != nil {
		return nil, fmt.Errorf("postgres archive: read chunk metadata: %w", err)
	}
	plaintext, err := snapshot.openChunk(auditID, chunk)
	var member *ArchiveMemberError
	if errors.As(err, &member) {
		return nil, fmt.Errorf("postgres archive: raw chunk does not open: %s", member.Reason)
	}
	return plaintext, err
}

func bytesToAny(values [][]byte) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
