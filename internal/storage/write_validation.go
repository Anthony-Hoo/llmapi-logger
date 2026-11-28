package storage

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The validators in this file check the write inputs of the unified write
// path (AuditCheckpoint, AuditCommit and the BeginAudit additions) before a
// store queues them. They repeat the element rules of the stores' own
// validateStage, validateHeader, validateBodyStream, validateChunk,
// validateStageFinish and validateAuditFinish, so both stores reject the same
// inputs, and add the rules the new shapes need: one capture version per
// write, per-value rows only for version 1, a header block only for version 2,
// and a block whenever a version 2 write inserts a stage row (the stage set
// invariant of the header block).

var stableCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// EffectiveCaptureVersion maps the zero value of a write input to version 1,
// the column default.
func EffectiveCaptureVersion(version int) int {
	if version == 0 {
		return CaptureVersion1
	}
	return version
}

func validCaptureVersion(version int) bool {
	return version == 0 || version == CaptureVersion1 || version == CaptureVersion2
}

// StageOrder returns the position of a stage in the fixed capture order, or -1
// for an unknown name.
func StageOrder(stage string) int {
	switch stage {
	case StageRequestReceived:
		return 0
	case StageRequestSent:
		return 1
	case StageResponseReceived:
		return 2
	case StageResponseSent:
		return 3
	default:
		return -1
	}
}

// pairedSourceStage is the stage whose body a merged duplicate points to.
func pairedSourceStage(stage string) string {
	switch stage {
	case StageRequestSent:
		return StageRequestReceived
	case StageResponseSent:
		return StageResponseReceived
	default:
		return ""
	}
}

// ValidateAuditRecordCapture checks the fields BeginAudit gained for the
// unified write path. It runs in addition to the store's own audit record
// validation, which it does not repeat.
func ValidateAuditRecordCapture(record AuditRecord) error {
	if !validCaptureVersion(record.CaptureVersion) {
		return fmt.Errorf("storage: invalid capture version %d", record.CaptureVersion)
	}
	version := EffectiveCaptureVersion(record.CaptureVersion)
	if len(record.UserAgentEnc) != 0 && version != CaptureVersion2 {
		return errors.New("storage: user agent ciphertext requires capture version 2")
	}
	if record.Inbound == nil {
		return nil
	}
	inbound := record.Inbound
	if inbound.Stage.AuditID != record.AuditID || inbound.Stage.Stage != StageRequestReceived {
		return errors.New("storage: BeginAudit inbound stage must be request_received of the same audit")
	}
	if err := validateStartStage(inbound.Stage); err != nil {
		return err
	}
	if err := validateVersionedHeaders(version, record.AuditID, inbound.Headers, inbound.HeaderBlock); err != nil {
		return err
	}
	for _, header := range inbound.Headers {
		if header.Stage != StageRequestReceived || header.Kind != HeaderKindHeader {
			return errors.New("storage: BeginAudit headers must be request_received headers")
		}
	}
	if version == CaptureVersion2 && inbound.HeaderBlock == nil {
		return errors.New("storage: capture version 2 inbound stage requires a header block")
	}
	return validateContentValues(version, inbound.ContentType, inbound.ContentEncoding)
}

// ValidateAuditCheckpoint checks one checkpoint without iterating its chunks;
// a store validates each chunk with ValidateOwnedChunk while it reads them.
func ValidateAuditCheckpoint(checkpoint AuditCheckpoint) error {
	if checkpoint.AuditID == "" {
		return errors.New("storage: checkpoint requires an audit id")
	}
	if !validCaptureVersion(checkpoint.CaptureVersion) {
		return fmt.Errorf("storage: invalid capture version %d", checkpoint.CaptureVersion)
	}
	version := EffectiveCaptureVersion(checkpoint.CaptureVersion)
	stages := make(map[string]bool, len(checkpoint.Stages))
	for _, stage := range checkpoint.Stages {
		if stage.AuditID != checkpoint.AuditID {
			return errors.New("storage: checkpoint stage belongs to another audit")
		}
		if err := validateStartStage(stage); err != nil {
			return err
		}
		if stages[stage.Stage] {
			return errors.New("storage: checkpoint repeats a stage")
		}
		stages[stage.Stage] = true
	}
	if version == CaptureVersion1 && len(checkpoint.Contents) != 0 {
		return errors.New("storage: stage content columns require capture version 2")
	}
	contents := make(map[string]bool, len(checkpoint.Contents))
	for _, content := range checkpoint.Contents {
		if !stages[content.Stage] || contents[content.Stage] {
			return errors.New("storage: checkpoint content must name one new stage once")
		}
		contents[content.Stage] = true
		if err := validateContentValues(version, content.ContentType, content.ContentEncoding); err != nil {
			return err
		}
	}
	if err := validateVersionedHeaders(version, checkpoint.AuditID, checkpoint.Headers, checkpoint.HeaderBlock); err != nil {
		return err
	}
	if version == CaptureVersion2 && len(checkpoint.Stages) != 0 && checkpoint.HeaderBlock == nil {
		return errors.New("storage: capture version 2 checkpoint inserting stages requires a header block")
	}
	bodies := make(map[string]bool, len(checkpoint.Bodies))
	for _, body := range checkpoint.Bodies {
		if body.AuditID != checkpoint.AuditID {
			return errors.New("storage: checkpoint body belongs to another audit")
		}
		if err := validateInitialBody(body); err != nil {
			return err
		}
		if bodies[body.Stage] {
			return errors.New("storage: checkpoint repeats a body")
		}
		bodies[body.Stage] = true
	}
	return nil
}

// ValidateAuditCommit checks one final commit without iterating its chunks.
func ValidateAuditCommit(commit AuditCommit) error {
	if err := validateAuditFinish(commit.Finish); err != nil {
		return err
	}
	auditID := commit.Finish.AuditID
	if !validCaptureVersion(commit.CaptureVersion) {
		return fmt.Errorf("storage: invalid capture version %d", commit.CaptureVersion)
	}
	version := EffectiveCaptureVersion(commit.CaptureVersion)
	if commit.PayloadBytes < 0 {
		return errors.New("storage: negative commit payload size")
	}
	previous := -1
	insertsStage := false
	for _, stage := range commit.Stages {
		if err := validateStageCommit(version, auditID, stage); err != nil {
			return err
		}
		order := StageOrder(stage.Stage.Stage)
		if order <= previous {
			return errors.New("storage: commit stages must be in stage order without repeats")
		}
		previous = order
		if !stage.StageWritten {
			insertsStage = true
		}
	}
	if err := validateVersionedHeaders(version, auditID, commit.Headers, commit.HeaderBlock); err != nil {
		return err
	}
	if version == CaptureVersion2 && insertsStage && commit.HeaderBlock == nil {
		return errors.New("storage: capture version 2 commit inserting stages requires a header block")
	}
	return nil
}

// ValidateHeaderBlock checks the stored triple of a header block.
func ValidateHeaderBlock(block HeaderBlock) error {
	if block.Compression != ChunkCompressionNone && block.Compression != ChunkCompressionGZIP {
		return errors.New("storage: invalid header block compression")
	}
	if block.PlaintextLength < 0 || block.PlaintextLength > HeaderBlockMaxPlaintextLength || len(block.DataEnc) == 0 {
		return errors.New("storage: invalid header block")
	}
	return nil
}

// ValidateOwnedChunk checks one chunk of a checkpoint or commit; the rules are
// those of the stores' validateChunk plus the audit identity.
func ValidateOwnedChunk(auditID string, chunk BodyChunk) error {
	if chunk.AuditID != auditID || auditID == "" {
		return errors.New("storage: chunk belongs to another audit")
	}
	if StageOrder(chunk.Stage) < 0 || chunk.Seq < 0 || chunk.Offset < 0 || chunk.PlaintextLength < 0 || chunk.EncodedLength < 0 ||
		chunk.ObservedAtNS == 0 || len(chunk.DataEnc) == 0 ||
		(chunk.Compression != ChunkCompressionNone && chunk.Compression != ChunkCompressionGZIP) {
		return errors.New("storage: invalid body chunk")
	}
	return nil
}

func validateVersionedHeaders(version int, auditID string, headers []HTTPHeader, block *HeaderBlock) error {
	switch version {
	case CaptureVersion1:
		if block != nil {
			return errors.New("storage: header block requires capture version 2")
		}
		for _, header := range headers {
			if header.AuditID != auditID {
				return errors.New("storage: header belongs to another audit")
			}
			if err := validateHeaderRow(header); err != nil {
				return err
			}
		}
	case CaptureVersion2:
		if len(headers) != 0 {
			return errors.New("storage: per-value header rows require capture version 1")
		}
		if block != nil {
			if err := ValidateHeaderBlock(*block); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateContentValues mirrors the http_stages CHECK that the two content
// columns are NULL or non-empty; only version 2 writes them.
func validateContentValues(version int, contentType, contentEncoding *string) error {
	if version != CaptureVersion2 {
		if contentType != nil || contentEncoding != nil {
			return errors.New("storage: stage content columns require capture version 2")
		}
		return nil
	}
	if contentType != nil && *contentType == "" || contentEncoding != nil && *contentEncoding == "" {
		return errors.New("storage: stage content values must be nil or non-empty")
	}
	return nil
}

func validateStageCommit(version int, auditID string, commit StageCommit) error {
	stage := commit.Stage
	if stage.AuditID != auditID || StageOrder(stage.Stage) < 0 || stage.StartedAtNS == 0 {
		return errors.New("storage: invalid commit stage identity or start time")
	}
	if !terminalState(stage.State) || stage.EndedAtNS == nil || *stage.EndedAtNS == 0 {
		return errors.New("storage: commit stage requires a terminal state and end time")
	}
	if err := validateStatus(stage.StatusCode); err != nil {
		return err
	}
	if err := validateLength(stage.ContentLength); err != nil {
		return err
	}
	if err := validateContentValues(version, commit.ContentType, commit.ContentEncoding); err != nil {
		return err
	}
	if commit.BodyWritten && (commit.Body == nil || !commit.StageWritten) {
		return errors.New("storage: a written body requires its body and stage rows")
	}
	if commit.Body == nil {
		if commit.Timeline != nil {
			return errors.New("storage: stream timeline requires a body")
		}
		return nil
	}
	body := *commit.Body
	if body.AuditID != auditID || body.Stage != stage.Stage || !validSourceStage(body.Stage, body.SourceStage) {
		return errors.New("storage: invalid commit body identity")
	}
	if !terminalState(body.State) || !validRetention(body.RetentionState) || body.ChunkCount < 0 || body.StreamEventCount < 0 ||
		!validRange(body.FirstObservedAtNS, body.LastObservedAtNS) {
		return errors.New("storage: invalid commit body metadata")
	}
	if timeline := commit.Timeline; timeline != nil {
		if timeline.EventCount != body.StreamEventCount || timeline.EventCount <= 0 ||
			!validRange(timeline.FirstEventAtNS, timeline.LastEventAtNS) ||
			timeline.Complete != body.StreamTimelineComplete || timeline.PlaintextLength <= 0 || len(timeline.DataEnc) == 0 ||
			(timeline.Compression != ChunkCompressionNone && timeline.Compression != ChunkCompressionGZIP) {
			return errors.New("storage: invalid stream timeline")
		}
	}
	return validateAggregate(body.ObservedLength, body.StoredLength, body.SHA256, body.HashComplete, body.EOFSeen)
}

// validateStartStage is the stores' validateStage: a stage row as inserted
// at stage start.
func validateStartStage(stage HTTPStage) error {
	if stage.AuditID == "" || StageOrder(stage.Stage) < 0 || stage.StartedAtNS == 0 {
		return errors.New("storage: invalid stage identity or start time")
	}
	if stage.State != StageStateStreaming || stage.EndedAtNS != nil {
		return errors.New("storage: a new stage row requires streaming state without end time")
	}
	if err := validateStatus(stage.StatusCode); err != nil {
		return err
	}
	return validateLength(stage.ContentLength)
}

// validateHeaderRow is the stores' validateHeader.
func validateHeaderRow(header HTTPHeader) error {
	if header.AuditID == "" || StageOrder(header.Stage) < 0 || (header.Kind != HeaderKindHeader && header.Kind != HeaderKindTrailer) || header.Name == "" {
		return errors.New("storage: invalid header identity")
	}
	if header.ValueIndex < 0 || header.ValueLength < 0 || len(header.ValueEnc) == 0 {
		return errors.New("storage: invalid encrypted header value")
	}
	return nil
}

// validateInitialBody is the stores' validateBodyStream, with the source
// stage limited to the body itself or the source of its pair.
func validateInitialBody(body BodyStream) error {
	if body.AuditID == "" || StageOrder(body.Stage) < 0 || !validSourceStage(body.Stage, body.SourceStage) ||
		body.State != StageStateStreaming || !validRetention(body.RetentionState) {
		return errors.New("storage: invalid body stream identity or state")
	}
	if body.ChunkCount < 0 || body.StreamEventCount < 0 || !validRange(body.FirstObservedAtNS, body.LastObservedAtNS) {
		return errors.New("storage: invalid body stream counters")
	}
	return validateAggregate(body.ObservedLength, body.StoredLength, body.SHA256, body.HashComplete, body.EOFSeen)
}

// validateAuditFinish is the stores' validateAuditFinish.
func validateAuditFinish(finish AuditFinish) error {
	if finish.AuditID == "" || finish.EndedAtNS == 0 || finish.ForwardStatus == "" || finish.ForwardStatus == ForwardInProgress {
		return errors.New("storage: invalid audit finish identity or status")
	}
	switch finish.ForwardStatus {
	case ForwardCompleted, ForwardRejected, ForwardClientCancelled, ForwardNewAPIError, ForwardProxyError, ForwardInterrupted:
	default:
		return errors.New("storage: invalid terminal audit status")
	}
	switch finish.CaptureStatus {
	case CapturePending, CaptureComplete, CapturePartial, CaptureFailed:
	default:
		return errors.New("storage: invalid terminal audit status")
	}
	switch finish.ParseStatus {
	case ParsePending, ParseProcessing, ParseOK, ParsePartial, ParseError, ParseSkipped:
	default:
		return errors.New("storage: invalid terminal audit status")
	}
	if err := validateStatus(finish.StatusCode); err != nil {
		return err
	}
	if finish.TTFTNS != nil && *finish.TTFTNS < 0 {
		return errors.New("storage: invalid TTFT")
	}
	if finish.NewAPIRequestID != nil && !validNewAPIRequestID(*finish.NewAPIRequestID) {
		return errors.New("storage: invalid NewAPI request id")
	}
	if finish.ForwardStatus == ForwardRejected {
		if finish.BlockedBy == nil || strings.TrimSpace(*finish.BlockedBy) == "" || finish.BlockCode == nil || !stableCode.MatchString(*finish.BlockCode) {
			return errors.New("storage: rejected audit requires stable blocked_by and block_code")
		}
		if finish.ParseStatus != ParseSkipped || finish.StatusCode == nil || !((*finish.StatusCode >= 400 && *finish.StatusCode <= 499) || *finish.StatusCode == 503) {
			return errors.New("storage: rejected audit requires skipped parse and 4xx/503 status")
		}
		return nil
	}
	if finish.BlockedBy != nil || finish.BlockCode != nil {
		return errors.New("storage: non-rejected audit cannot contain block fields")
	}
	return nil
}

func validSourceStage(stage, source string) bool {
	return source == stage || source != "" && source == pairedSourceStage(stage)
}

func validNewAPIRequestID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validateAggregate(observed, stored int64, digest []byte, hashComplete, eofSeen bool) error {
	if observed < 0 || stored < 0 || stored > observed || (len(digest) != 0 && len(digest) != 32) || (hashComplete && !eofSeen) {
		return errors.New("storage: invalid body aggregate")
	}
	return nil
}

func validRetention(value string) bool {
	return value == RetentionPending || value == RetentionMetadata || value == RetentionFull
}

func validRange(first, last *int64) bool {
	return first == nil && last == nil || first != nil && last != nil && *first > 0 && *last >= *first
}

func validateStatus(status *int) error {
	if status != nil && (*status < 100 || *status > 599) {
		return fmt.Errorf("storage: invalid HTTP status %d", *status)
	}
	return nil
}

func validateLength(length *int64) error {
	if length != nil && *length < -1 {
		return fmt.Errorf("storage: invalid content length %d", *length)
	}
	return nil
}

func terminalState(state string) bool {
	return state == StageStateComplete || state == StageStatePartial
}
