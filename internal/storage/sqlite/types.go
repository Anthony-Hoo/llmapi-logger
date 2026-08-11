// Package sqlite persists encrypted audit evidence in a single local SQLite
// database. All writes pass through one ordered writer goroutine.
package sqlite

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	StageRequestReceived  = "request_for_newapi_received_from_nginx"
	StageRequestSent      = "request_sent_to_newapi"
	StageResponseReceived = "response_received_from_newapi"
	StageResponseSent     = "response_from_newapi_sent_to_nginx"

	StageStateNotStarted = "not_started"
	StageStateStreaming  = "streaming"
	StageStateComplete   = "complete"
	StageStatePartial    = "partial"

	ForwardInProgress      = "in_progress"
	ForwardCompleted       = "completed"
	ForwardRejected        = "rejected"
	ForwardClientCancelled = "client_cancelled"
	ForwardNewAPIError     = "newapi_error"
	ForwardProxyError      = "proxy_error"
	ForwardInterrupted     = "interrupted"

	CapturePending  = "pending"
	CaptureComplete = "complete"
	CapturePartial  = "partial"
	CaptureFailed   = "failed"

	ParsePending    = "pending"
	ParseProcessing = "processing"
	ParseOK         = "ok"
	ParsePartial    = "partial"
	ParseError      = "error"
	ParseSkipped    = "skipped"

	HeaderKindHeader  = "header"
	HeaderKindTrailer = "trailer"

	GapReasonDBUnavailable = "db_unavailable"
	GapReasonQueueFull     = "queue_full"
	GapReasonEncryption    = "encryption_error"
	GapReasonWrite         = "write_error"
	GapReasonProcessExit   = "process_exit"

	GapDetailDBUnavailable = "audit_storage_unavailable"
	GapDetailQueueFull     = "audit_writer_queue_full"
	GapDetailEncryption    = "audit_encryption_failed"
	GapDetailWrite         = "audit_write_failed"
	GapDetailProcessExit   = "interrupted_audits_recovered"
)

const (
	writerQueueCapacity = 1024
	writerBatchSize     = 64

	// RetentionBatchLimit keeps each maintenance write small enough for the
	// normal audit writer to resume promptly.
	RetentionBatchLimit = 200
)

var (
	ErrClosed    = errors.New("sqlite store is closed")
	ErrQueueFull = errors.New("sqlite writer queue is full")
)

var stableBlockCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// AuditRecord is the parent row created before interceptor evaluation.
type AuditRecord struct {
	AuditID       string
	StartedAtNS   int64
	EndedAtNS     *int64
	RouteID       string
	Protocol      string
	ParserName    string
	Method        string
	Path          string
	RequestURIEnc []byte
	Mode          string
	StatusCode    *int
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
	BlockedBy     *string
	BlockCode     *string
	ErrorCode     *string
}

// HTTPStage represents one actually observed proxy boundary. Missing stages
// are represented by absent rows, never placeholder rows.
type HTTPStage struct {
	AuditID       string
	Stage         string
	State         string
	Proto         string
	Method        string
	Host          string
	StatusCode    *int
	ContentLength *int64
	StartedAtNS   int64
	EndedAtNS     *int64
	ErrorCode     *string
}

// HTTPHeader stores one encrypted Header or Trailer value.
type HTTPHeader struct {
	AuditID     string
	Stage       string
	Kind        string
	Name        string
	ValueIndex  int
	ValueLength int
	ValueEnc    []byte
}

// BodyStream stores aggregate integrity state for one observed stage body.
type BodyStream struct {
	AuditID        string
	Stage          string
	ObservedLength int64
	StoredLength   int64
	SHA256         []byte
	HashComplete   bool
	EOFSeen        bool
	State          string
	ErrorCode      *string
}

// BodyChunk stores one independently encrypted owning chunk.
type BodyChunk struct {
	AuditID         string
	Stage           string
	Seq             int64
	Offset          int64
	PlaintextLength int
	ObservedAtNS    int64
	DataEnc         []byte
}

// AuditGap is an aggregate indication that complete per-request evidence was
// unavailable. Reason and Detail are stable codes; arbitrary error text is
// deliberately rejected before it can reach SQLite.
type AuditGap struct {
	StartedAtNS  int64
	EndedAtNS    int64
	Reason       string
	RequestCount int
	Detail       string
	CreatedAtNS  int64
}

// TokenLink stores the non-secret NewAPI token snapshot associated with one
// audit. MaskedKey must already be redacted by the source; this store never
// accepts or derives the original credential.
type TokenLink struct {
	AuditID       string
	NewAPITokenID int64
	TokenName     string
	MaskedKey     string
	LinkedAtNS    int64
}

// RetentionResult reports rows removed by one bounded writer transaction.
type RetentionResult struct {
	DeletedAudits int
	DeletedGaps   int
}

// BodyFinish is optionally included in StageFinish when a body stream was
// actually opened for the stage.
type BodyFinish struct {
	ObservedLength int64
	StoredLength   int64
	SHA256         []byte
	HashComplete   bool
	EOFSeen        bool
	State          string
	ErrorCode      *string
}

// StageFinish atomically finalizes stage metadata and, when non-nil, its body
// aggregate within the writer batch transaction.
type StageFinish struct {
	AuditID       string
	Stage         string
	State         string
	StatusCode    *int
	ContentLength *int64
	EndedAtNS     int64
	ErrorCode     *string
	Body          *BodyFinish
}

// AuditFinish contains the terminal audit outcome. Rejected audits must carry
// both BlockedBy and BlockCode and use ParseSkipped.
type AuditFinish struct {
	AuditID       string
	EndedAtNS     int64
	StatusCode    *int
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
	BlockedBy     *string
	BlockCode     *string
	ErrorCode     *string
}

// Snapshot is a consistent encrypted evidence view used by integration and
// query layers. Ciphertext blobs are returned unchanged.
type Snapshot struct {
	Audit   AuditRecord
	Stages  []HTTPStage
	Headers []HTTPHeader
	Bodies  []BodyStream
	Chunks  []BodyChunk
}

func (record *AuditRecord) defaults() {
	if record.ForwardStatus == "" {
		record.ForwardStatus = ForwardInProgress
	}
	if record.CaptureStatus == "" {
		record.CaptureStatus = CapturePending
	}
	if record.ParseStatus == "" {
		record.ParseStatus = ParsePending
	}
}

func (stage *HTTPStage) defaults() {
	if stage.State == "" {
		stage.State = StageStateStreaming
	}
}

func (body *BodyStream) defaults() {
	if body.State == "" {
		body.State = StageStateStreaming
	}
}

func (finish *AuditFinish) defaults() {
	if finish.ForwardStatus == ForwardRejected && finish.ParseStatus == "" {
		finish.ParseStatus = ParseSkipped
	}
}

func validateAuditRecord(record AuditRecord) error {
	if record.AuditID == "" || record.RouteID == "" || record.Protocol == "" || record.ParserName == "" || record.Method == "" || record.Path == "" {
		return errors.New("sqlite: audit record has empty required field")
	}
	if len(record.RequestURIEnc) == 0 {
		return errors.New("sqlite: encrypted request URI is required")
	}
	if record.StartedAtNS == 0 {
		return errors.New("sqlite: audit started_at_ns is required")
	}
	if record.Mode != "available" && record.Mode != "strict" {
		return fmt.Errorf("sqlite: invalid audit mode %q", record.Mode)
	}
	if record.ForwardStatus != ForwardInProgress || record.BlockedBy != nil || record.BlockCode != nil || record.EndedAtNS != nil || record.StatusCode != nil || record.ErrorCode != nil {
		return errors.New("sqlite: BeginAudit requires an in-progress unblocked record")
	}
	if record.CaptureStatus != CapturePending || record.ParseStatus != ParsePending {
		return errors.New("sqlite: invalid initial audit status")
	}
	return nil
}

func validateStage(stage HTTPStage) error {
	if stage.AuditID == "" || !validStage(stage.Stage) || stage.StartedAtNS == 0 {
		return errors.New("sqlite: invalid stage identity or start time")
	}
	if stage.State != StageStateStreaming || stage.EndedAtNS != nil {
		return errors.New("sqlite: StartStage requires streaming state without end time")
	}
	if err := validateStatusCode(stage.StatusCode); err != nil {
		return err
	}
	return validateContentLength(stage.ContentLength)
}

func validateHeader(header HTTPHeader) error {
	if header.AuditID == "" || !validStage(header.Stage) || (header.Kind != HeaderKindHeader && header.Kind != HeaderKindTrailer) || header.Name == "" {
		return errors.New("sqlite: invalid header identity")
	}
	if header.ValueIndex < 0 || header.ValueLength < 0 || len(header.ValueEnc) == 0 {
		return errors.New("sqlite: invalid encrypted header value")
	}
	return nil
}

func validateBodyStream(body BodyStream) error {
	if body.AuditID == "" || !validStage(body.Stage) || body.State != StageStateStreaming {
		return errors.New("sqlite: invalid body stream identity or state")
	}
	return validateBodyAggregate(body.ObservedLength, body.StoredLength, body.SHA256, body.HashComplete, body.EOFSeen)
}

func validateChunk(chunk BodyChunk) error {
	if chunk.AuditID == "" || !validStage(chunk.Stage) || chunk.Seq < 0 || chunk.Offset < 0 || chunk.PlaintextLength < 0 || chunk.ObservedAtNS == 0 || len(chunk.DataEnc) == 0 {
		return errors.New("sqlite: invalid body chunk")
	}
	return nil
}

func validateAuditGap(gap AuditGap) error {
	if gap.StartedAtNS <= 0 || gap.EndedAtNS < gap.StartedAtNS || gap.CreatedAtNS <= 0 || gap.RequestCount <= 0 {
		return errors.New("sqlite: invalid audit gap time range or count")
	}
	wantDetail, ok := gapDetailForReason(gap.Reason)
	if !ok || gap.Detail != wantDetail {
		return errors.New("sqlite: invalid audit gap reason or detail")
	}
	return nil
}

func validateTokenLink(link TokenLink) error {
	if link.AuditID == "" || link.NewAPITokenID < 0 || link.LinkedAtNS <= 0 {
		return errors.New("sqlite: invalid token link identity or timestamp")
	}
	for _, value := range []string{link.TokenName, link.MaskedKey} {
		if len(value) > 512 || strings.ContainsRune(value, '\x00') {
			return errors.New("sqlite: invalid token link snapshot")
		}
	}
	return nil
}

func gapDetailForReason(reason string) (string, bool) {
	switch reason {
	case GapReasonDBUnavailable:
		return GapDetailDBUnavailable, true
	case GapReasonQueueFull:
		return GapDetailQueueFull, true
	case GapReasonEncryption:
		return GapDetailEncryption, true
	case GapReasonWrite:
		return GapDetailWrite, true
	case GapReasonProcessExit:
		return GapDetailProcessExit, true
	default:
		return "", false
	}
}

func validateStageFinish(finish StageFinish) error {
	if finish.AuditID == "" || !validStage(finish.Stage) || finish.EndedAtNS == 0 || !terminalStageState(finish.State) {
		return errors.New("sqlite: invalid stage finish")
	}
	if err := validateStatusCode(finish.StatusCode); err != nil {
		return err
	}
	if err := validateContentLength(finish.ContentLength); err != nil {
		return err
	}
	if finish.Body == nil {
		return nil
	}
	if !terminalStageState(finish.Body.State) {
		return errors.New("sqlite: invalid body finish state")
	}
	return validateBodyAggregate(
		finish.Body.ObservedLength,
		finish.Body.StoredLength,
		finish.Body.SHA256,
		finish.Body.HashComplete,
		finish.Body.EOFSeen,
	)
}

func validateAuditFinish(finish AuditFinish) error {
	if finish.AuditID == "" || finish.EndedAtNS == 0 || finish.ForwardStatus == "" || finish.ForwardStatus == ForwardInProgress {
		return errors.New("sqlite: invalid audit finish identity or status")
	}
	if !validForwardStatus(finish.ForwardStatus) || !validCaptureStatus(finish.CaptureStatus) || !validParseStatus(finish.ParseStatus) {
		return errors.New("sqlite: invalid terminal audit status")
	}
	if err := validateStatusCode(finish.StatusCode); err != nil {
		return err
	}
	if finish.ForwardStatus == ForwardRejected {
		if finish.BlockedBy == nil || strings.TrimSpace(*finish.BlockedBy) == "" || finish.BlockCode == nil || !stableBlockCode.MatchString(*finish.BlockCode) {
			return errors.New("sqlite: rejected audit requires stable blocked_by and block_code")
		}
		if finish.ParseStatus != ParseSkipped || finish.StatusCode == nil || !((*finish.StatusCode >= 400 && *finish.StatusCode <= 499) || *finish.StatusCode == 503) {
			return errors.New("sqlite: rejected audit requires skipped parse and 4xx/503 status")
		}
		return nil
	}
	if finish.BlockedBy != nil || finish.BlockCode != nil {
		return errors.New("sqlite: non-rejected audit cannot contain block fields")
	}
	return nil
}

func validateBodyAggregate(observed, stored int64, digest []byte, hashComplete, eofSeen bool) error {
	if observed < 0 || stored < 0 || stored > observed || (len(digest) != 0 && len(digest) != 32) || (hashComplete && !eofSeen) {
		return errors.New("sqlite: invalid body aggregate")
	}
	return nil
}

func validateStatusCode(status *int) error {
	if status != nil && (*status < 100 || *status > 599) {
		return fmt.Errorf("sqlite: invalid HTTP status %d", *status)
	}
	return nil
}

func validateContentLength(length *int64) error {
	if length != nil && *length < -1 {
		return fmt.Errorf("sqlite: invalid content length %d", *length)
	}
	return nil
}

func validStage(stage string) bool {
	switch stage {
	case StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent:
		return true
	default:
		return false
	}
}

func terminalStageState(state string) bool {
	return state == StageStateComplete || state == StageStatePartial
}

func validForwardStatus(status string) bool {
	switch status {
	case ForwardInProgress, ForwardCompleted, ForwardRejected, ForwardClientCancelled, ForwardNewAPIError, ForwardProxyError, ForwardInterrupted:
		return true
	default:
		return false
	}
}

func validCaptureStatus(status string) bool {
	switch status {
	case CapturePending, CaptureComplete, CapturePartial, CaptureFailed:
		return true
	default:
		return false
	}
}

func validParseStatus(status string) bool {
	switch status {
	case ParsePending, ParseProcessing, ParseOK, ParsePartial, ParseError, ParseSkipped:
		return true
	default:
		return false
	}
}
