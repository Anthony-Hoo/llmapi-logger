package storage

import (
	"errors"
)

const StageRequestReceived = "request_for_newapi_received_from_nginx"
const StageRequestSent = "request_sent_to_newapi"
const StageResponseReceived = "response_received_from_newapi"
const StageResponseSent = "response_from_newapi_sent_to_nginx"
const StageStateNotStarted = "not_started"
const StageStateStreaming = "streaming"
const StageStateComplete = "complete"
const StageStatePartial = "partial"
const ForwardInProgress = "in_progress"
const ForwardCompleted = "completed"
const ForwardRejected = "rejected"
const ForwardClientCancelled = "client_cancelled"
const ForwardNewAPIError = "newapi_error"
const ForwardProxyError = "proxy_error"
const ForwardInterrupted = "interrupted"
const CapturePending = "pending"
const CaptureComplete = "complete"
const CapturePartial = "partial"
const CaptureFailed = "failed"
const CaptureChunkMissing = "capture_chunk_missing"
const ParsePending = "pending"
const ParseProcessing = "processing"
const ParseOK = "ok"
const ParsePartial = "partial"
const ParseError = "error"
const ParseSkipped = "skipped"
const CallerNone = "none"
const CallerPending = "pending"
const CallerResolved = "resolved"
const CallerUnresolved = "unresolved"
const HeaderKindHeader = "header"
const HeaderKindTrailer = "trailer"
const RetentionPending = "pending"
const RetentionMetadata = "metadata"
const RetentionFull = "full"
const ChunkCompressionNone = "none"
const ChunkCompressionGZIP = "gzip"
const GapReasonDBUnavailable = "db_unavailable"
const GapReasonQueueFull = "queue_full"
const GapReasonEncryption = "encryption_error"
const GapReasonWrite = "write_error"
const GapReasonProcessExit = "process_exit"
const GapDetailDBUnavailable = "audit_storage_unavailable"
const GapDetailQueueFull = "audit_writer_queue_full"
const GapDetailEncryption = "audit_encryption_failed"
const GapDetailWrite = "audit_write_failed"
const GapDetailProcessExit = "interrupted_audits_recovered"

// APIKeyFingerprintSize is the width of audit_records.api_key_fpr, matching the
// HMAC-SHA-256 tag produced by security.CredentialFingerprinter.
const APIKeyFingerprintSize = 32

// RetentionBatchLimit keeps each maintenance write small enough for the
// normal audit writer to resume promptly.
const RetentionBatchLimit = 200

var ErrClosed = errors.New("sqlite store is closed")
var ErrQueueFull = errors.New("sqlite writer queue is full")
var ErrRecoveryOverflow = errors.New("sqlite capture recovery capacity exceeded; restart required")

// ErrWriteBatchFailed wraps the acknowledgement of an operation whose whole
// writer batch was rolled back, including a COMMIT with an uncertain outcome.
// It separates a batch-level failure, which a CommitAudit may retry, from the
// operation's own result, which it must not.
var ErrWriteBatchFailed = errors.New("audit writer batch failed")

// Capture versions of audit_records.capture_version. Version 1 stores Header
// values as per-value http_headers rows; version 2 stores one encrypted header
// block per audit, user_agent_enc and the stage content columns. Zero in a
// write input means version 1, the column default.
const (
	CaptureVersion1 = 1
	CaptureVersion2 = 2
)

// HeaderBlockMaxPlaintextLength bounds the decoded header block of one audit.
const HeaderBlockMaxPlaintextLength = 64 << 20

// AuditRecord is the parent row created before interceptor evaluation.
type AuditRecord struct {
	AuditID           string
	StartedAtNS       int64
	EndedAtNS         *int64
	RouteID           string
	Protocol          string
	ParserName        string
	Method            string
	Path              string
	RequestURIEnc     []byte
	Mode              string
	StatusCode        *int
	TTFTNS            *int64
	ForwardStatus     string
	CaptureStatus     string
	ParseStatus       string
	BlockedBy         *string
	BlockCode         *string
	ErrorCode         *string
	NewAPIRequestID   *string
	CallerStatus      string
	CallerAttempts    int
	CallerNextAtNS    *int64
	CallerUpdatedAtNS *int64
	// APIKeyFPR scopes developer sessions to the audits their own key produced.
	// It is nil when the request carried no credential.
	APIKeyFPR []byte
	// CaptureVersion is fixed by BeginAudit and never changes afterwards. The
	// legacy path leaves it zero, which stores the column default 1.
	CaptureVersion int
	// UserAgentEnc is the sealed inbound User-Agent of a version 2 audit, nil
	// when the request carried none. Version 1 audits never have one.
	UserAgentEnc []byte
	// Inbound is a BeginAudit input only: under the unified write path the
	// request_received stage row and its headers are written in the same
	// operation as the audit row. The legacy path passes nil, and readers
	// never fill it.
	Inbound *InboundStage
}

// InboundStage is the request_received stage that BeginAudit writes together
// with the audit row. Headers holds per-value rows for version 1; HeaderBlock
// holds a block with only this stage for version 2. ContentType and
// ContentEncoding are the version 2 http_stages columns.
type InboundStage struct {
	Stage           HTTPStage
	Headers         []HTTPHeader
	HeaderBlock     *HeaderBlock
	ContentType     *string
	ContentEncoding *string
}

// AuditCheckpoint is one write of an in-flight audit that the session does not
// wait for. It only inserts rows that were not written before, in the shape
// legacy has committed for an in-flight request, and never writes final values.
type AuditCheckpoint struct {
	AuditID        string
	CaptureVersion int
	// Stages are the new stages: streaming, no end time, status and length as
	// at stage start.
	Stages []HTTPStage
	// Contents carries the version 2 content columns of the new Stages, at most
	// one entry per stage. Version 1 leaves it empty.
	Contents []StageContent
	// Headers holds the new (stage, kind) groups, version 1 only.
	Headers []HTTPHeader
	// HeaderBlock is the whole block written so far, version 2 only; it
	// replaces the stored block.
	HeaderBlock *HeaderBlock
	// Bodies are new body rows with initial values; a merged request_sent
	// carries SourceStage request_received.
	Bodies []BodyStream
	// Chunks are newly sealed owning chunks; nil when there are none.
	Chunks ChunkSource
}

// StageContent is the content-type and content-encoding a version 2 stage
// row stores (nil for none); see headerblock.ContentHeaders.
type StageContent struct {
	Stage           string
	ContentType     *string
	ContentEncoding *string
}

// AuditCommit is the final write at Finish. BeginAudit has already written the
// audit row.
type AuditCommit struct {
	Finish         AuditFinish
	CaptureVersion int           // must equal the value on the audit row
	Stages         []StageCommit // every stage that was reached, in stage order
	Headers        []HTTPHeader  // version 1 only: groups no checkpoint wrote
	HeaderBlock    *HeaderBlock  // version 2 only: the full block; nil when unchanged since the last checkpoint
	Chunks         ChunkSource   // owning chunks no checkpoint wrote
	DedupInDB      [2]bool       // request pair, response pair: merge in the database as legacy does
	FinalAttempt   bool          // the last retry
	PayloadBytes   int64
}

// StageCommit is the final state of one stage at CommitAudit.
type StageCommit struct {
	Stage HTTPStage // final values
	// StageWritten: an earlier write inserted the stage row, a checkpoint or,
	// for request_received, BeginAudit (InboundStage); update it, otherwise
	// insert it.
	StageWritten    bool
	ContentType     *string // version 2 only
	ContentEncoding *string
	Body            *BodyStream // final values; the duplicate of a merged pair is already in merged form
	BodyWritten     bool        // a checkpoint inserted the body row
	Timeline        *StreamTimeline
}

// HeaderBlock is the sealed header block of one audit (http_header_blocks).
type HeaderBlock struct {
	Compression     string
	PlaintextLength int64
	DataEnc         []byte
}

// ChunkSource can be iterated more than once; each chunk is either ciphertext
// held in memory or a position in a staging file.
type ChunkSource interface {
	Each(visit func(BodyChunk) error) error
}

// ChunkList is a ChunkSource over chunks held in memory.
type ChunkList []BodyChunk

func (chunks ChunkList) Each(visit func(BodyChunk) error) error {
	for _, chunk := range chunks {
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
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
	AuditID                string
	Stage                  string
	SourceStage            string
	ObservedLength         int64
	StoredLength           int64
	SHA256                 []byte
	HashComplete           bool
	EOFSeen                bool
	State                  string
	RetentionState         string
	FirstObservedAtNS      *int64
	LastObservedAtNS       *int64
	ChunkCount             int64
	StreamEventCount       int64
	StreamTimelineComplete bool
	ErrorCode              *string
}

// BodyChunk stores one independently encrypted owning chunk.
type BodyChunk struct {
	AuditID         string
	Stage           string
	Seq             int64
	Offset          int64
	PlaintextLength int
	EncodedLength   int
	ObservedAtNS    int64
	Compression     string
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

// Billing states of a token link (doc/features/21-newapi-billing.md).
// Unchecked only exists for links written before migration 009; new links are
// always billed or unbilled.
const BillingUnchecked = "unchecked"

// Billing states of a token link (doc/features/21-newapi-billing.md).
// Unchecked only exists for links written before migration 009; new links are
// always billed or unbilled.

const BillingBilled = "billed"

// Billing states of a token link (doc/features/21-newapi-billing.md).
// Unchecked only exists for links written before migration 009; new links are
// always billed or unbilled.

const BillingUnbilled = "unbilled"

// MaxBillingAttempts bounds the historical billing backfill of one link.
const MaxBillingAttempts = 3

// TokenLink stores the non-secret NewAPI caller snapshot associated with one
// audit. It contains identifiers and names from the system log, never a key.
// The billing fields come from the same log rows: they are set exactly when
// BillingState is BillingBilled.
type TokenLink struct {
	AuditID         string
	NewAPIRequestID string
	NewAPIUserID    int64
	Username        string
	NewAPITokenID   int64
	TokenName       string
	LinkedAtNS      int64
	Attempts        int

	BillingState           string
	Quota                  *int64
	QuotaPerUnit           *float64
	BilledPromptTokens     *int64
	BilledCompletionTokens *int64
}

// CallerLookup is one due caller-identification job read by the NewAPI worker.
// StatusCode is the audit's response status, nil when no response was
// recorded.
type CallerLookup struct {
	AuditID    string
	RequestID  string
	Attempts   int
	StatusCode *int
}

// BillingBackfillItem is one pre-billing token link awaiting its historical
// billing lookup.
type BillingBackfillItem struct {
	AuditID   string
	RequestID string
	Attempts  int
}

// BillingUpdate replaces only the billing columns of an unchecked token link.
// State BillingUnchecked records one more failed attempt; the billing values
// must then be nil, as for BillingUnbilled.
type BillingUpdate struct {
	AuditID                string
	State                  string
	Attempts               int
	Quota                  *int64
	QuotaPerUnit           *float64
	BilledPromptTokens     *int64
	BilledCompletionTokens *int64
}

// CallerRetry reschedules or terminates one caller lookup attempt.
type CallerRetry struct {
	AuditID         string
	RequestID       string
	Attempts        int
	NextAttemptAtNS *int64
	UpdatedAtNS     int64
}

// RetentionResult reports rows removed by one bounded writer transaction.
type RetentionResult struct {
	DeletedAudits int
	DeletedGaps   int
}

// BodyFinish is optionally included in StageFinish when a body stream was
// actually opened for the stage.
type BodyFinish struct {
	ObservedLength         int64
	StoredLength           int64
	SHA256                 []byte
	HashComplete           bool
	EOFSeen                bool
	State                  string
	RetentionState         string
	FirstObservedAtNS      *int64
	LastObservedAtNS       *int64
	ChunkCount             int64
	StreamEventCount       int64
	StreamTimelineComplete bool
	Timeline               *StreamTimeline
	ErrorCode              *string
}

// StreamTimeline is one compressed and encrypted delta sequence of logical
// SSE event completion offsets and observation times.
type StreamTimeline struct {
	EventCount      int64
	FirstEventAtNS  *int64
	LastEventAtNS   *int64
	Complete        bool
	Compression     string
	PlaintextLength int64
	DataEnc         []byte
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
	AuditID         string
	EndedAtNS       int64
	StatusCode      *int
	TTFTNS          *int64
	ForwardStatus   string
	CaptureStatus   string
	ParseStatus     string
	BlockedBy       *string
	BlockCode       *string
	ErrorCode       *string
	NewAPIRequestID *string
}

// Snapshot is a consistent encrypted evidence view used by integration and
// query layers. Ciphertext blobs are returned unchanged.
type Snapshot struct {
	Audit   AuditRecord
	Stages  []HTTPStage
	Headers []HTTPHeader
	Bodies  []BodyStream
	Chunks  []BodyChunk
	// HeaderBlock is the stored header block of a version 2 audit, nil for
	// version 1.
	HeaderBlock *HeaderBlock
}

func (record *AuditRecord) Defaults() {
	if record.ForwardStatus == "" {
		record.ForwardStatus = ForwardInProgress
	}
	if record.CaptureStatus == "" {
		record.CaptureStatus = CapturePending
	}
	if record.ParseStatus == "" {
		record.ParseStatus = ParsePending
	}
	if record.CallerStatus == "" {
		record.CallerStatus = CallerNone
	}
}

func (stage *HTTPStage) Defaults() {
	if stage.State == "" {
		stage.State = StageStateStreaming
	}
}

func (body *BodyStream) Defaults() {
	if body.State == "" {
		body.State = StageStateStreaming
	}
	if body.SourceStage == "" {
		body.SourceStage = body.Stage
	}
	if body.RetentionState == "" {
		body.RetentionState = RetentionPending
	}
	if !body.StreamTimelineComplete && body.StreamEventCount == 0 {
		body.StreamTimelineComplete = true
	}
}

func (chunk *BodyChunk) Defaults() {
	if chunk.Compression == "" {
		chunk.Compression = ChunkCompressionNone
	}
	if chunk.EncodedLength == 0 && chunk.PlaintextLength > 0 {
		chunk.EncodedLength = chunk.PlaintextLength
	}
}

func (finish *AuditFinish) Defaults() {
	if finish.ForwardStatus == ForwardRejected && finish.ParseStatus == "" {
		finish.ParseStatus = ParseSkipped
	}
}

func (finish *StageFinish) Defaults() {
	if finish.Body == nil {
		return
	}
	if finish.Body.RetentionState == "" {
		finish.Body.RetentionState = RetentionPending
	}
	if !finish.Body.StreamTimelineComplete && finish.Body.StreamEventCount == 0 && finish.Body.Timeline == nil {
		finish.Body.StreamTimelineComplete = true
	}
}
