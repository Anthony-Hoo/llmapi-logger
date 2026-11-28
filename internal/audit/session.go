package audit

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/parser/streamterminal"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const bodyChunkSize = 1 << 20

const maxStreamTimelineEvents = 100_000

const newAPIRequestIDHeader = "X-Oneapi-Request-Id"

type stageCapture struct {
	name            string
	persisted       bool
	startedAtNS     int64
	proto           string
	method          string
	host            string
	statusCode      *int
	contentLength   *int64
	contentType     string
	contentEncoding string
	expectsBody     bool
	body            *bodyCapture
	faulted         bool
	errorCode       string

	// Write bookkeeping (design B.1): what earlier writes took.
	// groups are the sealed header groups in capture order.
	groups         []headerGroup
	rowWritten     bool
	bodyRowWritten bool
	// merged: a checkpoint wrote this duplicate's body row pointing at its
	// source, without chunks of its own.
	merged bool
	// spillWritten: the checkpoint of the stage's first spill to staging was
	// accepted (design F.3).
	spillWritten bool
	// Capture version 2: the Header fields snapshotted at stage start and the
	// Trailer fields when they arrived (hasTrailers).
	headerFields  []headerblock.Field
	trailerFields []headerblock.Field
	hasTrailers   bool
}

// TerminalSummary is the immutable, non-sensitive request outcome available
// after Finish returns. It contains no Header values, Body bytes, Query, keys,
// tokens, or underlying error text.
type TerminalSummary struct {
	AuditID       string
	StatusCode    int
	HasStatusCode bool
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
	BlockedBy     string
	BlockCode     string
	ErrorCode     string
}

// Session owns the concurrency-safe state for one audit. Capture uses bounded
// staging and codec working buffers instead of accumulating complete bodies.
type Session struct {
	auditID  string
	routeID  string
	started  time.Time
	store    Store
	cipher   security.Cipher
	logger   *slog.Logger
	now      func() time.Time
	request  context.Context
	writeCtx context.Context
	// terminalMatcher is the protocol-owned SSE terminal-line matcher for
	// this route's parser, provided by internal/parser/streamterminal.
	terminalMatcher streamterminal.Matcher
	notify          func(string) bool
	callerNotify    func(string) bool
	gaps            *gapBuffer

	// bodyEncoder is session-local and accessed only while holding mu.
	bodyEncoder     *bodycodec.Encoder
	mu              sync.Mutex
	stages          map[string]*stageCapture
	captureFault    bool
	statusCode      *int
	forwardStatus   string
	blockedBy       *string
	blockCode       *string
	errorCode       *string
	terminal        *TerminalSummary
	gapRecorded     bool
	newAPIRequestID *string

	finishOnce sync.Once
	finishErr  error

	// manager is the session's manager: budgets, stager, capture version.
	manager *Manager
	// identity is what the parser needs of the audit row (Protocol,
	// ParserName, Path), for the hand-over.
	identity storage.ParserAudit
	// memoryHeld is the plaintext this session holds in the global budget.
	memoryHeld int64
	// requestSentEnded: checkpoint 1's trigger has fired (or was skipped).
	requestSentEnded bool
	// committing is set when Finish builds the commit; no checkpoint follows.
	committing bool
	// inboundNotStored: BeginAudit kept the start row without the inbound
	// stage (storage.ErrInboundStageNotStored).
	inboundNotStored bool
	// writtenBlock is the shape of the last header block an accepted write
	// carried (capture version 2); blockWritten is false before the first.
	writtenBlock blockShape
	blockWritten bool
	// stagedChunks: some chunk of this session went to the stager, whose file
	// the session releases after the commit.
	stagedChunks bool
}

func newSession(manager *Manager, requestContext context.Context, auditID, routeID string, started time.Time) *Session {
	session := &Session{
		auditID:       auditID,
		routeID:       routeID,
		started:       started,
		store:         manager.store,
		cipher:        manager.cipher,
		logger:        manager.logger,
		now:           manager.now,
		request:       requestContext,
		writeCtx:      context.WithoutCancel(requestContext),
		notify:        manager.completionNotifier(),
		callerNotify:  manager.callerNotifier(),
		stages:        make(map[string]*stageCapture, 4),
		forwardStatus: storage.ForwardInProgress,
		manager:       manager,
	}
	if manager.mode == ModeAvailable {
		session.gaps = manager.gaps
	}
	return session
}

// ID returns the opaque audit identifier safe for logs and correlation.
func (session *Session) ID() string {
	if session == nil {
		return ""
	}
	return session.auditID
}

// Terminal returns a copy of the finalized non-sensitive outcome. The second
// result is false until Finish has completed.
func (session *Session) Terminal() (TerminalSummary, bool) {
	if session == nil {
		return TerminalSummary{}, false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.terminal == nil {
		return TerminalSummary{}, false
	}
	return *session.terminal, true
}

// WrapRequestReceived starts the inbound stage, stores its Header values, and
// wraps its Body before interceptors can read it.
func (session *Session) WrapRequestReceived(request *http.Request) {
	if session == nil || request == nil {
		return
	}
	stage := session.startStage(storage.StageRequestReceived, request.Proto, request.Method, request.Host, nil, contentLengthPointer(request.ContentLength), request.Header, hasBody(request.Body))
	if stage != nil && hasBody(request.Body) {
		request.Body = newObservedReadCloser(request.Body, session, stage.name, func() http.Header { return request.Trailer })
	}
}

// WrapRequestSent starts the actual outbound request stage after Rewrite and
// wraps the Body that Transport will consume.
func (session *Session) WrapRequestSent(request *http.Request) {
	if session == nil || request == nil {
		return
	}
	stage := session.startStage(storage.StageRequestSent, request.Proto, request.Method, request.Host, nil, contentLengthPointer(request.ContentLength), request.Header, hasBody(request.Body))
	if stage != nil && hasBody(request.Body) {
		request.Body = newObservedReadCloser(request.Body, session, stage.name, func() http.Header { return request.Trailer })
	}
}

// WrapResponseReceived starts the upstream response stage when headers arrive
// and wraps the Body ReverseProxy will consume.
func (session *Session) WrapResponseReceived(response *http.Response) {
	if session == nil || response == nil {
		return
	}
	host := ""
	method := ""
	if response.Request != nil {
		host = response.Request.Host
		method = response.Request.Method
	}
	if requestID := strings.TrimSpace(response.Header.Get(newAPIRequestIDHeader)); validNewAPIRequestID(requestID) {
		session.mu.Lock()
		session.newAPIRequestID = stringPointer(requestID)
		session.mu.Unlock()
	}
	stage := session.startStage(storage.StageResponseReceived, response.Proto, method, host, intPointer(response.StatusCode), contentLengthPointer(response.ContentLength), response.Header, hasBody(response.Body))
	if stage != nil && hasBody(response.Body) {
		response.Body = newObservedReadCloser(response.Body, session, stage.name, func() http.Header { return response.Trailer })
	}
}

// WrapResponseWriter returns a writer that lazily creates the downstream
// stage only when a response header or body write is attempted.
func (session *Session) WrapResponseWriter(writer http.ResponseWriter, request *http.Request) *observedResponseWriter {
	if session == nil || writer == nil {
		return nil
	}
	proto := ""
	if request != nil {
		proto = request.Proto
	}
	return &observedResponseWriter{underlying: writer, session: session, proto: proto}
}

// MarkRejected records the local interceptor terminal result. It never
// creates an outbound or response stage.
func (session *Session) MarkRejected(status int, blockedBy, blockCode string) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.forwardStatus != storage.ForwardInProgress {
		return
	}
	session.forwardStatus = storage.ForwardRejected
	session.statusCode = intPointer(status)
	session.blockedBy = stringPointer(blockedBy)
	session.blockCode = stringPointer(blockCode)
}

// MarkNewAPIError records a transport or upstream response-read failure.
func (session *Session) MarkNewAPIError(errorCode string) {
	session.markFailure(storage.ForwardNewAPIError, errorCode)
}

// MarkProxyError records a downstream response-write failure.
func (session *Session) MarkProxyError(errorCode string) {
	session.markFailure(storage.ForwardProxyError, errorCode)
}

// MarkClientCancelled records cancellation without block fields.
func (session *Session) MarkClientCancelled() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.forwardStatus == storage.ForwardRejected {
		return
	}
	if session.responseLogicallyCompleteLocked() {
		// A disconnect after the response was fully received (transport EOF
		// or a stream terminal event) is a benign hang-up, not a
		// cancellation; Finish will record the session as completed.
		return
	}
	session.forwardStatus = storage.ForwardClientCancelled
	session.blockedBy = nil
	session.blockCode = nil
	code := "client_cancelled"
	session.errorCode = &code
}

// responseLogicallyCompleteLocked reports whether the response was received
// in full AND every received byte was already handed to the client, so a
// subsequent client disconnect is a benign hang-up rather than a
// cancellation. Clients such as Codex close the connection immediately after
// the stream's terminal event without reading to transport EOF, which cancels
// the request context even though nothing was lost.
//
// Reception is complete when transport EOF was observed or the event stream
// dispatched its protocol-level terminal event, and the observed length
// satisfies any declared Content-Length. Delivery is complete when the
// response_sent stage has observed at least the same number of bytes without
// a downstream write failure. Capture-internal faults (persistence,
// encryption) intentionally do not change this transport classification;
// they still surface through capture_status.
func (session *Session) responseLogicallyCompleteLocked() bool {
	received := session.stages[storage.StageResponseReceived]
	if received == nil || received.body == nil {
		return false
	}
	receivedBody := received.body
	if !receivedBody.eofSeen && !receivedBody.streamTerminalSeen {
		return false
	}
	if received.contentLength != nil && *received.contentLength >= 0 &&
		receivedBody.observedLength < *received.contentLength {
		return false
	}
	sent := session.stages[storage.StageResponseSent]
	if sent == nil || sent.body == nil || sent.body.writeFailed {
		return false
	}
	return sent.body.observedLength >= receivedBody.observedLength
}

func (session *Session) markFailure(status, errorCode string) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.forwardStatus == storage.ForwardRejected || session.forwardStatus == storage.ForwardClientCancelled {
		return
	}
	if session.request != nil && session.request.Err() != nil && !session.responseLogicallyCompleteLocked() {
		session.forwardStatus = storage.ForwardClientCancelled
		code := "client_cancelled"
		session.errorCode = &code
		return
	}
	session.forwardStatus = status
	if errorCode != "" {
		session.errorCode = stringPointer(errorCode)
	}
}

// Finish finalizes all actually started stages, then synchronously commits the
// terminal parent update. It is safe to call more than once.
func (session *Session) Finish() error {
	if session == nil {
		return nil
	}
	session.finishOnce.Do(func() {
		session.finishErr = session.timedFinish()
	})
	return session.finishErr
}

func (session *Session) finishStageLocked(stage *stageCapture) storage.StageFinish {
	state := storage.StageStateComplete
	errorCode := stage.errorCode
	if stage.faulted || stage.expectsBody && stage.body == nil {
		state = storage.StageStatePartial
		session.captureFault = true
	}

	var bodyFinish *storage.BodyFinish
	if stage.body != nil {
		body := stage.body
		session.flushBodyLocked(stage, body, true)
		if stage.name == storage.StageResponseSent && !body.closed && !stage.faulted && session.forwardStatus == storage.ForwardCompleted {
			body.eofSeen = true
			body.hashComplete = true
			body.closed = true
		}
		storedLength := body.storedLength
		chunkCount := body.chunkCount
		streamEventCount := body.streamEvents
		streamTimelineComplete := true
		var timeline *storage.StreamTimeline
		if body.sourceStage == stage.name && body.streamEvents > 0 {
			var timelineErr error
			timeline, timelineErr = session.sealStreamTimelineLocked(stage, body)
			if timelineErr != nil {
				// No sealed timeline can vouch for these events.
				streamTimelineComplete = false
				body.faulted = true
				body.errorCode = "stream_timeline_failed"
				session.markStageFaultLocked(stage, body.errorCode)
			} else if timeline != nil {
				streamTimelineComplete = timeline.Complete
			}
		}
		if sourceStage := pairedBodySourceStage(stage.name); sourceStage != "" {
			if source := session.stages[sourceStage]; source != nil && source.body != nil &&
				body.hashComplete && body.eofSeen && source.body.hashComplete && source.body.eofSeen &&
				(body.observedLength != source.body.observedLength || !bytesEqual(body.digest.Sum(nil), source.body.digest.Sum(nil))) {
				body.faulted = true
				body.errorCode = "body_stage_mismatch"
				session.markStageFaultLocked(stage, body.errorCode)
			}
		}
		errorCode = stage.errorCode
		bodyState := storage.StageStateComplete
		if body.faulted || !body.eofSeen || storedLength != body.observedLength {
			bodyState = storage.StageStatePartial
			state = storage.StageStatePartial
			session.captureFault = true
		}
		bodyError := body.errorCode
		if bodyError == "" {
			bodyError = errorCode
		}
		// A body whose start was rejected has no row to finish. Its fault is
		// already on the stage; sending the body would fail as a writer error.
		if body.persisted {
			bodyFinish = &storage.BodyFinish{
				ObservedLength:         body.observedLength,
				StoredLength:           storedLength,
				SHA256:                 body.digest.Sum(nil),
				HashComplete:           body.hashComplete,
				EOFSeen:                body.eofSeen,
				State:                  bodyState,
				RetentionState:         storage.RetentionPending,
				FirstObservedAtNS:      optionalInt64(body.firstAtNS),
				LastObservedAtNS:       optionalInt64(body.lastAtNS),
				ChunkCount:             chunkCount,
				StreamEventCount:       streamEventCount,
				StreamTimelineComplete: streamTimelineComplete,
				Timeline:               timeline,
				ErrorCode:              optionalString(bodyError),
			}
		}
	}
	return storage.StageFinish{
		AuditID:       session.auditID,
		Stage:         stage.name,
		State:         state,
		StatusCode:    cloneInt(stage.statusCode),
		ContentLength: cloneInt64(stage.contentLength),
		EndedAtNS:     session.now().UnixNano(),
		ErrorCode:     optionalString(errorCode),
		Body:          bodyFinish,
	}
}

func optionalInt64(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func pairedBodySourceStage(stage string) string {
	switch stage {
	case storage.StageRequestSent:
		return storage.StageRequestReceived
	case storage.StageResponseSent:
		return storage.StageResponseReceived
	default:
		return ""
	}
}

func (session *Session) startStage(name, proto, method, host string, statusCode *int, contentLength *int64, headers http.Header, expectsBody bool) *stageCapture {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if existing := session.stages[name]; existing != nil {
		return existing
	}

	stage := &stageCapture{
		name:            name,
		startedAtNS:     session.now().UnixNano(),
		proto:           proto,
		method:          method,
		host:            host,
		statusCode:      cloneInt(statusCode),
		contentLength:   cloneInt64(contentLength),
		contentType:     headers.Get("Content-Type"),
		contentEncoding: headers.Get("Content-Encoding"),
		expectsBody:     expectsBody,
	}
	session.stages[name] = stage
	if statusCode != nil {
		session.statusCode = cloneInt(statusCode)
	}

	// The stage is written by a later checkpoint or the commit; its headers
	// are sealed (or, for capture version 2, snapshotted) now, at stage start.
	stage.persisted = true
	session.addHeadersLocked(stage, storage.HeaderKindHeader, headers)
	return stage
}

func (session *Session) addHeaders(stageName, kind string, headers http.Header) {
	if session == nil || len(headers) == 0 {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	stage := session.stages[stageName]
	if stage == nil || !stage.persisted {
		return
	}
	session.addHeadersLocked(stage, kind, headers)
}

func (session *Session) addHeadersLocked(stage *stageCapture, kind string, headers http.Header) {
	if len(headers) == 0 || !stage.persisted {
		return
	}
	if session.headerBlockLocked() {
		session.snapshotHeadersLocked(stage, kind, headers)
		return
	}
	session.addHeaderGroupLocked(stage, kind, headers)
}

func (session *Session) markStageFaultLocked(stage *stageCapture, errorCode string) {
	stage.faulted = true
	if stage.errorCode == "" {
		stage.errorCode = errorCode
	}
	session.captureFault = true
	if errorCode == "header_encryption_failed" || errorCode == "body_encryption_failed" {
		session.recordGapReasonLocked(storage.GapReasonEncryption)
	}
	session.logCaptureFailure(stage.name, errorCode)
}

func (session *Session) recordGapReason(reason string) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.recordGapReasonLocked(reason)
}

func (session *Session) recordGapReasonLocked(reason string) {
	if session == nil || session.gaps == nil || session.gapRecorded {
		return
	}
	session.gapRecorded = true
	session.gaps.record(reason)
}

func (session *Session) logCaptureFailure(stage, errorCode string) {
	if session.logger == nil {
		return
	}
	arguments := []any{"audit_id", session.auditID, "route_id", session.routeID, "error_code", errorCode}
	if stage != "" {
		arguments = append(arguments, "stage", stage)
	}
	session.logger.Warn("audit capture degraded", arguments...)
}

func stageOrder(stage string) int {
	switch stage {
	case storage.StageRequestReceived:
		return 1
	case storage.StageRequestSent:
		return 2
	case storage.StageResponseReceived:
		return 3
	case storage.StageResponseSent:
		return 4
	default:
		return 5
	}
}

func hasBody(body interface{ Close() error }) bool {
	return body != nil && reflect.TypeOf(body) != reflect.TypeOf(http.NoBody)
}

func contentLengthPointer(length int64) *int64 {
	value := length
	return &value
}

func intPointer(value int) *int {
	cloned := value
	return &cloned
}

func stringPointer(value string) *string {
	cloned := value
	return &cloned
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return stringPointer(value)
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	return intPointer(*value)
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
	return stringPointer(*value)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func validNewAPIRequestID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}
