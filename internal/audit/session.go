package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const bodyChunkSize = 32 << 10

type stageCapture struct {
	name          string
	persisted     bool
	startedAtNS   int64
	proto         string
	method        string
	host          string
	statusCode    *int
	contentLength *int64
	expectsBody   bool
	body          *bodyCapture
	faulted       bool
	errorCode     string
}

// Session owns the small, concurrency-safe state for one audit. It never
// retains complete request or response bodies.
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
	notify   func(string) bool

	mu            sync.Mutex
	stages        map[string]*stageCapture
	captureFault  bool
	statusCode    *int
	forwardStatus string
	blockedBy     *string
	blockCode     *string
	errorCode     *string

	finishOnce sync.Once
	finishErr  error
}

func newSession(manager *Manager, requestContext context.Context, auditID, routeID string, started time.Time) *Session {
	return &Session{
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
		stages:        make(map[string]*stageCapture, 4),
		forwardStatus: sqlite.ForwardInProgress,
	}
}

// ID returns the opaque audit identifier safe for logs and correlation.
func (session *Session) ID() string {
	if session == nil {
		return ""
	}
	return session.auditID
}

// WrapRequestReceived starts the inbound stage, stores its Header values, and
// wraps its Body before interceptors can read it.
func (session *Session) WrapRequestReceived(request *http.Request) {
	if session == nil || request == nil {
		return
	}
	stage := session.startStage(sqlite.StageRequestReceived, request.Proto, request.Method, request.Host, nil, contentLengthPointer(request.ContentLength), request.Header, hasBody(request.Body))
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
	stage := session.startStage(sqlite.StageRequestSent, request.Proto, request.Method, request.Host, nil, contentLengthPointer(request.ContentLength), request.Header, hasBody(request.Body))
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
	stage := session.startStage(sqlite.StageResponseReceived, response.Proto, method, host, intPointer(response.StatusCode), contentLengthPointer(response.ContentLength), response.Header, hasBody(response.Body))
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
	if session.forwardStatus != sqlite.ForwardInProgress {
		return
	}
	session.forwardStatus = sqlite.ForwardRejected
	session.statusCode = intPointer(status)
	session.blockedBy = stringPointer(blockedBy)
	session.blockCode = stringPointer(blockCode)
}

// MarkNewAPIError records a transport or upstream response-read failure.
func (session *Session) MarkNewAPIError(errorCode string) {
	session.markFailure(sqlite.ForwardNewAPIError, errorCode)
}

// MarkProxyError records a downstream response-write failure.
func (session *Session) MarkProxyError(errorCode string) {
	session.markFailure(sqlite.ForwardProxyError, errorCode)
}

// MarkClientCancelled records cancellation without block fields.
func (session *Session) MarkClientCancelled() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.forwardStatus == sqlite.ForwardRejected {
		return
	}
	session.forwardStatus = sqlite.ForwardClientCancelled
	session.blockedBy = nil
	session.blockCode = nil
	code := "client_cancelled"
	session.errorCode = &code
}

func (session *Session) markFailure(status, errorCode string) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.forwardStatus == sqlite.ForwardRejected || session.forwardStatus == sqlite.ForwardClientCancelled {
		return
	}
	if session.request != nil && session.request.Err() != nil {
		session.forwardStatus = sqlite.ForwardClientCancelled
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
		session.finishErr = session.finish()
	})
	return session.finishErr
}

func (session *Session) finish() error {
	session.mu.Lock()
	if session.forwardStatus == sqlite.ForwardInProgress {
		if session.request != nil && session.request.Err() != nil {
			session.forwardStatus = sqlite.ForwardClientCancelled
			session.errorCode = stringPointer("client_cancelled")
		} else {
			session.forwardStatus = sqlite.ForwardCompleted
		}
	}
	if session.forwardStatus == sqlite.ForwardClientCancelled || session.forwardStatus == sqlite.ForwardNewAPIError || session.forwardStatus == sqlite.ForwardProxyError {
		session.captureFault = true
	}

	stageNames := make([]string, 0, len(session.stages))
	for name := range session.stages {
		stageNames = append(stageNames, name)
	}
	sort.Slice(stageNames, func(left, right int) bool { return stageOrder(stageNames[left]) < stageOrder(stageNames[right]) })
	finishes := make([]sqlite.StageFinish, 0, len(stageNames))
	for _, name := range stageNames {
		stage := session.stages[name]
		finish := session.finishStageLocked(stage)
		if stage.persisted {
			finishes = append(finishes, finish)
		}
	}

	forwardStatus := session.forwardStatus
	statusCode := cloneInt(session.statusCode)
	blockedBy := cloneString(session.blockedBy)
	blockCode := cloneString(session.blockCode)
	errorCode := cloneString(session.errorCode)
	captureStatus := sqlite.CaptureComplete
	if session.captureFault {
		captureStatus = sqlite.CapturePartial
	}
	parseStatus := sqlite.ParsePending
	if forwardStatus == sqlite.ForwardRejected {
		parseStatus = sqlite.ParseSkipped
	}
	endedAtNS := session.now().UnixNano()
	session.mu.Unlock()

	var writeErrors []error
	for _, finish := range finishes {
		if err := session.store.FinishStage(session.writeCtx, finish); err != nil {
			writeErrors = append(writeErrors, fmt.Errorf("finish stage %s: %w", finish.Stage, err))
			captureStatus = sqlite.CapturePartial
			session.logCaptureFailure(finish.Stage, "finish_stage_failed")
		}
	}
	finish := sqlite.AuditFinish{
		AuditID:       session.auditID,
		EndedAtNS:     endedAtNS,
		StatusCode:    statusCode,
		ForwardStatus: forwardStatus,
		CaptureStatus: captureStatus,
		ParseStatus:   parseStatus,
		BlockedBy:     blockedBy,
		BlockCode:     blockCode,
		ErrorCode:     errorCode,
	}
	if err := session.store.FinishAudit(session.writeCtx, finish); err != nil {
		writeErrors = append(writeErrors, fmt.Errorf("finish audit: %w", err))
		session.logCaptureFailure("", "finish_audit_failed")
	} else if parseStatus == sqlite.ParsePending && session.notify != nil {
		_ = session.notify(session.auditID)
	}
	return errors.Join(writeErrors...)
}

func (session *Session) finishStageLocked(stage *stageCapture) sqlite.StageFinish {
	state := sqlite.StageStateComplete
	errorCode := stage.errorCode
	if stage.faulted || stage.expectsBody && stage.body == nil {
		state = sqlite.StageStatePartial
		session.captureFault = true
	}

	var bodyFinish *sqlite.BodyFinish
	if stage.body != nil {
		body := stage.body
		if stage.name == sqlite.StageResponseSent && !body.closed && !stage.faulted && session.forwardStatus == sqlite.ForwardCompleted {
			body.eofSeen = true
			body.hashComplete = true
			body.closed = true
		}
		bodyState := sqlite.StageStateComplete
		if body.faulted || !body.eofSeen || body.storedLength != body.observedLength {
			bodyState = sqlite.StageStatePartial
			state = sqlite.StageStatePartial
			session.captureFault = true
		}
		bodyError := body.errorCode
		if bodyError == "" {
			bodyError = errorCode
		}
		bodyFinish = &sqlite.BodyFinish{
			ObservedLength: body.observedLength,
			StoredLength:   body.storedLength,
			SHA256:         body.digest.Sum(nil),
			HashComplete:   body.hashComplete,
			EOFSeen:        body.eofSeen,
			State:          bodyState,
			ErrorCode:      optionalString(bodyError),
		}
	}
	return sqlite.StageFinish{
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
		name:          name,
		startedAtNS:   session.now().UnixNano(),
		proto:         proto,
		method:        method,
		host:          host,
		statusCode:    cloneInt(statusCode),
		contentLength: cloneInt64(contentLength),
		expectsBody:   expectsBody,
	}
	session.stages[name] = stage
	if statusCode != nil {
		session.statusCode = cloneInt(statusCode)
	}

	write := sqlite.HTTPStage{
		AuditID:       session.auditID,
		Stage:         name,
		State:         sqlite.StageStateStreaming,
		Proto:         proto,
		Method:        method,
		Host:          host,
		StatusCode:    cloneInt(statusCode),
		ContentLength: cloneInt64(contentLength),
		StartedAtNS:   stage.startedAtNS,
	}
	if err := session.store.StartStage(session.writeCtx, write); err != nil {
		stage.faulted = true
		stage.errorCode = "start_stage_failed"
		session.captureFault = true
		session.logCaptureFailure(name, stage.errorCode)
		return stage
	}
	stage.persisted = true
	session.addHeadersLocked(stage, sqlite.HeaderKindHeader, headers)
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
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]sqlite.HTTPHeader, 0)
	for _, name := range names {
		for index, value := range headers.Values(name) {
			aad, err := security.AAD(session.auditID, "header", stage.name, kind, name, strconv.Itoa(index))
			if err != nil {
				session.markStageFaultLocked(stage, "header_encryption_failed")
				continue
			}
			encrypted, err := session.cipher.Encrypt(aad, []byte(value))
			if err != nil {
				session.markStageFaultLocked(stage, "header_encryption_failed")
				continue
			}
			values = append(values, sqlite.HTTPHeader{
				AuditID:     session.auditID,
				Stage:       stage.name,
				Kind:        kind,
				Name:        name,
				ValueIndex:  index,
				ValueLength: len(value),
				ValueEnc:    encrypted,
			})
		}
	}
	if err := session.store.AddHeaders(session.writeCtx, values); err != nil {
		session.markStageFaultLocked(stage, "add_headers_failed")
	}
}

func (session *Session) markStageFaultLocked(stage *stageCapture, errorCode string) {
	stage.faulted = true
	if stage.errorCode == "" {
		stage.errorCode = errorCode
	}
	session.captureFault = true
	session.logCaptureFailure(stage.name, errorCode)
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
	case sqlite.StageRequestReceived:
		return 1
	case sqlite.StageRequestSent:
		return 2
	case sqlite.StageResponseReceived:
		return 3
	case sqlite.StageResponseSent:
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
