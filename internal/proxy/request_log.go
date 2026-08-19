package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/storage/sqlite"
)

const clientClosedRequestStatus = 499

type requestCompletionContextKey struct{}

type requestCompletionState struct {
	mu sync.Mutex

	auditID       string
	statusCode    int
	forwardStatus string
	captureStatus string
	parseStatus   string
	blockedBy     string
	blockCode     string
	errorCode     string
}

type requestCompletionSnapshot struct {
	auditID       string
	statusCode    int
	forwardStatus string
	captureStatus string
	parseStatus   string
	blockedBy     string
	blockCode     string
	errorCode     string
}

func newRequestCompletionState(auditConfigured bool) *requestCompletionState {
	state := &requestCompletionState{
		forwardStatus: sqlite.ForwardInProgress,
		captureStatus: sqlite.CaptureFailed,
		parseStatus:   sqlite.ParseSkipped,
	}
	if auditConfigured {
		state.captureStatus = sqlite.CapturePending
		state.parseStatus = sqlite.ParsePending
	}
	return state
}

func contextWithRequestCompletion(ctx context.Context, state *requestCompletionState) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestCompletionContextKey{}, state)
}

func requestCompletionFromContext(ctx context.Context) (*requestCompletionState, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(requestCompletionContextKey{}).(*requestCompletionState)
	return state, ok && state != nil
}

func (state *requestCompletionState) markAuditUnavailable(reject bool) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.captureStatus = sqlite.CaptureFailed
	state.parseStatus = sqlite.ParseSkipped
	state.errorCode = "audit_unavailable"
	if reject {
		state.forwardStatus = sqlite.ForwardRejected
		state.statusCode = http.StatusServiceUnavailable
	}
}

func (state *requestCompletionState) markRejected(status int, blockedBy, blockCode, errorCode string) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.forwardStatus = sqlite.ForwardRejected
	state.statusCode = status
	state.parseStatus = sqlite.ParseSkipped
	state.blockedBy = blockedBy
	state.blockCode = blockCode
	if errorCode != "" {
		state.errorCode = errorCode
	}
}

func (state *requestCompletionState) markClientCancelled() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.forwardStatus == sqlite.ForwardRejected {
		return
	}
	state.forwardStatus = sqlite.ForwardClientCancelled
	state.blockedBy = ""
	state.blockCode = ""
	state.errorCode = "client_cancelled"
	if state.statusCode == 0 {
		state.statusCode = clientClosedRequestStatus
	}
}

func (state *requestCompletionState) markNewAPIError(errorCode string) {
	state.markForwardFailure(sqlite.ForwardNewAPIError, errorCode)
}

func (state *requestCompletionState) markProxyError(errorCode string) {
	state.markForwardFailure(sqlite.ForwardProxyError, errorCode)
}

func (state *requestCompletionState) markForwardFailure(forwardStatus, errorCode string) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.forwardStatus == sqlite.ForwardRejected || state.forwardStatus == sqlite.ForwardClientCancelled {
		return
	}
	state.forwardStatus = forwardStatus
	if errorCode != "" {
		state.errorCode = errorCode
	}
}

func (state *requestCompletionState) markCompleted() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.forwardStatus == sqlite.ForwardInProgress {
		state.forwardStatus = sqlite.ForwardCompleted
	}
}

func (state *requestCompletionState) applyTerminal(summary audit.TerminalSummary) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.auditID = summary.AuditID
	state.forwardStatus = summary.ForwardStatus
	state.captureStatus = summary.CaptureStatus
	state.parseStatus = summary.ParseStatus
	state.blockedBy = summary.BlockedBy
	state.blockCode = summary.BlockCode
	if summary.HasStatusCode {
		state.statusCode = summary.StatusCode
	}
	if summary.ErrorCode != "" {
		state.errorCode = summary.ErrorCode
	} else if summary.ForwardStatus == sqlite.ForwardCompleted {
		// A benign post-terminal disconnect may have transiently recorded
		// client_cancelled before the audit session reclassified the
		// request as completed; the completion log must not mix the two.
		state.errorCode = ""
	}
}

func (state *requestCompletionState) finalize(ctx context.Context) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.forwardStatus != sqlite.ForwardInProgress {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		state.forwardStatus = sqlite.ForwardClientCancelled
		state.errorCode = "client_cancelled"
		if state.statusCode == 0 {
			state.statusCode = clientClosedRequestStatus
		}
		return
	}
	state.forwardStatus = sqlite.ForwardProxyError
	state.errorCode = "proxy_aborted"
}

func (state *requestCompletionState) snapshot() requestCompletionSnapshot {
	if state == nil {
		return requestCompletionSnapshot{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return requestCompletionSnapshot{
		auditID:       state.auditID,
		statusCode:    state.statusCode,
		forwardStatus: state.forwardStatus,
		captureStatus: state.captureStatus,
		parseStatus:   state.parseStatus,
		blockedBy:     state.blockedBy,
		blockCode:     state.blockCode,
		errorCode:     state.errorCode,
	}
}

type observedUpstreamBody struct {
	underlying io.ReadCloser
	ctx        context.Context
	state      *requestCompletionState
}

func (body *observedUpstreamBody) Read(buffer []byte) (int, error) {
	count, err := body.underlying.Read(buffer)
	if err == nil || errors.Is(err, io.EOF) {
		return count, err
	}
	if body.ctx != nil && body.ctx.Err() != nil || errors.Is(err, context.Canceled) {
		body.state.markClientCancelled()
	} else {
		body.state.markNewAPIError("upstream_body_read_error")
	}
	return count, err
}

func (body *observedUpstreamBody) Close() error {
	return body.underlying.Close()
}
