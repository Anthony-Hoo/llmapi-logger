// Package proxy implements the LLM API whitelist data-plane reverse proxy.
package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/observability"
	"llmapi-logger/internal/routing"
)

const (
	requestRejectedJSON        = `{"error":{"code":"request_rejected","message":"request rejected"}}`
	interceptorUnavailableJSON = `{"error":{"code":"interceptor_unavailable","message":"request cannot be processed"}}`
	auditUnavailableJSON       = `{"error":{"code":"audit_unavailable","message":"request cannot be audited"}}`
	routeNotAllowedJSON        = `{"error":{"code":"audit_route_not_allowed","message":"route is not enabled"}}`
	newAPIUnavailableJSON      = `{"error":{"code":"newapi_unavailable","message":"upstream request failed"}}`
	newAPITimeoutJSON          = `{"error":{"code":"newapi_timeout","message":"upstream response timed out"}}`
)

// New returns a handler that accepts only routes compiled into matcher,
// evaluates their interceptor chain, and forwards allowed requests to target.
func New(target *url.URL, matcher *routing.Matcher, engine *interceptor.Engine, logger *slog.Logger) http.Handler {
	return NewWithOptions(target, matcher, engine, Options{}, logger)
}

// NewWithAudit returns the stage-one proxy with encrypted evidence capture
// enabled for matched requests. Passing a nil sink preserves New's behavior.
func NewWithAudit(target *url.URL, matcher *routing.Matcher, engine *interceptor.Engine, sink audit.Sink, logger *slog.Logger) http.Handler {
	return NewWithOptions(target, matcher, engine, Options{Audit: sink}, logger)
}

// Options contains the optional data-plane dependencies. UpstreamProxy is
// nil for direct connections and never falls back to process environment
// proxy variables.
type Options struct {
	Audit         audit.Sink
	UpstreamProxy *url.URL
}

// NewWithOptions returns the data-plane proxy with explicit optional
// dependencies.
func NewWithOptions(target *url.URL, matcher *routing.Matcher, engine *interceptor.Engine, options Options, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	handler := &handler{
		matcher: matcher,
		engine:  engine,
		audit:   options.Audit,
		logger:  logger,
	}
	if target == nil {
		handler.initializationError = errors.New("proxy: nil NewAPI target")
		return handler
	}

	handler.target = cloneURL(target)
	handler.reverseProxy = newReverseProxy(handler.target, options.UpstreamProxy, logger)
	return handler
}

// NewPassthrough returns a transparent NewAPI reverse proxy without route
// matching, interception, audit capture, or completion logging. Callers must
// enforce the audited route boundary before dispatching requests here.
func NewPassthrough(target, upstreamProxy *url.URL, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	passthrough := &passthroughHandler{logger: logger}
	if target == nil {
		passthrough.initializationError = errors.New("proxy: nil NewAPI passthrough target")
		return passthrough
	}
	passthrough.reverseProxy = newReverseProxy(cloneURL(target), upstreamProxy, logger)
	return passthrough
}

type passthroughHandler struct {
	logger              *slog.Logger
	reverseProxy        *httputil.ReverseProxy
	initializationError error
}

func (h *passthroughHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if h == nil || h.reverseProxy == nil {
		if h != nil && h.logger != nil {
			h.logger.Error("NewAPI passthrough unavailable", "error", h.initializationError)
		}
		writeJSON(response, http.StatusServiceUnavailable, newAPIUnavailableJSON)
		return
	}
	h.reverseProxy.ServeHTTP(response, request)
}

type handler struct {
	target              *url.URL
	matcher             *routing.Matcher
	engine              *interceptor.Engine
	audit               audit.Sink
	logger              *slog.Logger
	reverseProxy        *httputil.ReverseProxy
	initializationError error
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	if h.initializationError != nil || h.matcher == nil || h.reverseProxy == nil {
		h.logger.Error("proxy unavailable", "error", h.initializationError)
		writeJSON(response, http.StatusServiceUnavailable, interceptorUnavailableJSON)
		return
	}

	escapedPath := "/"
	if request.URL != nil {
		escapedPath = request.URL.EscapedPath()
	}
	match, ok := h.matcher.Match(request.Method, escapedPath)
	if !ok {
		writeJSON(response, http.StatusNotFound, routeNotAllowedJSON)
		return
	}

	recorder := observability.NewResponseRecorder(response)
	response = recorder
	completion := newRequestCompletionState(h.audit != nil)
	request = request.WithContext(contextWithRequestCompletion(request.Context(), completion))
	var session *audit.Session
	defer func() {
		if recorder.WriteFailed() {
			completion.markProxyError("downstream_write_error")
		}
		if session != nil {
			if terminal, ready := session.Terminal(); ready {
				completion.applyTerminal(terminal)
			}
		}
		completion.finalize(request.Context())
		snapshot := completion.snapshot()
		statusCode := recorder.StatusCode()
		if statusCode == 0 {
			statusCode = snapshot.statusCode
		}
		ttft := time.Duration(-1)
		if firstWrite, exists := recorder.FirstWriteAt(); exists {
			ttft = firstWrite.Sub(started)
			if ttft < 0 {
				ttft = 0
			}
		}
		auditID := snapshot.auditID
		if auditID == "" && session != nil {
			auditID = session.ID()
		}
		observability.LogRequestCompleted(request.Context(), h.logger, observability.RequestCompletion{
			AuditID:       auditID,
			RouteID:       match.RouteID,
			Protocol:      protocolForParser(match.Parser),
			Method:        request.Method,
			EscapedPath:   escapedPath,
			StatusCode:    statusCode,
			Duration:      time.Since(started),
			TTFT:          ttft,
			ForwardStatus: snapshot.forwardStatus,
			CaptureStatus: snapshot.captureStatus,
			ParseStatus:   snapshot.parseStatus,
			BlockedBy:     snapshot.blockedBy,
			BlockCode:     snapshot.blockCode,
			ErrorCode:     snapshot.errorCode,
		})
	}()

	session, ok = h.beginAudit(request, match)
	if !ok {
		completion.markAuditUnavailable(true)
		writeJSON(response, http.StatusServiceUnavailable, auditUnavailableJSON)
		return
	}
	if session == nil && h.audit != nil {
		completion.markAuditUnavailable(false)
	}
	if session != nil {
		request = request.WithContext(audit.ContextWithSession(request.Context(), session))
		defer func() {
			if err := session.Finish(); err != nil {
				h.logger.WarnContext(
					context.WithoutCancel(request.Context()),
					"audit finish failed",
					"audit_id", session.ID(),
					"route_id", match.RouteID,
					"error_category", "write_error",
				)
			}
		}()
	}

	result := h.engine.Evaluate(request.Context(), request, match)
	if result.Cancelled || request.Context().Err() != nil {
		completion.markClientCancelled()
		if session != nil {
			session.MarkClientCancelled()
		}
		return
	}
	if result.Internal != nil {
		blockedBy, blockCode := stableBlock(result.BlockedBy, result.BlockCode)
		completion.markRejected(http.StatusServiceUnavailable, blockedBy, blockCode, blockCode)
		if session != nil {
			session.MarkRejected(http.StatusServiceUnavailable, blockedBy, blockCode)
		}
		h.logger.WarnContext(
			request.Context(),
			"interceptor unavailable",
			"route_id", match.RouteID,
			"blocked_by", blockedBy,
			"block_code", blockCode,
		)
		closeRequestBody(request)
		writeJSON(response, http.StatusServiceUnavailable, interceptorUnavailableJSON)
		return
	}
	if !result.Allowed {
		status := result.StatusCode
		blockedBy, blockCode := stableBlock(result.BlockedBy, result.BlockCode)
		if status < http.StatusBadRequest || status > 499 {
			status = http.StatusServiceUnavailable
			completion.markRejected(status, blockedBy, blockCode, blockCode)
			if session != nil {
				session.MarkRejected(status, blockedBy, blockCode)
			}
			closeRequestBody(request)
			writeJSON(response, status, interceptorUnavailableJSON)
			return
		}
		completion.markRejected(status, blockedBy, blockCode, "")
		if session != nil {
			session.MarkRejected(status, blockedBy, blockCode)
		}
		h.logger.InfoContext(
			request.Context(),
			"request rejected",
			"route_id", match.RouteID,
			"blocked_by", blockedBy,
			"block_code", blockCode,
			"status", status,
		)
		closeRequestBody(request)
		writeJSON(response, status, requestRejectedJSON)
		return
	}

	if session != nil {
		observedResponse := session.WrapResponseWriter(response, request)
		if observedResponse != nil {
			response = observedResponse
			defer observedResponse.CaptureTrailers()
		}
	}
	h.reverseProxy.ServeHTTP(response, request)
	completion.markCompleted()
}

func (h *handler) beginAudit(request *http.Request, match routing.Match) (*audit.Session, bool) {
	if h.audit == nil {
		return nil, true
	}
	session, err := h.audit.Begin(request.Context(), request, match)
	if err == nil && session != nil {
		return session, true
	}
	h.logger.WarnContext(request.Context(), "audit begin failed", "route_id", match.RouteID, "error_category", "audit_unavailable")
	if h.audit.Mode() == audit.ModeStrict {
		return nil, false
	}
	return nil, true
}

func newReverseProxy(target, upstreamProxy *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if upstreamProxy != nil {
		transport.Proxy = http.ProxyURL(cloneURL(upstreamProxy))
	}
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 64
	transport.ResponseHeaderTimeout = 5 * time.Minute

	return &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			inbound := proxyRequest.In
			outbound := proxyRequest.Out

			outbound.URL.Scheme = target.Scheme
			outbound.URL.Host = target.Host
			outbound.Host = target.Host
			outbound.Method = inbound.Method
			outbound.URL.Path = inbound.URL.Path
			outbound.URL.RawPath = inbound.URL.RawPath
			outbound.URL.RawQuery = inbound.URL.RawQuery
			outbound.URL.ForceQuery = inbound.URL.ForceQuery
			copyHeaderValues(outbound.Header, inbound.Header, "X-Real-IP")
			copyHeaderValues(outbound.Header, inbound.Header, "X-Forwarded-For")
			copyHeaderValues(outbound.Header, inbound.Header, "X-Forwarded-Proto")
			if session, ok := audit.SessionFromContext(inbound.Context()); ok {
				session.WrapRequestSent(outbound)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			if response != nil && response.Request != nil {
				if session, ok := audit.SessionFromContext(response.Request.Context()); ok {
					session.WrapResponseReceived(response)
				}
				if completion, ok := requestCompletionFromContext(response.Request.Context()); ok && response.Body != nil {
					response.Body = &observedUpstreamBody{
						underlying: response.Body,
						ctx:        response.Request.Context(),
						state:      completion,
					}
				}
			}
			return nil
		},
		Transport:     transport,
		BufferPool:    newBufferPool(32 << 10),
		FlushInterval: -1,
		// ReverseProxy otherwise sends response-copy errors, including raw
		// upstream error text, through the process-global logger.
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, err error) {
			if request.Context().Err() != nil || errors.Is(err, context.Canceled) {
				if completion, ok := requestCompletionFromContext(request.Context()); ok {
					completion.markClientCancelled()
				}
				if session, ok := audit.SessionFromContext(request.Context()); ok {
					session.MarkClientCancelled()
				}
				return
			}

			status := http.StatusBadGateway
			body := newAPIUnavailableJSON
			category := "upstream_unavailable"
			var networkError net.Error
			if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout() {
				status = http.StatusGatewayTimeout
				body = newAPITimeoutJSON
				category = "upstream_timeout"
			}
			if completion, ok := requestCompletionFromContext(request.Context()); ok {
				completion.markNewAPIError(category)
			}
			if session, ok := audit.SessionFromContext(request.Context()); ok {
				session.MarkNewAPIError(category)
			}
			logger.WarnContext(request.Context(), "NewAPI request failed", "status", status, "error_category", category)
			writeJSON(response, status, body)
		},
	}
}

func protocolForParser(parser string) string {
	protocol, _, _ := strings.Cut(parser, ".")
	if protocol == "" {
		return "unknown"
	}
	return protocol
}

func stableBlock(blockedBy, blockCode string) (string, string) {
	if blockedBy == "" {
		blockedBy = "interceptor_chain"
	}
	if blockCode == "" {
		blockCode = "interceptor_invalid_decision"
	}
	return blockedBy, blockCode
}

func closeRequestBody(request *http.Request) {
	if request == nil || request.Body == nil || request.Body == http.NoBody {
		return
	}
	_ = request.Body.Close()
}

func copyHeaderValues(destination, source http.Header, name string) {
	destination.Del(name)
	for _, value := range source.Values(name) {
		destination.Add(name, value)
	}
}

func writeJSON(response http.ResponseWriter, status int, body string) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(body))
}

func cloneURL(source *url.URL) *url.URL {
	cloned := *source
	if source.User != nil {
		user := *source.User
		cloned.User = &user
	}
	return &cloned
}

type bufferPool struct {
	size int
	pool sync.Pool
}

func newBufferPool(size int) *bufferPool {
	pool := &bufferPool{size: size}
	pool.pool.New = func() any {
		return make([]byte, size)
	}
	return pool
}

func (p *bufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *bufferPool) Put(buffer []byte) {
	if cap(buffer) < p.size {
		return
	}
	p.pool.Put(buffer[:p.size])
}
