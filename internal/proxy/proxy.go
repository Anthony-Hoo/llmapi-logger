// Package proxy implements the LLM API whitelist data-plane reverse proxy.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"llmapi-logger/internal/interceptor"
	"llmapi-logger/internal/routing"
)

const (
	requestRejectedJSON        = `{"error":{"code":"request_rejected","message":"request rejected"}}`
	interceptorUnavailableJSON = `{"error":{"code":"interceptor_unavailable","message":"request cannot be processed"}}`
	routeNotAllowedJSON        = `{"error":{"code":"audit_route_not_allowed","message":"route is not enabled"}}`
	newAPIUnavailableJSON      = `{"error":{"code":"newapi_unavailable","message":"upstream request failed"}}`
	newAPITimeoutJSON          = `{"error":{"code":"newapi_timeout","message":"upstream response timed out"}}`
)

// New returns a handler that accepts only routes compiled into matcher,
// evaluates their interceptor chain, and forwards allowed requests to target.
func New(target *url.URL, matcher *routing.Matcher, engine *interceptor.Engine, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	handler := &handler{
		matcher: matcher,
		engine:  engine,
		logger:  logger,
	}
	if target == nil {
		handler.initializationError = errors.New("proxy: nil NewAPI target")
		return handler
	}

	handler.target = cloneURL(target)
	handler.reverseProxy = newReverseProxy(handler.target, logger)
	return handler
}

type handler struct {
	target              *url.URL
	matcher             *routing.Matcher
	engine              *interceptor.Engine
	logger              *slog.Logger
	reverseProxy        *httputil.ReverseProxy
	initializationError error
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
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

	result := h.engine.Evaluate(request.Context(), request, match)
	if result.Cancelled || request.Context().Err() != nil {
		return
	}
	if result.Internal != nil {
		h.logger.WarnContext(
			request.Context(),
			"interceptor unavailable",
			"route_id", match.RouteID,
			"blocked_by", result.BlockedBy,
			"block_code", result.BlockCode,
		)
		writeJSON(response, http.StatusServiceUnavailable, interceptorUnavailableJSON)
		return
	}
	if !result.Allowed {
		status := result.StatusCode
		if status < http.StatusBadRequest || status > 499 {
			status = http.StatusServiceUnavailable
			writeJSON(response, status, interceptorUnavailableJSON)
			return
		}
		h.logger.InfoContext(
			request.Context(),
			"request rejected",
			"route_id", match.RouteID,
			"blocked_by", result.BlockedBy,
			"block_code", result.BlockCode,
			"status", status,
		)
		writeJSON(response, status, requestRejectedJSON)
		return
	}

	h.reverseProxy.ServeHTTP(response, request)
}

func newReverseProxy(target *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
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
		},
		Transport:     transport,
		BufferPool:    newBufferPool(32 << 10),
		FlushInterval: -1,
		ErrorHandler: func(response http.ResponseWriter, request *http.Request, err error) {
			if request.Context().Err() != nil || errors.Is(err, context.Canceled) {
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
			logger.WarnContext(request.Context(), "NewAPI request failed", "status", status, "error_category", category)
			writeJSON(response, status, body)
		},
	}
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
