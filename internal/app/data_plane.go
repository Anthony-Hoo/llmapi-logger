package app

import (
	"net/http"

	"llmapi-logger/internal/routing"
)

// dataPlaneHandler keeps the audited route matcher authoritative while
// allowing unrelated NewAPI endpoints to pass through without audit capture.
type dataPlaneHandler struct {
	matcher     *routing.Matcher
	audited     http.Handler
	passthrough http.Handler
}

func newDataPlaneHandler(matcher *routing.Matcher, audited, passthrough http.Handler) http.Handler {
	return &dataPlaneHandler{matcher: matcher, audited: audited, passthrough: passthrough}
}

func (handler *dataPlaneHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	escapedPath := "/"
	if request.URL != nil {
		escapedPath = request.URL.EscapedPath()
	}
	if _, matched := handler.matcher.Match(request.Method, escapedPath); matched || !handler.matcher.AllowsPassthrough(escapedPath) {
		handler.audited.ServeHTTP(response, request)
		return
	}
	handler.passthrough.ServeHTTP(response, request)
}
