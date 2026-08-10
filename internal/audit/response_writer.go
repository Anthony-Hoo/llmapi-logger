package audit

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"llmapi-logger/internal/storage/sqlite"
)

type observedResponseWriter struct {
	underlying http.ResponseWriter
	session    *Session
	proto      string

	startOnce sync.Once
	status    int
}

func (writer *observedResponseWriter) Header() http.Header {
	return writer.underlying.Header()
}

func (writer *observedResponseWriter) WriteHeader(status int) {
	writer.underlying.WriteHeader(status)
	writer.start(status)
}

func (writer *observedResponseWriter) Write(data []byte) (int, error) {
	written, err := writer.underlying.Write(data)
	writer.start(http.StatusOK)
	observedCount := written
	if observedCount < 0 {
		observedCount = 0
	}
	if observedCount > len(data) {
		observedCount = len(data)
	}
	writer.session.observeWrite(sqlite.StageResponseSent, data[:observedCount], err)
	return written, err
}

// Unwrap allows http.ResponseController and ReverseProxy to discover optional
// interfaces such as Flusher on the real writer.
func (writer *observedResponseWriter) Unwrap() http.ResponseWriter {
	return writer.underlying
}

// CaptureTrailers records values that became available only after the
// response body was copied. ReverseProxy may expose announced trailers under
// their normal names and unannounced trailers with http.TrailerPrefix.
func (writer *observedResponseWriter) CaptureTrailers() {
	if writer == nil || writer.session == nil || writer.underlying == nil {
		return
	}
	header := writer.underlying.Header()
	trailers := make(http.Header)
	for _, declaration := range header.Values("Trailer") {
		for _, name := range strings.Split(declaration, ",") {
			name = http.CanonicalHeaderKey(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			for _, value := range header.Values(name) {
				trailers.Add(name, value)
			}
		}
	}
	for name, values := range header {
		if !strings.HasPrefix(name, http.TrailerPrefix) {
			continue
		}
		trailerName := http.CanonicalHeaderKey(strings.TrimPrefix(name, http.TrailerPrefix))
		if trailerName == "" {
			continue
		}
		for _, value := range values {
			trailers.Add(trailerName, value)
		}
	}
	writer.session.addHeaders(sqlite.StageResponseSent, sqlite.HeaderKindTrailer, trailers)
}

func (writer *observedResponseWriter) start(status int) {
	writer.startOnce.Do(func() {
		writer.status = status
		contentLength := int64(-1)
		if raw := writer.underlying.Header().Get("Content-Length"); raw != "" {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed >= 0 {
				contentLength = parsed
			}
		}
		writer.session.startStage(
			sqlite.StageResponseSent,
			writer.proto,
			"",
			"",
			intPointer(status),
			contentLengthPointer(contentLength),
			writer.underlying.Header(),
			false,
		)
	})
}
