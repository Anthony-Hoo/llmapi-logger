// Package observability provides the small, non-sensitive runtime signals
// needed by the single-process proxy.
package observability

import (
	"net/http"
	"sync"
	"time"
)

// ResponseRecorder observes the final status, first response write, and
// downstream write failures without hiding optional interfaces on the real
// ResponseWriter. In particular, http.ResponseController can follow Unwrap
// to preserve ReverseProxy's immediate SSE flushing.
type ResponseRecorder struct {
	underlying http.ResponseWriter

	mu          sync.Mutex
	statusCode  int
	firstWrite  time.Time
	writeFailed bool
}

// NewResponseRecorder wraps writer without buffering or changing any bytes.
func NewResponseRecorder(writer http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{underlying: writer}
}

func (recorder *ResponseRecorder) Header() http.Header {
	return recorder.underlying.Header()
}

func (recorder *ResponseRecorder) WriteHeader(statusCode int) {
	recorder.recordHeader(statusCode)
	recorder.underlying.WriteHeader(statusCode)
}

func (recorder *ResponseRecorder) Write(data []byte) (int, error) {
	recorder.recordHeader(http.StatusOK)
	written, err := recorder.underlying.Write(data)

	recorder.mu.Lock()
	if err != nil || written != len(data) {
		recorder.writeFailed = true
	}
	recorder.mu.Unlock()
	return written, err
}

// Unwrap allows http.ResponseController and ReverseProxy to discover Flusher,
// Hijacker, Pusher, and other optional interfaces on the real writer.
func (recorder *ResponseRecorder) Unwrap() http.ResponseWriter {
	if recorder == nil {
		return nil
	}
	return recorder.underlying
}

// StatusCode returns the first final (non-1xx) status written to the client.
// Zero means that no final response was started.
func (recorder *ResponseRecorder) StatusCode() int {
	if recorder == nil {
		return 0
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.statusCode
}

// FirstWriteAt returns when the first informational/final header or implicit
// body response was attempted.
func (recorder *ResponseRecorder) FirstWriteAt() (time.Time, bool) {
	if recorder == nil {
		return time.Time{}, false
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.firstWrite, !recorder.firstWrite.IsZero()
}

// WriteFailed reports only whether the downstream writer returned an error or
// short write. It deliberately does not retain the underlying error text.
func (recorder *ResponseRecorder) WriteFailed() bool {
	if recorder == nil {
		return false
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.writeFailed
}

func (recorder *ResponseRecorder) recordHeader(statusCode int) {
	if recorder == nil {
		return
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.firstWrite.IsZero() {
		recorder.firstWrite = time.Now()
	}
	if recorder.statusCode == 0 && statusCode >= 200 {
		recorder.statusCode = statusCode
	}
}
