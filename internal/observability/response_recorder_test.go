package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseRecorderUnwrapPreservesFlush(t *testing.T) {
	underlying := &flushWriter{ResponseRecorder: httptest.NewRecorder()}
	recorder := NewResponseRecorder(underlying)

	recorder.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(recorder).Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if underlying.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", underlying.flushes)
	}
	if recorder.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.StatusCode(), http.StatusOK)
	}
	if _, ok := recorder.FirstWriteAt(); !ok {
		t.Fatal("FirstWriteAt() ok = false")
	}
}

func TestResponseRecorderKeepsFinalStatusAfterInformationalResponse(t *testing.T) {
	recorder := NewResponseRecorder(httptest.NewRecorder())
	recorder.WriteHeader(http.StatusEarlyHints)
	recorder.WriteHeader(http.StatusAccepted)
	if recorder.StatusCode() != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", recorder.StatusCode(), http.StatusAccepted)
	}
}

type flushWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (writer *flushWriter) Flush() {
	writer.flushes++
	writer.ResponseRecorder.Flush()
}
