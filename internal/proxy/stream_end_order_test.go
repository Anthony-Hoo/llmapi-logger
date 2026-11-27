package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// These tests pin what the proxy's direct HTTP peer (Nginx in deployment)
// observes while the audit's terminal commit is still pending. The handler
// defers, in run order: CaptureTrailers, session.Finish (which waits for
// FinishAuditWithResult with no timeout), then the completion log line; only
// after all three does ServeHTTP return to net/http. Moving work across the
// terminal commit is client-visible exactly where these tests say so.

const (
	// streamOrderDeadline bounds every wait for something that must happen.
	streamOrderDeadline = 10 * time.Second
	// streamOrderAbsenceProbe is the one bounded wait used to show that an
	// event has not happened while the terminal commit is blocked. Current
	// behaviour can never fail it: the event is gated on the handler
	// returning, which the blocked commit prevents. It exists so that a
	// regression that delivers the event early is caught rather than raced.
	streamOrderAbsenceProbe = 150 * time.Millisecond
)

// blockingFinishStore holds the terminal audit commit until the test
// releases it. Every other write goes straight to the real store.
type blockingFinishStore struct {
	*sqlite.Store
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
	releaseOnce sync.Once
	released    atomic.Bool
}

func newBlockingFinishStore(store *sqlite.Store) *blockingFinishStore {
	return &blockingFinishStore{Store: store, entered: make(chan struct{}), release: make(chan struct{})}
}

func (store *blockingFinishStore) FinishAuditWithResult(ctx context.Context, finish sqlite.AuditFinish) (sqlite.AuditFinish, error) {
	store.enteredOnce.Do(func() { close(store.entered) })
	<-store.release
	return store.Store.FinishAuditWithResult(ctx, finish)
}

func (store *blockingFinishStore) releaseFinish() {
	store.releaseOnce.Do(func() {
		store.released.Store(true)
		close(store.release)
	})
}

// lockedBuffer lets the test read the log while the handler may still write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(data)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

type streamOrderCase struct {
	name     string
	http2    bool
	upstream func(t *testing.T) string // returns the upstream base URL
	// framing is "chunked" or "content-length": what the proxied response
	// must use on the wire, so the case tests what it claims to test.
	framing    string
	wantStatus int
	wantBody   string
	// Whether each client-side event happens while the terminal commit is
	// still blocked (true) or only after it is released (false).
	headersBeforeCommit  bool
	lastByteBeforeCommit bool
	endBeforeCommit      bool
}

type streamOrderEvent int

const (
	eventHeaders streamOrderEvent = iota
	eventLastByte
	eventEnd
	streamOrderEventCount
)

var streamOrderEventNames = [...]string{"response headers", "last body byte", "end of response"}

const (
	sseUpstreamBody  = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
	jsonUpstreamBody = `{"id":"response-example","choices":[{"message":{"role":"assistant","content":"hi"}}]}`
)

func sseUpstream(t *testing.T) string {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, sseUpstreamBody)
		_ = http.NewResponseController(w).Flush()
	}))
	t.Cleanup(upstream.Close)
	return upstream.URL
}

func contentLengthUpstream(t *testing.T) string {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(jsonUpstreamBody)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, jsonUpstreamBody)
	}))
	t.Cleanup(upstream.Close)
	return upstream.URL
}

// unreachableUpstream returns the address of a listener that is already
// closed, so the proxy's ErrorHandler answers with its own 502 JSON.
func unreachableUpstream(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + address
}

func TestClientObservedResponseEndRelativeToTerminalAuditCommit(t *testing.T) {
	for _, test := range []streamOrderCase{
		{
			// The body bytes reach the client as soon as they are copied,
			// because ReverseProxy runs with FlushInterval -1 (proxy.go). The
			// terminating zero-length chunk is written by net/http's
			// finishRequest only after ServeHTTP returns, and ServeHTTP is held
			// by the deferred session.Finish, so the client sees the end of an
			// SSE stream only after the terminal commit.
			name:                 "http1 sse chunked",
			upstream:             sseUpstream,
			framing:              "chunked",
			wantStatus:           http.StatusOK,
			wantBody:             sseUpstreamBody,
			headersBeforeCommit:  true,
			lastByteBeforeCommit: true,
			endBeforeCommit:      false,
		},
		{
			// With a declared Content-Length the client knows the response is
			// complete once it has that many bytes, and the flushed copy
			// delivers them before Finish runs: the client sees the whole
			// response, end included, before the terminal commit. Only the
			// keep-alive connection stays busy until the handler returns.
			name:                 "http1 content-length",
			upstream:             contentLengthUpstream,
			framing:              "content-length",
			wantStatus:           http.StatusOK,
			wantBody:             jsonUpstreamBody,
			headersBeforeCommit:  true,
			lastByteBeforeCommit: true,
			endBeforeCommit:      true,
		},
		{
			// The proxy's own error responses (ErrorHandler here; interceptor
			// rejections use the same writeJSON) are never flushed, so net/http
			// keeps headers and body in its buffer until ServeHTTP returns and
			// then sends them with a computed Content-Length: the client sees
			// nothing at all, not even the status line, before the terminal
			// commit.
			name:                 "http1 proxy error response",
			upstream:             unreachableUpstream,
			framing:              "content-length",
			wantStatus:           http.StatusBadGateway,
			wantBody:             newAPIUnavailableJSON,
			headersBeforeCommit:  false,
			lastByteBeforeCommit: false,
			endBeforeCommit:      false,
		},
		{
			// HTTP/2 through the same handler (TLS test server; the deployed
			// path behind Nginx is HTTP/1.1): END_STREAM is sent only once the
			// handler is done, so the end of an SSE stream again waits for the
			// terminal commit.
			name:                 "http2 sse",
			http2:                true,
			upstream:             sseUpstream,
			framing:              "chunked",
			wantStatus:           http.StatusOK,
			wantBody:             sseUpstreamBody,
			headersBeforeCommit:  true,
			lastByteBeforeCommit: true,
			endBeforeCommit:      false,
		},
		{
			// Unlike HTTP/1.1, an HTTP/2 client does not end the body at the
			// declared Content-Length; it waits for END_STREAM, which the
			// server sends only after the handler returns, so here the end of
			// the response also waits for the terminal commit.
			name:                 "http2 content-length",
			http2:                true,
			upstream:             contentLengthUpstream,
			framing:              "content-length",
			wantStatus:           http.StatusOK,
			wantBody:             jsonUpstreamBody,
			headersBeforeCommit:  true,
			lastByteBeforeCommit: true,
			endBeforeCommit:      false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runStreamOrderCase(t, test)
		})
	}
}

func runStreamOrderCase(t *testing.T, test streamOrderCase) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x37}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	blocking := newBlockingFinishStore(store)
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	manager, err := audit.NewManager(blocking, cipher, nil, audit.ModeAvailable, logger)
	if err != nil {
		t.Fatal(err)
	}
	inner := newTestHandlerWithOptions(t, test.upstream(t), manager, logger, nil, defaultTestRoutes())
	returned := make(chan struct{})
	var returnedOnce sync.Once
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer returnedOnce.Do(func() { close(returned) })
		inner.ServeHTTP(w, r)
	})

	server := httptest.NewUnstartedServer(outer)
	if test.http2 {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	// Runs before the Cleanup above, so a failed assertion never leaves
	// server.Close waiting for a handler parked in the terminal commit.
	defer blocking.releaseFinish()

	type clientEvent struct {
		event    streamOrderEvent
		response *http.Response
		body     []byte
		err      error
	}
	events := make(chan clientEvent, streamOrderEventCount)
	requestCtx, cancel := context.WithTimeout(ctx, 2*streamOrderDeadline)
	defer cancel()
	go func() {
		request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, server.URL+"/v1/chat/completions",
			strings.NewReader(`{"model":"model-example","stream":true}`))
		if err != nil {
			events <- clientEvent{event: eventHeaders, err: err}
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		events <- clientEvent{event: eventHeaders, response: response, err: err}
		if err != nil {
			return
		}
		defer response.Body.Close()
		// Read exactly the expected bytes first, so "last byte" and "end" are
		// two separate observations; io.ReadAll would merge them.
		body := make([]byte, len(test.wantBody))
		_, err = io.ReadFull(response.Body, body)
		events <- clientEvent{event: eventLastByte, body: body, err: err}
		if err != nil {
			return
		}
		var extra [1]byte
		n, err := response.Body.Read(extra[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			err = errors.Join(errors.New("response did not end after the expected body"), err)
		} else {
			err = nil
		}
		events <- clientEvent{event: eventEnd, err: err}
	}()

	select {
	case <-blocking.entered:
	case <-time.After(streamOrderDeadline):
		t.Fatal("terminal audit commit was never reached")
	}

	want := [streamOrderEventCount]bool{test.headersBeforeCommit, test.lastByteBeforeCommit, test.endBeforeCommit}
	var observed [streamOrderEventCount]*clientEvent
	next := eventHeaders
	// Events arrive in order, so the first one expected only after the
	// commit ends the blocked phase; its absence is shown by the bounded probe.
	for ; next < streamOrderEventCount; next++ {
		timeout := streamOrderDeadline
		if !want[next] {
			timeout = streamOrderAbsenceProbe
		}
		select {
		case event := <-events:
			if event.err != nil {
				t.Fatalf("%s: %v", streamOrderEventNames[event.event], event.err)
			}
			if !want[next] {
				t.Fatalf("client saw the %s while the terminal commit was still blocked", streamOrderEventNames[next])
			}
			observed[next] = &event
		case <-returned:
			t.Fatal("handler returned while the terminal commit was still blocked")
		case <-time.After(timeout):
			if want[next] {
				t.Fatalf("client did not see the %s before the terminal commit", streamOrderEventNames[next])
			}
		}
		if observed[next] == nil {
			break
		}
	}
	// The completion log line is written after Finish returns, so it never
	// precedes the terminal commit either.
	if records := completionLogRecords(t, logs.Bytes()); len(records) != 0 {
		t.Fatal("completion log was written before the terminal commit")
	}

	blocking.releaseFinish()
	for ; next < streamOrderEventCount; next++ {
		select {
		case event := <-events:
			if event.err != nil {
				t.Fatalf("%s: %v", streamOrderEventNames[event.event], event.err)
			}
			observed[next] = &event
		case <-time.After(streamOrderDeadline):
			t.Fatalf("client never saw the %s after the terminal commit", streamOrderEventNames[next])
		}
	}
	select {
	case <-returned:
	case <-time.After(streamOrderDeadline):
		t.Fatal("handler did not return after the terminal commit")
	}

	response := observed[eventHeaders].response
	if response.StatusCode != test.wantStatus {
		t.Fatalf("status = %d, want %d", response.StatusCode, test.wantStatus)
	}
	wantMajor := 1
	if test.http2 {
		wantMajor = 2
	}
	if response.ProtoMajor != wantMajor {
		t.Fatalf("protocol = %s, want HTTP/%d", response.Proto, wantMajor)
	}
	switch test.framing {
	case "chunked":
		if response.ContentLength != -1 || (!test.http2 && !slices.Contains(response.TransferEncoding, "chunked")) {
			t.Fatalf("response framing = length %d, transfer encoding %v; want chunked without Content-Length",
				response.ContentLength, response.TransferEncoding)
		}
	case "content-length":
		if response.ContentLength != int64(len(test.wantBody)) || len(response.TransferEncoding) != 0 {
			t.Fatalf("response framing = length %d, transfer encoding %v; want Content-Length %d",
				response.ContentLength, response.TransferEncoding, len(test.wantBody))
		}
	}
	if got := string(observed[eventLastByte].body); got != test.wantBody {
		t.Fatalf("body = %q, want %q", got, test.wantBody)
	}
	singleCompletionLogRecord(t, logs.Bytes())
}
