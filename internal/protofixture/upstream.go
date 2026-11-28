package protofixture

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ExchangeHeader carries the id of a registered exchange. The audit proxy
// forwards request headers unchanged, so the client sets it and the fake
// upstream reads it back. It is recorded like any other request header.
const ExchangeHeader = "X-Protofixture-Exchange"

// NewAPIRequestIDHeader is the response header NewAPI uses for its request id.
// The fake upstream answers with the exchange id in it, which lands in the
// indexed audit_records.newapi_request_id column and lets a load driver find
// the audit of each request without decrypting anything.
const NewAPIRequestIDHeader = "X-Oneapi-Request-Id"

// UpstreamStats counts what the fake upstream served.
type UpstreamStats struct {
	Served     int64
	Unknown    int64
	Mismatched int64
	Aborted    int64
	Cancelled  int64
}

// Upstream is a fake provider that answers registered exchanges. Register an
// exchange, send its request with ExchangeHeader set to the returned id, and
// the upstream checks the forwarded request and writes the recorded answer,
// one flushed chunk at a time. An exchange is forgotten once served.
type Upstream struct {
	// FirstByteDelay is waited before the response headers are written.
	FirstByteDelay time.Duration
	// ChunkDelay is waited between two chunks of a streamed answer.
	ChunkDelay time.Duration
	// CancelWait bounds how long a client-cancel answer waits at its cut
	// point for the client to go away before it finishes the stream.
	CancelWait time.Duration
	// SetRequestID answers with NewAPIRequestIDHeader set to the exchange id.
	SetRequestID bool

	mu        sync.Mutex
	exchanges map[string]*Exchange
	sequence  atomic.Uint64
	prefix    string

	served, unknown, mismatched, aborted, cancelled atomic.Int64
}

// NewUpstream returns an empty upstream. The prefix starts every exchange id;
// it must be a short token without spaces.
func NewUpstream(prefix string) *Upstream {
	return &Upstream{exchanges: make(map[string]*Exchange), prefix: prefix, CancelWait: 30 * time.Second, SetRequestID: true}
}

// Register stores the exchange until it is served and returns its id.
func (upstream *Upstream) Register(exchange *Exchange) string {
	id := upstream.prefix + strconv.FormatUint(upstream.sequence.Add(1), 10)
	upstream.mu.Lock()
	upstream.exchanges[id] = exchange
	upstream.mu.Unlock()
	return id
}

// Forget drops an exchange that will not be sent.
func (upstream *Upstream) Forget(id string) {
	upstream.mu.Lock()
	delete(upstream.exchanges, id)
	upstream.mu.Unlock()
}

// Stats returns the counters so far.
func (upstream *Upstream) Stats() UpstreamStats {
	return UpstreamStats{
		Served: upstream.served.Load(), Unknown: upstream.unknown.Load(), Mismatched: upstream.mismatched.Load(),
		Aborted: upstream.aborted.Load(), Cancelled: upstream.cancelled.Load(),
	}
}

func (upstream *Upstream) take(id string) *Exchange {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	exchange := upstream.exchanges[id]
	delete(upstream.exchanges, id)
	return exchange
}

func (upstream *Upstream) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	id := request.Header.Get(ExchangeHeader)
	exchange := upstream.take(id)
	body, readErr := io.ReadAll(request.Body)
	if exchange == nil {
		upstream.unknown.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"error":{"message":"unknown fixture exchange","type":"invalid_request_error","code":"unknown_exchange"}}`)
		return
	}
	upstream.served.Add(1)
	if readErr != nil || request.Method != exchange.Method || request.URL.RequestURI() != exchange.Path || !bytes.Equal(body, exchange.RequestBody) {
		upstream.mismatched.Add(1)
	}
	if !wait(request, upstream.FirstByteDelay) {
		return
	}
	response := exchange.Response
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	if upstream.SetRequestID {
		writer.Header().Set(NewAPIRequestIDHeader, id)
	}
	status := response.Status
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	flusher, _ := writer.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	written := 0
	for index, piece := range response.Chunks {
		if index > 0 && !wait(request, upstream.ChunkDelay) {
			return
		}
		if response.CutAt > 0 && written < response.CutAt && written+len(piece) >= response.CutAt {
			head := response.CutAt - written
			_, _ = writer.Write(piece[:head])
			flush()
			if response.Abort {
				upstream.aborted.Add(1)
				// Drops the connection without a clean end of the body.
				panic(http.ErrAbortHandler)
			}
			if response.ClientCancel {
				if !wait(request, upstream.CancelWait) {
					upstream.cancelled.Add(1)
					return
				}
			}
			_, _ = writer.Write(piece[head:])
			flush()
			written += len(piece)
			continue
		}
		if _, err := writer.Write(piece); err != nil {
			return
		}
		flush()
		written += len(piece)
	}
}

// wait sleeps for delay unless the request goes away first.
func wait(request *http.Request, delay time.Duration) bool {
	if delay <= 0 {
		return request.Context().Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-request.Context().Done():
		return false
	}
}
