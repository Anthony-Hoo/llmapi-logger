package audit

import (
	"errors"
	"io"
	"strings"
	"testing"

	"llmapi-logger/internal/storage/sqlite"
)

// closedAfterEOF is a request body that ends with io.EOF and, once closed,
// answers every further Read with an error, as net/http's server body does
// ("http: invalid Read on closed Body").
type closedAfterEOF struct {
	reader io.Reader
	closed bool
}

func (body *closedAfterEOF) Read(p []byte) (int, error) {
	if body.closed {
		return 0, errors.New("http: invalid Read on closed Body")
	}
	return body.reader.Read(p)
}

func (body *closedAfterEOF) Close() error {
	body.closed = true
	return nil
}

// A body read to io.EOF is complete. The proxy's transport can still read
// once more after the body was closed (it raced the response on a loaded
// host: the acceptance tests saw it about once in 15 runs of the catalogue
// with twelve concurrent conversations); that read returns no data and an
// error, and must not turn the complete body into a partial one with
// body_read_error. Before the fix it did: the request stages ended partial,
// the parse partial without a turn, and the raw was kept as for a failed
// capture, while the client had sent and received everything.
func TestAReadErrorAfterEOFLeavesTheBodyComplete(t *testing.T) {
	store := &commitStore{}
	session := bufferSession(t, store, sqlite.StageRequestReceived)
	underlying := &closedAfterEOF{reader: strings.NewReader(`{"model":"model-example","input":"hello"}`)}
	reader := newObservedReadCloser(underlying, session, sqlite.StageRequestReceived, nil)
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if count, err := reader.Read(make([]byte, 16)); count != 0 || err == nil {
		t.Fatalf("read after close = %d, %v", count, err)
	}
	stage := session.stages[sqlite.StageRequestReceived]
	body := stage.body
	if body.faulted || body.errorCode != "" || !body.eofSeen || !body.hashComplete {
		t.Fatalf("complete body after a late read error: faulted %v, error %q, eof %v, hash complete %v",
			body.faulted, body.errorCode, body.eofSeen, body.hashComplete)
	}
	if stage.faulted || stage.errorCode != "" {
		t.Fatalf("stage faulted %v, error %q", stage.faulted, stage.errorCode)
	}
}
