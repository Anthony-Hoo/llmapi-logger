package audit

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/parser/streamterminal"
	"llmapi-logger/internal/storage/sqlite"
)

func TestTerminalStreamMarkerDetection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		parser string
		chunks []string
		want   bool
	}{
		{name: "chat completions done", parser: "openai.chat_completions", chunks: []string{"data: {\"id\":\"x\"}\n\ndata: [DONE]\n\n"}, want: true},
		{name: "responses completed", parser: "openai.responses", chunks: []string{"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"}, want: true},
		{name: "responses failed", parser: "openai.responses", chunks: []string{"event: response.failed\ndata: {}\n\n"}, want: true},
		{name: "anthropic message stop", parser: "anthropic.messages", chunks: []string{"event: message_stop\ndata: {}\n\n"}, want: true},
		{name: "marker split across reads", parser: "openai.responses", chunks: []string{"event: respon", "se.completed\ndata: {}\n", "\n"}, want: true},
		{name: "crlf line endings", parser: "openai.chat_completions", chunks: []string{"data: [DONE]\r\n\r\n"}, want: true},
		{name: "marker without event dispatch stays candidate", parser: "openai.responses", chunks: []string{"event: response.completed\ndata: {"}, want: false},
		{name: "regular data only", parser: "openai.chat_completions", chunks: []string{"data: {\"delta\":\"hello\"}\n\n"}, want: false},
		{name: "long payload line never matches", parser: "openai.chat_completions", chunks: []string{"data: " + strings.Repeat("x", 4096) + "\n\n"}, want: false},
		{name: "overflowed line with terminal-looking prefix", parser: "openai.chat_completions", chunks: []string{"data: [DONE]" + strings.Repeat(" ", 36) + "trailing-payload\n\n"}, want: false},
		{name: "done inside payload not a marker", parser: "openai.chat_completions", chunks: []string{"data: {\"text\":\"[DONE]\"}\n\n"}, want: false},
		{name: "protocol without terminal marker", parser: "gemini.generate_content", chunks: []string{"data: [DONE]\n\n"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &bodyCapture{
				stream:          true,
				streamComplete:  true,
				terminalMatcher: streamterminal.MatcherFor(test.parser),
			}
			offset := int64(0)
			for _, chunk := range test.chunks {
				observeStreamEvents(body, []byte(chunk), offset, 1)
				offset += int64(len(chunk))
			}
			if body.streamTerminalSeen != test.want {
				t.Fatalf("streamTerminalSeen = %v, want %v", body.streamTerminalSeen, test.want)
			}
		})
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// streamResponseSession builds a session whose response_received stage saw
// receivedLength bytes of an event stream and whose response_sent stage has
// already written sentLength of them to the client.
func streamResponseSession(terminalSeen bool, receivedLength, sentLength int64) (*Session, *stageCapture, *stageCapture) {
	received := &stageCapture{
		name:        sqlite.StageResponseReceived,
		expectsBody: true,
		body: &bodyCapture{
			digest:             sha256.New(),
			stream:             true,
			streamComplete:     true,
			streamTerminalSeen: terminalSeen,
			observedLength:     receivedLength,
		},
	}
	sent := &stageCapture{
		name:        sqlite.StageResponseSent,
		expectsBody: true,
		body: &bodyCapture{
			digest:         sha256.New(),
			observedLength: sentLength,
		},
	}
	session := &Session{
		now: func() time.Time { return time.Unix(0, 100) },
		stages: map[string]*stageCapture{
			received.name: received,
			sent.name:     sent,
		},
		forwardStatus: sqlite.ForwardInProgress,
		request:       cancelledContext(),
	}
	return session, received, sent
}

func TestClientDisconnectAfterTerminalEventIsNotCancellation(t *testing.T) {
	t.Parallel()
	session, received, _ := streamResponseSession(true, 64, 64)

	session.observeRead(sqlite.StageResponseReceived, nil, context.Canceled)

	if received.body.faulted {
		t.Fatalf("body faulted = true, want false")
	}
	if !received.body.eofSeen || !received.body.hashComplete || !received.body.closed {
		t.Fatalf("body eof/hash/closed = %v/%v/%v, want all true", received.body.eofSeen, received.body.hashComplete, received.body.closed)
	}
	if session.forwardStatus != sqlite.ForwardInProgress {
		t.Fatalf("forward status = %q, want %q", session.forwardStatus, sqlite.ForwardInProgress)
	}

	session.MarkClientCancelled()
	if session.forwardStatus != sqlite.ForwardInProgress {
		t.Fatalf("forward status after MarkClientCancelled = %q, want %q", session.forwardStatus, sqlite.ForwardInProgress)
	}
	if !session.responseLogicallyCompleteLocked() {
		t.Fatalf("responseLogicallyCompleteLocked = false, want true")
	}
}

func TestClientDisconnectBeforeTerminalEventStaysCancelled(t *testing.T) {
	t.Parallel()
	session, received, _ := streamResponseSession(false, 64, 64)

	session.observeRead(sqlite.StageResponseReceived, nil, context.Canceled)

	if !received.body.faulted || received.body.errorCode != "body_read_error" {
		t.Fatalf("body faulted/error = %v/%q, want true/body_read_error", received.body.faulted, received.body.errorCode)
	}
	if session.forwardStatus != sqlite.ForwardClientCancelled {
		t.Fatalf("forward status = %q, want %q", session.forwardStatus, sqlite.ForwardClientCancelled)
	}
	if session.errorCode == nil || *session.errorCode != "client_cancelled" {
		t.Fatalf("error code = %v, want client_cancelled", session.errorCode)
	}
}

func TestClientDisconnectWithUndeliveredBytesStaysCancelled(t *testing.T) {
	t.Parallel()

	// Terminal event received, but the client never got the final bytes.
	shortDelivery, _, _ := streamResponseSession(true, 64, 40)
	shortDelivery.MarkClientCancelled()
	if shortDelivery.forwardStatus != sqlite.ForwardClientCancelled {
		t.Fatalf("short delivery forward status = %q, want %q", shortDelivery.forwardStatus, sqlite.ForwardClientCancelled)
	}

	// Same, but the downstream write itself failed.
	writeFault, _, sent := streamResponseSession(true, 64, 64)
	sent.body.errorCode = "body_write_error"
	sent.body.faulted = true
	writeFault.MarkClientCancelled()
	if writeFault.forwardStatus != sqlite.ForwardClientCancelled {
		t.Fatalf("write fault forward status = %q, want %q", writeFault.forwardStatus, sqlite.ForwardClientCancelled)
	}
}

func TestDeclaredContentLengthGuardsSynthesizedCompletion(t *testing.T) {
	t.Parallel()
	session, received, _ := streamResponseSession(true, 64, 64)
	declared := int64(128)
	received.contentLength = &declared

	session.MarkClientCancelled()
	if session.forwardStatus != sqlite.ForwardClientCancelled {
		t.Fatalf("forward status = %q, want %q", session.forwardStatus, sqlite.ForwardClientCancelled)
	}
}

func TestCaptureFaultDoesNotChangeTransportClassification(t *testing.T) {
	t.Parallel()
	session, received, _ := streamResponseSession(true, 64, 64)
	// A capture-internal persistence fault must not flip a benign hang-up
	// back into a cancellation; it only degrades capture_status.
	received.body.faulted = true
	received.body.errorCode = "add_chunk_failed"

	session.MarkClientCancelled()
	if session.forwardStatus != sqlite.ForwardInProgress {
		t.Fatalf("forward status = %q, want %q", session.forwardStatus, sqlite.ForwardInProgress)
	}
	if !session.responseLogicallyCompleteLocked() {
		t.Fatalf("responseLogicallyCompleteLocked = false, want true")
	}
}
