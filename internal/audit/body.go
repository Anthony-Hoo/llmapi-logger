package audit

import (
	"crypto/sha256"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/parser/streamterminal"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

type bodyCapture struct {
	digest         hash.Hash
	persisted      bool
	persistChunks  bool
	sourceStage    string
	observedLength int64
	storedLength   int64
	nextSeq        int64
	chunkCount     int64
	pending        []byte
	pendingAtNS    int64
	firstAtNS      int64
	lastAtNS       int64
	eofSeen        bool
	hashComplete   bool
	closed         bool
	faulted        bool
	errorCode      string
	// writeFailed records that a downstream write actually failed, which is
	// a transport fact and must not be confused with a capture-side fault.
	// errorCode cannot carry this: persistence and encryption failures
	// overwrite it on the same body, which would silently erase the signal
	// that bytes never reached the client.
	writeFailed    bool
	stream         bool
	streamLineData bool
	streamHasData  bool
	streamAfterCR  bool
	streamEvents   int64
	streamComplete bool
	streamPoints   []streamtimeline.Point
	firstEventAtNS int64
	lastEventAtNS  int64
	// terminalMatcher is the protocol-owned terminal-line matcher from the
	// parser layer (internal/parser/streamterminal), or nil when the
	// protocol has no reliable in-stream terminal marker or the upstream
	// body is content-encoded.
	terminalMatcher streamterminal.Matcher
	// streamTerminalSeen is set once the event stream has dispatched a
	// complete event whose line matched the terminal marker (`data: [DONE]`,
	// `event: response.completed`, ...). Clients such as Codex close the
	// connection right after that event without reading to transport EOF,
	// so this is the only reliable completion signal for those streams.
	streamTerminalSeen bool
	// streamTerminalCandidate remembers a matched line until its SSE event
	// is fully dispatched (terminating blank line observed), so a stream
	// cut inside the terminal event is still treated as truncated.
	streamTerminalCandidate bool
	// streamLine transiently buffers up to maxStreamLineProbe bytes of the
	// current SSE line for terminal-marker matching. It is cleared at every
	// line boundary and never persisted. streamLineOverflow marks lines
	// longer than the probe, which must never match.
	streamLine         []byte
	streamLineOverflow bool
}

type observedReadCloser struct {
	underlying io.ReadCloser
	session    *Session
	stage      string
	trailers   func() http.Header

	closeOnce   sync.Once
	closeErr    error
	trailerOnce sync.Once
}

func newObservedReadCloser(underlying io.ReadCloser, session *Session, stage string, trailers func() http.Header) io.ReadCloser {
	return &observedReadCloser{underlying: underlying, session: session, stage: stage, trailers: trailers}
}

func (reader *observedReadCloser) Read(buffer []byte) (int, error) {
	count, err := reader.underlying.Read(buffer)
	observedCount := count
	if observedCount < 0 {
		observedCount = 0
	}
	if observedCount > len(buffer) {
		observedCount = len(buffer)
	}
	reader.session.observeRead(reader.stage, buffer[:observedCount], err)
	if err == io.EOF {
		reader.captureTrailers()
	}
	return count, err
}

func (reader *observedReadCloser) Close() error {
	reader.closeOnce.Do(func() {
		reader.closeErr = reader.underlying.Close()
		reader.session.closeReadBody(reader.stage, reader.closeErr)
		reader.captureTrailers()
	})
	return reader.closeErr
}

func (reader *observedReadCloser) captureTrailers() {
	reader.trailerOnce.Do(func() {
		if reader.trailers != nil {
			reader.session.addHeaders(reader.stage, storage.HeaderKindTrailer, reader.trailers())
		}
	})
}

func (session *Session) observeRead(stageName string, data []byte, readErr error) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	stage := session.stages[stageName]
	if stage == nil {
		return
	}
	body := session.ensureBodyLocked(stage)
	session.observeBodyLocked(stage, body, data)
	if readErr == io.EOF {
		session.flushBodyLocked(stage, body, true)
		body.eofSeen = true
		body.hashComplete = true
		body.closed = true
		return
	}
	if readErr != nil {
		if stageName == storage.StageResponseReceived &&
			session.request != nil && session.request.Err() != nil &&
			session.responseLogicallyCompleteLocked() {
			// The client hung up after the stream's terminal event, which
			// cancels the upstream read before transport EOF arrives. The
			// captured stream is logically complete and every received byte
			// was already handed to the client; treat it like EOF instead
			// of a cancellation.
			session.flushBodyLocked(stage, body, true)
			body.eofSeen = true
			body.hashComplete = true
			body.closed = true
			return
		}
		body.faulted = true
		body.closed = true
		body.errorCode = "body_read_error"
		session.markStageFaultLocked(stage, body.errorCode)
		if stageName == storage.StageResponseReceived {
			if session.request != nil && session.request.Err() != nil {
				session.forwardStatus = storage.ForwardClientCancelled
				session.errorCode = stringPointer("client_cancelled")
			} else if session.forwardStatus == storage.ForwardInProgress {
				session.forwardStatus = storage.ForwardNewAPIError
				session.errorCode = stringPointer("upstream_body_read_error")
			}
		}
	}
}

func (session *Session) closeReadBody(stageName string, closeErr error) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	stage := session.stages[stageName]
	if stage == nil || stage.body == nil {
		return
	}
	body := stage.body
	session.flushBodyLocked(stage, body, true)
	body.closed = true
	if closeErr != nil {
		body.faulted = true
		body.errorCode = "body_close_error"
		session.markStageFaultLocked(stage, body.errorCode)
	}
}

func (session *Session) observeWrite(stageName string, data []byte, writeErr error) {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	stage := session.stages[stageName]
	if stage == nil {
		return
	}
	body := session.ensureBodyLocked(stage)
	session.observeBodyLocked(stage, body, data)
	if writeErr == nil {
		return
	}
	body.faulted = true
	body.writeFailed = true
	body.errorCode = "body_write_error"
	session.markStageFaultLocked(stage, body.errorCode)
	if session.request != nil && session.request.Err() != nil {
		if !session.responseLogicallyCompleteLocked() {
			session.forwardStatus = storage.ForwardClientCancelled
			session.errorCode = stringPointer("client_cancelled")
		}
	} else if session.forwardStatus == storage.ForwardInProgress {
		session.forwardStatus = storage.ForwardProxyError
		session.errorCode = stringPointer("downstream_write_error")
	}
}

func (session *Session) ensureBodyLocked(stage *stageCapture) *bodyCapture {
	if stage.body != nil {
		return stage.body
	}
	body := &bodyCapture{
		digest:         sha256.New(),
		persistChunks:  true,
		sourceStage:    stage.name,
		streamComplete: true,
	}
	body.stream = body.persistChunks && stage.name == storage.StageResponseReceived && isEventStream(stage.contentType)
	if body.stream {
		body.streamPoints = make([]streamtimeline.Point, 0, 256)
		// The probe sees raw upstream bytes, so terminal detection is only
		// possible for identity-encoded streams. Audited routes ask NewAPI
		// for identity, so this is a safety net for an upstream that encodes
		// anyway: such a stream keeps the plain cancellation classification
		// rather than being sealed on bytes nothing here can read.
		if encoding := strings.ToLower(strings.TrimSpace(stage.contentEncoding)); encoding == "" || encoding == "identity" {
			body.terminalMatcher = session.terminalMatcher
		}
	}
	stage.body = body
	if !stage.persisted {
		body.faulted = true
		body.errorCode = "start_stage_failed"
		return body
	}
	if err := session.store.StartBody(session.writeCtx, storage.BodyStream{
		AuditID:        session.auditID,
		Stage:          stage.name,
		SourceStage:    stage.name,
		State:          storage.StageStateStreaming,
		RetentionState: storage.RetentionPending,
	}); err != nil {
		body.faulted = true
		body.errorCode = "start_body_failed"
		session.recordGapReasonLocked(gapReasonForWrite(err))
		session.markStageFaultLocked(stage, body.errorCode)
		return body
	}
	body.persisted = true
	return body
}

func (session *Session) observeBodyLocked(stage *stageCapture, body *bodyCapture, data []byte) {
	if len(data) == 0 {
		return
	}
	_, _ = body.digest.Write(data)
	observedAtNS := session.now().UnixNano()
	if body.firstAtNS == 0 {
		body.firstAtNS = observedAtNS
	}
	body.lastAtNS = observedAtNS
	if body.stream {
		observeStreamEvents(body, data, body.observedLength, observedAtNS)
	}
	body.observedLength += int64(len(data))
	if !body.persistChunks || !body.persisted {
		return
	}
	// Bound staging memory even when an upstream Reader returns a very large
	// buffer. Small bodies allocate only what they need, not a full chunk.
	for len(data) > 0 {
		if len(body.pending) == 0 {
			body.pendingAtNS = observedAtNS
		}
		count := min(len(data), bodyChunkSize-len(body.pending))
		needed := len(body.pending) + count
		if needed > cap(body.pending) {
			capacity := min(bodyChunkSize, max(needed, 2*cap(body.pending)))
			next := make([]byte, len(body.pending), capacity)
			copy(next, body.pending)
			clear(body.pending)
			body.pending = next
		}
		body.pending = append(body.pending, data[:count]...)
		data = data[count:]
		if len(body.pending) == bodyChunkSize {
			session.flushBodyLocked(stage, body, false)
		}
	}
}

func (session *Session) flushBodyLocked(stage *stageCapture, body *bodyCapture, force bool) {
	if body == nil {
		return
	}
	if force {
		// Completed request stages must not retain a chunk for the lifetime
		// of a potentially long-running streaming response.
		defer func() { clear(body.pending); body.pending = nil; body.pendingAtNS = 0 }()
	}
	if !body.persistChunks || !body.persisted || len(body.pending) == 0 {
		return
	}
	if !force && len(body.pending) < bodyChunkSize {
		return
	}
	// observeBodyLocked never stages more than one chunk. Encoding and
	// encryption are synchronous; AddChunk receives only owned ciphertext.
	plaintext := body.pending
	observedAtNS := body.pendingAtNS
	body.pending = body.pending[:0]
	body.pendingAtNS = 0
	defer clear(plaintext)

	sequence := body.nextSeq
	offset := body.storedLength
	body.nextSeq++
	compression, encoded, err := bodycodec.Encode(plaintext, stage.contentType)
	if err != nil {
		clear(plaintext)
		body.faulted = true
		body.errorCode = "body_compression_failed"
		session.markStageFaultLocked(stage, body.errorCode)
		return
	}
	encodedLength := len(encoded)
	aad, err := security.AAD(session.auditID, "body_chunk_v2", stage.name, strconv.FormatInt(sequence, 10), compression)
	if err != nil {
		clear(plaintext)
		clear(encoded)
		body.faulted = true
		body.errorCode = "body_encryption_failed"
		session.markStageFaultLocked(stage, body.errorCode)
		return
	}
	encrypted, err := session.cipher.Encrypt(aad, encoded)
	clear(encoded)
	if err != nil {
		clear(plaintext)
		body.faulted = true
		body.errorCode = "body_encryption_failed"
		session.markStageFaultLocked(stage, body.errorCode)
		return
	}
	if err := session.store.AddChunk(session.writeCtx, storage.BodyChunk{
		AuditID:         session.auditID,
		Stage:           stage.name,
		Seq:             sequence,
		Offset:          offset,
		PlaintextLength: len(plaintext),
		EncodedLength:   encodedLength,
		ObservedAtNS:    observedAtNS,
		Compression:     compression,
		DataEnc:         encrypted,
	}); err != nil {
		clear(plaintext)
		body.faulted = true
		body.errorCode = "add_chunk_failed"
		session.recordGapReasonLocked(gapReasonForWrite(err))
		session.markStageFaultLocked(stage, body.errorCode)
		return
	}
	body.storedLength += int64(len(plaintext))
	body.chunkCount++
	clear(plaintext)
}

func isEventStream(contentType string) bool {
	mediaType, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(mediaType) == "text/event-stream"
}

func observeStreamEvents(body *bodyCapture, data []byte, baseOffset, observedAtNS int64) {
	for index, value := range data {
		offset := baseOffset + int64(index) + 1
		if body.streamAfterCR {
			body.streamAfterCR = false
			if value == '\n' {
				continue
			}
		}
		switch value {
		case '\r':
			noteStreamLineEnd(body)
			finishStreamLine(body, offset, observedAtNS)
			body.streamAfterCR = true
		case '\n':
			noteStreamLineEnd(body)
			finishStreamLine(body, offset, observedAtNS)
		default:
			body.streamLineData = true
			body.streamHasData = true
			if len(body.streamLine) < maxStreamLineProbe {
				body.streamLine = append(body.streamLine, value)
			} else {
				body.streamLineOverflow = true
			}
		}
	}
}

// maxStreamLineProbe bounds the transient per-line buffer used for
// terminal-marker matching. Terminal marker lines are all shorter than this;
// longer lines (regular payload data) are truncated and can never match.
const maxStreamLineProbe = 48

func noteStreamLineEnd(body *bodyCapture) {
	if len(body.streamLine) == 0 && !body.streamLineOverflow {
		return
	}
	if body.terminalMatcher != nil && !body.streamTerminalCandidate &&
		!body.streamLineOverflow && body.terminalMatcher(body.streamLine) {
		body.streamTerminalCandidate = true
	}
	clear(body.streamLine)
	body.streamLine = body.streamLine[:0]
	body.streamLineOverflow = false
}

func finishStreamLine(body *bodyCapture, offset, observedAtNS int64) {
	if !body.streamLineData && body.streamHasData {
		body.streamEvents++
		if body.streamTerminalCandidate {
			body.streamTerminalSeen = true
			body.streamTerminalCandidate = false
		}
		if body.firstEventAtNS == 0 {
			body.firstEventAtNS = observedAtNS
		}
		body.lastEventAtNS = observedAtNS
		if len(body.streamPoints) < maxStreamTimelineEvents {
			body.streamPoints = append(body.streamPoints, streamtimeline.Point{Offset: offset, AtNS: observedAtNS})
		} else {
			body.streamComplete = false
		}
		body.streamHasData = false
	}
	body.streamLineData = false
}

func (session *Session) sealStreamTimelineLocked(stage *stageCapture, body *bodyCapture) (*storage.StreamTimeline, error) {
	if body == nil || !body.stream || body.streamEvents == 0 {
		return nil, nil
	}
	complete := body.streamComplete && !body.streamHasData && !body.streamLineData && int64(len(body.streamPoints)) == body.streamEvents
	plaintext, err := streamtimeline.Encode(body.streamPoints)
	if err != nil {
		return nil, err
	}
	plaintextLength := int64(len(plaintext))
	compression, encoded, err := bodycodec.Encode(plaintext, "application/x-llmapi-stream-timeline")
	clear(plaintext)
	if err != nil {
		return nil, err
	}
	aad, err := security.AAD(session.auditID, "stream_timeline_v1", stage.name, compression)
	if err != nil {
		clear(encoded)
		return nil, err
	}
	encrypted, err := session.cipher.Encrypt(aad, encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &storage.StreamTimeline{
		EventCount:      body.streamEvents,
		FirstEventAtNS:  optionalInt64(body.firstEventAtNS),
		LastEventAtNS:   optionalInt64(body.lastEventAtNS),
		Complete:        complete,
		Compression:     compression,
		PlaintextLength: plaintextLength,
		DataEnc:         encrypted,
	}, nil
}
