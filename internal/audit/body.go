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
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
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
	stream         bool
	streamLineData bool
	streamHasData  bool
	streamAfterCR  bool
	streamEvents   int64
	streamComplete bool
	streamPoints   []streamtimeline.Point
	firstEventAtNS int64
	lastEventAtNS  int64
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
			reader.session.addHeaders(reader.stage, sqlite.HeaderKindTrailer, reader.trailers())
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
		body.faulted = true
		body.closed = true
		body.errorCode = "body_read_error"
		session.markStageFaultLocked(stage, body.errorCode)
		if stageName == sqlite.StageResponseReceived {
			if session.request != nil && session.request.Err() != nil {
				session.forwardStatus = sqlite.ForwardClientCancelled
				session.errorCode = stringPointer("client_cancelled")
			} else if session.forwardStatus == sqlite.ForwardInProgress {
				session.forwardStatus = sqlite.ForwardNewAPIError
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
	body.errorCode = "body_write_error"
	session.markStageFaultLocked(stage, body.errorCode)
	if session.request != nil && session.request.Err() != nil {
		session.forwardStatus = sqlite.ForwardClientCancelled
		session.errorCode = stringPointer("client_cancelled")
	} else if session.forwardStatus == sqlite.ForwardInProgress {
		session.forwardStatus = sqlite.ForwardProxyError
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
		pending:        make([]byte, 0, bodyChunkSize),
		streamComplete: true,
	}
	body.stream = body.persistChunks && stage.name == sqlite.StageResponseReceived && isEventStream(stage.contentType)
	if body.stream {
		body.streamPoints = make([]streamtimeline.Point, 0, 256)
	}
	stage.body = body
	if !stage.persisted {
		body.faulted = true
		body.errorCode = "start_stage_failed"
		return body
	}
	if err := session.store.StartBody(session.writeCtx, sqlite.BodyStream{
		AuditID:        session.auditID,
		Stage:          stage.name,
		SourceStage:    stage.name,
		State:          sqlite.StageStateStreaming,
		RetentionState: sqlite.RetentionPending,
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
	if len(body.pending) == 0 {
		body.pendingAtNS = observedAtNS
	}
	body.pending = append(body.pending, data...)
	for len(body.pending) >= bodyChunkSize {
		session.flushBodyLocked(stage, body, false)
	}
}

func (session *Session) flushBodyLocked(stage *stageCapture, body *bodyCapture, force bool) {
	if body == nil || !body.persistChunks || !body.persisted || len(body.pending) == 0 {
		return
	}
	if !force && len(body.pending) < bodyChunkSize {
		return
	}
	length := min(len(body.pending), bodyChunkSize)
	plaintext := append([]byte(nil), body.pending[:length]...)
	remaining := append([]byte(nil), body.pending[length:]...)
	clear(body.pending)
	body.pending = append(body.pending[:0], remaining...)
	observedAtNS := body.pendingAtNS
	if len(body.pending) == 0 {
		body.pendingAtNS = 0
	} else {
		body.pendingAtNS = body.lastAtNS
	}

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
	if err := session.store.AddChunk(session.writeCtx, sqlite.BodyChunk{
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
			finishStreamLine(body, offset, observedAtNS)
			body.streamAfterCR = true
		case '\n':
			finishStreamLine(body, offset, observedAtNS)
		default:
			body.streamLineData = true
			body.streamHasData = true
		}
	}
}

func finishStreamLine(body *bodyCapture, offset, observedAtNS int64) {
	if !body.streamLineData && body.streamHasData {
		body.streamEvents++
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

func (session *Session) sealStreamTimelineLocked(stage *stageCapture, body *bodyCapture) (*sqlite.StreamTimeline, error) {
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
	return &sqlite.StreamTimeline{
		EventCount:      body.streamEvents,
		FirstEventAtNS:  optionalInt64(body.firstEventAtNS),
		LastEventAtNS:   optionalInt64(body.lastEventAtNS),
		Complete:        complete,
		Compression:     compression,
		PlaintextLength: plaintextLength,
		DataEnc:         encrypted,
	}, nil
}
