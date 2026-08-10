package audit

import (
	"crypto/sha256"
	"hash"
	"io"
	"net/http"
	"strconv"
	"sync"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

type bodyCapture struct {
	digest         hash.Hash
	persisted      bool
	observedLength int64
	storedLength   int64
	nextSeq        int64
	eofSeen        bool
	hashComplete   bool
	closed         bool
	faulted        bool
	errorCode      string
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
	body := &bodyCapture{digest: sha256.New()}
	stage.body = body
	if !stage.persisted {
		body.faulted = true
		body.errorCode = "start_stage_failed"
		return body
	}
	if err := session.store.StartBody(session.writeCtx, sqlite.BodyStream{
		AuditID: session.auditID,
		Stage:   stage.name,
		State:   sqlite.StageStateStreaming,
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
	baseOffset := body.observedLength
	body.observedLength += int64(len(data))

	for start := 0; start < len(data); start += bodyChunkSize {
		end := min(start+bodyChunkSize, len(data))
		plaintext := data[start:end]
		sequence := body.nextSeq
		offset := baseOffset + int64(start)
		body.nextSeq++
		if !body.persisted {
			continue
		}
		aad, err := security.AAD(session.auditID, "body_chunk", stage.name, strconv.FormatInt(sequence, 10))
		if err != nil {
			body.faulted = true
			body.errorCode = "body_encryption_failed"
			session.markStageFaultLocked(stage, body.errorCode)
			continue
		}
		encrypted, err := session.cipher.Encrypt(aad, plaintext)
		if err != nil {
			body.faulted = true
			body.errorCode = "body_encryption_failed"
			session.markStageFaultLocked(stage, body.errorCode)
			continue
		}
		if err := session.store.AddChunk(session.writeCtx, sqlite.BodyChunk{
			AuditID:         session.auditID,
			Stage:           stage.name,
			Seq:             sequence,
			Offset:          offset,
			PlaintextLength: len(plaintext),
			ObservedAtNS:    session.now().UnixNano(),
			DataEnc:         encrypted,
		}); err != nil {
			body.faulted = true
			body.errorCode = "add_chunk_failed"
			session.recordGapReasonLocked(gapReasonForWrite(err))
			session.markStageFaultLocked(stage, body.errorCode)
			continue
		}
		body.storedLength += int64(len(plaintext))
	}
}
