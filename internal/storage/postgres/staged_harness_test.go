package postgres

// The staged write harness describes one request the way internal/audit
// observes it and writes it twice: once with the legacy operations in the
// order Session issues them (session.go, body.go), once with BeginAudit
// carrying the inbound stage, the checkpoints and CommitAudit. The model
// mirrors the session's bookkeeping (1 MiB chunk boundaries, forced flush at
// EOF, Close and Finish, the response_sent logical EOF, the paired
// body_stage_mismatch check) and decides what each checkpoint carries by the
// rules of doc/design/issue-59-stage3-write-path.md B.1 and B.5. Values come
// from one deterministic clock, so both sequences carry the same values;
// each sequence seals its own ciphertext, so the comparison decrypts.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

const harnessChunkSize = 1 << 20

type harnessClock struct{ now int64 }

func (clock *harnessClock) tick() int64 {
	clock.now += 1000
	return clock.now
}

type hHeader struct {
	stage, kind, name string
	index             int
	value             string
}

type hChunk struct {
	stage       string
	seq, offset int64
	plaintext   []byte
	observedAt  int64
	contentType string
}

type hEventKind int

const (
	evStage hEventKind = iota + 1
	evBody
	evChunk
	evTrailer
)

type hEvent struct {
	kind    hEventKind
	stage   string
	headers []hHeader
	chunk   *hChunk
}

type hBody struct {
	digest                     hash.Hash
	observed, stored           int64
	nextSeq, chunkCount        int64
	pending                    []byte
	pendingAt                  int64
	first, last                int64
	eof, hashComplete, closed  bool
	faulted, writeFailed       bool
	errorCode                  string
	stream                     bool
	lineData, hasData, afterCR bool
	events                     int64
	points                     []streamtimeline.Point
	firstEvent, lastEvent      int64
}

type hStage struct {
	start       HTTPStage
	contentType string
	expectsBody bool
	body        *hBody
	faulted     bool
	errorCode   string
}

// hCheckpoint is one planned checkpoint: the events it carries, and whether
// request_sent's body row is written merged.
type hCheckpoint struct {
	events       []int
	mergedSentAt bool
}

type hStageFinish struct {
	finish   StageFinish
	timeline []byte // plaintext of the sealed stream timeline, nil for none
	tlCompr  string
}

type harness struct {
	t      *testing.T
	clock  *harnessClock
	id     string
	record AuditRecord
	uri    string
	stages map[string]*hStage
	events []hEvent

	forward                  string
	statusCode               *int
	blockedBy, blockCode     *string
	errorCode, newAPIRequest *string
	cancelled                bool
	captureFault             bool
	finished, crashed        bool
	stageFinishes            []hStageFinish
	auditFinish              AuditFinish
	recoverAt                int64
	checkpoints              []hCheckpoint
	// consumed marks the events a checkpoint or BeginAudit (event 0, the
	// request_received start) already carried.
	consumed                 map[int]bool
	mergedAtCheckpoint       bool
	requestSentWrittenAsSelf bool
	// responseInDB leaves the response pair to the database merge, as a
	// session does when it cannot decide the pair in memory.
	responseInDB bool
	// noRequestMerge never merges the request pair in memory, as a session
	// does after BeginAudit reported storage.ErrInboundStageNotStored.
	noRequestMerge bool
}

func newHarness(t *testing.T, clock *harnessClock, id string) *harness {
	h := &harness{t: t, clock: clock, id: id, stages: make(map[string]*hStage), forward: ForwardInProgress, consumed: map[int]bool{0: true}}
	h.uri = "/v1/chat/completions?trace=" + id
	h.record = AuditRecord{
		AuditID: id, StartedAtNS: clock.tick(), RouteID: "openai-chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions", Mode: "available",
	}
	return h
}

// --- the session model -----------------------------------------------------

func (h *harness) startStage(name, proto, method, host string, status *int, contentLength int64, headers http.Header, expectsBody bool) {
	if h.stages[name] != nil {
		return
	}
	stage := &hStage{
		start: HTTPStage{AuditID: h.id, Stage: name, State: StageStateStreaming, Proto: proto, Method: method, Host: host,
			StatusCode: cloneInt(status), ContentLength: &contentLength, StartedAtNS: h.clock.tick()},
		contentType: headers.Get("Content-Type"),
		expectsBody: expectsBody,
	}
	h.stages[name] = stage
	if status != nil {
		h.statusCode = cloneInt(status)
	}
	h.events = append(h.events, hEvent{kind: evStage, stage: name, headers: headerValues(name, HeaderKindHeader, headers)})
}

// headerValues is addHeadersLocked's iteration: byte-sorted map keys, then
// headers.Values(name) in order.
func headerValues(stage, kind string, headers http.Header) []hHeader {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]hHeader, 0)
	for _, name := range names {
		for index, value := range headers.Values(name) {
			values = append(values, hHeader{stage: stage, kind: kind, name: name, index: index, value: value})
		}
	}
	return values
}

func (h *harness) ensureBody(stage *hStage) *hBody {
	if stage.body != nil {
		return stage.body
	}
	body := &hBody{digest: sha256.New()}
	body.stream = stage.start.Stage == StageResponseReceived && isEventStreamType(stage.contentType)
	stage.body = body
	h.events = append(h.events, hEvent{kind: evBody, stage: stage.start.Stage})
	return body
}

func isEventStreamType(contentType string) bool {
	mediaType, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(mediaType) == "text/event-stream"
}

func (h *harness) observe(name string, data []byte) {
	stage := h.stages[name]
	if stage == nil {
		h.t.Fatalf("observe on unstarted stage %s", name)
	}
	body := h.ensureBody(stage)
	if len(data) == 0 {
		return
	}
	body.digest.Write(data)
	at := h.clock.tick()
	if body.first == 0 {
		body.first = at
	}
	body.last = at
	if body.stream {
		observeHarnessStream(body, data, body.observed, at)
	}
	body.observed += int64(len(data))
	for len(data) > 0 {
		if len(body.pending) == 0 {
			body.pendingAt = at
		}
		count := min(len(data), harnessChunkSize-len(body.pending))
		body.pending = append(body.pending, data[:count]...)
		data = data[count:]
		if len(body.pending) == harnessChunkSize {
			h.flush(stage, body, false)
		}
	}
}

func (h *harness) flush(stage *hStage, body *hBody, force bool) {
	if len(body.pending) == 0 || !force && len(body.pending) < harnessChunkSize {
		if force {
			body.pending, body.pendingAt = nil, 0
		}
		return
	}
	chunk := &hChunk{stage: stage.start.Stage, seq: body.nextSeq, offset: body.stored,
		plaintext: append([]byte(nil), body.pending...), observedAt: body.pendingAt, contentType: stage.contentType}
	body.nextSeq++
	body.stored += int64(len(chunk.plaintext))
	body.chunkCount++
	body.pending, body.pendingAt = nil, 0
	h.events = append(h.events, hEvent{kind: evChunk, stage: chunk.stage, chunk: chunk})
}

func observeHarnessStream(body *hBody, data []byte, baseOffset, at int64) {
	for index, value := range data {
		offset := baseOffset + int64(index) + 1
		if body.afterCR {
			body.afterCR = false
			if value == '\n' {
				continue
			}
		}
		switch value {
		case '\r', '\n':
			if !body.lineData && body.hasData {
				body.events++
				if body.firstEvent == 0 {
					body.firstEvent = at
				}
				body.lastEvent = at
				body.points = append(body.points, streamtimeline.Point{Offset: offset, AtNS: at})
				body.hasData = false
			}
			body.lineData = false
			body.afterCR = value == '\r'
		default:
			body.lineData = true
			body.hasData = true
		}
	}
}

// read observes a body read; eof ends it as observeRead does on io.EOF and
// then captures its trailers.
func (h *harness) read(name string, data []byte) { h.observe(name, data) }

func (h *harness) eof(name string, trailers http.Header) {
	stage := h.stages[name]
	body := h.ensureBody(stage)
	h.flush(stage, body, true)
	body.eof, body.hashComplete, body.closed = true, true, true
	h.trailers(name, trailers)
}

func (h *harness) trailers(name string, trailers http.Header) {
	if len(trailers) == 0 || h.stages[name] == nil {
		return
	}
	h.events = append(h.events, hEvent{kind: evTrailer, stage: name, headers: headerValues(name, HeaderKindTrailer, trailers)})
}

// closeBody is closeReadBody.
func (h *harness) closeBody(name string, closeErr bool) {
	stage := h.stages[name]
	if stage == nil || stage.body == nil {
		return
	}
	h.flush(stage, stage.body, true)
	stage.body.closed = true
	if closeErr {
		stage.body.faulted = true
		stage.body.errorCode = "body_close_error"
		h.markStageFault(stage, "body_close_error")
	}
}

// readError is observeRead with a read error.
func (h *harness) readError(name string) {
	stage := h.stages[name]
	body := h.ensureBody(stage)
	body.faulted, body.closed = true, true
	body.errorCode = "body_read_error"
	h.markStageFault(stage, body.errorCode)
	if name == StageResponseReceived {
		if h.cancelled {
			h.forward = ForwardClientCancelled
			h.errorCode = stringPointer("client_cancelled")
		} else if h.forward == ForwardInProgress {
			h.forward = ForwardNewAPIError
			h.errorCode = stringPointer("upstream_body_read_error")
		}
	}
}

// write is observedResponseWriter.Write: it starts response_sent first.
func (h *harness) write(data []byte, failed bool, headers http.Header, status int) {
	h.startResponseSent(headers, status)
	stage := h.stages[StageResponseSent]
	body := h.ensureBody(stage)
	h.observe(StageResponseSent, data)
	if !failed {
		return
	}
	body.faulted, body.writeFailed = true, true
	body.errorCode = "body_write_error"
	h.markStageFault(stage, body.errorCode)
	if h.cancelled {
		h.forward = ForwardClientCancelled
		h.errorCode = stringPointer("client_cancelled")
	} else if h.forward == ForwardInProgress {
		h.forward = ForwardProxyError
		h.errorCode = stringPointer("downstream_write_error")
	}
}

func (h *harness) startResponseSent(headers http.Header, status int) {
	if h.stages[StageResponseSent] != nil {
		return
	}
	length := int64(-1)
	if raw := headers.Get("Content-Length"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			length = parsed
		}
	}
	h.startStage(StageResponseSent, "HTTP/1.1", "", "", &status, length, headers, false)
}

func (h *harness) markStageFault(stage *hStage, code string) {
	stage.faulted = true
	if stage.errorCode == "" {
		stage.errorCode = code
	}
	h.captureFault = true
}

func (h *harness) markRejected(status int, blockedBy, blockCode string) {
	h.forward = ForwardRejected
	h.statusCode = &status
	h.blockedBy, h.blockCode = &blockedBy, &blockCode
}

func (h *harness) markNewAPIError(code string) {
	if h.cancelled {
		h.forward = ForwardClientCancelled
		h.errorCode = stringPointer("client_cancelled")
		return
	}
	h.forward = ForwardNewAPIError
	h.errorCode = stringPointer(code)
}

// --- the unified plan ------------------------------------------------------

func requestSide(stage string) bool {
	return stage == StageRequestReceived || stage == StageRequestSent
}

// bodyQualifies is B.5's in-memory form of the merge conditions 3 to 5 for
// a body as it stands now.
func bodyQualifies(body *hBody) bool {
	return body != nil && !body.faulted && body.eof && body.hashComplete && body.stored == body.observed
}

func bodiesEqual(source, duplicate *hBody) bool {
	return source.observed == duplicate.observed && bytes.Equal(source.digest.Sum(nil), duplicate.digest.Sum(nil))
}

// checkpoint plans one checkpoint: every new stage row and header group, the
// request-side body rows and sealed request-side chunks (B.1). It decides the
// request pair when request_sent's body row is first written (B.5).
func (h *harness) checkpoint() {
	var plan hCheckpoint
	for index, event := range h.events {
		if h.consumed[index] {
			continue
		}
		switch event.kind {
		case evStage, evTrailer:
		case evBody:
			if !requestSide(event.stage) {
				continue
			}
			if event.stage == StageRequestSent {
				source, duplicate := h.stages[StageRequestReceived], h.stages[StageRequestSent]
				if !h.noRequestMerge && source.body != nil && bodyQualifies(source.body) && bodyQualifies(duplicate.body) && bodiesEqual(source.body, duplicate.body) {
					h.mergedAtCheckpoint = true
					plan.mergedSentAt = true
				} else {
					h.requestSentWrittenAsSelf = true
				}
			}
		case evChunk:
			if !requestSide(event.stage) || event.stage == StageRequestSent && h.mergedAtCheckpoint {
				continue
			}
		}
		h.consumed[index] = true
		plan.events = append(plan.events, index)
	}
	if len(plan.events) != 0 {
		h.checkpoints = append(h.checkpoints, plan)
	}
}

// --- finish and crash ------------------------------------------------------

func (h *harness) finish() {
	if h.forward == ForwardInProgress {
		if h.cancelled && !h.responseLogicallyComplete() {
			h.forward = ForwardClientCancelled
			h.errorCode = stringPointer("client_cancelled")
		} else {
			h.forward = ForwardCompleted
		}
	}
	if h.forward == ForwardClientCancelled || h.forward == ForwardNewAPIError || h.forward == ForwardProxyError {
		h.captureFault = true
	}
	for _, name := range captureStageNames {
		stage := h.stages[name]
		if stage == nil {
			continue
		}
		h.stageFinishes = append(h.stageFinishes, h.finishStage(stage))
	}
	captureStatus := CaptureComplete
	if h.captureFault {
		captureStatus = CapturePartial
	}
	parseStatus := ParsePending
	if h.forward == ForwardRejected {
		parseStatus = ParseSkipped
	}
	h.auditFinish = AuditFinish{AuditID: h.id, EndedAtNS: h.clock.tick(), StatusCode: cloneInt(h.statusCode),
		ForwardStatus: h.forward, CaptureStatus: captureStatus, ParseStatus: parseStatus,
		BlockedBy: cloneString(h.blockedBy), BlockCode: cloneString(h.blockCode), ErrorCode: cloneString(h.errorCode),
		NewAPIRequestID: cloneString(h.newAPIRequest)}
	if sent := h.stages[StageResponseSent]; sent != nil {
		ttft := max(sent.start.StartedAtNS-h.record.StartedAtNS, 0)
		h.auditFinish.TTFTNS = &ttft
	}
	h.finished = true
}

func (h *harness) responseLogicallyComplete() bool {
	received := h.stages[StageResponseReceived]
	if received == nil || received.body == nil || !received.body.eof {
		return false
	}
	if received.start.ContentLength != nil && *received.start.ContentLength >= 0 && received.body.observed < *received.start.ContentLength {
		return false
	}
	sent := h.stages[StageResponseSent]
	return sent != nil && sent.body != nil && !sent.body.writeFailed && sent.body.observed >= received.body.observed
}

// finishStage is finishStageLocked.
func (h *harness) finishStage(stage *hStage) hStageFinish {
	name := stage.start.Stage
	state := StageStateComplete
	if stage.faulted || stage.expectsBody && stage.body == nil {
		state = StageStatePartial
		h.captureFault = true
	}
	var result hStageFinish
	var bodyFinish *BodyFinish
	if body := stage.body; body != nil {
		h.flush(stage, body, true)
		if name == StageResponseSent && !body.closed && !stage.faulted && h.forward == ForwardCompleted {
			body.eof, body.hashComplete, body.closed = true, true, true
		}
		timelineComplete := true
		if body.events > 0 {
			complete := !body.hasData && !body.lineData && int64(len(body.points)) == body.events
			plaintext, err := streamtimeline.Encode(body.points)
			if err != nil {
				h.t.Fatal(err)
			}
			result.timeline = plaintext
			timelineComplete = complete
		}
		if sourceName := pairedHarnessSource(name); sourceName != "" {
			if source := h.stages[sourceName]; source != nil && source.body != nil &&
				body.hashComplete && body.eof && source.body.hashComplete && source.body.eof && !bodiesEqual(source.body, body) {
				body.faulted = true
				body.errorCode = "body_stage_mismatch"
				h.markStageFault(stage, body.errorCode)
			}
		}
		bodyState := StageStateComplete
		if body.faulted || !body.eof || body.stored != body.observed {
			bodyState = StageStatePartial
			state = StageStatePartial
			h.captureFault = true
		}
		bodyError := body.errorCode
		if bodyError == "" {
			bodyError = stage.errorCode
		}
		bodyFinish = &BodyFinish{ObservedLength: body.observed, StoredLength: body.stored, SHA256: body.digest.Sum(nil),
			HashComplete: body.hashComplete, EOFSeen: body.eof, State: bodyState, RetentionState: RetentionPending,
			FirstObservedAtNS: optionalNS(body.first), LastObservedAtNS: optionalNS(body.last), ChunkCount: body.chunkCount,
			StreamEventCount: body.events, StreamTimelineComplete: timelineComplete, ErrorCode: optionalCode(bodyError)}
		if body.events > 0 {
			bodyFinish.Timeline = &StreamTimeline{EventCount: body.events, FirstEventAtNS: optionalNS(body.firstEvent),
				LastEventAtNS: optionalNS(body.lastEvent), Complete: timelineComplete}
		}
	}
	result.finish = StageFinish{AuditID: h.id, Stage: name, State: state, StatusCode: cloneInt(stage.start.StatusCode),
		ContentLength: cloneInt64(stage.start.ContentLength), EndedAtNS: h.clock.tick(), ErrorCode: optionalCode(stage.errorCode), Body: bodyFinish}
	return result
}

func pairedHarnessSource(stage string) string {
	switch stage {
	case StageRequestSent:
		return StageRequestReceived
	case StageResponseSent:
		return StageResponseReceived
	}
	return ""
}

func (h *harness) crash() {
	h.crashed = true
	h.recoverAt = h.clock.tick()
}

func optionalNS(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}

func optionalCode(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringPointer(value string) *string { return &value }

// --- sealing ---------------------------------------------------------------

type harnessSealer struct {
	t      *testing.T
	cipher *security.AESGCM
}

func (s harnessSealer) seal(plaintext []byte, parts ...string) []byte {
	aad, err := security.AAD(parts...)
	if err != nil {
		s.t.Fatal(err)
	}
	sealed, err := s.cipher.Encrypt(aad, plaintext)
	if err != nil {
		s.t.Fatal(err)
	}
	return sealed
}

func (s harnessSealer) headers(auditID string, values []hHeader) []HTTPHeader {
	rows := make([]HTTPHeader, 0, len(values))
	for _, value := range values {
		rows = append(rows, HTTPHeader{AuditID: auditID, Stage: value.stage, Kind: value.kind, Name: value.name,
			ValueIndex: value.index, ValueLength: len(value.value),
			ValueEnc: s.seal([]byte(value.value), auditID, "header", value.stage, value.kind, value.name, strconv.Itoa(value.index))})
	}
	return rows
}

func (s harnessSealer) chunk(auditID string, chunk *hChunk) BodyChunk {
	compression, encoded, err := bodycodec.Encode(chunk.plaintext, chunk.contentType)
	if err != nil {
		s.t.Fatal(err)
	}
	return BodyChunk{AuditID: auditID, Stage: chunk.stage, Seq: chunk.seq, Offset: chunk.offset,
		PlaintextLength: len(chunk.plaintext), EncodedLength: len(encoded), ObservedAtNS: chunk.observedAt, Compression: compression,
		DataEnc: s.seal(encoded, auditID, "body_chunk_v2", chunk.stage, strconv.FormatInt(chunk.seq, 10), compression)}
}

// stageFinish seals the timeline of one finished stage.
func (s harnessSealer) stageFinish(auditID string, value hStageFinish) StageFinish {
	finish := value.finish
	if finish.Body != nil {
		body := *finish.Body
		if value.timeline != nil {
			compression, encoded, err := bodycodec.Encode(value.timeline, "application/x-llmapi-stream-timeline")
			if err != nil {
				s.t.Fatal(err)
			}
			timeline := *body.Timeline
			timeline.Compression = compression
			timeline.PlaintextLength = int64(len(value.timeline))
			timeline.DataEnc = s.seal(encoded, auditID, "stream_timeline_v1", finish.Stage, compression)
			body.Timeline = &timeline
		}
		finish.Body = &body
	}
	return finish
}

// --- emitting the two sequences ---------------------------------------------

// hOp is one store call of a sequence. event is the model event a legacy
// operation comes from, or the ordinal of a checkpoint; -1 otherwise.
type hOp struct {
	kind  writeKind
	data  any
	event int
}

func (h *harness) sealedRecord(s harnessSealer) AuditRecord {
	record := h.record
	record.RequestURIEnc = s.seal([]byte(h.uri), h.id, "request_uri")
	return record
}

// legacyOps is the session's operation sequence today.
func (h *harness) legacyOps(s harnessSealer) []hOp {
	ops := []hOp{{writeBeginAudit, h.sealedRecord(s), -1}}
	for index, event := range h.events {
		switch event.kind {
		case evStage:
			ops = append(ops, hOp{writeStartStage, h.stages[event.stage].start, index})
			if len(event.headers) != 0 {
				ops = append(ops, hOp{writeAddHeaders, s.headers(h.id, event.headers), index})
			}
		case evBody:
			ops = append(ops, hOp{writeStartBody, BodyStream{AuditID: h.id, Stage: event.stage, SourceStage: event.stage,
				State: StageStateStreaming, RetentionState: RetentionPending}, index})
		case evChunk:
			ops = append(ops, hOp{writeAddChunk, s.chunk(h.id, event.chunk), index})
		case evTrailer:
			ops = append(ops, hOp{writeAddHeaders, s.headers(h.id, event.headers), index})
		}
	}
	if h.finished {
		for _, finish := range h.stageFinishes {
			ops = append(ops, hOp{writeFinishStage, s.stageFinish(h.id, finish), -1})
		}
		ops = append(ops, hOp{writeFinishAudit, h.auditFinish, -1})
	}
	if h.crashed {
		ops = append(ops, hOp{writeRecoverInterruptedAudits, h.recoverAt, -1})
	}
	return ops
}

func initialBody(auditID, stage, source string) BodyStream {
	body := BodyStream{AuditID: auditID, Stage: stage, SourceStage: source, State: StageStateStreaming, RetentionState: RetentionPending}
	body.Defaults()
	return body
}

// pairMergesAtFinish is the database merge condition on final values
// (deduplicateEquivalentBodyPair) for an audit that is not failed.
func (h *harness) pairMergesAtFinish(sourceName, duplicateName string) bool {
	var source, duplicate *BodyFinish
	for _, value := range h.stageFinishes {
		switch value.finish.Stage {
		case sourceName:
			source = value.finish.Body
		case duplicateName:
			duplicate = value.finish.Body
		}
	}
	return source != nil && duplicate != nil && source.State == StageStateComplete && duplicate.State == StageStateComplete &&
		source.HashComplete && duplicate.HashComplete && source.EOFSeen && duplicate.EOFSeen &&
		source.StoredLength == source.ObservedLength && duplicate.StoredLength == duplicate.ObservedLength &&
		source.ObservedLength == duplicate.ObservedLength && len(source.SHA256) == 32 && bytes.Equal(source.SHA256, duplicate.SHA256)
}

// unifiedOps is BeginAudit with the inbound stage, the planned checkpoints
// and the commit (or the recovery after a crash).
func (h *harness) unifiedOps(s harnessSealer) []hOp {
	record := h.sealedRecord(s)
	first := h.events[0]
	if first.kind != evStage || first.stage != StageRequestReceived {
		h.t.Fatal("request_received must start first")
	}
	record.Inbound = &InboundStage{Stage: h.stages[StageRequestReceived].start, Headers: s.headers(h.id, first.headers)}
	ops := []hOp{{writeBeginAudit, record, -1}}
	stageWritten := map[string]bool{StageRequestReceived: true}
	bodyWritten := map[string]bool{}
	written := map[int]bool{0: true}
	for ordinal, plan := range h.checkpoints {
		checkpoint := AuditCheckpoint{AuditID: h.id}
		var chunks storage.ChunkList
		for _, index := range plan.events {
			written[index] = true
			event := h.events[index]
			switch event.kind {
			case evStage:
				stageWritten[event.stage] = true
				checkpoint.Stages = append(checkpoint.Stages, h.stages[event.stage].start)
				checkpoint.Headers = append(checkpoint.Headers, s.headers(h.id, event.headers)...)
			case evTrailer:
				checkpoint.Headers = append(checkpoint.Headers, s.headers(h.id, event.headers)...)
			case evBody:
				bodyWritten[event.stage] = true
				source := event.stage
				if event.stage == StageRequestSent && plan.mergedSentAt {
					source = StageRequestReceived
				}
				checkpoint.Bodies = append(checkpoint.Bodies, initialBody(h.id, event.stage, source))
			case evChunk:
				chunks = append(chunks, s.chunk(h.id, event.chunk))
			}
		}
		if len(chunks) != 0 {
			checkpoint.Chunks = chunks
		}
		ops = append(ops, hOp{writeCheckpoint, checkpoint, ordinal})
	}
	if h.crashed {
		return append(ops, hOp{writeRecoverInterruptedAudits, h.recoverAt, -1})
	}
	if !h.finished {
		return ops
	}

	requestMerged := false
	var dedup [2]bool
	switch {
	case h.requestSentWrittenAsSelf, h.noRequestMerge:
		dedup[0] = true // written with its own chunks: merge as legacy does
	default:
		requestMerged = h.pairMergesAtFinish(StageRequestReceived, StageRequestSent)
	}
	responseMerged := !h.responseInDB && h.pairMergesAtFinish(StageResponseReceived, StageResponseSent)
	dedup[1] = h.responseInDB
	commit := AuditCommit{Finish: h.auditFinish, DedupInDB: dedup}
	finals := make(map[string]*BodyFinish)
	for _, value := range h.stageFinishes {
		finals[value.finish.Stage] = value.finish.Body
	}
	for _, value := range h.stageFinishes {
		sealed := s.stageFinish(h.id, value)
		name := sealed.Stage
		stage := h.stages[name]
		final := stage.start
		final.State = sealed.State
		final.StatusCode = cloneInt(sealed.StatusCode)
		final.ContentLength = cloneInt64(sealed.ContentLength)
		final.EndedAtNS = &sealed.EndedAtNS
		final.ErrorCode = cloneString(sealed.ErrorCode)
		entry := StageCommit{Stage: final, StageWritten: stageWritten[name], BodyWritten: bodyWritten[name]}
		if body := sealed.Body; body != nil {
			stream := BodyStream{AuditID: h.id, Stage: name, SourceStage: name, ObservedLength: body.ObservedLength,
				StoredLength: body.StoredLength, SHA256: body.SHA256, HashComplete: body.HashComplete, EOFSeen: body.EOFSeen,
				State: body.State, RetentionState: body.RetentionState, FirstObservedAtNS: body.FirstObservedAtNS,
				LastObservedAtNS: body.LastObservedAtNS, ChunkCount: body.ChunkCount, StreamEventCount: body.StreamEventCount,
				StreamTimelineComplete: body.StreamTimelineComplete, ErrorCode: body.ErrorCode}
			if name == StageRequestSent && requestMerged || name == StageResponseSent && responseMerged {
				source := finals[pairedHarnessSource(name)]
				stream.SourceStage = pairedHarnessSource(name)
				stream.StoredLength, stream.ChunkCount = source.StoredLength, source.ChunkCount
				stream.StreamEventCount, stream.StreamTimelineComplete = source.StreamEventCount, source.StreamTimelineComplete
			}
			entry.Body = &stream
			entry.Timeline = body.Timeline
		}
		commit.Stages = append(commit.Stages, entry)
	}
	var chunks storage.ChunkList
	for index, event := range h.events {
		if written[index] {
			continue
		}
		switch event.kind {
		case evStage, evTrailer:
			commit.Headers = append(commit.Headers, s.headers(h.id, event.headers)...)
		case evChunk:
			if event.stage == StageRequestSent && requestMerged || event.stage == StageResponseSent && responseMerged {
				continue
			}
			chunk := s.chunk(h.id, event.chunk)
			commit.PayloadBytes += int64(len(chunk.DataEnc))
			chunks = append(chunks, chunk)
		}
	}
	if len(chunks) != 0 {
		commit.Chunks = chunks
	}
	return append(ops, hOp{writeCommitAudit, commit, -1})
}

// run applies a sequence through the public store methods.
func runHarnessOps(t *testing.T, store *Store, ops []hOp) AuditFinish {
	t.Helper()
	ctx := context.Background()
	var outcome AuditFinish
	for index, op := range ops {
		var err error
		switch op.kind {
		case writeBeginAudit:
			err = store.BeginAudit(ctx, op.data.(AuditRecord))
		case writeStartStage:
			err = store.StartStage(ctx, op.data.(HTTPStage))
		case writeAddHeaders:
			err = store.AddHeaders(ctx, op.data.([]HTTPHeader))
		case writeStartBody:
			err = store.StartBody(ctx, op.data.(BodyStream))
		case writeAddChunk:
			err = store.AddChunk(ctx, op.data.(BodyChunk))
		case writeFinishStage:
			err = store.FinishStage(ctx, op.data.(StageFinish))
		case writeFinishAudit:
			outcome, err = store.FinishAuditWithResult(ctx, op.data.(AuditFinish))
		case writeCheckpoint:
			err = store.Checkpoint(ctx, op.data.(AuditCheckpoint))
		case writeCommitAudit:
			outcome, err = store.CommitAudit(ctx, op.data.(AuditCommit))
		case writeRecoverInterruptedAudits:
			_, err = store.RecoverInterruptedAudits(ctx, op.data.(int64))
		default:
			t.Fatalf("operation %d: unknown kind %d", index, op.kind)
		}
		if err != nil {
			t.Fatalf("operation %d (kind %d): %v", index, op.kind, err)
		}
	}
	return outcome
}

// --- comparing rows ----------------------------------------------------------

type harnessRow map[string]any

type harnessDump map[string][]harnessRow

var harnessTables = []struct{ name, order string }{
	{"audit_records", "audit_id"},
	{"http_stages", "stage"},
	{"http_headers", "stage, kind, name, value_index"},
	{"body_streams", "stage"},
	{"body_chunks", "stage, seq"},
	{"stream_timelines", "stage"},
	{"integrity_events", "sequence"},
}

// dumpAudit reads every row of one audit. Ciphertext is opened with the AAD
// rebuilt from the row's own identity and kept as plaintext plus ciphertext
// length; integrity MACs and payload digests are dropped (B.10: they cover
// ciphertext hashes).
func dumpAudit(t *testing.T, database *sql.DB, cipher *security.AESGCM, auditID string) harnessDump {
	t.Helper()
	dump := make(harnessDump)
	for _, table := range harnessTables {
		rows, err := database.Query(`SELECT * FROM `+table.name+` WHERE audit_id = $1 ORDER BY `+table.order, auditID)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			row := make(harnessRow, len(columns))
			for index, column := range columns {
				row[column] = values[index]
			}
			openHarnessRow(t, cipher, table.name, row)
			dump[table.name] = append(dump[table.name], row)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return dump
}

func openHarnessRow(t *testing.T, cipher *security.AESGCM, table string, row harnessRow) {
	text := func(column string) string { return fmt.Sprint(row[column]) }
	open := func(column string, parts ...string) {
		blob, _ := row[column].([]byte)
		if blob == nil {
			return
		}
		aad, err := security.AAD(parts...)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := cipher.Decrypt(aad, blob)
		if err != nil {
			row[column] = fmt.Sprintf("undecryptable (%d bytes)", len(blob))
			return
		}
		row[column] = fmt.Sprintf("len=%d plaintext=%s", len(blob), hex.EncodeToString(plaintext))
	}
	switch table {
	case "audit_records":
		open("request_uri_enc", text("audit_id"), "request_uri")
	case "http_headers":
		open("value_enc", text("audit_id"), "header", text("stage"), text("kind"), text("name"), text("value_index"))
	case "body_chunks":
		open("data_enc", text("audit_id"), "body_chunk_v2", text("stage"), text("seq"), text("compression"))
	case "stream_timelines":
		open("timeline_enc", text("audit_id"), "stream_timeline_v1", text("stage"), text("compression"))
	case "integrity_events":
		delete(row, "previous_mac")
		delete(row, "payload_digest")
		delete(row, "event_mac")
	}
	for column, value := range row {
		if blob, ok := value.([]byte); ok {
			row[column] = hex.EncodeToString(blob)
		}
	}
}

// diffDumps lists every difference between two dumps.
func diffDumps(legacy, unified harnessDump) []string {
	var differences []string
	for _, table := range harnessTables {
		left, right := legacy[table.name], unified[table.name]
		if len(left) != len(right) {
			differences = append(differences, fmt.Sprintf("%s: %d legacy rows, %d unified rows\n  legacy:  %v\n  unified: %v", table.name, len(left), len(right), summarizeRows(left), summarizeRows(right)))
			continue
		}
		for index := range left {
			for column := range mergeKeys(left[index], right[index]) {
				if !reflect.DeepEqual(left[index][column], right[index][column]) {
					differences = append(differences, fmt.Sprintf("%s row %d column %s: legacy %v, unified %v",
						table.name, index, column, shorten(left[index][column]), shorten(right[index][column])))
				}
			}
		}
	}
	return differences
}

func summarizeRows(rows []harnessRow) []string {
	summary := make([]string, 0, len(rows))
	for _, row := range rows {
		key := fmt.Sprint(row["stage"])
		if seq, ok := row["seq"]; ok {
			key += "#" + fmt.Sprint(seq)
		}
		if name, ok := row["name"]; ok {
			key += "/" + fmt.Sprint(row["kind"]) + "/" + fmt.Sprint(name)
		}
		summary = append(summary, key)
	}
	return summary
}

func mergeKeys(left, right harnessRow) map[string]bool {
	keys := make(map[string]bool, len(left))
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	return keys
}

func shorten(value any) string {
	text := fmt.Sprint(value)
	if len(text) > 120 {
		return text[:120] + "..."
	}
	return text
}

func countRows(dump harnessDump, table string) int { return len(dump[table]) }

// dropRows removes the rows of a table that match.
func (dump harnessDump) dropRows(table string, match func(harnessRow) bool) int {
	kept := dump[table][:0]
	dropped := 0
	for _, row := range dump[table] {
		if match(row) {
			dropped++
			continue
		}
		kept = append(kept, row)
	}
	dump[table] = kept
	return dropped
}

func stageIs(names ...string) func(harnessRow) bool {
	return func(row harnessRow) bool {
		for _, name := range names {
			if row["stage"] == name {
				return true
			}
		}
		return false
	}
}
