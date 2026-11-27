package sqlite

// This file is the equivalence harness for the unified write path. One
// described request runs through a model of the capture session
// (internal/audit session.go and body.go: stage starts, 1 MiB chunk
// boundaries, the forced flush at end of body, the logical EOF of
// response_sent, finishStageLocked and the deterministic clock calls) and
// drives two databases at once:
//
//   - the legacy sink issues StartStage, AddHeaders, StartBody, AddChunk,
//     FinishStage and FinishAuditWithResult in the order the session issues
//     them, and lets the store merge equivalent stage pairs in the database;
//   - the unified sink issues BeginAudit with the inbound stage, the two
//     checkpoints at the moments of design B.1, and CommitAudit, and decides
//     the pair merges itself from the final values (B.5).
//
// The merge decision of the unified sink is written independently of the
// store's deduplicateEquivalentBodyPair, so agreement of the two databases is
// evidence, not a tautology. Each sink encrypts with its own cipher, so every
// ciphertext differs and the comparison decrypts with the AAD derived from the
// row's own columns.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

const (
	eqChunkSize   = 1 << 20
	eqClockOrigin = 1_700_000_000_000_000_000
)

var eqKey = bytes.Repeat([]byte{0x5e}, security.KeySize)

type eqValue struct {
	name  string
	index int
	value string
}

type eqGroup struct {
	kind   string
	values []eqValue
}

type eqChunk struct {
	stage       string
	seq         int64
	offset      int64
	plain       int
	encoded     []byte
	compression string
	observedAt  int64
}

type eqTimeline struct {
	events          int64
	first, last     *int64
	complete        bool
	compression     string
	plaintextLength int64
	encoded         []byte
}

type eqBody struct {
	digest      hash.Hash
	observed    int64
	stored      int64
	nextSeq     int64
	chunkCount  int64
	pending     []byte
	pendingAt   int64
	first, last int64
	eof         bool
	hashDone    bool
	closed      bool
	faulted     bool
	writeFailed bool
	errorCode   string

	stream         bool
	lineData       bool
	hasData        bool
	afterCR        bool
	events         int64
	points         []streamtimeline.Point
	firstEvent     int64
	lastEvent      int64
	streamComplete bool

	chunks []eqChunk
}

type eqStage struct {
	name          string
	proto         string
	method        string
	host          string
	status        *int
	contentLength *int64
	contentType   string
	expectsBody   bool
	startedAt     int64
	faulted       bool
	errorCode     string
	body          *eqBody
	groups        []eqGroup
	timeline      *eqTimeline
}

// eqRun is the session model. Both sinks see exactly the same values and
// timestamps, so any difference in the stored rows comes from the write path.
type eqRun struct {
	t         *testing.T
	ctx       context.Context
	clock     int64
	id        string
	started   int64
	stages    map[string]*eqStage
	forward   string
	status    *int
	blockedBy *string
	blockCode *string
	errorCode *string
	requestID *string
	fault     bool
	cancelled bool
	encoder   bodycodec.Encoder

	legacy  *eqLegacy
	unified *eqUnified
	paths   map[*Store]string
	// commitResult is what CommitAudit returned; legacyResult is what
	// FinishAuditWithResult returned.
	commitResult AuditFinish
	legacyResult AuditFinish
}

func newEqRun(t *testing.T, id string) *eqRun {
	t.Helper()
	ctx := context.Background()
	run := &eqRun{
		t:       t,
		ctx:     ctx,
		clock:   eqClockOrigin,
		id:      id,
		stages:  make(map[string]*eqStage, 4),
		forward: ForwardInProgress,
	}
	legacyStore, legacyPath := openEqStore(t, "legacy")
	unifiedStore, unifiedPath := openEqStore(t, "unified")
	run.paths = map[*Store]string{legacyStore: legacyPath, unifiedStore: unifiedPath}
	run.legacy = &eqLegacy{run: run, store: legacyStore, cipher: newEqCipher(t)}
	run.unified = &eqUnified{
		run: run, store: unifiedStore, cipher: newEqCipher(t),
		stageWritten: map[string]bool{}, groupsWritten: map[string]int{}, bodyWritten: map[string]bool{},
		chunksWritten: map[string]int{}, merged: map[string]bool{},
	}
	return run
}

func openEqStore(t *testing.T, name string) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name, "audit.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnableIntegrity(context.Background(), eqKey); err != nil {
		t.Fatal(err)
	}
	return store, path
}

func newEqCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(eqKey)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func (run *eqRun) now() int64 {
	run.clock++
	return run.clock
}

// ---- session model -------------------------------------------------------

func (run *eqRun) begin(method string, headers http.Header, contentLength int64, hasBody bool) {
	run.started = run.now()
	record := AuditRecord{
		AuditID: run.id, StartedAtNS: run.started, RouteID: "openai-chat", Protocol: "openai",
		ParserName: "openai.chat_completions", Method: method, Path: "/v1/chat/completions", Mode: "available",
	}
	run.legacy.beginAudit(record)
	stage := run.startStage(StageRequestReceived, "HTTP/1.1", method, "proxy.example.com", nil, &contentLength, headers, hasBody)
	run.unified.beginAudit(record, stage)
}

func (run *eqRun) startRequestSent(headers http.Header, contentLength int64, hasBody bool) {
	method := run.stages[StageRequestReceived].method
	run.startStage(StageRequestSent, "HTTP/1.1", method, "newapi.example.com", nil, &contentLength, headers, hasBody)
}

func (run *eqRun) startResponseReceived(status int, headers http.Header, contentLength int64, hasBody bool) {
	if requestID := strings.TrimSpace(headers.Get("X-Oneapi-Request-Id")); requestID != "" {
		run.requestID = &requestID
	}
	method := run.stages[StageRequestReceived].method
	run.startStage(StageResponseReceived, "HTTP/1.1", method, "newapi.example.com", &status, &contentLength, headers, hasBody)
}

// startResponseSent is observedResponseWriter.start; checkpoint 2 follows it
// when the upstream response stage exists and the forward is in progress.
func (run *eqRun) startResponseSent(status int, headers http.Header) {
	contentLength := int64(-1)
	if raw := headers.Get("Content-Length"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed >= 0 {
			contentLength = parsed
		}
	}
	run.startStage(StageResponseSent, "HTTP/1.1", "", "", &status, &contentLength, headers, false)
	if run.stages[StageResponseReceived] != nil && run.forwardInProgress() {
		run.unified.checkpoint()
	}
}

// requestSentDone is the end of the request_sent body (EOF, Close or read
// error, after its trailers): checkpoint 1 when the forward is in progress.
func (run *eqRun) requestSentDone() {
	if run.forwardInProgress() {
		run.unified.checkpoint()
	}
}

func (run *eqRun) forwardInProgress() bool {
	return run.forward == ForwardInProgress && !run.cancelled
}

func (run *eqRun) startStage(name, proto, method, host string, status *int, contentLength *int64, headers http.Header, expectsBody bool) *eqStage {
	stage := &eqStage{
		name: name, proto: proto, method: method, host: host, status: cloneInt(status), contentLength: cloneInt64(contentLength),
		contentType: headers.Get("Content-Type"), expectsBody: expectsBody, startedAt: run.now(),
	}
	run.stages[name] = stage
	if status != nil {
		run.status = cloneInt(status)
	}
	var group *eqGroup
	if len(headers) != 0 {
		group = run.addGroup(stage, HeaderKindHeader, headers)
	}
	run.legacy.startStage(stage, group)
	return stage
}

// addGroup is addHeadersLocked: names in byte order, Values per name.
func (run *eqRun) addGroup(stage *eqStage, kind string, headers http.Header) *eqGroup {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	group := eqGroup{kind: kind}
	for _, name := range names {
		for index, value := range headers.Values(name) {
			group.values = append(group.values, eqValue{name: name, index: index, value: value})
		}
	}
	stage.groups = append(stage.groups, group)
	return &stage.groups[len(stage.groups)-1]
}

// trailers is observedReadCloser.captureTrailers or CaptureTrailers.
func (run *eqRun) trailers(name string, headers http.Header) {
	stage := run.stages[name]
	if stage == nil || len(headers) == 0 {
		return
	}
	run.legacy.addHeaders(stage, run.addGroup(stage, HeaderKindTrailer, headers))
}

func (run *eqRun) ensureBody(stage *eqStage) *eqBody {
	if stage.body != nil {
		return stage.body
	}
	body := &eqBody{digest: sha256.New(), streamComplete: true}
	body.stream = stage.name == StageResponseReceived && strings.HasPrefix(strings.ToLower(stage.contentType), "text/event-stream")
	stage.body = body
	run.legacy.startBody(stage)
	return body
}

func (run *eqRun) observe(stage *eqStage, body *eqBody, data []byte) {
	if len(data) == 0 {
		return
	}
	_, _ = body.digest.Write(data)
	at := run.now()
	if body.first == 0 {
		body.first = at
	}
	body.last = at
	if body.stream {
		run.observeEvents(body, data, body.observed, at)
	}
	body.observed += int64(len(data))
	for len(data) > 0 {
		if len(body.pending) == 0 {
			body.pendingAt = at
		}
		count := min(len(data), eqChunkSize-len(body.pending))
		body.pending = append(body.pending, data[:count]...)
		data = data[count:]
		if len(body.pending) == eqChunkSize {
			run.flush(stage, body, false)
		}
	}
}

func (run *eqRun) observeEvents(body *eqBody, data []byte, base, at int64) {
	for index, value := range data {
		offset := base + int64(index) + 1
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

func (run *eqRun) flush(stage *eqStage, body *eqBody, force bool) {
	if len(body.pending) == 0 || !force && len(body.pending) < eqChunkSize {
		return
	}
	plain := body.pending
	body.pending = nil
	compression, encoded, err := run.encoder.Encode(plain, stage.contentType)
	if err != nil {
		run.t.Fatal(err)
	}
	chunk := eqChunk{
		stage: stage.name, seq: body.nextSeq, offset: body.stored, plain: len(plain),
		encoded: append([]byte(nil), encoded...), compression: compression, observedAt: body.pendingAt,
	}
	body.nextSeq++
	body.pendingAt = 0
	body.chunks = append(body.chunks, chunk)
	run.legacy.addChunk(chunk)
	body.stored += int64(len(plain))
	body.chunkCount++
}

func (run *eqRun) markStageFault(stage *eqStage, code string) {
	stage.faulted = true
	if stage.errorCode == "" {
		stage.errorCode = code
	}
	run.fault = true
}

// read is observeRead with data and a nil error.
func (run *eqRun) read(name string, data []byte) {
	stage := run.stages[name]
	run.observe(stage, run.ensureBody(stage), data)
}

// readBoth is one Transport read of the outbound body: the inbound reader is
// observed first, then the outbound one.
func (run *eqRun) readBoth(data []byte) {
	run.read(StageRequestReceived, data)
	run.read(StageRequestSent, data)
}

// eof is observeRead(io.EOF) followed by captureTrailers.
func (run *eqRun) eof(name string, trailers http.Header) {
	stage := run.stages[name]
	body := run.ensureBody(stage)
	run.flush(stage, body, true)
	body.eof, body.hashDone, body.closed = true, true, true
	run.trailers(name, trailers)
}

func (run *eqRun) requestEOF(trailers http.Header) {
	run.eof(StageRequestReceived, trailers)
	run.eof(StageRequestSent, trailers)
	run.requestSentDone()
}

// readError is observeRead with a non-EOF error.
func (run *eqRun) readError(name string) {
	stage := run.stages[name]
	body := run.ensureBody(stage)
	body.faulted, body.closed, body.errorCode = true, true, "body_read_error"
	run.markStageFault(stage, body.errorCode)
	if name == StageResponseReceived {
		if run.cancelled {
			run.forward = ForwardClientCancelled
			run.errorCode = stringPointer("client_cancelled")
		} else if run.forward == ForwardInProgress {
			run.forward = ForwardNewAPIError
			run.errorCode = stringPointer("upstream_body_read_error")
		}
	}
}

// closeBody is closeReadBody.
func (run *eqRun) closeBody(name string, closeErr error) {
	stage := run.stages[name]
	if stage == nil || stage.body == nil {
		return
	}
	body := stage.body
	run.flush(stage, body, true)
	body.closed = true
	if closeErr != nil {
		body.faulted, body.errorCode = true, "body_close_error"
		run.markStageFault(stage, body.errorCode)
	}
}

// write is observeWrite on response_sent.
func (run *eqRun) write(data []byte, writeErr error) {
	stage := run.stages[StageResponseSent]
	body := run.ensureBody(stage)
	run.observe(stage, body, data)
	if writeErr == nil {
		return
	}
	body.faulted, body.writeFailed, body.errorCode = true, true, "body_write_error"
	run.markStageFault(stage, body.errorCode)
	if run.cancelled {
		if !run.responseLogicallyComplete() {
			run.forward = ForwardClientCancelled
			run.errorCode = stringPointer("client_cancelled")
		}
	} else if run.forward == ForwardInProgress {
		run.forward = ForwardProxyError
		run.errorCode = stringPointer("downstream_write_error")
	}
}

func (run *eqRun) reject(status int, blockedBy, blockCode string) {
	run.forward = ForwardRejected
	run.status = &status
	run.blockedBy, run.blockCode = &blockedBy, &blockCode
}

func (run *eqRun) markNewAPIError(code string) {
	if run.forward == ForwardRejected || run.forward == ForwardClientCancelled {
		return
	}
	if run.cancelled && !run.responseLogicallyComplete() {
		run.forward = ForwardClientCancelled
		run.errorCode = stringPointer("client_cancelled")
		return
	}
	run.forward = ForwardNewAPIError
	run.errorCode = stringPointer(code)
}

func (run *eqRun) responseLogicallyComplete() bool {
	received := run.stages[StageResponseReceived]
	if received == nil || received.body == nil || !received.body.eof {
		return false
	}
	if received.contentLength != nil && *received.contentLength >= 0 && received.body.observed < *received.contentLength {
		return false
	}
	sent := run.stages[StageResponseSent]
	if sent == nil || sent.body == nil || sent.body.writeFailed {
		return false
	}
	return sent.body.observed >= received.body.observed
}

// finish is Session.finish.
func (run *eqRun) finish() {
	if run.forward == ForwardInProgress {
		if run.cancelled && !run.responseLogicallyComplete() {
			run.forward = ForwardClientCancelled
			run.errorCode = stringPointer("client_cancelled")
		} else {
			run.forward = ForwardCompleted
		}
	}
	if run.forward == ForwardClientCancelled || run.forward == ForwardNewAPIError || run.forward == ForwardProxyError {
		run.fault = true
	}
	var finishes []StageFinish
	for _, name := range captureStageNames {
		if stage := run.stages[name]; stage != nil {
			finishes = append(finishes, run.finishStage(stage))
		}
	}
	endedAt := run.now()
	capture := CaptureComplete
	if run.fault {
		capture = CapturePartial
	}
	parse := ParsePending
	if run.forward == ForwardRejected {
		parse = ParseSkipped
	}
	finish := AuditFinish{
		AuditID: run.id, EndedAtNS: endedAt, StatusCode: cloneInt(run.status), ForwardStatus: run.forward,
		CaptureStatus: capture, ParseStatus: parse, BlockedBy: run.blockedBy, BlockCode: run.blockCode,
		ErrorCode: cloneString(run.errorCode), NewAPIRequestID: cloneString(run.requestID),
	}
	if sent := run.stages[StageResponseSent]; sent != nil {
		ttft := max(sent.startedAt-run.started, 0)
		finish.TTFTNS = &ttft
	}
	run.legacyResult = run.legacy.finish(finishes, finish)
	run.commitResult = run.unified.commit(finishes, finish)
}

func (run *eqRun) finishStage(stage *eqStage) StageFinish {
	state := StageStateComplete
	errorCode := stage.errorCode
	if stage.faulted || stage.expectsBody && stage.body == nil {
		state = StageStatePartial
		run.fault = true
	}
	var bodyFinish *BodyFinish
	if body := stage.body; body != nil {
		run.flush(stage, body, true)
		if stage.name == StageResponseSent && !body.closed && !stage.faulted && run.forward == ForwardCompleted {
			body.eof, body.hashDone, body.closed = true, true, true
		}
		timelineComplete := true
		if body.events > 0 {
			stage.timeline = run.sealTimeline(body)
			timelineComplete = stage.timeline.complete
		}
		if source := pairSource(stage.name); source != "" {
			if src := run.stages[source]; src != nil && src.body != nil && body.hashDone && body.eof && src.body.hashDone && src.body.eof &&
				(body.observed != src.body.observed || !bytes.Equal(body.digest.Sum(nil), src.body.digest.Sum(nil))) {
				body.faulted, body.errorCode = true, "body_stage_mismatch"
				run.markStageFault(stage, body.errorCode)
			}
		}
		errorCode = stage.errorCode
		bodyState := StageStateComplete
		if body.faulted || !body.eof || body.stored != body.observed {
			bodyState, state = StageStatePartial, StageStatePartial
			run.fault = true
		}
		bodyError := body.errorCode
		if bodyError == "" {
			bodyError = errorCode
		}
		bodyFinish = &BodyFinish{
			ObservedLength: body.observed, StoredLength: body.stored, SHA256: body.digest.Sum(nil),
			HashComplete: body.hashDone, EOFSeen: body.eof, State: bodyState, RetentionState: RetentionPending,
			FirstObservedAtNS: optionalNS(body.first), LastObservedAtNS: optionalNS(body.last), ChunkCount: body.chunkCount,
			StreamEventCount: body.events, StreamTimelineComplete: timelineComplete, ErrorCode: optionalCode(bodyError),
		}
	}
	return StageFinish{
		AuditID: run.id, Stage: stage.name, State: state, StatusCode: cloneInt(stage.status),
		ContentLength: cloneInt64(stage.contentLength), EndedAtNS: run.now(), ErrorCode: optionalCode(errorCode), Body: bodyFinish,
	}
}

func (run *eqRun) sealTimeline(body *eqBody) *eqTimeline {
	plain, err := streamtimeline.Encode(body.points)
	if err != nil {
		run.t.Fatal(err)
	}
	compression, encoded, err := run.encoder.Encode(plain, "application/x-llmapi-stream-timeline")
	if err != nil {
		run.t.Fatal(err)
	}
	return &eqTimeline{
		events: body.events, first: optionalNS(body.firstEvent), last: optionalNS(body.lastEvent),
		complete:    body.streamComplete && !body.hasData && !body.lineData && int64(len(body.points)) == body.events,
		compression: compression, plaintextLength: int64(len(plain)), encoded: append([]byte(nil), encoded...),
	}
}

func pairSource(stage string) string {
	switch stage {
	case StageRequestSent:
		return StageRequestReceived
	case StageResponseSent:
		return StageResponseReceived
	}
	return ""
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

// ---- sealing shared by both sinks ----------------------------------------

func sealHeaders(t *testing.T, cipher security.Cipher, auditID, stage string, group eqGroup) []HTTPHeader {
	t.Helper()
	rows := make([]HTTPHeader, 0, len(group.values))
	for _, value := range group.values {
		aad, err := security.AAD(auditID, "header", stage, group.kind, value.name, strconv.Itoa(value.index))
		if err != nil {
			t.Fatal(err)
		}
		enc, err := cipher.Encrypt(aad, []byte(value.value))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, HTTPHeader{AuditID: auditID, Stage: stage, Kind: group.kind, Name: value.name,
			ValueIndex: value.index, ValueLength: len(value.value), ValueEnc: enc})
	}
	return rows
}

func sealChunk(t *testing.T, cipher security.Cipher, auditID string, chunk eqChunk) BodyChunk {
	t.Helper()
	aad, err := security.AAD(auditID, "body_chunk_v2", chunk.stage, strconv.FormatInt(chunk.seq, 10), chunk.compression)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt(aad, chunk.encoded)
	if err != nil {
		t.Fatal(err)
	}
	return BodyChunk{AuditID: auditID, Stage: chunk.stage, Seq: chunk.seq, Offset: chunk.offset, PlaintextLength: chunk.plain,
		EncodedLength: len(chunk.encoded), ObservedAtNS: chunk.observedAt, Compression: chunk.compression, DataEnc: enc}
}

func sealTimeline(t *testing.T, cipher security.Cipher, auditID, stage string, timeline *eqTimeline) *StreamTimeline {
	t.Helper()
	if timeline == nil {
		return nil
	}
	aad, err := security.AAD(auditID, "stream_timeline_v1", stage, timeline.compression)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt(aad, timeline.encoded)
	if err != nil {
		t.Fatal(err)
	}
	return &StreamTimeline{EventCount: timeline.events, FirstEventAtNS: timeline.first, LastEventAtNS: timeline.last,
		Complete: timeline.complete, Compression: timeline.compression, PlaintextLength: timeline.plaintextLength, DataEnc: enc}
}

func sealRequestURI(t *testing.T, cipher security.Cipher, auditID string) []byte {
	t.Helper()
	aad, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt(aad, []byte("/v1/chat/completions?trace=example"))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func startValues(auditID string, stage *eqStage) HTTPStage {
	return HTTPStage{AuditID: auditID, Stage: stage.name, State: StageStateStreaming, Proto: stage.proto, Method: stage.method,
		Host: stage.host, StatusCode: cloneInt(stage.status), ContentLength: cloneInt64(stage.contentLength), StartedAtNS: stage.startedAt}
}

// ---- legacy sink -----------------------------------------------------------

type eqLegacy struct {
	run    *eqRun
	store  *Store
	cipher security.Cipher
}

func (sink *eqLegacy) beginAudit(record AuditRecord) {
	record.RequestURIEnc = sealRequestURI(sink.run.t, sink.cipher, record.AuditID)
	if err := sink.store.BeginAudit(sink.run.ctx, record); err != nil {
		sink.run.t.Fatal(err)
	}
}

func (sink *eqLegacy) startStage(stage *eqStage, group *eqGroup) {
	if err := sink.store.StartStage(sink.run.ctx, startValues(sink.run.id, stage)); err != nil {
		sink.run.t.Fatal(err)
	}
	if group != nil {
		sink.addHeaders(stage, group)
	}
}

func (sink *eqLegacy) addHeaders(stage *eqStage, group *eqGroup) {
	if err := sink.store.AddHeaders(sink.run.ctx, sealHeaders(sink.run.t, sink.cipher, sink.run.id, stage.name, *group)); err != nil {
		sink.run.t.Fatal(err)
	}
}

func (sink *eqLegacy) startBody(stage *eqStage) {
	body := BodyStream{AuditID: sink.run.id, Stage: stage.name, SourceStage: stage.name, State: StageStateStreaming, RetentionState: RetentionPending}
	if err := sink.store.StartBody(sink.run.ctx, body); err != nil {
		sink.run.t.Fatal(err)
	}
}

func (sink *eqLegacy) addChunk(chunk eqChunk) {
	if err := sink.store.AddChunk(sink.run.ctx, sealChunk(sink.run.t, sink.cipher, sink.run.id, chunk)); err != nil {
		sink.run.t.Fatal(err)
	}
}

func (sink *eqLegacy) finish(finishes []StageFinish, finish AuditFinish) AuditFinish {
	for _, stageFinish := range finishes {
		if stageFinish.Body != nil {
			body := *stageFinish.Body
			body.Timeline = sealTimeline(sink.run.t, sink.cipher, sink.run.id, stageFinish.Stage, sink.run.stages[stageFinish.Stage].timeline)
			stageFinish.Body = &body
		}
		if err := sink.store.FinishStage(sink.run.ctx, stageFinish); err != nil {
			sink.run.t.Fatal(err)
		}
	}
	result, err := sink.store.FinishAuditWithResult(sink.run.ctx, finish)
	if err != nil {
		sink.run.t.Fatal(err)
	}
	return result
}

// ---- unified sink ----------------------------------------------------------

type eqUnified struct {
	run    *eqRun
	store  *Store
	cipher security.Cipher

	stageWritten  map[string]bool
	groupsWritten map[string]int
	bodyWritten   map[string]bool
	chunksWritten map[string]int
	// merged marks a duplicate whose body row a checkpoint wrote pointing at
	// its source, without its own chunks.
	merged      map[string]bool
	checkpoints int
	// lastCommit is the last CommitAudit input, kept for retry tests.
	lastCommit AuditCommit
	// failCommit, when set, replaces the CommitAudit call.
	failCommit func(AuditCommit) (AuditFinish, error)
}

func (sink *eqUnified) beginAudit(record AuditRecord, inbound *eqStage) {
	record.RequestURIEnc = sealRequestURI(sink.run.t, sink.cipher, record.AuditID)
	stage := InboundStage{Stage: startValues(record.AuditID, inbound)}
	for _, group := range inbound.groups {
		stage.Headers = append(stage.Headers, sealHeaders(sink.run.t, sink.cipher, record.AuditID, inbound.name, group)...)
	}
	record.Inbound = &stage
	if err := sink.store.BeginAudit(sink.run.ctx, record); err != nil {
		sink.run.t.Fatal(err)
	}
	sink.stageWritten[inbound.name] = true
	sink.groupsWritten[inbound.name] = len(inbound.groups)
}

// mergeableNow reports whether the request pair can be merged when
// checkpoint 1 writes request_sent's body: both bodies ended without fault,
// fully retained, the same length and digest.
func mergeableNow(source, duplicate *eqBody) bool {
	ok := func(body *eqBody) bool {
		return body != nil && body.eof && body.hashDone && !body.faulted && body.stored == body.observed && len(body.pending) == 0
	}
	return ok(source) && ok(duplicate) && source.observed == duplicate.observed &&
		bytes.Equal(source.digest.Sum(nil), duplicate.digest.Sum(nil))
}

// checkpoint writes everything new since the last write: new stages, new
// header groups, request body rows and sealed request chunks. Response
// bodies are left to CommitAudit (design B.1).
func (sink *eqUnified) checkpoint() {
	run := sink.run
	checkpoint := AuditCheckpoint{AuditID: run.id}
	var chunks storage.ChunkList
	for _, name := range captureStageNames {
		stage := run.stages[name]
		if stage == nil {
			continue
		}
		if !sink.stageWritten[name] {
			checkpoint.Stages = append(checkpoint.Stages, startValues(run.id, stage))
		}
		for _, group := range stage.groups[sink.groupsWritten[name]:] {
			checkpoint.Headers = append(checkpoint.Headers, sealHeaders(run.t, sink.cipher, run.id, name, group)...)
		}
		if name != StageRequestReceived && name != StageRequestSent || stage.body == nil {
			continue
		}
		if !sink.bodyWritten[name] {
			body := BodyStream{AuditID: run.id, Stage: name, SourceStage: name, State: StageStateStreaming, RetentionState: RetentionPending}
			if name == StageRequestSent {
				if source := run.stages[StageRequestReceived]; source != nil && mergeableNow(source.body, stage.body) {
					body.SourceStage = StageRequestReceived
					sink.merged[name] = true
				}
			}
			checkpoint.Bodies = append(checkpoint.Bodies, body)
		}
		if sink.merged[name] {
			continue
		}
		for _, chunk := range stage.body.chunks[sink.chunksWritten[name]:] {
			chunks = append(chunks, sealChunk(run.t, sink.cipher, run.id, chunk))
		}
	}
	if len(chunks) != 0 {
		checkpoint.Chunks = chunks
	}
	if len(checkpoint.Stages) == 0 && len(checkpoint.Headers) == 0 && len(checkpoint.Bodies) == 0 && len(chunks) == 0 {
		return
	}
	if err := sink.store.Checkpoint(run.ctx, checkpoint); err != nil {
		run.t.Fatal(err)
	}
	sink.checkpoints++
	sink.markWritten(checkpoint)
}

func (sink *eqUnified) markWritten(checkpoint AuditCheckpoint) {
	for _, stage := range checkpoint.Stages {
		sink.stageWritten[stage.Stage] = true
	}
	for _, body := range checkpoint.Bodies {
		sink.bodyWritten[body.Stage] = true
	}
	for name, stage := range sink.run.stages {
		sink.groupsWritten[name] = len(stage.groups)
		if stage.body != nil && sink.bodyWritten[name] && !sink.merged[name] {
			sink.chunksWritten[name] = len(stage.body.chunks)
		}
	}
}

// finalMergeable is the in-memory version of the store's eight merge
// conditions (design B.5), on the final body values.
func finalMergeable(source, duplicate *BodyFinish) bool {
	ok := func(body *BodyFinish) bool {
		return body != nil && body.State == StageStateComplete && body.HashComplete && body.EOFSeen && body.StoredLength == body.ObservedLength
	}
	return ok(source) && ok(duplicate) && source.ObservedLength == duplicate.ObservedLength &&
		len(source.SHA256) == 32 && bytes.Equal(source.SHA256, duplicate.SHA256)
}

func (sink *eqUnified) commit(finishes []StageFinish, finish AuditFinish) AuditFinish {
	run := sink.run
	byStage := make(map[string]StageFinish, len(finishes))
	for _, stageFinish := range finishes {
		byStage[stageFinish.Stage] = stageFinish
	}
	commit := AuditCommit{Finish: finish}
	omitChunks := map[string]bool{}
	mergedForm := map[string]string{}
	for index, pair := range [][2]string{{StageRequestReceived, StageRequestSent}, {StageResponseReceived, StageResponseSent}} {
		source, duplicate := byStage[pair[0]].Body, byStage[pair[1]].Body
		if duplicate == nil {
			continue
		}
		// A duplicate whose own rows were already written self-sourced cannot
		// be merged here; the store decides from the rows, as legacy does.
		if !sink.merged[pair[1]] && (sink.bodyWritten[pair[1]] || sink.chunksWritten[pair[1]] > 0) {
			commit.DedupInDB[index] = true
			continue
		}
		if finalMergeable(source, duplicate) {
			mergedForm[pair[1]] = pair[0]
			omitChunks[pair[1]] = true
		} else if sink.merged[pair[1]] {
			// Merged at checkpoint 1, no longer equal at Finish: unmerge and
			// write the duplicate's own chunks.
			sink.chunksWritten[pair[1]] = 0
		}
	}
	var chunks storage.ChunkList
	for _, name := range captureStageNames {
		stage := run.stages[name]
		if stage == nil {
			continue
		}
		stageFinish := byStage[name]
		final := startValues(run.id, stage)
		final.State, final.StatusCode, final.ContentLength = stageFinish.State, stageFinish.StatusCode, stageFinish.ContentLength
		final.EndedAtNS, final.ErrorCode = &stageFinish.EndedAtNS, stageFinish.ErrorCode
		stageCommit := StageCommit{Stage: final, StageWritten: sink.stageWritten[name], BodyWritten: sink.bodyWritten[name]}
		if bodyFinish := stageFinish.Body; bodyFinish != nil {
			body := BodyStream{
				AuditID: run.id, Stage: name, SourceStage: name, ObservedLength: bodyFinish.ObservedLength,
				StoredLength: bodyFinish.StoredLength, SHA256: bodyFinish.SHA256, HashComplete: bodyFinish.HashComplete,
				EOFSeen: bodyFinish.EOFSeen, State: bodyFinish.State, RetentionState: bodyFinish.RetentionState,
				FirstObservedAtNS: bodyFinish.FirstObservedAtNS, LastObservedAtNS: bodyFinish.LastObservedAtNS,
				ChunkCount: bodyFinish.ChunkCount, StreamEventCount: bodyFinish.StreamEventCount,
				StreamTimelineComplete: bodyFinish.StreamTimelineComplete, ErrorCode: bodyFinish.ErrorCode,
			}
			if source, ok := mergedForm[name]; ok {
				sourceBody := byStage[source].Body
				body.SourceStage = source
				body.StoredLength, body.ChunkCount = sourceBody.StoredLength, sourceBody.ChunkCount
				body.StreamEventCount, body.StreamTimelineComplete = sourceBody.StreamEventCount, sourceBody.StreamTimelineComplete
			}
			stageCommit.Body = &body
			stageCommit.Timeline = sealTimeline(run.t, sink.cipher, run.id, name, stage.timeline)
			if !omitChunks[name] {
				for _, chunk := range stage.body.chunks[sink.chunksWritten[name]:] {
					chunks = append(chunks, sealChunk(run.t, sink.cipher, run.id, chunk))
				}
			}
		}
		for _, group := range stage.groups[sink.groupsWritten[name]:] {
			commit.Headers = append(commit.Headers, sealHeaders(run.t, sink.cipher, run.id, name, group)...)
		}
		commit.Stages = append(commit.Stages, stageCommit)
	}
	if len(chunks) != 0 {
		commit.Chunks = chunks
	}
	sink.lastCommit = commit
	if sink.failCommit != nil {
		result, err := sink.failCommit(commit)
		if err != nil {
			run.t.Fatal(err)
		}
		return result
	}
	result, err := sink.store.CommitAudit(run.ctx, commit)
	if err != nil {
		run.t.Fatal(err)
	}
	return result
}

// ---- comparison ------------------------------------------------------------

type eqRow map[string]string

// volatileColumns differ between two databases for reasons unrelated to the
// write path: migration bookkeeping and the rows migrations seed with the
// wall clock when each database is created.
var volatileColumns = map[string]bool{
	"schema_migrations.applied_at_ns": true,
	"user_agent_rules.created_at_ns":  true, "user_agent_rules.updated_at_ns": true,
}

// macColumns differ by design (B.10): the payload digest covers ciphertext
// hashes and the MACs chain over it. Only their presence is compared.
var macColumns = map[string]bool{
	"integrity_events.previous_mac": true, "integrity_events.payload_digest": true, "integrity_events.event_mac": true,
}

func dumpDatabase(t *testing.T, database *sql.DB, cipher security.Cipher) map[string][]eqRow {
	t.Helper()
	names, err := database.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for names.Next() {
		var name string
		if err := names.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := names.Close(); err != nil {
		t.Fatal(err)
	}
	dump := make(map[string][]eqRow, len(tables))
	for _, table := range tables {
		rows, err := database.Query(`SELECT * FROM "` + table + `"`)
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
			raw := make(map[string]any, len(columns))
			for index, column := range columns {
				raw[column] = values[index]
			}
			row := make(eqRow, len(columns))
			for _, column := range columns {
				key := table + "." + column
				switch {
				case volatileColumns[key]:
					row[column] = "<volatile>"
				case macColumns[key]:
					row[column] = fmt.Sprintf("<mac:%v>", raw[column] != nil)
				default:
					row[column] = renderColumn(t, cipher, table, column, raw)
				}
			}
			dump[table] = append(dump[table], row)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return dump
}

func renderValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "NULL"
	case []byte:
		return "x:" + hex.EncodeToString(typed)
	case string:
		return "s:" + strconv.Quote(typed)
	default:
		return fmt.Sprintf("%T:%v", value, value)
	}
}

func text(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(value)
	}
}

// renderColumn decrypts ciphertext columns with the AAD derived from the
// row's own identity columns, so a misplaced ciphertext fails the comparison.
func renderColumn(t *testing.T, cipher security.Cipher, table, column string, row map[string]any) string {
	var aadParts []string
	switch table + "." + column {
	case "audit_records.request_uri_enc":
		aadParts = []string{text(row["audit_id"]), "request_uri"}
	case "http_headers.value_enc":
		aadParts = []string{text(row["audit_id"]), "header", text(row["stage"]), text(row["kind"]), text(row["name"]), text(row["value_index"])}
	case "body_chunks.data_enc":
		aadParts = []string{text(row["audit_id"]), "body_chunk_v2", text(row["stage"]), text(row["seq"]), text(row["compression"])}
	case "stream_timelines.timeline_enc":
		aadParts = []string{text(row["audit_id"]), "stream_timeline_v1", text(row["stage"]), text(row["compression"])}
	default:
		return renderValue(row[column])
	}
	blob, _ := row[column].([]byte)
	aad, err := security.AAD(aadParts...)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Decrypt(aad, blob)
	if err != nil {
		return "DECRYPT-FAILED"
	}
	return fmt.Sprintf("dec(len=%d):%s", len(plain), hex.EncodeToString(plain))
}

func (row eqRow) render() string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for index, key := range keys {
		value := row[key]
		if len(value) > 96 {
			value = value[:96] + "..."
		}
		parts[index] = key + "=" + value
	}
	return strings.Join(parts, " ")
}

func (row eqRow) full() string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(row[key])
		builder.WriteByte('\x00')
	}
	return builder.String()
}

// diffDumps lists every row present in one dump and not the other.
func diffDumps(legacy, unified map[string][]eqRow) []string {
	tables := map[string]bool{}
	for table := range legacy {
		tables[table] = true
	}
	for table := range unified {
		tables[table] = true
	}
	var names []string
	for table := range tables {
		names = append(names, table)
	}
	sort.Strings(names)
	var diffs []string
	for _, table := range names {
		count := map[string]int{}
		shown := map[string]string{}
		for _, row := range legacy[table] {
			count[row.full()]++
			shown[row.full()] = row.render()
		}
		for _, row := range unified[table] {
			count[row.full()]--
			shown[row.full()] = row.render()
		}
		var keys []string
		for key := range count {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			switch {
			case count[key] > 0:
				diffs = append(diffs, fmt.Sprintf("%s: only legacy (x%d): %s", table, count[key], shown[key]))
			case count[key] < 0:
				diffs = append(diffs, fmt.Sprintf("%s: only unified (x%d): %s", table, -count[key], shown[key]))
			}
		}
	}
	return diffs
}

func (run *eqRun) dumps() (map[string][]eqRow, map[string][]eqRow) {
	run.t.Helper()
	return dumpDatabase(run.t, run.legacy.store.writerDB, run.legacy.cipher), dumpDatabase(run.t, run.unified.store.writerDB, run.unified.cipher)
}

// assertSameRows compares both databases after both stores drained their
// queues, then checks that each integrity chain and payload verifies.
func (run *eqRun) assertSameRows() {
	run.t.Helper()
	legacy, unified := run.dumps()
	if diffs := diffDumps(legacy, unified); len(diffs) != 0 {
		run.t.Fatalf("unified rows differ from legacy rows:\n%s", strings.Join(diffs, "\n"))
	}
	run.verifyIntegrity()
}

func (run *eqRun) verifyIntegrity() {
	run.t.Helper()
	for _, store := range []*Store{run.legacy.store, run.unified.store} {
		if err := store.VerifyIntegrityPayloads(run.ctx); err != nil {
			run.t.Fatalf("payload verification: %v", err)
		}
	}
}

// ---- request content -------------------------------------------------------

func eqJSON(size int, seed byte) []byte {
	var buffer bytes.Buffer
	for index := 0; buffer.Len() < size; index++ {
		fmt.Fprintf(&buffer, `{"role":"user","seq":%d,"seed":%d,"content":"example text %d"},`, index, seed, index*7)
	}
	return buffer.Bytes()[:size]
}

// eqNoise is incompressible, so its chunks are stored with compression none.
func eqNoise(size int, seed uint64) []byte {
	data := make([]byte, size)
	state := seed*0x9e3779b97f4a7c15 | 1
	for index := range data {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		data[index] = byte(state)
	}
	return data
}

func eqSSE(events int) [][]byte {
	parts := make([][]byte, 0, events+1)
	for index := 0; index < events; index++ {
		parts = append(parts, []byte(fmt.Sprintf("data: {\"id\":\"chatcmpl-example\",\"delta\":%d}\n\n", index)))
	}
	return append(parts, []byte("data: [DONE]\n\n"))
}

func pieces(data []byte, size int) [][]byte {
	var parts [][]byte
	for len(data) > 0 {
		count := min(size, len(data))
		parts = append(parts, data[:count])
		data = data[count:]
	}
	return parts
}

func requestHeaders(contentType string) http.Header {
	header := http.Header{}
	header.Set("Content-Type", contentType)
	header.Set("Authorization", "Bearer sk-example-test-only")
	header.Add("X-Multi", "first")
	header.Add("X-Multi", "second")
	header.Set("User-Agent", "example-client/1.0")
	return header
}

func responseHeaders(contentType string) http.Header {
	header := http.Header{}
	header.Set("Content-Type", contentType)
	header.Set("X-Oneapi-Request-Id", "request-example-1")
	return header
}

var errEqClose = errors.New("close failed")
