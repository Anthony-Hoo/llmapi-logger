package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"llmapi-logger/internal/bodycodec"
	"strconv"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

type bufferStore struct {
	Store
	chunks []sqlite.BodyChunk
}

func (s *bufferStore) StartBody(context.Context, sqlite.BodyStream) error { return nil }
func (s *bufferStore) AddChunk(_ context.Context, value sqlite.BodyChunk) error {
	s.chunks = append(s.chunks, value)
	return nil
}

func bufferSession(t *testing.T) (*Session, *stageCapture, *bufferStore) {
	t.Helper()
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &bufferStore{}
	stage := &stageCapture{name: sqlite.StageRequestReceived, persisted: true}
	session := &Session{store: store, cipher: cipher, auditID: "buffer-test", writeCtx: context.Background(), now: func() time.Time { return time.Unix(0, 100) }, stages: map[string]*stageCapture{stage.name: stage}}
	return session, stage, store
}

func TestBodyBufferLazyBoundedAndReleased(t *testing.T) {
	session, stage, store := bufferSession(t)
	body := session.ensureBodyLocked(stage)
	if cap(body.pending) != 0 {
		t.Fatal("empty body allocated staging buffer")
	}
	session.observeRead(stage.name, []byte("tiny"), nil)
	if cap(body.pending) > 64 {
		t.Fatalf("tiny body capacity = %d", cap(body.pending))
	}
	// One oversized read must not cause unbounded staging or quadratic tail copies.
	data := bytes.Repeat([]byte("abcdefgh"), bodyChunkSize/8*3+1)
	session.observeRead(stage.name, data, nil)
	if cap(body.pending) > bodyChunkSize {
		t.Fatalf("oversized buffer capacity = %d", cap(body.pending))
	}
	pending := body.pending[:cap(body.pending)]
	session.observeRead(stage.name, nil, io.EOF)
	if body.pending != nil || body.pendingAtNS != 0 {
		t.Fatal("EOF retained staging memory")
	}
	if !bytes.Equal(pending, make([]byte, len(pending))) {
		t.Fatal("staging plaintext not cleared")
	}
	expected := append([]byte("tiny"), data...)
	digest := sha256.Sum256(expected)
	if !bytes.Equal(body.digest.Sum(nil), digest[:]) || body.observedLength != int64(len(expected)) || body.storedLength != int64(len(expected)) {
		t.Fatal("capture evidence changed")
	}
	if len(store.chunks) != 4 {
		t.Fatalf("chunks = %d", len(store.chunks))
	}
	var rebuilt []byte
	for i, chunk := range store.chunks {
		if chunk.Seq != int64(i) || chunk.Offset != int64(i*bodyChunkSize) || chunk.PlaintextLength > bodyChunkSize {
			t.Fatal("chunk boundary changed")
		}
		aad, err := security.AAD(session.auditID, "body_chunk_v2", stage.name, strconv.Itoa(i), chunk.Compression)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := session.cipher.Decrypt(aad, chunk.DataEnc)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := bodycodec.Decode(encoded, chunk.Compression, chunk.PlaintextLength)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt = append(rebuilt, plain...)
	}
	if !bytes.Equal(rebuilt, expected) {
		t.Fatal("persisted bytes changed")
	}
}

func TestBodyBufferForceReleasesEmptyAndFaulted(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		body := &bodyCapture{persistChunks: true, persisted: persisted, pending: make([]byte, 0, bodyChunkSize)}
		session := &Session{}
		session.flushBodyLocked(nil, body, true)
		if body.pending != nil {
			t.Fatal("empty final flush retained capacity")
		}
	}
}

func BenchmarkBodyCaptureSmall(b *testing.B) {
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store := &bufferStore{}
		stage := &stageCapture{name: sqlite.StageRequestReceived, persisted: true}
		session := &Session{store: store, cipher: cipher, auditID: "buffer-benchmark", writeCtx: context.Background(), now: func() time.Time { return time.Unix(0, 100) }, stages: map[string]*stageCapture{stage.name: stage}}
		session.observeRead(stage.name, data, io.EOF)
		if stage.body.storedLength != int64(len(data)) {
			b.Fatal("capture incomplete")
		}
	}
}

func (s *bufferStore) FinishStage(context.Context, sqlite.StageFinish) error { return nil }
func (s *bufferStore) FinishAuditWithResult(_ context.Context, value sqlite.AuditFinish) (sqlite.AuditFinish, error) {
	return value, nil
}

func TestBodyEncoderReleasedOnFinish(t *testing.T) {
	session, stage, _ := bufferSession(t)
	session.observeRead(stage.name, bytes.Repeat([]byte("x"), 1024), io.EOF)
	if session.bodyEncoder == nil {
		t.Fatal("encoder not created")
	}
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	if session.bodyEncoder != nil {
		t.Fatal("session retained encoder after finalization")
	}
}

func BenchmarkBodyCaptureFourStages(b *testing.B) {
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	names := []string{sqlite.StageRequestReceived, sqlite.StageRequestSent, sqlite.StageResponseReceived, sqlite.StageResponseSent}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store := &bufferStore{}
		session := &Session{store: store, cipher: cipher, auditID: "four-stage-benchmark", writeCtx: context.Background(), now: func() time.Time { return time.Unix(0, 100) }, stages: make(map[string]*stageCapture)}
		for _, name := range names {
			session.stages[name] = &stageCapture{name: name, persisted: true}
			session.observeRead(name, data, io.EOF)
		}
		if err := session.Finish(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBodyEncoderConcurrentStages(t *testing.T) {
	session, _, store := bufferSession(t)
	names := []string{sqlite.StageRequestReceived, sqlite.StageRequestSent, sqlite.StageResponseReceived, sqlite.StageResponseSent}
	for _, name := range names {
		session.stages[name] = &stageCapture{name: name, persisted: true}
	}
	var wait sync.WaitGroup
	for _, name := range names {
		wait.Add(1)
		go func() { defer wait.Done(); session.observeRead(name, bytes.Repeat([]byte(name), 200), io.EOF) }()
	}
	wait.Wait()
	for _, chunk := range store.chunks {
		aad, err := security.AAD(session.auditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), chunk.Compression)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := session.cipher.Decrypt(aad, chunk.DataEnc)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := bodycodec.Decode(encoded, chunk.Compression, chunk.PlaintextLength)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, bytes.Repeat([]byte(chunk.Stage), 200)) {
			t.Fatal("one stage leaked into another")
		}
	}
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	if session.bodyEncoder != nil {
		t.Fatal("retained shared encoder")
	}
}

type failingFinalizeStore struct {
	*bufferStore
	session *Session
	t       *testing.T
}

func (s *failingFinalizeStore) FinishStage(context.Context, sqlite.StageFinish) error {
	if s.session.bodyEncoder != nil {
		s.t.Fatal("encoder retained during final persistence")
	}
	return io.ErrClosedPipe
}
func (s *failingFinalizeStore) FinishAuditWithResult(_ context.Context, value sqlite.AuditFinish) (sqlite.AuditFinish, error) {
	return value, io.ErrClosedPipe
}

func TestBodyEncoderReleasedAfterDeferredFlushAndFailedFinish(t *testing.T) {
	session, stage, store := bufferSession(t)
	session.store = &failingFinalizeStore{bufferStore: store, session: session, t: t}
	session.observeRead(stage.name, bytes.Repeat([]byte("x"), 1024), nil)
	if len(store.chunks) != 0 {
		t.Fatal("small body flushed prematurely")
	}
	if err := session.Finish(); err == nil {
		t.Fatal("finalization failure suppressed")
	}
	if len(store.chunks) != 1 || stage.body.pending != nil || session.bodyEncoder != nil {
		t.Fatal("final pending chunk not flushed/released before failed persistence")
	}
	// A deferred upstream Close or repeated Finish must not recreate a codec.
	session.closeReadBody(stage.name, nil)
	if err := session.Finish(); err == nil {
		t.Fatal("repeated finish lost failure")
	}
	if session.bodyEncoder != nil {
		t.Fatal("deferred close retained codec")
	}
}
