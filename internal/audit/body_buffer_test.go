package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"llmapi-logger/internal/bodycodec"
	"strconv"
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
