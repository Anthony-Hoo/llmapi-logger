package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// commitStore answers the unified write path's operations in memory and
// keeps the commits. Any other operation of Store panics: the session no
// longer issues them.
type commitStore struct {
	Store
	mu          sync.Mutex
	begins      []storage.AuditRecord
	checkpoints []storage.AuditCheckpoint
	commits     []storage.AuditCommit
	commitErr   error
	onCommit    func()
}

func (s *commitStore) Healthy() bool { return true }
func (s *commitStore) BeginAudit(_ context.Context, record storage.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begins = append(s.begins, record)
	return nil
}
func (s *commitStore) Checkpoint(_ context.Context, checkpoint storage.AuditCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints = append(s.checkpoints, checkpoint)
	return nil
}
func (s *commitStore) CommitAudit(_ context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	if s.onCommit != nil {
		s.onCommit()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits = append(s.commits, commit)
	return commit.Finish, s.commitErr
}
func (s *commitStore) InsertAuditGaps(context.Context, []storage.AuditGap) error { return nil }

// chunks returns every chunk the checkpoints and commits carried.
func (s *commitStore) chunks(t testing.TB) []storage.BodyChunk {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []storage.BodyChunk
	collect := func(source storage.ChunkSource) {
		if source == nil {
			return
		}
		if err := source.Each(func(chunk storage.BodyChunk) error { out = append(out, chunk); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, checkpoint := range s.checkpoints {
		collect(checkpoint.Chunks)
	}
	for _, commit := range s.commits {
		collect(commit.Chunks)
	}
	return out
}

// bufferSession is a unified session with the given stages started and
// persisted, as Begin and the Wrap calls leave them.
func bufferSession(t testing.TB, store *commitStore, names ...string) *Session {
	t.Helper()
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	manager := newTestManager(t, store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Now: func() time.Time { return time.Unix(0, 100) }})
	session := newSession(manager, context.Background(), "apx_buffertest", "chat", time.Unix(0, 100))
	for _, name := range names {
		session.stages[name] = &stageCapture{name: name, persisted: true}
	}
	return session
}

func openChunk(t testing.TB, cipher security.Cipher, auditID string, chunk storage.BodyChunk) []byte {
	t.Helper()
	aad, err := security.AAD(auditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), chunk.Compression)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.Decrypt(aad, chunk.DataEnc)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bodycodec.Decode(encoded, chunk.Compression, chunk.PlaintextLength)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

// A body over several chunks is cut at the 1 MiB grid, whatever the sizes of
// the reads, and every chunk opens to its bytes; the retained plaintext is
// released after Finish.
func TestBodyChunksFollowTheGridAndAreReleased(t *testing.T) {
	store := &commitStore{}
	session := bufferSession(t, store, sqlite.StageRequestReceived)
	session.observeRead(sqlite.StageRequestReceived, []byte("tiny"), nil)
	data := bytes.Repeat([]byte("abcdefgh"), bodyChunkSize/8*3+1)
	session.observeRead(sqlite.StageRequestReceived, data, nil)
	session.observeRead(sqlite.StageRequestReceived, nil, io.EOF)
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	expected := append([]byte("tiny"), data...)
	chunks := store.chunks(t)
	if len(chunks) != 4 {
		t.Fatalf("chunks = %d", len(chunks))
	}
	var rebuilt []byte
	for index, chunk := range chunks {
		if chunk.Seq != int64(index) || chunk.Offset != int64(index*bodyChunkSize) || chunk.PlaintextLength > bodyChunkSize {
			t.Fatal("chunk boundary changed")
		}
		rebuilt = append(rebuilt, openChunk(t, session.cipher, session.auditID, chunk)...)
	}
	if !bytes.Equal(rebuilt, expected) {
		t.Fatal("persisted bytes changed")
	}
	if session.memoryHeld != 0 || session.manager.MemoryInUse() != 0 {
		t.Fatalf("plaintext still held: %d, budget %d", session.memoryHeld, session.manager.MemoryInUse())
	}
	for _, chunk := range session.stages[sqlite.StageRequestReceived].body.unified.chunks {
		if chunk.data != nil {
			t.Fatal("a chunk kept its plaintext after Finish")
		}
	}
}

func TestBodyEncoderReleasedOnFinish(t *testing.T) {
	store := &commitStore{}
	session := bufferSession(t, store, sqlite.StageRequestReceived)
	session.observeRead(sqlite.StageRequestReceived, bytes.Repeat([]byte("x"), 1024), io.EOF)
	store.onCommit = func() {
		if session.bodyEncoder != nil {
			t.Error("encoder retained while the commit is written")
		}
	}
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(store.chunks(t)) != 1 || session.bodyEncoder != nil {
		t.Fatal("chunk not sealed, or the session retained its encoder after finalization")
	}
}

func TestBodyEncoderConcurrentStages(t *testing.T) {
	store := &commitStore{}
	names := []string{sqlite.StageRequestReceived, sqlite.StageRequestSent, sqlite.StageResponseReceived, sqlite.StageResponseSent}
	session := bufferSession(t, store, names...)
	var wait sync.WaitGroup
	for _, name := range names {
		wait.Go(func() { session.observeRead(name, bytes.Repeat([]byte(name), 200), io.EOF) })
	}
	wait.Wait()
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	chunks := store.chunks(t)
	if len(chunks) != len(names) {
		t.Fatalf("%d chunks for %d stages", len(chunks), len(names))
	}
	for _, chunk := range chunks {
		if !bytes.Equal(openChunk(t, session.cipher, session.auditID, chunk), bytes.Repeat([]byte(chunk.Stage), 200)) {
			t.Fatal("one stage leaked into another")
		}
	}
	if session.bodyEncoder != nil {
		t.Fatal("retained shared encoder")
	}
}

func TestBodyEncoderReleasedAfterFailedFinish(t *testing.T) {
	store := &commitStore{commitErr: io.ErrClosedPipe}
	session := bufferSession(t, store, sqlite.StageRequestReceived)
	session.observeRead(sqlite.StageRequestReceived, bytes.Repeat([]byte("x"), 1024), nil)
	if err := session.Finish(); err == nil {
		t.Fatal("finalization failure suppressed")
	}
	if len(store.chunks(t)) != 1 || session.bodyEncoder != nil {
		t.Fatal("open chunk not sealed, or the encoder not released, before the failed commit")
	}
	// A deferred upstream Close or repeated Finish must not recreate a codec
	// or retain bytes again.
	session.closeReadBody(sqlite.StageRequestReceived, nil)
	session.observeRead(sqlite.StageRequestReceived, []byte("late"), io.EOF)
	if err := session.Finish(); err == nil {
		t.Fatal("repeated finish lost failure")
	}
	if session.bodyEncoder != nil || session.memoryHeld != 0 {
		t.Fatal("deferred close retained codec or plaintext")
	}
}

func BenchmarkBodyCaptureSmall(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		session := bufferSession(b, &commitStore{}, sqlite.StageRequestReceived)
		session.observeRead(sqlite.StageRequestReceived, data, io.EOF)
		if err := session.Finish(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBodyCaptureFourStages(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1024)
	names := []string{sqlite.StageRequestReceived, sqlite.StageRequestSent, sqlite.StageResponseReceived, sqlite.StageResponseSent}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		session := bufferSession(b, &commitStore{}, names...)
		for _, name := range names {
			session.observeRead(name, data, io.EOF)
		}
		if err := session.Finish(); err != nil {
			b.Fatal(err)
		}
	}
}
