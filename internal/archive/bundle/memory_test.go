package bundle

import (
	"context"
	"crypto/sha256"
	"math/rand/v2"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// heapWatch samples the live heap while a step runs and returns the peak
// above the heap at the start.
func heapWatch(step func()) uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	start := stats.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			var sample runtime.MemStats
			runtime.ReadMemStats(&sample)
			if sample.HeapAlloc > peak.Load() {
				peak.Store(sample.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	step()
	close(stop)
	wait.Wait()
	if peak.Load() < start {
		return 0
	}
	return peak.Load() - start
}

// A raw body twice the memory bound is written, verified and streamed
// back with the heap staying within a few chunks (H.7): the writer asks for
// one chunk at a time and the reader holds one entry at a time.
func TestLargeRawBodyMemoryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a large body")
	}
	const chunkSize, chunks = 1 << 20, 32
	const bound = 16 << 20
	previous := debug.SetGCPercent(20)
	defer debug.SetGCPercent(previous)

	chunk := func(seq int64) []byte {
		data := make([]byte, chunkSize)
		source := rand.NewChaCha8([32]byte{byte(seq), 1})
		_, _ = source.Read(data)
		return data
	}
	f := newFixture(t)
	f.payloads.generate = func(_, _ string, seq int64) []byte { return chunk(seq) }
	record := f.audit("big-1", "openai", minute(0), storage.CaptureVersion2)
	whole := sha256.New()
	for seq := int64(0); seq < chunks; seq++ {
		data := chunk(seq)
		_, _ = whole.Write(data)
		record.RawChunks = append(record.RawChunks, archive.RawChunk{Stage: storage.StageResponseReceived, Seq: seq, Offset: seq * chunkSize,
			PlaintextLength: chunkSize, ObservedAtNS: minute(0) + seq, SHA256: sha256.Sum256(data)})
	}
	record.Bodies = []storage.BodyStream{{Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived,
		ObservedLength: chunks * chunkSize, StoredLength: chunks * chunkSize, SHA256: whole.Sum(nil), HashComplete: true, EOFSeen: true,
		State: storage.StageStateComplete, RetentionState: storage.RetentionFull, ChunkCount: chunks}}
	canonical(t, record)

	root := t.TempDir()
	var sealed *Sealed
	written := heapWatch(func() {
		sealed = f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, record)
	})
	var bundle *Bundle
	verified := heapWatch(func() { bundle, _ = f.verify(sealed.ManifestPath(), true) })
	var lines []*archive.Record
	if err := bundle.Records(context.Background(), func(line Line) error { lines = append(lines, line.Record); return nil }); err != nil {
		t.Fatal(err)
	}
	read := sha256.New()
	var streamErr error
	streamed := heapWatch(func() {
		streamErr = bundle.StreamRaw(context.Background(), lines[0], storage.StageResponseReceived, func(chunk query.PlainChunk) error {
			_, _ = read.Write(chunk.Data)
			return nil
		})
	})
	if streamErr != nil {
		t.Fatal(streamErr)
	}
	if string(read.Sum(nil)) != string(record.Bodies[0].SHA256) {
		t.Fatal("streamed body differs")
	}
	t.Logf("body %d MiB; heap peak above start: write %d MiB, verify %d MiB, stream %d MiB",
		chunks*chunkSize>>20, written>>20, verified>>20, streamed>>20)
	for name, peak := range map[string]uint64{"write": written, "verify": verified, "stream": streamed} {
		if peak > bound {
			t.Errorf("%s held %d MiB of heap for a %d MiB body", name, peak>>20, chunks*chunkSize>>20)
		}
	}
}
