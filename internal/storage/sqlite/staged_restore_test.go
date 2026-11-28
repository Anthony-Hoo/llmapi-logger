package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"llmapi-logger/internal/storage"
)

func restoreChunk(auditID, stage string, seq, offset int64) BodyChunk {
	return BodyChunk{AuditID: auditID, Stage: stage, Seq: seq, Offset: offset, PlaintextLength: 10, EncodedLength: 10,
		ObservedAtNS: 100 + seq, Compression: "none", DataEnc: []byte{byte(seq), 1, 2, 3}}
}

// RestoreStagedChunks inserts only what continues the stored chunks of an
// owning body, reports the rest, and changes nothing the second time or for
// a finalized audit (design F.7).
func TestRestoreStagedChunks(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	const id = "apx_restore"
	if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
		t.Fatal(err)
	}
	stage := func(name string) HTTPStage {
		return HTTPStage{AuditID: id, Stage: name, State: StageStateStreaming, Proto: "HTTP/1.1", Method: "POST", Host: "proxy.example.com", StartedAtNS: 2}
	}
	body := func(name, source string) BodyStream {
		return BodyStream{AuditID: id, Stage: name, SourceStage: source, State: StageStateStreaming, RetentionState: RetentionPending}
	}
	if err := store.Checkpoint(ctx, AuditCheckpoint{AuditID: id, CaptureVersion: 1,
		Stages: []HTTPStage{stage(StageRequestReceived), stage(StageRequestSent), stage(StageResponseReceived)},
		Bodies: []BodyStream{body(StageRequestReceived, StageRequestReceived), body(StageRequestSent, StageRequestReceived)},
		Chunks: storage.ChunkList{restoreChunk(id, StageRequestReceived, 0, 0)},
	}); err != nil {
		t.Fatal(err)
	}
	chunks := storage.ChunkList{
		restoreChunk(id, StageRequestReceived, 0, 0),
		restoreChunk(id, StageRequestReceived, 1, 10),
		restoreChunk(id, StageRequestReceived, 2, 20),
		restoreChunk(id, StageRequestSent, 0, 0),
		restoreChunk(id, StageResponseReceived, 0, 0),
	}
	result, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: id, Chunks: chunks})
	want := storage.StagedChunkRestoreResult{Outcome: storage.StagedRestoreImported, Inserted: 2, Present: 1, Borrowed: 1, NoBody: []string{StageResponseReceived}}
	if err != nil || !reflect.DeepEqual(result, want) {
		t.Fatalf("restore %+v, %v", result, err)
	}
	again, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: id, Chunks: chunks})
	if err != nil || again.Inserted != 0 || again.Present != 3 {
		t.Fatalf("repeated restore %+v, %v", again, err)
	}
	gap, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: id, Chunks: storage.ChunkList{restoreChunk(id, StageRequestReceived, 5, 50)}})
	if err != nil || gap.Inserted != 0 || !reflect.DeepEqual(gap.Discontinuous, []string{StageRequestReceived}) {
		t.Fatalf("discontinuous restore %+v, %v", gap, err)
	}
	snapshot, err := store.Snapshot(ctx, id)
	if err != nil || len(snapshot.Chunks) != 3 {
		t.Fatalf("%d chunks stored, %v", len(snapshot.Chunks), err)
	}

	// A source that cannot be read fails the operation alone, locally.
	broken, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: id, Chunks: failingSource{restoreChunk(id, StageRequestReceived, 3, 30)}})
	if err == nil || broken.Outcome != "" || !store.Healthy() {
		t.Fatalf("unreadable source: %+v, %v, healthy %v", broken, err, store.Healthy())
	}
	if snapshot, _ := store.Snapshot(ctx, id); len(snapshot.Chunks) != 3 {
		t.Fatalf("failed restore stored chunks: %d", len(snapshot.Chunks))
	}

	missing, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: "apx_missing", Chunks: chunks})
	if err != nil || missing.Outcome != storage.StagedRestoreNoAudit {
		t.Fatalf("missing audit %+v, %v", missing, err)
	}
	if _, err := store.RecoverInterruptedAudits(ctx, 1_000); err != nil {
		t.Fatal(err)
	}
	finalized, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: id, Chunks: storage.ChunkList{restoreChunk(id, StageRequestReceived, 3, 30)}})
	if err != nil || finalized.Outcome != storage.StagedRestoreFinalized {
		t.Fatalf("finalized audit %+v, %v", finalized, err)
	}
	if snapshot, _ := store.Snapshot(ctx, id); len(snapshot.Chunks) != 3 || snapshot.Bodies[0].StoredLength != 30 {
		t.Fatalf("recovery did not see the restored chunks: %+v", snapshot.Bodies)
	}
}

// failingSource yields its chunk, then fails as an unreadable staging file.
type failingSource []BodyChunk

func (source failingSource) Each(visit func(BodyChunk) error) error {
	for _, chunk := range source {
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return errors.New("staging: read failed")
}

// A checkpoint whose staged chunks cannot be read is a local failure of that
// write (design F.4): the audit is failed, the writer stays healthy, and the
// failure bookkeeping takes the chunk bounds without reading the source.
func TestCheckpointWithUnreadableChunkSource(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	const id = "apx_unreadable"
	if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
		t.Fatal(err)
	}
	reads := 0
	source := metadataSource{chunks: failingSource{restoreChunk(id, StageRequestReceived, 0, 0)}, reads: &reads}
	if err := store.Checkpoint(ctx, AuditCheckpoint{AuditID: id, CaptureVersion: 1,
		Stages: []HTTPStage{{AuditID: id, Stage: StageRequestReceived, State: StageStateStreaming, Proto: "HTTP/1.1", Method: "POST", Host: "proxy.example.com", StartedAtNS: 2}},
		Bodies: []BodyStream{{AuditID: id, Stage: StageRequestReceived, SourceStage: StageRequestReceived, State: StageStateStreaming, RetentionState: RetentionPending}},
		Chunks: source,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverInterruptedAudits(ctx, 1_000); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(ctx, id)
	if err != nil || snapshot.Audit.CaptureStatus != CaptureFailed || !store.Healthy() {
		t.Fatalf("audit %+v, healthy %v, %v", snapshot.Audit, store.Healthy(), err)
	}
	before := reads
	if bounds := chunkBounds(source); bounds[StageRequestReceived] != 10 || reads != before {
		t.Fatalf("bounds %v read the source", bounds)
	}
}

type metadataSource struct {
	chunks failingSource
	reads  *int
}

func (source metadataSource) Each(visit func(BodyChunk) error) error {
	*source.reads++
	return source.chunks.Each(visit)
}

func (source metadataSource) EachMetadata(visit func(BodyChunk) error) error {
	for _, chunk := range source.chunks {
		chunk.DataEnc = nil
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
}
