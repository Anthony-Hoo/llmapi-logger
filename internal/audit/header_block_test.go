package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// blockStore records the version 2 writes of a session without storing them:
// it reports that it writes the header block, as the PostgreSQL store does.
type blockStore struct {
	Store
	mu          sync.Mutex
	begin       storage.AuditRecord
	checkpoints []storage.AuditCheckpoint
	commits     []storage.AuditCommit
	// refuse makes the next n checkpoints fail to enqueue.
	refuse int
}

func (store *blockStore) Healthy() bool             { return true }
func (store *blockStore) SupportsHeaderBlock() bool { return true }
func (store *blockStore) BeginAudit(_ context.Context, record storage.AuditRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.begin = record
	return nil
}
func (store *blockStore) Checkpoint(_ context.Context, checkpoint storage.AuditCheckpoint) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.refuse > 0 {
		store.refuse--
		return storage.ErrQueueFull
	}
	store.checkpoints = append(store.checkpoints, checkpoint)
	return nil
}
func (store *blockStore) CommitAudit(_ context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commits = append(store.commits, commit)
	return commit.Finish, nil
}
func (*blockStore) InsertAuditGaps(context.Context, []storage.AuditGap) error { return nil }

func blockStages(t *testing.T, cipher security.Cipher, auditID string, block *storage.HeaderBlock) []string {
	t.Helper()
	if block == nil {
		return nil
	}
	stages, err := headerblock.OpenBlock(cipher, auditID, storage.HeaderBlockEvidence{Compression: block.Compression, PlaintextLength: block.PlaintextLength, DataEnc: block.DataEnc})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, stage := range stages {
		name := stage.Name
		if len(stage.Trailers) != 0 {
			name += "+trailers"
		}
		names = append(names, name)
	}
	return names
}

// The version 2 session: BeginAudit carries the inbound stage's block and
// content columns, each checkpoint the whole block of the stages written so
// far, and the commit no block when the last checkpoint's is still the same.
// A checkpoint that cannot be enqueued leaves its block to the next write.
func TestSessionWritesTheHeaderBlock(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	all := []string{storage.StageRequestReceived, storage.StageRequestSent, storage.StageResponseReceived, storage.StageResponseSent}
	for _, test := range []struct {
		name        string
		refuse      int
		checkpoints [][]string
	}{
		{"every checkpoint accepted", 0, [][]string{all[:2], all}},
		{"checkpoint 1 deferred", 1, [][]string{all}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &blockStore{refuse: test.refuse}
			manager, err := NewManagerWithOptions(store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{WritePath: WritePathUnified})
			if err != nil {
				t.Fatal(err)
			}
			if manager.captureVersion != storage.CaptureVersion2 {
				t.Fatalf("capture version %d", manager.captureVersion)
			}
			session := driveStream(t, manager, []byte(`{"model":"model-example","stream":true}`), sseBody(64<<10, 1))
			if err := session.Finish(); err != nil {
				t.Fatal(err)
			}
			id := session.ID()
			begin := store.begin
			if begin.CaptureVersion != storage.CaptureVersion2 || begin.UserAgentEnc != nil || begin.Inbound == nil ||
				!reflect.DeepEqual(blockStages(t, cipher, id, begin.Inbound.HeaderBlock), all[:1]) ||
				begin.Inbound.ContentType == nil || *begin.Inbound.ContentType != "application/json" || len(begin.Inbound.Headers) != 0 {
				t.Fatalf("BeginAudit record %+v", begin)
			}
			var got [][]string
			for _, checkpoint := range store.checkpoints {
				if checkpoint.CaptureVersion != storage.CaptureVersion2 || len(checkpoint.Headers) != 0 || len(checkpoint.Contents) != len(checkpoint.Stages) {
					t.Fatalf("checkpoint %+v", checkpoint)
				}
				got = append(got, blockStages(t, cipher, id, checkpoint.HeaderBlock))
			}
			if !reflect.DeepEqual(got, test.checkpoints) {
				t.Fatalf("checkpoint blocks %v, want %v", got, test.checkpoints)
			}
			if len(store.commits) != 1 || store.commits[0].HeaderBlock != nil || len(store.commits[0].Headers) != 0 {
				t.Fatalf("commit %+v", store.commits)
			}
			for _, stage := range store.commits[0].Stages {
				if stage.ContentType == nil {
					t.Fatalf("commit stage %s without content type", stage.Stage.Stage)
				}
			}
		})
	}
}
