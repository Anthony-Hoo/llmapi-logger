package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/routing"
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
	// validate rejects a checkpoint or commit the stores would reject.
	validate bool
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
	if store.validate {
		if err := storage.ValidateAuditCheckpoint(checkpoint); err != nil {
			return err
		}
	}
	store.checkpoints = append(store.checkpoints, checkpoint)
	return nil
}
func (store *blockStore) CommitAudit(_ context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.validate {
		if err := storage.ValidateAuditCommit(commit); err != nil {
			return storage.AuditFinish{}, err
		}
	}
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
			manager := newTestManager(t, store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
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

// The block's shape covers all four stages. Two orders the proxy produces put
// only response_sent into a later write: the upstream answers before the
// request_sent body has ended, so checkpoint 1 already holds response_received
// and checkpoint 2 inserts response_sent alone; and Trailers that the
// response writer captures after checkpoint 2. Each write must carry a block
// that holds what it adds: a version 2 write that inserts a stage without one
// is rejected by the stores, and a commit that leaves out the Trailers of
// response_sent loses them.
func TestHeaderBlockCoversTheResponseSentStage(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	all := []string{storage.StageRequestReceived, storage.StageRequestSent, storage.StageResponseReceived, storage.StageResponseSent}
	for _, test := range []struct {
		name        string
		answerFirst bool
		trailers    bool
		checkpoints [][]string
		commitBlock []string
	}{
		{"upstream answers before the request body ends", true, false, [][]string{all[:3], all}, nil},
		{"response trailers after checkpoint 2", false, true, [][]string{all[:2], all},
			[]string{all[0], all[1], all[2], all[3] + "+trailers"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &blockStore{validate: true}
			manager := newTestManager(t, store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
			ctx := context.Background()
			request := []byte(`{"model":"model-example"}`)
			inbound := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", bytes.NewReader(request))
			inbound.Header.Set("Content-Type", "application/json")
			session, err := manager.Begin(ctx, inbound, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
			if err != nil {
				t.Fatal(err)
			}
			outbound := inbound.Clone(ctx)
			outbound.Body = inbound.Body
			outbound.Host = "newapi.example.com"
			session.WrapRequestSent(outbound)
			upstream := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ContentLength: -1, Request: outbound,
				Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"example"}`))}
			sendBody := func() {
				_, _ = io.Copy(io.Discard, outbound.Body)
				_ = outbound.Body.Close()
			}
			if test.answerFirst {
				session.WrapResponseReceived(upstream)
				sendBody()
			} else {
				sendBody()
				session.WrapResponseReceived(upstream)
			}
			writer := session.WrapResponseWriter(httptest.NewRecorder(), inbound)
			writer.Header().Set("Content-Type", "application/json")
			if test.trailers {
				writer.Header().Set("Trailer", "X-Example-Checksum")
			}
			writer.WriteHeader(200)
			_, _ = io.Copy(writer, upstream.Body)
			_ = upstream.Body.Close()
			if test.trailers {
				writer.Header().Set("X-Example-Checksum", "example-value")
			}
			writer.CaptureTrailers()
			if err := session.Finish(); err != nil {
				t.Fatalf("Finish: %v", err)
			}
			id := session.ID()
			var got [][]string
			for _, checkpoint := range store.checkpoints {
				got = append(got, blockStages(t, cipher, id, checkpoint.HeaderBlock))
			}
			if !reflect.DeepEqual(got, test.checkpoints) {
				t.Fatalf("checkpoint blocks %v, want %v", got, test.checkpoints)
			}
			if len(store.commits) != 1 {
				t.Fatalf("%d commits", len(store.commits))
			}
			if block := blockStages(t, cipher, id, store.commits[0].HeaderBlock); !reflect.DeepEqual(block, test.commitBlock) {
				t.Fatalf("commit block %v, want %v", block, test.commitBlock)
			}
		})
	}
}
