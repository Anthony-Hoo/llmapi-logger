package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestStartupRecoveryKeepsFailedCaptureFragmentsReadable(t *testing.T) {
	t.Parallel()
	for _, finishedStage := range []bool{false, true} {
		for _, missing := range []int{0, 1, 2, -1} {
			t.Run(fmt.Sprintf("stage finished=%v missing=%d", finishedStage, missing), func(t *testing.T) {
				ctx := context.Background()
				path := filepath.Join(t.TempDir(), "audit.db")
				store, err := sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = store.Close() })
				cipher := testCipher(t)
				const id, stage = "interrupted-chunk-loss", sqlite.StageRequestReceived
				if err := store.BeginAudit(ctx, sqlite.AuditRecord{AuditID: id, StartedAtNS: 1, RouteID: "route", Protocol: "openai", ParserName: "parser", Method: "POST", Path: "/v1/responses", RequestURIEnc: []byte{1}, Mode: "available"}); err != nil {
					t.Fatal(err)
				}
				injection, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer injection.Close()
				if _, err := injection.Exec(fmt.Sprintf(`CREATE TRIGGER fail_chunk BEFORE INSERT ON body_chunks
WHEN NEW.seq = %d OR %d = -1 BEGIN SELECT RAISE(ABORT, 'test capture failure'); END`, missing, missing)); err != nil {
					t.Fatal(err)
				}
				if err := injection.Close(); err != nil {
					t.Fatal(err)
				}
				if err := store.StartStage(ctx, sqlite.HTTPStage{AuditID: id, Stage: stage, StartedAtNS: 2}); err != nil {
					t.Fatal(err)
				}
				if err := store.StartBody(ctx, sqlite.BodyStream{AuditID: id, Stage: stage}); err != nil {
					t.Fatal(err)
				}
				var expected bytes.Buffer
				for seq, part := range []byte("ABC") {
					aad, err := security.AAD(id, "body_chunk", stage, strconv.Itoa(seq))
					if err != nil {
						t.Fatal(err)
					}
					data, err := cipher.Encrypt(aad, []byte{part})
					if err != nil {
						t.Fatal(err)
					}
					if err := store.AddChunk(ctx, sqlite.BodyChunk{AuditID: id, Stage: stage, Seq: int64(seq), Offset: int64(seq), PlaintextLength: 1, ObservedAtNS: int64(3 + seq), DataEnc: data}); err != nil {
						t.Fatal(err)
					}
					if missing != -1 && seq != missing {
						expected.WriteByte(part)
					}
				}
				if finishedStage {
					digest := sha256.Sum256([]byte("ABC"))
					if err := store.FinishStage(ctx, sqlite.StageFinish{AuditID: id, Stage: stage, State: sqlite.StageStateComplete, EndedAtNS: 6, Body: &sqlite.BodyFinish{ObservedLength: 3, StoredLength: 3, ChunkCount: 3, SHA256: digest[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete}}); err != nil {
						t.Fatal(err)
					}
				}
				// Drain accepted writes, but deliberately never finalize the parent.
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				store, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x41}, security.KeySize)); err != nil {
					t.Fatal(err)
				}
				if count, err := store.RecoverInterruptedAudits(ctx, 10); err != nil || count != 1 {
					t.Fatalf("recovered=%d err=%v", count, err)
				}
				snapshot, err := store.Snapshot(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if snapshot.Audit.ForwardStatus != sqlite.ForwardInterrupted || snapshot.Audit.CaptureStatus != sqlite.CaptureFailed {
					t.Fatal("recovery lost the known capture failure")
				}
				service, err := New(store, cipher)
				if err != nil {
					t.Fatal(err)
				}
				meta, err := service.RawMeta(ctx, id, SideRequest)
				if err != nil || !meta.MissingChunks || meta.Complete || meta.StoredLength != int64(expected.Len()) || meta.ObservedLength != 3 {
					t.Fatalf("recovered fragment metadata = %+v, %v", meta, err)
				}
				var actual bytes.Buffer
				if err := service.StreamRaw(ctx, id, SideRequest, &actual); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual.Bytes(), expected.Bytes()) {
					t.Fatal("recovered fragment export changed the saved bytes")
				}
				if count, err := store.RecoverInterruptedAudits(ctx, 11); err != nil || count != 0 {
					t.Fatal("recovery is not idempotent")
				}
				if err := store.VerifyIntegrityPayloads(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
