package audit

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// newTestStager opens a stager with the key runDiverge uses.
func newTestStager(t *testing.T, options staging.Options) *staging.Stager {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{9}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	stager, err := staging.Open(filepath.Join(t.TempDir(), "staging"), cipher, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	return stager
}

// syncStager writes every chunk before Stage returns, so a write failure is
// seen by the next chunk deterministically.
type syncStager struct{ *staging.Stager }

func (stager syncStager) Stage(chunk storage.BodyChunk) (*staging.Ref, error) {
	ref, err := stager.Stager.Stage(chunk)
	stager.Flush()
	return ref, err
}

func requireStagingEmpty(t *testing.T, stager *staging.Stager) {
	t.Helper()
	stager.Flush()
	entries, err := os.ReadDir(stager.Dir())
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging directory holds %v (%v)", entries, err)
	}
	if used := stager.Stats().UsedBytes; used != 0 {
		t.Fatalf("staging still counts %d bytes", used)
	}
}

func compareSnapshots(t *testing.T, legacy, unified sqlite.Snapshot, chunks bool) {
	t.Helper()
	parts := []struct {
		name            string
		legacy, unified any
	}{
		{"audit", legacy.Audit, unified.Audit},
		{"stages", legacy.Stages, unified.Stages},
		{"headers", legacy.Headers, unified.Headers},
		{"bodies", legacy.Bodies, unified.Bodies},
	}
	if chunks {
		parts = append(parts, struct {
			name            string
			legacy, unified any
		}{"chunks", chunkSummary(legacy.Chunks), chunkSummary(unified.Chunks)})
	}
	for _, part := range parts {
		if !reflect.DeepEqual(part.legacy, part.unified) {
			t.Fatalf("%s differ:\n legacy  %+v\n unified %+v", part.name, part.legacy, part.unified)
		}
	}
}

// Bodies over the per-stage budget spill to staging; the stored rows, chunk
// boundaries included, are legacy's. The pairs are merged or not exactly as
// legacy decides, also when the duplicate borrows bytes its source staged,
// and the staging file is gone after the commit.
func TestStagedBodiesMatchLegacy(t *testing.T) {
	request := noise(5<<19, 11)
	response := noise(7<<19, 12)
	for _, test := range []struct {
		name  string
		drive divergeDrive
	}{
		{"both pairs equal", divergeDrive{inbound: request, outbound: request, received: response, sent: response, piece: 48 << 10}},
		{"request differs at byte 100", divergeDrive{inbound: request, outbound: withChange(request, 100), received: response, sent: response, piece: 48 << 10}},
		{"request differs after 2 MiB", divergeDrive{inbound: request, outbound: withChange(request, 2<<20+5), received: response, sent: response, piece: 48 << 10}},
		{"response differs after 3 MiB", divergeDrive{inbound: request, outbound: request, received: response, sent: withChange(response, 3<<20+77), piece: 32 << 10}},
		{"response differs at byte 10", divergeDrive{inbound: request, outbound: request, received: response, sent: withChange(response, 10), piece: 32 << 10}},
		{"outbound longer", divergeDrive{inbound: request, outbound: append(bytes.Clone(request), noise(1<<20, 13)...), received: response, sent: response, piece: 48 << 10}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stager := newTestStager(t, staging.Options{})
			legacyOutcome, legacy := runDiverge(t, WritePathLegacy, test.drive)
			unifiedOutcome, unified := runDivergeWith(t, Options{WritePath: WritePathUnified, StageBytes: 1 << 20, Stager: stager}, test.drive)
			if legacyOutcome != unifiedOutcome {
				t.Fatalf("outcome %+v, unified %+v", legacyOutcome, unifiedOutcome)
			}
			compareSnapshots(t, legacy, unified, true)
			if stats := stager.Stats(); stats.Records < 4 || stats.Fsyncs == 0 {
				t.Fatalf("staging stats %+v", stats)
			}
			requireStagingEmpty(t, stager)
		})
	}
}

// Under global budget pressure a stage spills its open chunk early, so its
// chunks may be shorter than 1 MiB (F.2); the content and every other row
// are legacy's. The staging queue counts against the global budget until it
// is written, so the stager here writes at once, as a fast disk does.
func TestGlobalBudgetPressureSpillsShortChunks(t *testing.T) {
	request := noise(5<<19, 21)
	response := noise(5<<19, 22)
	drive := divergeDrive{inbound: request, outbound: request, received: response, sent: response, piece: 40 << 10}
	stager := newTestStager(t, staging.Options{})
	legacyOutcome, legacy := runDiverge(t, WritePathLegacy, drive)
	unifiedOutcome, unified := runDivergeWith(t, Options{WritePath: WritePathUnified, StageBytes: 1 << 20, GlobalBytes: 1 << 20, Stager: syncStager{stager}}, drive)
	if legacyOutcome != unifiedOutcome || unifiedOutcome.CaptureStatus != storage.CaptureComplete {
		for _, body := range unified.Bodies {
			t.Logf("%s %s %v stored %d of %d", body.Stage, body.State, valueOrEmpty(body.ErrorCode), body.StoredLength, body.ObservedLength)
		}
		t.Fatalf("outcome %+v, unified %+v", legacyOutcome, unifiedOutcome)
	}
	// Chunk counts may differ; every other column of the body rows may not.
	for index := range legacy.Bodies {
		legacy.Bodies[index].ChunkCount, unified.Bodies[index].ChunkCount = 0, 0
	}
	compareSnapshots(t, legacy, unified, false)
	short := 0
	for _, stage := range []string{storage.StageRequestReceived, storage.StageResponseReceived} {
		var content []byte
		for _, chunk := range unified.Chunks {
			if chunk.Stage == stage {
				content = append(content, chunk.DataEnc...)
				if chunk.PlaintextLength < 1<<20 && chunk.Offset+int64(chunk.PlaintextLength) < int64(len(request)) {
					short++
				}
			}
		}
		want := request
		if stage == storage.StageResponseReceived {
			want = response
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("%s: stored %d bytes differ from the %d observed", stage, len(content), len(want))
		}
	}
	if short == 0 {
		t.Fatal("no chunk was spilled early")
	}
	requireStagingEmpty(t, stager)
}

// The global budget is full and the staging queue does not drain (a slow
// disk): the queue holds the budget, and a stage that needs more memory
// stops retaining with capture_budget_exhausted (F.6).
func TestGlobalBudgetExhaustedWithSlowStaging(t *testing.T) {
	request := noise(5<<19, 25)
	drive := divergeDrive{inbound: request, outbound: request, received: []byte("ok"), sent: []byte("ok"), piece: 40 << 10}
	stager := newTestStager(t, staging.Options{BatchDelay: time.Hour})
	outcome, snapshot := runDivergeWith(t, Options{WritePath: WritePathUnified, StageBytes: 1 << 20, GlobalBytes: 1 << 20, Stager: stager}, drive)
	if outcome.CaptureStatus != storage.CapturePartial || outcome.ForwardStatus != storage.ForwardCompleted {
		t.Fatalf("outcome %+v", outcome)
	}
	body := snapshot.Bodies[0]
	if body.ErrorCode == nil || *body.ErrorCode != "capture_budget_exhausted" || body.RetentionState != storage.RetentionFull || body.StoredLength >= body.ObservedLength {
		t.Fatalf("request body %+v", body)
	}
}

// Staging refuses: the stage stops retaining with the F.6 error code, keeps
// what it had (a chunk whose write failed included), is partial with raw in
// full, and forwarding is unaffected.
func TestStagingRefusalExhaustsTheStage(t *testing.T) {
	request := noise(5<<19, 31)
	drive := divergeDrive{inbound: request, outbound: request, received: []byte("ok"), sent: []byte("ok"), piece: 48 << 10}
	for _, test := range []struct {
		name    string
		options staging.Options
		code    string
	}{
		{"staging full", staging.Options{MaxBytes: 600 << 10}, "capture_budget_exhausted"},
		{"no space left", staging.Options{Fault: faultAfter("write", 0, syscall.ENOSPC)}, "capture_budget_exhausted"},
		{"write error", staging.Options{Fault: faultAfter("write", 0, syscall.EIO)}, "staging_write_failed"},
		{"sync error", staging.Options{Fault: faultAfter("sync", 0, syscall.EIO)}, "staging_write_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stager := newTestStager(t, test.options)
			outcome, snapshot := runDivergeWith(t, Options{WritePath: WritePathUnified, StageBytes: 1 << 20, Stager: syncStager{stager}}, drive)
			if outcome.CaptureStatus != storage.CapturePartial || outcome.ForwardStatus != storage.ForwardCompleted {
				t.Fatalf("outcome %+v", outcome)
			}
			body := snapshot.Bodies[0]
			if body.Stage != storage.StageRequestReceived || body.ErrorCode == nil || *body.ErrorCode != test.code ||
				body.State != storage.StageStatePartial || body.RetentionState != storage.RetentionFull || body.StoredLength < 1<<20 || body.StoredLength >= body.ObservedLength {
				t.Fatalf("request body %+v", body)
			}
			var stored []byte
			for _, chunk := range snapshot.Chunks {
				if chunk.Stage == storage.StageRequestReceived {
					stored = append(stored, chunk.DataEnc...)
				}
			}
			if int64(len(stored)) != body.StoredLength || !bytes.Equal(stored, request[:len(stored)]) {
				t.Fatalf("stored %d bytes, row says %d", len(stored), body.StoredLength)
			}
		})
	}
}

// faultAfter fails the operation once it has succeeded skip times.
func faultAfter(operation string, skip int, err error) func(string, string) error {
	count := 0
	return func(name, _ string) error {
		if name != operation {
			return nil
		}
		count++
		if count > skip {
			return err
		}
		return nil
	}
}

// A staged chunk's plaintext reads back through its index entry, as the
// finalizer and a borrowing duplicate read it.
func TestStagedPlaintextReadBack(t *testing.T) {
	stager := newTestStager(t, staging.Options{})
	cipher, _ := security.NewAESGCM(bytes.Repeat([]byte{9}, security.KeySize))
	plaintext := noise(300<<10, 41)
	session := &Session{auditID: "apx_readback", cipher: cipher}
	stage := &stageCapture{name: storage.StageResponseReceived, contentType: "application/json"}
	chunk, failure := session.sealChunkLocked(stage, 0, 0, plaintext, 7)
	if failure != "" {
		t.Fatal(failure)
	}
	ref, err := stager.Stage(chunk)
	if err != nil {
		t.Fatal(err)
	}
	stager.Flush()
	got, err := ref.Plaintext()
	if err != nil || !bytes.Equal(got, plaintext) || ref.Metadata().PlaintextLength != len(plaintext) {
		t.Fatalf("read back %d bytes, %v, %+v", len(got), err, ref.Metadata())
	}
}
