package parser

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// evidenceOf builds the evidence a session would hand over for an audit of
// a test store: its stages as stored, with the plaintext of their chunks.
func evidenceOf(t *testing.T, worker *Worker, auditID string) *handover.Evidence {
	t.Helper()
	ctx := context.Background()
	evidence := &handover.Evidence{CaptureVersion: storage.CaptureVersion1}
	for _, target := range []struct {
		name  string
		stage *handover.Stage
	}{{storage.StageRequestReceived, &evidence.Request}, {storage.StageResponseReceived, &evidence.Response}} {
		loaded, err := worker.store.LoadParserStage(ctx, auditID, target.name)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		stage := handover.Stage{Present: true, StatusCode: loaded.Stage.StatusCode, HeaderRows: loaded.Headers, Body: loaded.Body}
		if loaded.Body != nil {
			source := storedChunks{ctx: ctx, worker: worker, auditID: auditID, stage: target.name}
			page, err := source.page(-1)
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range page {
				plaintext, err := source.plaintext(chunk)
				if err != nil {
					t.Fatal(err)
				}
				stage.Chunks = append(stage.Chunks, handover.Chunk{Seq: chunk.seq, Offset: chunk.offset, Data: plaintext})
			}
		}
		*target.stage = stage
	}
	return evidence
}

// The backfill watermark relies on every saved ok or partial parse reaching
// analyze, on the parser goroutine. An audit parsed through Submit, with its
// evidence handed over, and left without an analysis is reported to the
// backfill exactly as the same audit parsed after Notify: the same retries,
// the same skips, the same later passes.
func TestBackfillWatermarkAuditParsedThroughSubmit(t *testing.T) {
	t.Parallel()
	outage := fmt.Errorf("save analysis: %w", storage.ErrQueueFull)
	for _, test := range []struct {
		name         string
		saveFailures int
		liveErr      error
		noRequest    bool
		wantAttempts int
		wantAnalysed bool
	}{
		{name: "live analysis succeeds", wantAttempts: 0, wantAnalysed: true},
		{name: "live analysis hits a storage outage", liveErr: outage, wantAttempts: 1, wantAnalysed: true},
		{name: "live analysis rejects the evidence", liveErr: errors.New("request is not JSON"), wantAttempts: 0},
		{name: "parse retried after a save failure", saveFailures: 1, liveErr: outage, wantAttempts: 1, wantAnalysed: true},
		{name: "no request body when parsed", noRequest: true, wantAttempts: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			type outcome struct {
				attempts         int
				analysed, retry  bool
				skipped, covered bool
			}
			run := func(submit bool) outcome {
				world := newCostWorld()
				seedAnalysed(t, world, 10)
				addInFlight(t, world, "long", 150)
				if test.noRequest {
					key := stageKey("long", sqlite.StageRequestReceived)
					delete(world.stages, key)
					delete(world.chunks, key)
					response, chunks := encryptedStage(t, testCipher(t), "long", sqlite.StageResponseReceived, "application/json", "", []byte(`{"id":"r"}`))
					responseKey := stageKey("long", sqlite.StageResponseReceived)
					world.stages[responseKey], world.chunks[responseKey] = response, chunks
				}
				analyzer := &worldAnalyzer{world: world, fail: map[string]error{"long": test.liveErr}}
				worker, clock := watermarkWorker(t, world, analyzer)
				insightsPass(t, worker, clock)
				world.saveFailures = test.saveFailures
				if submit {
					evidence := evidenceOf(t, worker, "long")
					world.takeLoads()
					released := 0
					worker.serve(context.Background(), FinalizeJob{Audit: world.audits["long"], Evidence: evidence, Release: func() { released++ }})
					if released != 1 {
						t.Fatalf("released %d times", released)
					}
					if loads := world.takeLoads(); loads["long"] != 0 {
						t.Fatalf("the parse of a handed-over audit read its body %d times", loads["long"])
					}
				} else {
					worker.process(context.Background(), "long")
				}
				if test.saveFailures > 0 {
					insightsPass(t, worker, clock)
					worker.process(context.Background(), "long")
				}
				if status := world.audits["long"].ParseStatus; status != StatusOK && status != StatusPartial {
					t.Fatalf("parse status %q", status)
				}
				_, retry := worker.backfillRetry["long"]
				skipped := worker.backfillSkipped != nil && len(worker.backfillSkipped) != 0
				delete(analyzer.fail, "long")
				attempts := insightsPass(t, worker, clock) + insightsPass(t, worker, clock)
				if again := insightsPass(t, worker, clock); again != 0 {
					t.Fatalf("a later pass attempted %d", again)
				}
				return outcome{attempts: attempts, analysed: world.analysed["long"], retry: retry, skipped: skipped,
					covered: worker.backfillMark.covered != nil}
			}
			notified, submitted := run(false), run(true)
			if notified != submitted {
				t.Fatalf("parsed after Notify %+v, through Submit %+v", notified, submitted)
			}
			if submitted.attempts != test.wantAttempts || submitted.analysed != test.wantAnalysed {
				t.Fatalf("attempted %d analysed %v, want %d and %v", submitted.attempts, submitted.analysed, test.wantAttempts, test.wantAnalysed)
			}
		})
	}
}
