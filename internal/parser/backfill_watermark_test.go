package parser

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// horizonWorld adds the horizon reads the PostgreSQL store has, which turn
// the watermark on.
type horizonWorld struct{ *costWorld }

func (world horizonWorld) AnalysisBackfillHorizon(context.Context) (storage.AnalysisBackfillCursor, bool, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	ids := world.ordered()
	if len(ids) == 0 {
		return storage.AnalysisBackfillCursor{}, false, nil
	}
	last := ids[len(ids)-1]
	return storage.AnalysisBackfillCursor{StartedAtNS: world.started[last], AuditID: last}, true, nil
}

func (world horizonWorld) ProjectBackfillHorizon(context.Context) (storage.ProjectBackfillCursor, bool, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	ids := world.ordered()
	for index := len(ids) - 1; index >= 0; index-- {
		if world.analysed[ids[index]] {
			return storage.ProjectBackfillCursor{StartedAtNS: world.started[ids[index]], AuditID: ids[index]}, true, nil
		}
	}
	return storage.ProjectBackfillCursor{}, false, nil
}

const watermarkParser = "test.parser"

// seedAnalysed adds count audits that are parsed and analysed, at times
// 100, 200, ...
func seedAnalysed(t *testing.T, world *costWorld, count int) {
	t.Helper()
	for index := range count {
		id := fmt.Sprintf("done-%04d", index)
		world.add(t, id, watermarkParser, StatusOK, int64(100*(index+1)), []byte(`{"model":"m"}`))
		world.analysed[id] = true
		world.identity[id] = true
	}
}

// addInFlight adds an audit that started at startedAtNS and is not parsed yet.
func addInFlight(t *testing.T, world *costWorld, auditID string, startedAtNS int64) {
	t.Helper()
	world.add(t, auditID, watermarkParser, sqlite.ParsePending, startedAtNS, []byte(`{"model":"m"}`))
}

func watermarkWorker(t *testing.T, world *costWorld, analyzer *worldAnalyzer) (*Worker, *testClock) {
	t.Helper()
	worker, clock := newCostWorker(t, horizonWorld{world}, &recordingParser{name: watermarkParser})
	worker.SetAnalyzer(analyzer)
	return worker, clock
}

// Once everything is analysed, a pass reads only the rows written since the
// previous one began.
func TestBackfillWatermarkBoundsSteadyStatePasses(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 500)
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})

	if attempted := insightsPass(t, worker, clock); attempted != 0 {
		t.Fatalf("first pass attempted %d", attempted)
	}
	if examined := world.takeExamined(); examined != 500 {
		t.Fatalf("the first pass after a start must read everything: %d rows", examined)
	}
	if insightsPass(t, worker, clock); world.takeExamined() != 0 {
		t.Fatal("a pass with nothing new read rows")
	}
	for index := range 3 {
		id := fmt.Sprintf("new-%d", index)
		world.add(t, id, watermarkParser, StatusOK, int64(100_000+index), []byte(`{"model":"m"}`))
		world.analysed[id] = true
	}
	insightsPass(t, worker, clock)
	if examined := world.takeExamined(); examined != 3 {
		t.Fatalf("steady-state pass read %d rows, want the 3 new ones", examined)
	}
	if insightsPass(t, worker, clock); world.takeExamined() != 0 {
		t.Fatal("the new rows were read twice")
	}
}

// An audit that started before the watermark but is parsed after the pass
// that set it: a long request, a parse retried after a save failure, a row
// left pending for a later scan, or one closed by startup recovery. The live
// analysis either writes its row or hands the audit to the backfill: a
// failure that may clear is retried after its backoff, one that cannot is
// remembered as skipped and its body is not loaded again.
func TestBackfillWatermarkAuditParsedAfterThePassThatCoveredIt(t *testing.T) {
	t.Parallel()
	outage := fmt.Errorf("save analysis: %w", storage.ErrQueueFull)
	for _, test := range []struct {
		name          string
		saveFailures  int
		liveErr       error
		noRequest     bool
		requestUnread bool
		wantAttempts  int
		wantAnalysed  bool
	}{
		{name: "live analysis succeeds", wantAttempts: 0, wantAnalysed: true},
		{name: "live analysis hits a storage outage", liveErr: outage, wantAttempts: 1, wantAnalysed: true},
		{name: "live analysis times out while the worker runs", liveErr: context.DeadlineExceeded, wantAttempts: 1, wantAnalysed: true},
		{name: "live analysis rejects the evidence", liveErr: errors.New("request is not JSON"), wantAttempts: 0},
		{name: "parse retried after a save failure", saveFailures: 1, liveErr: outage, wantAttempts: 1, wantAnalysed: true},
		{name: "no request body when parsed", noRequest: true, wantAttempts: 0},
		{name: "request body unreadable when parsed", requestUnread: true, wantAttempts: 1, wantAnalysed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			world := newCostWorld()
			seedAnalysed(t, world, 10)
			addInFlight(t, world, "long", 150) // between done-0000 and done-0001
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
			if worker.backfillMark.covered == nil || worker.backfillMark.covered.AuditID != "done-0009" {
				t.Fatalf("watermark = %+v, want the newest audit", worker.backfillMark.covered)
			}

			world.saveFailures = test.saveFailures
			if test.requestUnread {
				world.chunkFailures = map[string]int{"long": 1}
			}
			worker.process(context.Background(), "long")
			if test.saveFailures > 0 {
				// Released to pending; a later scan parses it again.
				insightsPass(t, worker, clock)
				worker.process(context.Background(), "long")
			}
			if status := world.audits["long"].ParseStatus; status != StatusOK && status != StatusPartial {
				t.Fatalf("parse status %q", status)
			}
			delete(analyzer.fail, "long")
			// A retry falls due one rescan interval after the live failure.
			attempted := insightsPass(t, worker, clock) + insightsPass(t, worker, clock)
			if attempted != test.wantAttempts || world.analysed["long"] != test.wantAnalysed {
				t.Fatalf("attempted %d analysed %v, want %d and %v", attempted, world.analysed["long"], test.wantAttempts, test.wantAnalysed)
			}
			if again := insightsPass(t, worker, clock); again != 0 {
				t.Fatalf("a later pass attempted %d", again)
			}
		})
	}
}

// The insights backfill analyses an old audit, which makes it an identity
// candidate below the identity backfill's watermark (that backfill walks
// newest first and has already passed it).
func TestProjectWatermarkPicksUpAuditsTheInsightsBackfillAnalyses(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	world.add(t, "old", watermarkParser, StatusOK, 150, []byte(`{"model":"m"}`))
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	project := &failingProjectAnalyzer{world: world, fail: map[string]bool{}}
	worker.SetProjectAnalyzer(project)

	if attempted := projectPass(t, worker, clock); attempted != 0 {
		t.Fatalf("project pass attempted %d", attempted)
	}
	if worker.projectMark.covered == nil || worker.projectMark.covered.AuditID != "done-0009" {
		t.Fatalf("project watermark = %+v", worker.projectMark.covered)
	}
	world.takeExamined()
	if attempted := insightsPass(t, worker, clock); attempted != 1 || !world.analysed["old"] {
		t.Fatalf("insights pass attempted %d", attempted)
	}
	world.takeExamined()
	if attempted := projectPass(t, worker, clock); attempted != 1 || !world.identity["old"] {
		t.Fatalf("project pass attempted %d, identity %v", attempted, world.identity["old"])
	}
	// The watermark was lowered to the old audit: the pass walked the rows
	// from there up (old and done-0001..done-0009) and nothing below.
	if examined := world.takeExamined(); examined != 10 {
		t.Fatalf("project pass read %d rows, want 10", examined)
	}
	if attempted := projectPass(t, worker, clock); attempted != 0 || world.takeExamined() != 0 {
		t.Fatalf("a later project pass attempted %d", attempted)
	}
}

// After a version bump the insights backfill re-analyses audits that already
// have a current identity. Handing them over must not make the identity
// backfill read their evidence again.
func TestProjectWatermarkHandoffSparesIdentifiedAudits(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	project := &failingProjectAnalyzer{world: world}
	worker.SetProjectAnalyzer(project)
	projectPass(t, worker, clock)
	for _, id := range []string{"done-0001", "done-0004"} {
		world.analysed[id] = false // the analysis is outdated; the identity is not
	}
	restarted, restartedClock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	restarted.SetProjectAnalyzer(project)
	restarted.projectMark = worker.projectMark // only the insights side starts over
	if attempted := insightsPass(t, restarted, restartedClock); attempted != 2 {
		t.Fatalf("insights pass attempted %d", attempted)
	}
	world.takeLoads()
	if attempted := projectPass(t, restarted, restartedClock); attempted != 0 {
		t.Fatalf("identity pass attempted %d", attempted)
	}
	if loads := world.takeLoads(); len(loads) != 0 {
		t.Fatalf("identity pass read bodies %v", loads)
	}
}

// A handed-over audit whose position is unknown is checked against the
// stored identity before any evidence is read.
func TestProjectRetryChecksTheStoredIdentityFirst(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 3)
	worker, clock := newCostWorker(t, identityWorld{horizonWorld{world}}, &recordingParser{name: watermarkParser})
	worker.SetAnalyzer(&worldAnalyzer{world: world})
	worker.SetProjectAnalyzer(&failingProjectAnalyzer{world: world})
	worker.projectBackfillLater("done-0001", nil)
	if attempted := projectPass(t, worker, clock); attempted != 0 || len(worker.projectRetry) != 0 || len(world.takeLoads()) != 0 {
		t.Fatalf("attempted %d, retries %v", attempted, worker.projectRetry)
	}
}

// identityWorld adds the identity row lookup the PostgreSQL store has.
type identityWorld struct{ horizonWorld }

func (world identityWorld) LoadProjectIdentity(_ context.Context, auditID string) (storage.ProjectIdentityRow, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	if !world.identity[auditID] {
		return storage.ProjectIdentityRow{}, errors.New("no rows")
	}
	return storage.ProjectIdentityRow{AuditID: auditID, Version: insights.ProjectIdentityVersion}, nil
}

// A live identity failure on an old audit: the insights row written right
// after it makes the audit a candidate below the identity watermark.
func TestProjectWatermarkRetriesALiveIdentityFailure(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	addInFlight(t, world, "long", 150)
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	project := &failingProjectAnalyzer{world: world, outage: map[string]bool{"long": true}}
	worker.SetProjectAnalyzer(project)
	projectPass(t, worker, clock)

	worker.process(context.Background(), "long")
	if !world.analysed["long"] || world.identity["long"] {
		t.Fatalf("live path: analysed %v identity %v", world.analysed["long"], world.identity["long"])
	}
	delete(project.outage, "long")
	if attempted := projectPass(t, worker, clock) + projectPass(t, worker, clock); attempted != 1 || !world.identity["long"] {
		t.Fatalf("project pass attempted %d, identity %v", attempted, world.identity["long"])
	}
}

// A restart forgets the watermark: the first pass lists everything, which is
// how a new AnalysisVersion or rows written while the process was down are
// found. Without a restart those rows are not candidates by construction.
func TestBackfillWatermarkStartsOverAfterARestart(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	insightsPass(t, worker, clock)
	// A version bump at the next start makes an old row a candidate.
	world.analysed["done-0002"] = false
	restarted, restartedClock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	if attempted := insightsPass(t, restarted, restartedClock); attempted != 1 || !world.analysed["done-0002"] {
		t.Fatalf("restarted pass attempted %d", attempted)
	}
}

// Retention deletes an audit that waits for a retry: it is tried once, found
// missing and forgotten. Deleting covered rows never uncovers anything.
func TestBackfillWatermarkAfterRetention(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	world.add(t, "failing", watermarkParser, StatusOK, 150, []byte(`{"model":"m"}`))
	analyzer := &worldAnalyzer{world: world, fail: map[string]error{"failing": fmt.Errorf("save: %w", storage.ErrQueueFull)}}
	worker, clock := watermarkWorker(t, world, analyzer)
	insightsPass(t, worker, clock)
	if _, waiting := worker.backfillRetry["failing"]; !waiting {
		t.Fatal("failed audit not kept for a retry")
	}
	world.remove("failing")
	world.remove("done-0009") // the horizon row itself
	if attempted := insightsPass(t, worker, clock); attempted != 1 || len(worker.backfillRetry) != 0 {
		t.Fatalf("attempted %d, retries %v", attempted, worker.backfillRetry)
	}
	if attempted := insightsPass(t, worker, clock); attempted != 0 {
		t.Fatalf("deleted audit attempted again: %d", attempted)
	}
}

// A failure that does not fit the retry set uncovers its position, so the
// next pass lists it again; an unknown position uncovers everything.
func TestBackfillWatermarkLowersWhenTheRetrySetIsFull(t *testing.T) {
	t.Parallel()
	var mark watermark
	mark.covered = &keyset{StartedAtNS: 900, AuditID: "z"}
	retries := make(map[string]*backfillRetry, backfillRetryCap)
	for index := range backfillRetryCap {
		retries[fmt.Sprintf("r-%d", index)] = &backfillRetry{}
	}
	recordRetry(&retries, &mark, "overflow", &keyset{StartedAtNS: 500, AuditID: "overflow"}, time.Now())
	if _, kept := retries["overflow"]; kept {
		t.Fatal("full retry set grew")
	}
	mark.begin(nil)
	if mark.passAfter == nil || mark.passAfter.StartedAtNS != 500 || mark.passAfter.AuditID != "" {
		t.Fatalf("next pass lists after %+v, want just below the overflowed audit", mark.passAfter)
	}
	mark.complete()
	mark.covered = &keyset{StartedAtNS: 900, AuditID: "z"}
	recordRetry(&retries, &mark, "live-overflow", nil, time.Now())
	if mark.begin(nil); mark.passAfter != nil {
		t.Fatalf("an unknown position must uncover everything, pass lists after %+v", mark.passAfter)
	}
}

// A lowering recorded while a pass is open applies to the next pass, after
// the open one completes; an abandoned pass keeps its own start.
func TestWatermarkLoweringWhileAPassIsOpen(t *testing.T) {
	t.Parallel()
	var mark watermark
	mark.begin(&keyset{StartedAtNS: 100, AuditID: "a"})
	mark.complete()
	mark.begin(&keyset{StartedAtNS: 300, AuditID: "c"})
	if mark.passAfter.StartedAtNS != 100 {
		t.Fatalf("pass after %+v", mark.passAfter)
	}
	mark.lower(&keyset{StartedAtNS: 50, AuditID: "x"})
	mark.complete()
	if mark.covered.StartedAtNS != 50 || mark.covered.AuditID != "" {
		t.Fatalf("covered %+v, want lowered below 50", mark.covered)
	}
	mark.begin(&keyset{StartedAtNS: 400, AuditID: "d"})
	mark.abandon()
	if mark.begin(nil); mark.passAfter == nil || mark.passAfter.StartedAtNS != 50 {
		t.Fatalf("abandoned pass moved the start to %+v", mark.passAfter)
	}
}

// A bounded pass claims coverage of the region below its watermark only
// once it has retried what waits there.
func TestBackfillProgressOfABoundedPass(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	seedAnalysed(t, world, 10)
	analyzer := &worldAnalyzer{world: world, fail: map[string]error{}}
	for index := range backfillBatch + 5 {
		id := fmt.Sprintf("retry-%02d", index)
		world.add(t, id, watermarkParser, StatusOK, int64(150+index), []byte(`{"model":"m"}`))
		analyzer.fail[id] = fmt.Errorf("save: %w", storage.ErrQueueFull)
	}
	worker, clock := watermarkWorker(t, world, analyzer)
	insightsPass(t, worker, clock)
	if len(worker.backfillRetry) != backfillBatch+5 {
		t.Fatalf("retries = %d", len(worker.backfillRetry))
	}
	analyzer.fail = map[string]error{}
	since := clock.now.UnixNano()
	until := int64(1000) // below the watermark (done-0009 at 1000 is the horizon)
	if attempted := worker.backfill(context.Background()); attempted != backfillBatch {
		t.Fatalf("first tick attempted %d", attempted)
	}
	if worker.AnalysisBackfillCovered(until, since) {
		t.Fatal("coverage claimed with retries still waiting")
	}
	worker.backfill(context.Background())
	if !worker.AnalysisBackfillCovered(until, since) {
		t.Fatal("coverage not claimed after the retries ran")
	}
}

// A storage failure in the middle of a body load used to be parsed as if it
// were the evidence; with an empty request the audit was skipped for good as
// no_request_body. It is now a retryable failure.
func TestBackfillRetriesABodyLoadThatFailedHalfway(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	world.add(t, "flaky", watermarkParser, StatusOK, 100, []byte(`{"model":"m"}`))
	world.chunkFailures = map[string]int{"flaky": 1}
	worker, clock := watermarkWorker(t, world, &worldAnalyzer{world: world})
	if attempted := insightsPass(t, worker, clock); attempted != 1 || world.analysed["flaky"] {
		t.Fatalf("first pass attempted %d, analysed %v", attempted, world.analysed["flaky"])
	}
	if _, skipped := worker.backfillSkipped["flaky"]; skipped {
		t.Fatal("a failed read skipped the audit for good")
	}
	if attempted := insightsPass(t, worker, clock); attempted != 1 || !world.analysed["flaky"] {
		t.Fatalf("retry attempted %d, analysed %v", attempted, world.analysed["flaky"])
	}
}
