package parser

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// costWorld is an in-memory store whose candidate lists follow the
// PostgreSQL anti-joins: insights candidates are ok/partial audits without a
// current analysis, oldest first; project candidates are analysed audits
// without a current identity, newest first. It counts body loads per audit.
type costWorld struct {
	*fakeStore
	started   map[string]int64
	analysed  map[string]bool
	identity  map[string]bool
	bodyLoads map[string]int
	// chunkFailures fails the next body reads of an audit, as a storage
	// outage in the middle of a load does.
	chunkFailures map[string]int
	// examined counts the rows each list walks: those after its lower bound,
	// up to the last one it returns, as an ordered index range scan would.
	examined int
}

func newCostWorld() *costWorld {
	world := &costWorld{
		fakeStore: newFakeStore("unused", "unused"),
		started:   map[string]int64{}, analysed: map[string]bool{}, identity: map[string]bool{}, bodyLoads: map[string]int{},
	}
	delete(world.audits, "unused")
	world.saved = make(chan sqlite.ParsedResult, 1<<16)
	return world
}

func (world *costWorld) LoadParserAudit(_ context.Context, auditID string) (sqlite.ParserAudit, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	audit, ok := world.audits[auditID]
	if !ok {
		return sqlite.ParserAudit{}, sql.ErrNoRows
	}
	return audit, nil
}

// remove deletes an audit with everything derived from it, as retention does.
func (world *costWorld) remove(auditID string) {
	world.mu.Lock()
	defer world.mu.Unlock()
	delete(world.audits, auditID)
	delete(world.started, auditID)
	delete(world.analysed, auditID)
	delete(world.identity, auditID)
}

func (world *costWorld) takeExamined() int {
	world.mu.Lock()
	defer world.mu.Unlock()
	examined := world.examined
	world.examined = 0
	return examined
}

// add stores one parsed audit with a retained request body.
func (world *costWorld) add(t *testing.T, auditID, parserName, status string, startedAtNS int64, body []byte) {
	t.Helper()
	world.audits[auditID] = sqlite.ParserAudit{AuditID: auditID, Protocol: "anthropic", ParserName: parserName, ParseStatus: status}
	world.started[auditID] = startedAtNS
	stage, chunks := encryptedStage(t, testCipher(t), auditID, sqlite.StageRequestReceived, "application/json", "", body)
	key := stageKey(auditID, sqlite.StageRequestReceived)
	world.stages[key], world.chunks[key] = stage, chunks
}

func (world *costWorld) ordered() []string {
	ids := make([]string, 0, len(world.started))
	for id := range world.started {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := world.started[ids[i]], world.started[ids[j]]
		return a < b || a == b && ids[i] < ids[j]
	})
	return ids
}

func (world *costWorld) ListAnalysisBackfillCandidates(_ context.Context, _ int, after *storage.AnalysisBackfillCursor, limit int) ([]storage.AnalysisBackfillCandidate, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	var out []storage.AnalysisBackfillCandidate
	for _, id := range world.ordered() {
		audit, ok := world.audits[id]
		started := world.started[id]
		if after != nil && (started < after.StartedAtNS || started == after.StartedAtNS && id <= after.AuditID) {
			continue
		}
		world.examined++
		if !ok || world.analysed[id] || (audit.ParseStatus != StatusOK && audit.ParseStatus != StatusPartial) {
			continue
		}
		out = append(out, storage.AnalysisBackfillCandidate{AuditID: id, StartedAtNS: started})
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (world *costWorld) ListProjectIdentityBackfillCandidates(_ context.Context, _ int, after, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error) {
	world.mu.Lock()
	defer world.mu.Unlock()
	ids := world.ordered()
	var out []storage.ProjectBackfillCandidate
	for index := len(ids) - 1; index >= 0; index-- {
		id := ids[index]
		started := world.started[id]
		if before != nil && (started > before.StartedAtNS || started == before.StartedAtNS && id >= before.AuditID) {
			continue
		}
		if after != nil && (started < after.StartedAtNS || started == after.StartedAtNS && id <= after.AuditID) {
			continue
		}
		if !world.analysed[id] {
			continue
		}
		world.examined++
		if world.identity[id] {
			continue
		}
		out = append(out, storage.ProjectBackfillCandidate{AuditID: id, StartedAtNS: started, Protocol: "anthropic"})
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (world *costWorld) ReadParserChunks(ctx context.Context, auditID, stage string, afterSeq int64, limit int) ([]storage.BodyChunk, error) {
	world.mu.Lock()
	if afterSeq < 0 {
		world.bodyLoads[auditID]++
	}
	failing := world.chunkFailures[auditID] > 0
	if failing {
		world.chunkFailures[auditID]--
	}
	world.mu.Unlock()
	if failing {
		return nil, fmt.Errorf("read chunks: %w", storage.ErrClosed)
	}
	return world.fakeStore.ReadParserChunks(ctx, auditID, stage, afterSeq, limit)
}

func (world *costWorld) takeLoads() map[string]int {
	world.mu.Lock()
	defer world.mu.Unlock()
	loads := world.bodyLoads
	world.bodyLoads = map[string]int{}
	return loads
}

func totalLoads(loads map[string]int) int {
	total := 0
	for _, count := range loads {
		total += count
	}
	return total
}

// worldAnalyzer records an analysis row, or fails for the named audits.
type worldAnalyzer struct {
	world *costWorld
	fail  map[string]error
}

func (analyzer worldAnalyzer) AnalyzeAudit(_ context.Context, input insights.Input) error {
	if err := analyzer.fail[input.AuditID]; err != nil {
		return err
	}
	analyzer.world.mu.Lock()
	analyzer.world.analysed[input.AuditID] = true
	analyzer.world.mu.Unlock()
	return nil
}

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

func newCostWorker(t *testing.T, store Store, parsers ...Parser) (*Worker, *testClock) {
	t.Helper()
	worker, err := NewWorker(store, testCipher(t), parsers, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	worker.now = clock.Now
	return worker, clock
}

// insightsPass runs one complete insights backfill pass and then lets the
// rescan interval elapse. It returns the audits attempted.
func insightsPass(t *testing.T, worker *Worker, clock *testClock) int {
	t.Helper()
	attempted := 0
	for range 100000 {
		attempted += worker.backfill(context.Background())
		if !worker.backfillProgress.open && worker.now().Before(worker.backfillNextScan) {
			clock.now = clock.now.Add(backfillRescanInterval)
			return attempted
		}
	}
	t.Fatal("insights pass did not complete")
	return 0
}

// projectPass runs one complete project identity pass and lets the rescan
// interval elapse.
func projectPass(t *testing.T, worker *Worker, clock *testClock) int {
	t.Helper()
	attempted := 0
	for range 100000 {
		attempted += worker.projectBackfill(context.Background())
		if worker.projectCursor == nil && worker.now().Before(worker.projectNextScan) {
			clock.now = clock.now.Add(projectBackfillRescanInterval)
			return attempted
		}
	}
	t.Fatal("project pass did not complete")
	return 0
}

// oldBackfillSkipCap is the skip-set size before issue #59. The set used to
// be thrown away whenever it filled: a pass ended with only the last N-4096
// skips remembered, the next pass re-attempted the first ones, refilled the
// set before it reached the remembered tail and threw that away too, so every
// pass re-read every one of them (5000 of 5000 here). Now the set is not
// reset, so each is read once.
const oldBackfillSkipCap = 4096

func TestBackfillSkipCapThrash(t *testing.T) {
	t.Parallel()
	const audits = oldBackfillSkipCap + 904
	world := newCostWorld()
	for index := range audits {
		world.add(t, fmt.Sprintf("audit-%05d", index), "unusable.parser", StatusPartial, int64(index+1), []byte(`{"model":"m"}`))
	}
	unusable := Result{Status: StatusError, ErrorCode: "parse_error"}
	worker, clock := newCostWorker(t, world, &recordingParser{name: "unusable.parser", result: &unusable})
	worker.SetAnalyzer(worldAnalyzer{world: world})
	for pass := range 3 {
		attempted := insightsPass(t, worker, clock)
		loads := totalLoads(world.takeLoads())
		t.Logf("pass %d: attempted %d, body loads %d of %d skipped audits", pass+1, attempted, loads, audits)
		want := 0
		if pass == 0 {
			want = audits
		}
		if attempted != want || loads != want {
			t.Errorf("pass %d: attempted %d loads %d, want %d", pass+1, attempted, loads, want)
		}
	}
}

// A project identity save that fails every time used to re-read the
// weak-header body on every pass (projectBackfillOne kept no memory). A
// failure that cannot clear now ends the attempts after one load; a storage
// outage keeps being retried on a backoff of 10, 20, 40, 80 minutes and
// succeeds once it ends.
func TestProjectBackfillCostOfARepeatedFailure(t *testing.T) {
	t.Parallel()
	world := newCostWorld()
	for index, id := range []string{"identified", "doomed", "outage"} {
		world.add(t, id, "test.parser", StatusOK, int64(index+1), []byte(`{"model":"m"}`))
		world.analysed[id] = true
	}
	worker, clock := newCostWorker(t, world)
	project := &failingProjectAnalyzer{world: world, fail: map[string]bool{"doomed": true}, outage: map[string]bool{"outage": true}}
	worker.SetProjectAnalyzer(project)
	// Passes start every 10 minutes; the outage retries fall due at 10, 30
	// and 70 minutes.
	for pass, want := range []map[string]int{
		{"identified": 1, "doomed": 1, "outage": 1}, {"outage": 1}, {}, {"outage": 1}, {}, {}, {}, {"outage": 1},
	} {
		if pass == 7 {
			delete(project.outage, "outage")
		}
		attempted := projectPass(t, worker, clock)
		loads := world.takeLoads()
		t.Logf("pass %d: attempted %d, body loads %v", pass+1, attempted, loads)
		if len(loads) != len(want) || loads["doomed"] != want["doomed"] || loads["identified"] != want["identified"] || loads["outage"] != want["outage"] {
			t.Errorf("pass %d: body loads %v, want %v", pass+1, loads, want)
		}
	}
	if !world.identity["outage"] || world.identity["doomed"] {
		t.Fatalf("identities: outage %v doomed %v", world.identity["outage"], world.identity["doomed"])
	}
}

// failingProjectAnalyzer stores an identity unless the audit is named in
// fail; its headers are always weak, so the body is read.
type failingProjectAnalyzer struct {
	world  *costWorld
	fail   map[string]bool
	outage map[string]bool
}

func (analyzer *failingProjectAnalyzer) AnalyzeAudit(ctx context.Context, input insights.Input) error {
	return analyzer.Save(ctx, input, len(input.Request) != 0)
}

func (analyzer *failingProjectAnalyzer) Save(_ context.Context, input insights.Input, _ bool) error {
	if analyzer.fail[input.AuditID] {
		return errors.New("synthetic identity failure")
	}
	if analyzer.outage[input.AuditID] {
		return fmt.Errorf("synthetic identity save: %w", storage.ErrQueueFull)
	}
	analyzer.world.mu.Lock()
	analyzer.world.identity[input.AuditID] = true
	analyzer.world.mu.Unlock()
	return nil
}

func (*failingProjectAnalyzer) Strong(insights.Input) bool { return false }
