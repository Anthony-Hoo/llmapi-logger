package parser

import (
	"context"
	"errors"
	"sync"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

type projectCall struct {
	input       insights.Input
	bodyScanned bool
}

type fakeProjectAnalyzer struct {
	mu    sync.Mutex
	calls []projectCall
	fail  error
}

func (analyzer *fakeProjectAnalyzer) AnalyzeAudit(ctx context.Context, input insights.Input) error {
	return analyzer.Save(ctx, input, len(input.Request) != 0)
}

func (analyzer *fakeProjectAnalyzer) Save(_ context.Context, input insights.Input, bodyScanned bool) error {
	analyzer.mu.Lock()
	defer analyzer.mu.Unlock()
	analyzer.calls = append(analyzer.calls, projectCall{input: input, bodyScanned: bodyScanned})
	return analyzer.fail
}

func (*fakeProjectAnalyzer) Strong(input insights.Input) bool {
	return input.Headers.Get("X-Codex-Turn-Metadata") != ""
}

type failingInsights struct{}

func (failingInsights) AnalyzeAudit(context.Context, insights.Input) error {
	return errors.New("analysis exploded")
}

type projectBackfillStore struct {
	*fakeStore
	candidates []storage.ProjectBackfillCandidate
	listed     int
	stageLoads int
}

func (store *projectBackfillStore) ListProjectIdentityBackfillCandidates(_ context.Context, version int, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error) {
	store.listed++
	if version != insights.ProjectIdentityVersion || limit != projectBackfillBatch {
		return nil, errors.New("unexpected request")
	}
	out := []storage.ProjectBackfillCandidate{}
	for _, candidate := range store.candidates {
		if before != nil && (candidate.StartedAtNS > before.StartedAtNS || candidate.StartedAtNS == before.StartedAtNS && candidate.AuditID >= before.AuditID) {
			continue
		}
		out = append(out, candidate)
	}
	return out, nil
}

func (store *projectBackfillStore) LoadParserStage(ctx context.Context, auditID, stage string) (sqlite.ParserStage, error) {
	store.mu.Lock()
	store.stageLoads++
	store.mu.Unlock()
	return store.fakeStore.LoadParserStage(ctx, auditID, stage)
}

func TestProjectHookRunsOnTheLivePathEvenWhenAnalysisFails(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-project-live"
	store := newFakeStore(auditID, "test.parser")
	stage, chunks := encryptedStage(t, cipher, auditID, sqlite.StageRequestReceived, "application/json", "", []byte(`{"model":"m"}`))
	key := stageKey(auditID, sqlite.StageRequestReceived)
	store.stages[key], store.chunks[key] = stage, chunks
	store.headers = []sqlite.HeaderEvidence{encryptedRequestHeader(t, cipher, auditID, "X-Agent-Project", 0, "demo")}
	worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "test.parser"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	project := &fakeProjectAnalyzer{}
	worker.SetAnalyzer(failingInsights{})
	worker.SetProjectAnalyzer(project)
	worker.SetHeaderAllowlist([]string{"x-agent-project"})
	worker.process(context.Background(), auditID)
	<-store.saved
	if len(project.calls) != 1 {
		t.Fatalf("project calls = %d", len(project.calls))
	}
	call := project.calls[0]
	if !call.bodyScanned || string(call.input.Request) != `{"model":"m"}` || call.input.Headers.Get("X-Agent-Project") != "demo" || call.input.Endpoint != "parser" {
		t.Fatalf("call = %+v", call)
	}
}

func TestProjectHookIsAbsentByDefault(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-project-off"
	store := &projectBackfillStore{fakeStore: newFakeStore(auditID, "test.parser"), candidates: []storage.ProjectBackfillCandidate{{AuditID: auditID, StartedAtNS: 5}}}
	worker, err := NewWorker(store, cipher, []Parser{&recordingParser{name: "test.parser"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	if got := worker.projectBackfill(context.Background()); got != 0 || store.listed != 0 {
		t.Fatalf("disabled project backfill attempted %d, listed %d", got, store.listed)
	}
}

func TestProjectBackfillReadsTheBodyOnlyWhenHeadersAreWeak(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	base := newFakeStore("strong", "openai.responses")
	store := &projectBackfillStore{fakeStore: base}
	for _, id := range []string{"weak", "released"} {
		base.audits[id] = sqlite.ParserAudit{AuditID: id, Protocol: "anthropic", ParserName: "anthropic.messages", ParseStatus: sqlite.ParseOK}
	}
	strong := base.audits["strong"]
	strong.ParseStatus = sqlite.ParseOK
	base.audits["strong"] = strong
	store.candidates = []storage.ProjectBackfillCandidate{
		{AuditID: "strong", StartedAtNS: 30}, {AuditID: "weak", StartedAtNS: 20}, {AuditID: "released", StartedAtNS: 10},
	}
	for _, id := range []string{"strong", "weak", "released"} {
		stage, chunks := encryptedStage(t, cipher, id, sqlite.StageRequestReceived, "application/json", "", []byte(`{"id":"`+id+`"}`))
		if id == "released" {
			stage.Body.RetentionState = sqlite.RetentionMetadata
			chunks = nil
		}
		key := stageKey(id, sqlite.StageRequestReceived)
		base.stages[key], base.chunks[key] = stage, chunks
	}
	base.headers = []sqlite.HeaderEvidence{encryptedRequestHeader(t, cipher, "strong", "X-Codex-Turn-Metadata", 0, `{"workspaces":{}}`)}
	worker, err := NewWorker(store, cipher, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	project := &fakeProjectAnalyzer{}
	worker.SetProjectAnalyzer(project)
	worker.SetHeaderAllowlist([]string{"x-codex-turn-metadata"})

	if got := worker.projectBackfill(context.Background()); got != 3 {
		t.Fatalf("attempted %d, want 3", got)
	}
	byID := map[string]projectCall{}
	for _, call := range project.calls {
		byID[call.input.AuditID] = call
	}
	if call := byID["strong"]; call.bodyScanned || call.input.Request != nil || call.input.Endpoint != "responses" {
		t.Fatalf("strong headers must skip the body: %+v", call)
	}
	// Header decryption is bound to each audit id: the "strong" header does
	// not decrypt for the other audits, which therefore have weak headers.
	if call := byID["weak"]; !call.bodyScanned || string(call.input.Request) != `{"id":"weak"}` {
		t.Fatalf("weak headers must read the retained body: %+v", call)
	}
	if call := byID["released"]; call.bodyScanned || call.input.Request != nil {
		t.Fatalf("released anthropic body must be skipped: %+v", call)
	}
	if worker.projectCursor == nil || worker.projectCursor.AuditID != "released" {
		t.Fatalf("cursor = %+v", worker.projectCursor)
	}
	// The next pass finds nothing below the cursor and pauses.
	if got := worker.projectBackfill(context.Background()); got != 0 || worker.projectCursor != nil || worker.projectNextScan.IsZero() {
		t.Fatalf("second pass attempted %d cursor %+v", got, worker.projectCursor)
	}
	listed := store.listed
	if got := worker.projectBackfill(context.Background()); got != 0 || store.listed != listed {
		t.Fatal("paused backfill listed again")
	}
}

func TestProjectBackfillYieldsToLiveWork(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	store := &projectBackfillStore{fakeStore: newFakeStore("a", "test.parser"), candidates: []storage.ProjectBackfillCandidate{{AuditID: "a", StartedAtNS: 1}}}
	worker, err := NewWorker(store, cipher, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	worker.SetProjectAnalyzer(&fakeProjectAnalyzer{})
	worker.queue <- "live"
	if got := worker.projectBackfill(context.Background()); got != 0 || store.listed != 0 {
		t.Fatalf("backfill ran with live work queued: %d", got)
	}
}
