package parser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// recordingProject is a project analyzer that extracts the identity with the
// default vocabulary and records it per audit, live and in the backfill.
type recordingProject struct {
	extractor *insights.ProjectExtractor
	mu        sync.Mutex
	seen      map[string][]orgreport.Identity
	scanned   map[string][]bool
}

func (project *recordingProject) AnalyzeAudit(ctx context.Context, input insights.Input) error {
	return project.Save(ctx, input, len(input.Request) != 0)
}

func (project *recordingProject) Save(_ context.Context, input insights.Input, bodyScanned bool) error {
	identity := project.extractor.Extract(input)
	project.mu.Lock()
	defer project.mu.Unlock()
	project.seen[input.AuditID] = append(project.seen[input.AuditID], identity)
	project.scanned[input.AuditID] = append(project.scanned[input.AuditID], bodyScanned)
	return nil
}

func (*recordingProject) Strong(insights.Input) bool { return false }

// projectListingStore adds the project identity listing to the SQLite store:
// every candidate once, newest first, as the PostgreSQL listing orders them.
type projectListingStore struct {
	*sqlite.Store
	candidates []storage.ProjectBackfillCandidate
}

func (store *projectListingStore) ListProjectIdentityBackfillCandidates(_ context.Context, _ int, after, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error) {
	sorted := append([]storage.ProjectBackfillCandidate(nil), store.candidates...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].StartedAtNS != sorted[j].StartedAtNS {
			return sorted[i].StartedAtNS > sorted[j].StartedAtNS
		}
		return sorted[i].AuditID > sorted[j].AuditID
	})
	var result []storage.ProjectBackfillCandidate
	for _, candidate := range sorted {
		if before != nil && (candidate.StartedAtNS > before.StartedAtNS || candidate.StartedAtNS == before.StartedAtNS && candidate.AuditID >= before.AuditID) {
			continue
		}
		if after != nil && (candidate.StartedAtNS < after.StartedAtNS || candidate.StartedAtNS == after.StartedAtNS && candidate.AuditID <= after.AuditID) {
			continue
		}
		if len(result) < limit {
			result = append(result, candidate)
		}
	}
	return result, nil
}

// analysisView is what an analysis row says about an audit, without the
// fields that record when and by which version it was computed.
func analysisView(t *testing.T, row sqlite.AnalysisRow) string {
	t.Helper()
	row.AnalysisVersion, row.AnalyzedAtNS = 0, 0
	row.DetailEnc, row.DetailRoot, row.DetailObjects = nil, nil, nil
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestReleasedGeminiAuditsAnalyseLikeRaw sends a Gemini answer as JSON and
// as SSE through the proxy, the store and the worker. Both are verified and
// their raw bodies are released. The insights backfill and the project
// identity backfill then analyse them from the bodies rebuilt from the turn
// graph and reach the same result the live analysis reached from the raw
// bodies.
func TestReleasedGeminiAuditsAnalyseLikeRaw(t *testing.T) {
	t.Parallel()
	harness := newInsightsHarness(t, runnerAnalyzer(t))
	extractor, err := insights.NewProjectExtractor(insights.DefaultVocabulary())
	if err != nil {
		t.Fatal(err)
	}
	project := &recordingProject{extractor: extractor, seen: map[string][]orgreport.Identity{}, scanned: map[string][]bool{}}
	harness.worker.SetProjectAnalyzer(project)
	ctx := context.Background()
	h := headers("User-Agent", "example-agent/1.0", "X-Goog-Api-Key", "sk-geminikey")
	request := `{"systemInstruction":{"parts":[{"text":"You are an agent."}]},"contents":[` +
		`{"role":"user","parts":[{"text":"<environment_context>\n  <cwd>/work/sample-repo</cwd>\n</environment_context>"},{"text":"read the file"}]},` +
		`{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"main.go"}}}]},` +
		`{"role":"user","parts":[{"functionResponse":{"name":"read_file","response":{"output":"package main"}}}]}],` +
		`"tools":[{"functionDeclarations":[{"name":"read_file","description":"Read a file.","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}]}],` +
		`"generationConfig":{"maxOutputTokens":256}}`
	usage := `"usageMetadata":{"promptTokenCount":40,"cachedContentTokenCount":30,"candidatesTokenCount":6,"thoughtsTokenCount":2,"totalTokenCount":48},"modelVersion":"model-example","responseId":"gem-e2e"`
	jsonID := harness.send("/v1beta/models/model-example:generateContent", h, request, upstreamResponse{contentType: "application/json",
		body: `{"candidates":[{"content":{"role":"model","parts":[{"text":"weighing it","thought":true},{"text":"It is a main package."},` +
			`{"functionCall":{"name":"read_file","args":{"path":"util.go"}}}]},"finishReason":"STOP","index":0}],` + usage + `}`})
	streamID := harness.send("/v1beta/models/model-example:streamGenerateContent", h, request, upstreamResponse{contentType: "text/event-stream",
		body: "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"weighing it\",\"thought\":true}]},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":40,\"totalTokenCount\":40},\"modelVersion\":\"model-example\",\"responseId\":\"gem-e2e\"}\r\n\r\n" +
			"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"It is a \"}]},\"index\":0}],\"modelVersion\":\"model-example\",\"responseId\":\"gem-e2e\"}\r\n\r\n" +
			"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"main package.\"},{\"functionCall\":{\"name\":\"read_file\",\"args\":{\"path\":\"util.go\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]," + usage + "}\r\n\r\n"})

	ids := map[string]string{"json": jsonID, "stream": streamID}
	live := map[string]string{}
	for name, id := range ids {
		for _, side := range []string{sqlite.StageRequestReceived, sqlite.StageResponseReceived} {
			stage, err := harness.store.LoadParserStage(ctx, id, side)
			if err != nil || stage.Body == nil || stage.Body.RetentionState != sqlite.RetentionMetadata {
				t.Fatalf("%s %s must be released: %+v %v", name, side, stage.Body, err)
			}
		}
		row := harness.analysis(id)
		if row.StopReason == nil || *row.StopReason != insights.StopToolUse || row.CacheRead == nil || *row.CacheRead != 30 || row.RespToolCalls != 1 || row.EstUser == 0 {
			t.Fatalf("%s live analysis = stop %v cache %v tool calls %d est_user %d", name, row.StopReason, row.CacheRead, row.RespToolCalls, row.EstUser)
		}
		live[name] = analysisView(t, row)
		// Make the row outdated so the backfill recomputes it.
		row.AnalysisVersion = insights.AnalysisVersion - 1
		if err := harness.store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	harness.enableInsights(true)
	if got := harness.worker.BackfillForTest(ctx); got != 2 {
		t.Fatalf("backfill attempted %d audits, want 2", got)
	}
	for name, id := range ids {
		row := harness.analysis(id)
		if row.AnalysisVersion != insights.AnalysisVersion {
			t.Fatalf("%s was not recomputed", name)
		}
		if got := analysisView(t, row); got != live[name] {
			t.Errorf("%s analysis differs\nfrom raw:     %s\nfrom rebuilt: %s", name, live[name], got)
		}
	}

	// The live path already gave these audits an identity attempt in this
	// worker; a restarted worker's first pass covers nothing and lists them.
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	// The SQLite store has no identity listing (only PostgreSQL runs the
	// organisation reports); this one lists the two audits, so the worker's
	// own backfill pass loads their evidence.
	listing := &projectListingStore{Store: harness.store}
	for _, id := range []string{jsonID, streamID} {
		listing.candidates = append(listing.candidates, storage.ProjectBackfillCandidate{AuditID: id, StartedAtNS: harness.analysis(id).StartedAtNS, Protocol: "gemini"})
	}
	restarted, err := parser.NewWorker(listing, cipher, builtin.All(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	service, err := query.New(harness.store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetReconstructor(service)
	restarted.SetProjectAnalyzer(project)
	if got := restarted.ProjectBackfillForTest(ctx); got != 2 {
		t.Fatalf("project backfill attempted %d audits, want 2", got)
	}
	project.mu.Lock()
	defer project.mu.Unlock()
	for name, id := range ids {
		seen, scanned := project.seen[id], project.scanned[id]
		if len(seen) < 2 || !scanned[0] || !scanned[len(scanned)-1] {
			t.Fatalf("%s project identity calls = %d, body scanned %v", name, len(seen), scanned)
		}
		first, _ := json.Marshal(seen[0])
		last, _ := json.Marshal(seen[len(seen)-1])
		if string(first) != string(last) || seen[0].Cwd != "/work/sample-repo" {
			t.Errorf("%s project identity from raw %s, from rebuilt %s", name, first, last)
		}
	}
}
