package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/storage"
)

// fakeProjects books sessions by agent-tree root, like the organisation
// report service does from its catalog.
type fakeProjects struct {
	byRoot map[string]orgreport.SessionProject
	names  map[int64]string
	fail   bool
	calls  int
}

func (projects *fakeProjects) ResolveSession(_ context.Context, root, _ []byte) (orgreport.SessionProject, error) {
	projects.calls++
	if projects.fail {
		return orgreport.SessionProject{}, errors.New("catalog unavailable")
	}
	if project, ok := projects.byRoot[hex.EncodeToString(root)]; ok {
		return project, nil
	}
	return orgreport.SessionProject{Known: true, Project: orgreport.ProjectNoContext}, nil
}

func (projects *fakeProjects) ProjectName(id int64) string { return projects.names[id] }

func (store *memoryStore) ListSessionProjects(_ context.Context, sinceNS, computedBeforeNS int64, limit int) ([]storage.SessionProjectRef, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionProjectRef, 0)
	for _, signals := range store.signals {
		if signals.LastNS >= sinceNS && signals.ComputedAtNS < computedBeforeNS {
			out = append(out, storage.SessionProjectRef{
				SessionKey: signals.SessionKey, AgentRootFPR: signals.AgentRootFPR, APIKeyFPR: signals.APIKeyFPR,
				ProjectID: signals.ProjectID, Bucket: signals.Bucket,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].SessionKey, out[j].SessionKey) < 0 })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) UpdateSessionProjects(_ context.Context, refs []storage.SessionProjectRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, ref := range refs {
		key := hex.EncodeToString(ref.SessionKey)
		if signals, ok := store.signals[key]; ok && signals.Bucket != storage.BucketService {
			signals.ProjectID, signals.Bucket = ref.ProjectID, ref.Bucket
			store.signals[key] = signals
		}
	}
	return nil
}

func projectID(signals storage.SessionSignals) int64 {
	if signals.ProjectID == nil {
		return 0
	}
	return *signals.ProjectID
}

// A session is booked to its project when analysed, re-booked when the rules
// change, and keeps signals only while its caller is a service principal.
func TestRunnerBooksSessionsToProjects(t *testing.T) {
	store := newMemoryStore()
	ownKey := bytes.Repeat([]byte{1}, 32)
	store.sessions[hex.EncodeToString(sessionK)] = []storage.SessionAuditRow{
		auditRow("ag1", baseTime, nodeMain, "main", true),
		auditRow("ag2", baseTime.Add(5*time.Minute), nodeMain, "main", true),
	}
	chatRoot := bytes.Repeat([]byte{0x2a}, 32)
	store.sessions[hex.EncodeToString(chatRoot)] = chatRows("chat1", ownKey, bytes.Repeat([]byte{0x3a}, 32), baseTime.Add(time.Hour))
	views := map[string]*conversation.Conversation{
		"ag2":   convo(user("把导出接口改成流式输出"), answer("好"), user("再补一下接口文档"), answer("完成")),
		"chat1": convo(user("解释一下这段正则"), answer("……")),
	}
	projects := &fakeProjects{names: map[int64]string{10: "orders", 11: "billing"}, byRoot: map[string]orgreport.SessionProject{
		hex.EncodeToString(sessionK): {Known: true, Project: 10, Name: "orders", Level: orgreport.LevelRemote},
	}}
	now := baseTime.Add(24 * time.Hour)
	vocab, insightsVocab := testVocabularies(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: testCipher(t), Location: time.UTC, Projects: projects,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentID, chatID := analysisID(sessionK, ownKey), analysisID(chatRoot, ownKey)
	run := func() storage.SessionAnalysisRun {
		t.Helper()
		summary, err := runner.RunOnce(context.Background(), TriggerManual)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
		return summary
	}

	run()
	agent, chat := store.signals[agentID], store.signals[chatID]
	if projectID(agent) != 10 || agent.Bucket != storage.BucketAttributed || !agent.Eligible {
		t.Fatalf("agent booking = %d %q eligible=%v", projectID(agent), agent.Bucket, agent.Eligible)
	}
	if chat.ProjectID != nil || chat.Bucket != storage.BucketNoContext || len(chat.DigestBucket) == 0 {
		t.Fatalf("chat booking = %v %q digest=%d", chat.ProjectID, chat.Bucket, len(chat.DigestBucket))
	}
	firstPack, ok := store.packs[agentID]
	if !ok || len(store.textFPRs[agentID]) == 0 || len(store.packs) != 2 {
		t.Fatalf("packs = %d, own pack %v, fingerprints %d", len(store.packs), ok, len(store.textFPRs[agentID]))
	}

	// A rule change re-books the session without analysing it again.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Level: orgreport.LevelRoot}
	if summary := run(); summary.Candidates != 0 || summary.Analyzed != 0 {
		t.Fatalf("rebooking analysed sessions: %+v", summary)
	}
	if agent = store.signals[agentID]; projectID(agent) != 11 || agent.Bucket != storage.BucketAttributed || store.packs[agentID].BuiltAtNS != firstPack.BuiltAtNS {
		t.Fatalf("after rule change: %d %q", projectID(agent), agent.Bucket)
	}

	// No verdict (identity extraction still running) keeps the stored booking.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Project: orgreport.ProjectNoContext}
	run()
	if agent = store.signals[agentID]; projectID(agent) != 11 || agent.Bucket != storage.BucketAttributed {
		t.Fatalf("unknown booking overwrote: %d %q", projectID(agent), agent.Bucket)
	}

	// A resolver failure leaves everything as it was.
	projects.fail = true
	if summary := run(); summary.SkipReasons != `{"project_refresh_error":1}` {
		t.Fatalf("skip reasons = %s", summary.SkipReasons)
	}
	projects.fail = false

	// The caller becomes a service principal: both sessions are analysed again
	// and keep signals only.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Service: true}
	projects.byRoot[hex.EncodeToString(chatRoot)] = orgreport.SessionProject{Known: true, Project: orgreport.ProjectNoContext, Service: true}
	run()
	agent, chat = store.signals[agentID], store.signals[chatID]
	if agent.Bucket != storage.BucketService || agent.Eligible || agent.SkipReason != SkipService || projectID(agent) != 11 {
		t.Fatalf("service agent = %+v", agent)
	}
	if chat.Bucket != storage.BucketService || chat.SkipReason != SkipService || len(chat.DigestBucket) != 0 {
		t.Fatalf("service chat = %q %q digest=%d", chat.Bucket, chat.SkipReason, len(chat.DigestBucket))
	}
	if len(store.packs) != 0 || len(store.textFPRs[agentID]) != 0 {
		t.Fatalf("service sessions kept %d packs, %d fingerprints", len(store.packs), len(store.textFPRs[agentID]))
	}

	// Classified human again: the pack and the digest come back.
	projects.byRoot[hex.EncodeToString(sessionK)] = orgreport.SessionProject{Known: true, Project: 11, Name: "billing", Level: orgreport.LevelRoot}
	delete(projects.byRoot, hex.EncodeToString(chatRoot))
	run()
	agent, chat = store.signals[agentID], store.signals[chatID]
	if agent.Bucket != storage.BucketAttributed || !agent.Eligible || chat.Bucket != storage.BucketNoContext || len(store.packs) != 2 {
		t.Fatalf("after reclassification: %q eligible=%v, chat %q, packs %d", agent.Bucket, agent.Eligible, chat.Bucket, len(store.packs))
	}
}

// Without organisation reports nothing is booked and nothing changes.
func TestRunnerWithoutProjectsStoresNoBooking(t *testing.T) {
	store := newMemoryStore()
	seedAgentSession(store)
	runner := facetRunner(t, store, nil, baseTime.Add(48*time.Hour))
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	for _, signals := range store.signals {
		if signals.ProjectID != nil || signals.Bucket != "" {
			t.Fatalf("booking without org reports: %v %q", signals.ProjectID, signals.Bucket)
		}
	}
}
