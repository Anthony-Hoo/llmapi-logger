package sessionanalysis

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// memoryStore is an in-memory Store and QueryStore for runner tests.
type memoryStore struct {
	mu       sync.Mutex
	sessions map[string][]storage.SessionAuditRow
	signals  map[string]storage.SessionSignals
	packs    map[string]storage.SessionPack
	members  map[string][][]byte
	runs     []storage.SessionAnalysisRun
	views    []storage.AnalysisView
}

func newMemoryStore() *memoryStore {
	return &memoryStore{sessions: map[string][]storage.SessionAuditRow{}, signals: map[string]storage.SessionSignals{},
		packs: map[string]storage.SessionPack{}, members: map[string][][]byte{}}
}

func (store *memoryStore) ListSessionCandidates(_ context.Context, _, _, _ int64, _ int) ([]storage.SessionCandidate, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionCandidate, 0)
	for key := range store.sessions {
		raw, _ := hex.DecodeString(key)
		if _, done := store.signals[key]; !done {
			out = append(out, storage.SessionCandidate{SessionKey: raw})
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].SessionKey, out[j].SessionKey) < 0 })
	return out, nil
}

func (store *memoryStore) LoadSessionAudits(_ context.Context, key []byte) ([]storage.SessionAuditRow, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.sessions[hex.EncodeToString(key)], false, nil
}

func (store *memoryStore) SaveSessionSignals(_ context.Context, signals storage.SessionSignals, _ []storage.SessionTextFPR) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.signals[hex.EncodeToString(signals.SessionKey)] = signals
	return nil
}

func (store *memoryStore) PruneSessionAnalysis(context.Context, int64) (int64, error) { return 0, nil }

func (store *memoryStore) RecordSessionAnalysisRun(_ context.Context, run storage.SessionAnalysisRun) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.runs = append(store.runs, run)
	return nil
}

func (store *memoryStore) SaveSessionPack(_ context.Context, pack storage.SessionPack, members [][]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.packs[hex.EncodeToString(pack.SessionKey)] = pack
	store.members[hex.EncodeToString(pack.SessionKey)] = members
	return nil
}

func (store *memoryStore) ListChatDigestMembers(_ context.Context, apiKey []byte, client string, fromNS, toNS int64, limit int) ([]storage.SessionSignals, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionSignals, 0)
	for _, signals := range store.signals {
		if signals.SkipReason == SkipSingleTurnChat && bytes.Equal(signals.APIKeyFPR, apiKey) && signals.Client == client &&
			signals.LastNS >= fromNS && signals.LastNS < toNS {
			out = append(out, signals)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastNS < out[j].LastNS })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) ListSessionSignals(context.Context, storage.SessionSignalFilter, storage.SessionSignalCursor, int) (storage.SessionSignalPage, error) {
	return storage.SessionSignalPage{}, nil
}

func (store *memoryStore) SessionSignalTotals(context.Context, storage.SessionSignalFilter) (storage.SessionSignalTotals, error) {
	return storage.SessionSignalTotals{}, nil
}

func (store *memoryStore) LatestSessionAnalysisRun(context.Context) (storage.SessionAnalysisRun, error) {
	return storage.SessionAnalysisRun{}, sql.ErrNoRows
}

func (store *memoryStore) LoadSessionPack(_ context.Context, key []byte) (storage.SessionPack, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if pack, ok := store.packs[hex.EncodeToString(key)]; ok {
		return pack, nil
	}
	for packKey, members := range store.members {
		for _, member := range members {
			if bytes.Equal(member, key) {
				return store.packs[packKey], nil
			}
		}
	}
	return storage.SessionPack{}, sql.ErrNoRows
}

func (store *memoryStore) RecordAnalysisView(_ context.Context, view storage.AnalysisView) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.views = append(store.views, view)
	return nil
}

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func chatRows(id string, key []byte, node []byte, at time.Time) []storage.SessionAuditRow {
	row := auditRow(id, at, node, "main", true)
	row.AgentClient = "unknown"
	row.APIKeyFPR = key
	return []storage.SessionAuditRow{row}
}

func TestRunnerBuildsEncryptedPacksAndDigests(t *testing.T) {
	store := newMemoryStore()
	keyA := bytes.Repeat([]byte{0x0a}, 32)
	views := map[string]*conversation.Conversation{}
	// One eligible agent session.
	agentRows := []storage.SessionAuditRow{
		auditRow("ag1", baseTime, nodeMain, "main", true),
		auditRow("ag2", baseTime.Add(5*time.Minute), nodeMain, "main", true),
	}
	store.sessions[hex.EncodeToString(sessionK)] = agentRows
	views["ag2"] = convo(user("把导出改成流式"), call("x", "exec_command", map[string]any{"cmd": "go test ./..."}), result("x", "Process exited with code 0"), user("再补一下文档"), answer("完成"))
	// Three single-turn chats of one key and day, one of another key.
	for index, question := range []string{"解释一下这段正则", "SQL 怎么按月分组 password=Sup3rS3cret", "推荐一本书"} {
		key := bytes.Repeat([]byte{byte(0x20 + index)}, 32)
		node := bytes.Repeat([]byte{byte(0x30 + index)}, 32)
		id := "chat" + string(rune('a'+index))
		store.sessions[hex.EncodeToString(key)] = chatRows(id, keyA, node, baseTime.Add(time.Duration(index)*time.Hour))
		views[id] = convo(user(question), answer("……"))
	}
	otherKey := bytes.Repeat([]byte{0x0b}, 32)
	store.sessions[hex.EncodeToString(bytes.Repeat([]byte{0x29}, 32))] = chatRows("chatz", otherKey, bytes.Repeat([]byte{0x39}, 32), baseTime)
	views["chatz"] = convo(user("别人的问题"), answer("……"))

	vocab, insightsVocab := testVocabularies(t)
	cipher := testCipher(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: cipher, Location: time.UTC,
		Now: func() time.Time { return baseTime.Add(24 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunOnce(context.Background(), TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if run.Candidates != 5 || run.Analyzed != 5 || !strings.Contains(run.SkipReasons, `"single_turn_chat":4`) {
		t.Fatalf("run = %+v", run)
	}
	if len(store.packs) != 3 {
		t.Fatalf("packs = %d (want agent + two digests)", len(store.packs))
	}
	agentPack := store.packs[hex.EncodeToString(sessionK)]
	if agentPack.Kind != storage.PackKindSession || bytes.Contains(agentPack.PackEnc, []byte("流式")) {
		t.Fatalf("agent pack not encrypted: %+v", agentPack.Kind)
	}
	service, err := NewQueryService(store, runner, cipher, false)
	if err != nil {
		t.Fatal(err)
	}
	// A member chat resolves to its digest; the digest holds the three
	// questions of key A in time order, redacted, and not key B's.
	memberID := hex.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	response, err := service.Pack(context.Background(), memberID, nil, Viewer{Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Kind != storage.PackKindChatDigest || response.Members != 3 {
		t.Fatalf("digest = %+v", response)
	}
	if !strings.Contains(response.Text, "[U1 14:02] 解释一下这段正则") || !strings.Contains(response.Text, "[REDACTED:password_assignment]") ||
		strings.Contains(response.Text, "Sup3rS3cret") || strings.Contains(response.Text, "别人的问题") {
		t.Fatalf("digest text:\n%s", response.Text)
	}
	if len(store.views) != 1 || store.views[0].Resource != "pack" || store.views[0].ViewerRole != "admin" {
		t.Fatalf("views = %+v", store.views)
	}
	// A developer of another key cannot read it.
	if _, err := service.Pack(context.Background(), memberID, scopeOf(otherKey), Viewer{Role: "developer"}); err == nil {
		t.Fatal("foreign developer read the digest")
	}
	if _, err := service.Pack(context.Background(), memberID, scopeOf(keyA), Viewer{Role: "developer"}); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	agentResponse, err := service.Pack(context.Background(), hex.EncodeToString(sessionK), scopeOf(bytes.Repeat([]byte{1}, 32)), Viewer{Role: "developer"})
	if err != nil || !strings.Contains(agentResponse.Text, "[U1] 把导出改成流式") || agentResponse.Refs["U2"] != "ag2" {
		t.Fatalf("agent pack: %v %+v", err, agentResponse)
	}
}

func scopeOf(key []byte) *query.Scope { return &query.Scope{Fingerprint: key} }
