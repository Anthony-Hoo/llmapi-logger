package sessionanalysis

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
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
	facets   map[string]storage.SessionFacet
	facetFPR map[string][]storage.SessionTextFPR
	calib    []storage.FacetCalibration
	textFPRs map[string][]storage.SessionTextFPR
	suggest  map[string]storage.Suggestion
	stats    map[string]storage.PeriodStats
	// failSignals makes the next SaveSessionSignals calls fail.
	failSignals int
	// prunes records the (expiredBeforeNS, fingerprintCutoffNS) of each prune.
	prunes [][2]int64
}

func newMemoryStore() *memoryStore {
	return &memoryStore{sessions: map[string][]storage.SessionAuditRow{}, signals: map[string]storage.SessionSignals{},
		packs: map[string]storage.SessionPack{}, members: map[string][][]byte{}, facets: map[string]storage.SessionFacet{}, facetFPR: map[string][]storage.SessionTextFPR{},
		textFPRs: map[string][]storage.SessionTextFPR{}, suggest: map[string]storage.Suggestion{}, stats: map[string]storage.PeriodStats{}}
}

// ListSessionCandidates splits every root of store.sessions (keyed by root)
// by API key, like the PostgreSQL query; a pair is due until signals with the
// same pair exist and cover its newest request.
func (store *memoryStore) ListSessionCandidates(_ context.Context, _, _, _ int64, _ int) ([]storage.SessionCandidate, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionCandidate, 0)
	for rootHex, rows := range store.sessions {
		root, _ := hex.DecodeString(rootHex)
		latest := map[string]int64{}
		for _, row := range rows {
			if row.StartedAtNS > latest[string(row.APIKeyFPR)] || latest[string(row.APIKeyFPR)] == 0 {
				latest[string(row.APIKeyFPR)] = row.StartedAtNS
			}
		}
		for apiKey, last := range latest {
			done := false
			for _, signals := range store.signals {
				if bytes.Equal(signals.AgentRootFPR, root) && string(signals.APIKeyFPR) == apiKey && signals.LastNS >= last {
					done = true
				}
			}
			if !done {
				candidate := storage.SessionCandidate{AgentRootFPR: root, LastStartedNS: last}
				if apiKey != "" {
					candidate.APIKeyFPR = []byte(apiKey)
				}
				out = append(out, candidate)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if order := bytes.Compare(out[i].AgentRootFPR, out[j].AgentRootFPR); order != 0 {
			return order < 0
		}
		return bytes.Compare(out[i].APIKeyFPR, out[j].APIKeyFPR) < 0
	})
	return out, nil
}

func (store *memoryStore) LoadSessionAudits(_ context.Context, root, apiKey []byte) ([]storage.SessionAuditRow, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionAuditRow, 0)
	for _, row := range store.sessions[hex.EncodeToString(root)] {
		if bytes.Equal(row.APIKeyFPR, apiKey) {
			out = append(out, row)
		}
	}
	return out, false, nil
}

// analysisID is the API session id of one root and key.
func analysisID(root, apiKey []byte) string {
	return hex.EncodeToString(SessionKey(testFingerprinter{}, root, apiKey))
}

func (store *memoryStore) SaveSessionSignals(_ context.Context, signals storage.SessionSignals, fprs []storage.SessionTextFPR, pack *storage.SessionPack) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failSignals > 0 {
		store.failSignals--
		return errors.New("write failed")
	}
	key := hex.EncodeToString(signals.SessionKey)
	if previous, ok := store.signals[key]; ok && len(previous.DigestBucket) != 0 && !bytes.Equal(previous.DigestBucket, signals.DigestBucket) {
		store.dropDigestsOfLocked(signals.SessionKey)
	}
	signals.DigestPending = len(signals.DigestBucket) != 0
	store.signals[key] = signals
	store.textFPRs[key] = fprs
	if pack != nil {
		store.packs[key] = *pack
		store.members[key] = nil
	} else if existing, ok := store.packs[key]; ok && existing.Kind == storage.PackKindSession {
		delete(store.packs, key)
		delete(store.members, key)
	}
	return nil
}

func (store *memoryStore) PruneSessionAnalysis(_ context.Context, expiredBeforeNS, fingerprintCutoffNS int64) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.prunes = append(store.prunes, [2]int64{expiredBeforeNS, fingerprintCutoffNS})
	return 0, nil
}

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

// dropDigestsOfLocked drops the digests holding member, with their facets,
// and marks their other members pending, like dropChatDigestsOf.
func (store *memoryStore) dropDigestsOfLocked(member []byte) {
	for packKey, members := range store.members {
		holds := false
		for _, candidate := range members {
			holds = holds || bytes.Equal(candidate, member)
		}
		if !holds || store.packs[packKey].Kind != storage.PackKindChatDigest {
			continue
		}
		for _, other := range members {
			if signals, ok := store.signals[hex.EncodeToString(other)]; ok && len(signals.DigestBucket) != 0 {
				signals.DigestPending = true
				store.signals[hex.EncodeToString(other)] = signals
			}
		}
		delete(store.packs, packKey)
		delete(store.members, packKey)
		delete(store.facets, packKey)
		delete(store.facetFPR, packKey)
	}
}

func (store *memoryStore) ListPendingDigestMembers(_ context.Context, limit int) ([]storage.SessionSignals, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionSignals, 0)
	for _, signals := range store.signals {
		if signals.DigestPending {
			out = append(out, signals)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastNS < out[j].LastNS })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) SaveChatDigests(_ context.Context, bucket storage.ChatDigestBucket, chunks []storage.ChatDigestChunk, staleKeys [][]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, chunk := range chunks {
		key := hex.EncodeToString(chunk.Pack.SessionKey)
		store.packs[key] = chunk.Pack
		store.members[key] = chunk.Members
	}
	for _, stale := range staleKeys {
		key := hex.EncodeToString(stale)
		if store.packs[key].Kind == storage.PackKindChatDigest {
			delete(store.packs, key)
			delete(store.members, key)
			delete(store.facets, key)
			delete(store.facetFPR, key)
		}
	}
	for key, signals := range store.signals {
		client := signals.Client
		if client == "" {
			client = "unknown"
		}
		if signals.DigestPending && bytes.Equal(signals.APIKeyFPR, bucket.APIKeyFPR) && client == bucket.Client &&
			signals.LastNS >= bucket.FromNS && signals.LastNS < bucket.ToNS {
			signals.DigestPending = false
			store.signals[key] = signals
		}
	}
	return nil
}

func (store *memoryStore) ListSessionSignals(context.Context, storage.SessionSignalFilter, storage.SessionSignalCursor, int) (storage.SessionSignalPage, error) {
	return storage.SessionSignalPage{}, nil
}

func (store *memoryStore) SessionSignalTotals(_ context.Context, filter storage.SessionSignalFilter) (storage.SessionSignalTotals, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.SessionSignalTotalsLocked(filter), nil
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

func (store *memoryStore) ListFacetCandidates(_ context.Context, settledBeforeNS int64, promptVersion, model string, limit int) ([]storage.SessionPack, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionPack, 0)
	for key, pack := range store.packs {
		facet, ok := store.facets[key]
		if pack.LastNS >= settledBeforeNS {
			continue
		}
		if ok && facet.PackHash == pack.PackHash && facet.PromptVersion == promptVersion && facet.Model == model &&
			(facet.Status != "failed" || facet.Attempts > storage.FacetRetryLimit) {
			continue
		}
		out = append(out, pack)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastNS > out[j].LastNS })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) SaveSessionFacet(_ context.Context, facet storage.SessionFacet, fprs []storage.SessionTextFPR) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	facet.Attempts = 1
	if old, ok := store.facets[hex.EncodeToString(facet.SessionKey)]; ok && old.Status == "failed" &&
		old.PackHash == facet.PackHash && old.PromptVersion == facet.PromptVersion && old.Model == facet.Model {
		facet.Attempts = old.Attempts + 1
	}
	store.facets[hex.EncodeToString(facet.SessionKey)] = facet
	store.facetFPR[hex.EncodeToString(facet.SessionKey)] = fprs
	return nil
}

func (store *memoryStore) LoadSessionFacet(_ context.Context, key []byte) (storage.SessionFacet, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if facet, ok := store.facets[hex.EncodeToString(key)]; ok {
		return facet, nil
	}
	return storage.SessionFacet{}, sql.ErrNoRows
}

func (store *memoryStore) SaveFacetCalibration(_ context.Context, calibration storage.FacetCalibration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calib = append(store.calib, calibration)
	return nil
}

func (store *memoryStore) LatestFacetCalibration(context.Context, string, string) (storage.FacetCalibration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.calib) == 0 {
		return storage.FacetCalibration{}, sql.ErrNoRows
	}
	return store.calib[len(store.calib)-1], nil
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
	agentPack := store.packs[analysisID(sessionK, bytes.Repeat([]byte{1}, 32))]
	if agentPack.Kind != storage.PackKindSession || bytes.Contains(agentPack.PackEnc, []byte("流式")) {
		t.Fatalf("agent pack not encrypted: %+v", agentPack.Kind)
	}
	service, err := NewQueryService(store, runner, cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	// A member chat resolves to its digest; the digest holds the three
	// questions of key A in time order, redacted, and not key B's.
	memberID := analysisID(bytes.Repeat([]byte{0x21}, 32), keyA)
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
	agentResponse, err := service.Pack(context.Background(), analysisID(sessionK, bytes.Repeat([]byte{1}, 32)), scopeOf(bytes.Repeat([]byte{1}, 32)), Viewer{Role: "developer"})
	if err != nil || !strings.Contains(agentResponse.Text, "[U1] 把导出改成流式") || agentResponse.Refs["U2"] != "ag2" {
		t.Fatalf("agent pack: %v %+v", err, agentResponse)
	}
}

// Two API keys reusing one client session id are two analysis sessions: each
// pack holds only its own key's requests, and neither key can read the other.
func TestRunnerSplitsOneRootByAPIKey(t *testing.T) {
	store := newMemoryStore()
	keyA, keyB := bytes.Repeat([]byte{0x0a}, 32), bytes.Repeat([]byte{0x0b}, 32)
	rows := make([]storage.SessionAuditRow, 0, 4)
	for index, spec := range []struct {
		id  string
		key []byte
	}{{"sa1", keyA}, {"sb1", keyB}, {"sa2", keyA}, {"sb2", keyB}} {
		row := auditRow(spec.id, baseTime.Add(time.Duration(index)*time.Minute), nodeMain, "main", true)
		row.APIKeyFPR = spec.key
		rows = append(rows, row)
	}
	store.sessions[hex.EncodeToString(sessionK)] = rows
	views := map[string]*conversation.Conversation{
		"sa2": convo(user("A 的第一个问题需要分析"), answer("好"), user("A 的第二个问题继续追问"), answer("完成")),
		"sb2": convo(user("B 的第一个问题需要分析"), answer("好"), user("B 的第二个问题继续追问"), answer("完成")),
	}
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
	if err != nil || run.Candidates != 2 || run.Analyzed != 2 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	idA, idB := analysisID(sessionK, keyA), analysisID(sessionK, keyB)
	if idA == idB || len(store.signals) != 2 {
		t.Fatalf("one root and two keys gave %d sessions", len(store.signals))
	}
	for id, want := range map[string]struct {
		key        []byte
		own, other string
		lastAudit  string
	}{idA: {keyA, "A 的第二个问题", "B 的", "sa2"}, idB: {keyB, "B 的第二个问题", "A 的", "sb2"}} {
		signals := store.signals[id]
		if !bytes.Equal(signals.APIKeyFPR, want.key) || !bytes.Equal(signals.AgentRootFPR, sessionK) || signals.Requests != 2 || signals.LastAuditID != want.lastAudit {
			t.Fatalf("signals of %s = %+v", want.lastAudit, signals)
		}
		service, err := NewQueryService(store, runner, cipher, "")
		if err != nil {
			t.Fatal(err)
		}
		pack, err := service.Pack(context.Background(), id, scopeOf(want.key), Viewer{Role: "developer"})
		if err != nil || !strings.Contains(pack.Text, want.own) || strings.Contains(pack.Text, want.other) {
			t.Fatalf("pack of %s: %v\n%s", want.lastAudit, err, pack.Text)
		}
		foreign := keyA
		if bytes.Equal(want.key, keyA) {
			foreign = keyB
		}
		if _, err := service.Pack(context.Background(), id, scopeOf(foreign), Viewer{Role: "developer"}); err == nil {
			t.Fatalf("the other key read the pack of %s", want.lastAudit)
		}
		// The insights tree link still points at the shared root.
		if item := mapSession(signals); item.TreeID != hex.EncodeToString(sessionK[:12]) {
			t.Fatalf("tree id = %q", item.TreeID)
		}
	}
}

// A failed write stores neither signals nor pack, so the session stays due
// and the next run stores both.
func TestRunnerKeepsSessionDueUntilSignalsAndPackAreStored(t *testing.T) {
	store := newMemoryStore()
	store.sessions[hex.EncodeToString(sessionK)] = []storage.SessionAuditRow{
		auditRow("ag1", baseTime, nodeMain, "main", true),
		auditRow("ag2", baseTime.Add(5*time.Minute), nodeMain, "main", true),
	}
	vocab, insightsVocab := testVocabularies(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
		Store:  store, Loader: &fakeLoader{views: map[string]*conversation.Conversation{"ag2": convo(user("把导出改成流式"), answer("好"), user("再补一下文档"), answer("完成"))}},
		Vocabulary: vocab, Insights: insightsVocab, Fingerprints: testFingerprinter{}, Cipher: testCipher(t), Location: time.UTC,
		Now: func() time.Time { return baseTime.Add(24 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	store.failSignals = 1
	run, err := runner.RunOnce(context.Background(), TriggerManual)
	if err != nil || run.Skipped != 1 || len(store.signals) != 0 || len(store.packs) != 0 {
		t.Fatalf("failed write left state: run=%+v signals=%d packs=%d err=%v", run, len(store.signals), len(store.packs), err)
	}
	run, err = runner.RunOnce(context.Background(), TriggerManual)
	id := analysisID(sessionK, bytes.Repeat([]byte{1}, 32))
	if err != nil || run.Candidates != 1 || run.Analyzed != 1 || store.packs[id].Kind != storage.PackKindSession || !store.signals[id].Eligible {
		t.Fatalf("retry: run=%+v err=%v", run, err)
	}
}

// A single-turn chat that gains a turn leaves its day's digest: the digest is
// rebuilt from the remaining members (its stale facet goes with it), and a
// digest left without members is removed.
func TestRunnerRebuildsDigestsWhenChatsLeave(t *testing.T) {
	store := newMemoryStore()
	keyA := bytes.Repeat([]byte{0x0a}, 32)
	rootX, rootY := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32)
	nodeX, nodeY := bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32)
	store.sessions[hex.EncodeToString(rootX)] = chatRows("cx1", keyA, nodeX, baseTime)
	store.sessions[hex.EncodeToString(rootY)] = chatRows("cy1", keyA, nodeY, baseTime.Add(time.Hour))
	views := map[string]*conversation.Conversation{
		"cx1": convo(user("第一个问题关于正则表达式"), answer("……")),
		"cy1": convo(user("第二个问题关于数据库索引"), answer("……")),
	}
	now := baseTime.Add(24 * time.Hour)
	vocab, insightsVocab := testVocabularies(t)
	runner, err := NewRunner(Options{
		Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
		Store:  store, Loader: &fakeLoader{views: views}, Vocabulary: vocab, Insights: insightsVocab,
		Fingerprints: testFingerprinter{}, Cipher: testCipher(t), Location: time.UTC,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewQueryService(store, runner, runner.options.Cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	digests := func() []storage.SessionPack {
		out := make([]storage.SessionPack, 0)
		for _, pack := range store.packs {
			if pack.Kind == storage.PackKindChatDigest {
				out = append(out, pack)
			}
		}
		return out
	}
	gainTurn := func(root, node []byte, id, first, second string, at time.Time) {
		row := auditRow(id, at, node, "main", true)
		row.AgentClient, row.APIKeyFPR = "unknown", keyA
		store.sessions[hex.EncodeToString(root)] = append(store.sessions[hex.EncodeToString(root)], row)
		views[id] = convo(user(first), answer("……"), user(second), answer("完成"))
	}
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	before := digests()
	if len(before) != 1 || before[0].Members != 2 {
		t.Fatalf("digests after run 1 = %+v", before)
	}
	digestKey := hex.EncodeToString(before[0].SessionKey)
	store.facets[digestKey] = storage.SessionFacet{SessionKey: before[0].SessionKey, Kind: storage.PackKindChatDigest, Status: "ok", TaskType: "stale", LastNS: before[0].LastNS}

	// Chat X gains a second turn: it is no longer a single-turn chat.
	gainTurn(rootX, nodeX, "cx2", "第一个问题关于正则表达式", "再追问一下贪婪匹配", baseTime.Add(10*time.Minute))
	now = now.Add(24 * time.Hour)
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	after := digests()
	if len(after) != 1 || after[0].Members != 1 || len(store.members[digestKey]) != 1 {
		t.Fatalf("digests after chat X left = %+v", after)
	}
	if facet, ok := store.facets[digestKey]; ok && facet.TaskType == "stale" {
		t.Fatal("the digest kept the facet that classified chat X")
	}
	text, err := service.Pack(context.Background(), analysisID(rootY, keyA), nil, Viewer{Role: "admin"})
	if err != nil || strings.Contains(text.Text, "正则表达式") || !strings.Contains(text.Text, "数据库索引") {
		t.Fatalf("rebuilt digest: %v\n%s", err, text.Text)
	}
	own, err := service.Pack(context.Background(), analysisID(rootX, keyA), nil, Viewer{Role: "admin"})
	if err != nil || own.Kind != storage.PackKindSession || !strings.Contains(own.Text, "贪婪匹配") {
		t.Fatalf("chat X pack: %v %+v", err, own)
	}
	for _, signals := range store.signals {
		if signals.DigestPending {
			t.Fatalf("member still pending after the rebuild: %+v", signals.LastAuditID)
		}
	}

	// Chat Y leaves too: the day has no single-turn chat left.
	gainTurn(rootY, nodeY, "cy2", "第二个问题关于数据库索引", "联合索引的顺序呢", baseTime.Add(70*time.Minute))
	now = now.Add(24 * time.Hour)
	if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
		t.Fatal(err)
	}
	if left := digests(); len(left) != 0 {
		t.Fatalf("empty digest kept: %+v", left)
	}
}

func scopeOf(key []byte) *query.Scope { return &query.Scope{Fingerprint: key} }

// The prune only looks behind the retention cutoff: audits are deleted by
// start time, so younger sessions cannot have lost theirs. Without retention
// it looks at none.
func TestRunnerPrunesBehindTheRetentionCutoff(t *testing.T) {
	now := baseTime.Add(48 * time.Hour)
	for _, test := range []struct {
		days int
		want int64
	}{{30, now.Add(-30 * 24 * time.Hour).UnixNano()}, {0, 0}} {
		store := newMemoryStore()
		vocab, insightsVocab := testVocabularies(t)
		runner, err := NewRunner(Options{
			Config: config.SessionAnalysisConfig{RunAt: "02:00", SessionIdleMinutes: 120, MinUserTurns: 2, MinActiveSeconds: 1, Pack: config.SessionAnalysisPack{MaxTokens: 6000}},
			Store:  store, Loader: &fakeLoader{}, Vocabulary: vocab, Insights: insightsVocab, RetentionDays: test.days,
			Fingerprints: testFingerprinter{}, Cipher: testCipher(t), Location: time.UTC,
			Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.RunOnce(context.Background(), TriggerManual); err != nil {
			t.Fatal(err)
		}
		if len(store.prunes) != 1 || store.prunes[0][0] != test.want || store.prunes[0][1] != now.Add(-fingerprintKeep).UnixNano() {
			t.Fatalf("retention %d days: prunes = %v, want cutoff %d", test.days, store.prunes, test.want)
		}
	}
}

// --- report surface of the in-memory store ---

func (store *memoryStore) ActiveAnalysisKeys(_ context.Context, fromNS, toNS int64) ([]storage.ScopeKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	seen := map[string]storage.ScopeKey{}
	for _, signals := range store.signals {
		if signals.LastNS >= fromNS && signals.LastNS < toNS && len(signals.APIKeyFPR) != 0 && signals.Bucket != storage.BucketService {
			seen[string(signals.APIKeyFPR)] = storage.ScopeKey{APIKeyFPR: signals.APIKeyFPR, NewAPITokenID: signals.NewAPITokenID}
		}
	}
	out := make([]storage.ScopeKey, 0, len(seen))
	for _, key := range seen {
		out = append(out, key)
	}
	return out, nil
}

func (store *memoryStore) inScope(signals storage.SessionSignals, filter storage.SessionSignalFilter) bool {
	if signals.LastNS < filter.FromNS || (filter.ToNS != 0 && signals.LastNS >= filter.ToNS) {
		return false
	}
	if filter.Scope != nil && !bytes.Equal(signals.APIKeyFPR, filter.Scope.Fingerprint) {
		return false
	}
	if filter.ExcludeService && signals.Bucket == storage.BucketService {
		return false
	}
	if filter.ProjectID != nil && (signals.ProjectID == nil || *signals.ProjectID != *filter.ProjectID) {
		return false
	}
	if filter.UserIDs != nil {
		member := false
		for _, user := range filter.UserIDs {
			member = member || (signals.NewAPIUserID != nil && *signals.NewAPIUserID == user)
		}
		if !member {
			return false
		}
	}
	for _, flag := range filter.Flags {
		if flag == "loop" && signals.Loops == 0 || flag == "thrash" && signals.ThrashFiles == 0 || flag == "unverified" && signals.Verified != "no" {
			return false
		}
	}
	return true
}

func (store *memoryStore) SessionSignalTotalsLocked(filter storage.SessionSignalFilter) storage.SessionSignalTotals {
	var totals storage.SessionSignalTotals
	callers := map[string]bool{}
	for _, signals := range store.signals {
		if !store.inScope(signals, filter) {
			continue
		}
		if signals.NewAPIUserID != nil {
			callers["u"+strconv.FormatInt(*signals.NewAPIUserID, 10)] = true
		} else {
			callers["k"+string(signals.APIKeyFPR)] = true
		}
		totals.Sessions++
		if signals.Kind == "agent" {
			totals.AgentSessions++
		} else {
			totals.ChatSessions++
		}
		if signals.Eligible {
			totals.Eligible++
		}
		if signals.Loops > 0 {
			totals.LoopSessions++
		}
		if signals.Verified == "no" {
			totals.Unverified++
		}
		if signals.Verified != "no_writes" {
			totals.WithWrites++
		}
	}
	totals.Contributors = int64(len(callers))
	return totals
}

func (store *memoryStore) ActiveAnalysisProjects(_ context.Context, fromNS, toNS int64) ([]int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	seen := map[int64]bool{}
	for _, signals := range store.signals {
		if signals.LastNS >= fromNS && signals.LastNS < toNS && signals.ProjectID != nil && signals.Bucket != storage.BucketService {
			seen[*signals.ProjectID] = true
		}
	}
	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (store *memoryStore) ListPeriodScopeKeys(_ context.Context, weekStartNS int64, scope string) ([][]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([][]byte, 0)
	for _, stats := range store.stats {
		if stats.WeekStartNS == weekStartNS && stats.Scope == scope {
			out = append(out, stats.ScopeKey)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out, nil
}

// facetInScope applies a FacetScope like the PostgreSQL join: project and
// user scopes read session facets through their signals row.
func (store *memoryStore) facetInScope(key string, facet storage.SessionFacet, scope storage.FacetScope) bool {
	if scope.APIKeyFPR != nil && !bytes.Equal(facet.APIKeyFPR, scope.APIKeyFPR) {
		return false
	}
	if scope.ProjectID == nil && scope.UserIDs == nil {
		return true
	}
	signals, ok := store.signals[key]
	return ok && store.inScope(signals, storage.SessionSignalFilter{ExcludeService: true, ProjectID: scope.ProjectID, UserIDs: scope.UserIDs})
}

func (store *memoryStore) FacetEnums(_ context.Context, fromNS, toNS int64, scope storage.FacetScope) ([]storage.FacetEnumRow, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.FacetEnumRow, 0)
	for key, facet := range store.facets {
		if facet.Status == "ok" && facet.LastNS >= fromNS && facet.LastNS < toNS && store.facetInScope(key, facet, scope) {
			out = append(out, storage.FacetEnumRow{Kind: facet.Kind, TaskType: facet.TaskType, Outcome: facet.Outcome, Collaboration: facet.Collaboration, Friction: facet.Friction, Items: facet.Items})
		}
	}
	return out, nil
}

func (store *memoryStore) RepeatedFingerprints(_ context.Context, sinceNS int64, scope storage.FacetScope, limit int) ([]storage.RepeatedFPR, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	apiKey := scope.APIKeyFPR
	groups := map[string]*storage.RepeatedFPR{}
	rules := map[string]int64{}
	add := func(session string, fpr storage.SessionTextFPR) {
		if fpr.SeenAtNS < sinceNS || (apiKey != nil && !bytes.Equal(fpr.APIKeyFPR, apiKey)) {
			return
		}
		// Fingerprints carry their session's current project.
		if booked := store.signals[session].ProjectID; scope.ProjectID != nil && (booked == nil || *booked != *scope.ProjectID) {
			return
		}
		if fpr.Source == storage.TextSourceInjectedRules {
			if seen, ok := rules[string(fpr.FPR)]; !ok || fpr.SeenAtNS > seen {
				rules[string(fpr.FPR)] = fpr.SeenAtNS
			}
			return
		}
		kind := "instruction"
		if fpr.Source == storage.TextSourceFacetSkill {
			kind = "skill"
		}
		id := kind + string(fpr.FPR)
		group, ok := groups[id]
		if !ok {
			group = &storage.RepeatedFPR{FPR: fpr.FPR, Kind: kind, FirstNS: fpr.SeenAtNS, LastNS: fpr.SeenAtNS}
			groups[id] = group
		}
		raw, _ := hex.DecodeString(session)
		for _, existing := range group.SessionKeys {
			if bytes.Equal(existing, raw) {
				return
			}
		}
		group.SessionKeys = append(group.SessionKeys, raw)
		group.Sessions++
		if fpr.SeenAtNS < group.FirstNS {
			group.FirstNS = fpr.SeenAtNS
		}
		if fpr.SeenAtNS > group.LastNS {
			group.LastNS = fpr.SeenAtNS
		}
	}
	for session, fprs := range store.textFPRs {
		for _, fpr := range fprs {
			add(session, fpr)
		}
	}
	for session, fprs := range store.facetFPR {
		for _, fpr := range fprs {
			add(session, fpr)
		}
	}
	out := make([]storage.RepeatedFPR, 0)
	for _, group := range groups {
		if group.Sessions < 2 {
			continue
		}
		if seen, ok := rules[string(group.FPR)]; ok && seen >= group.FirstNS {
			group.Adopted = true
		}
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sessions > out[j].Sessions })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) UpsertSuggestion(_ context.Context, suggestion storage.Suggestion) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	id := suggestion.Scope + string(suggestion.ScopeKey) + suggestion.Kind + string(suggestion.FPR)
	if existing, ok := store.suggest[id]; ok {
		suggestion.ID = existing.ID
		if existing.Status == "dismissed" {
			suggestion.Status = "dismissed"
		}
	} else {
		suggestion.ID = int64(len(store.suggest) + 1)
	}
	store.suggest[id] = suggestion
	return nil
}

func (store *memoryStore) ListSuggestions(_ context.Context, scope string, scopeKey []byte, _ *int64, limit int) ([]storage.Suggestion, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.Suggestion, 0)
	for _, suggestion := range store.suggest {
		if suggestion.Scope == scope && bytes.Equal(suggestion.ScopeKey, scopeKey) {
			out = append(out, suggestion)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Support > out[j].Support || out[i].Support == out[j].Support && out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (store *memoryStore) DismissSuggestion(_ context.Context, id int64, scope string, _ int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, suggestion := range store.suggest {
		if suggestion.ID == id && suggestion.Scope == scope {
			suggestion.Status = "dismissed"
			store.suggest[key] = suggestion
			return nil
		}
	}
	return sql.ErrNoRows
}

func (store *memoryStore) SavePeriodStats(_ context.Context, stats storage.PeriodStats) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.stats[strconv.FormatInt(stats.WeekStartNS, 10)+stats.Scope+string(stats.ScopeKey)] = stats
	return nil
}

func (store *memoryStore) LoadPeriodStats(_ context.Context, weekStartNS int64, scope string, scopeKey []byte, _ *int64) (storage.PeriodStats, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if stats, ok := store.stats[strconv.FormatInt(weekStartNS, 10)+scope+string(scopeKey)]; ok {
		return stats, nil
	}
	return storage.PeriodStats{}, sql.ErrNoRows
}

func (store *memoryStore) TopCostSessions(_ context.Context, filter storage.SessionSignalFilter, limit int) ([]storage.SessionSignals, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]storage.SessionSignals, 0)
	for _, signals := range store.signals {
		if store.inScope(signals, filter) && signals.CostUSD != nil {
			out = append(out, signals)
		}
	}
	sort.Slice(out, func(i, j int) bool { return *out[i].CostUSD > *out[j].CostUSD })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
