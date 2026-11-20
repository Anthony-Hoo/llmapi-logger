package web

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/uaguard"
)

// The fixture of the write facade tests. Every service is the real one
// (uaguard and contentpolicy over SQLite, orgreport with saved settings and
// snapshots in memory, the session analysis settings with saved rows in
// memory), so a test of "only this field changed" or "same result as the web
// route" exercises the services' own merging and validation.

// plantedModelKey is the API key the key tests send; it must appear nowhere
// but in the request to the model endpoint.
const plantedModelKey = "sk-planted-model-key-0099"

// writeClock is the injected clock of the agent service and orgreport.
type writeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *writeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *writeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

// fakeRunTrigger is the session analysis runner's trigger.
type fakeRunTrigger struct {
	mu        sync.Mutex
	running   bool
	triggered int
}

func (trigger *fakeRunTrigger) TriggerNow() error {
	trigger.mu.Lock()
	defer trigger.mu.Unlock()
	if trigger.running {
		return sessionanalysis.ErrRunInProgress
	}
	trigger.triggered++
	return nil
}

func (trigger *fakeRunTrigger) Running() bool {
	trigger.mu.Lock()
	defer trigger.mu.Unlock()
	return trigger.running
}

// suggestionMemory adds dismissable suggestions to the analysis store: 42
// and 43 are open all-keys suggestions.
type suggestionMemory struct {
	*memoryAnalysisStore
	mu        sync.Mutex
	open      map[int64]string
	dismissed []int64
}

func (memory *suggestionMemory) DismissSuggestion(_ context.Context, id int64, scope string, _ int64) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if memory.open[id] != scope {
		// Like the PostgreSQL store, a dismissed suggestion is still found
		// and dismissing it again succeeds.
		for _, dismissed := range memory.dismissed {
			if dismissed == id && scope == storage.ScopeAll {
				return nil
			}
		}
		return sql.ErrNoRows
	}
	delete(memory.open, id)
	memory.dismissed = append(memory.dismissed, id)
	return nil
}

func (memory *suggestionMemory) SuggestionExists(_ context.Context, id int64, scopes []string) (bool, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if scope, ok := memory.open[id]; ok {
		return contains(scopes, scope), nil
	}
	for _, dismissed := range memory.dismissed {
		if dismissed == id {
			return contains(scopes, storage.ScopeAll), nil
		}
	}
	return false, nil
}

// nopApplier takes settings changes without a runner.
type nopApplier struct{}

func (nopApplier) Apply(config.SessionAnalysisConfig, sessionanalysis.Completer) error { return nil }
func (nopApplier) Running() bool                                                       { return false }

// snapshotMemory is an in-memory orgreport.SnapshotStore.
// When hold is set, a save signals entered and waits for hold to be closed
// before it stores anything, so a test can keep the snapshot lock busy.
type snapshotMemory struct {
	mu        sync.Mutex
	snapshots map[string]orgreport.WeeklySnapshot
	saves     int
	hold      chan struct{}
	entered   chan struct{}
}

func (memory *snapshotMemory) SaveWeeklySnapshot(_ context.Context, snapshot orgreport.WeeklySnapshot) error {
	if memory.hold != nil {
		memory.entered <- struct{}{}
		<-memory.hold
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if memory.snapshots == nil {
		memory.snapshots = map[string]orgreport.WeeklySnapshot{}
	}
	memory.snapshots[snapshot.Week] = snapshot
	memory.saves++
	return nil
}

func (memory *snapshotMemory) LoadWeeklySnapshot(_ context.Context, week string) (orgreport.WeeklySnapshot, bool, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	snapshot, ok := memory.snapshots[week]
	return snapshot, ok, nil
}

func (memory *snapshotMemory) CountOrgPendingAudits(context.Context, int64, int64, int) (orgreport.PendingAudits, error) {
	return orgreport.PendingAudits{}, nil
}

// modelServer is the analysis model endpoint; it records the Authorization
// headers it receives.
type modelServer struct {
	*httptest.Server
	mu            sync.Mutex
	authorization []string
}

func newModelServer(t *testing.T) *modelServer {
	t.Helper()
	server := &modelServer{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.mu.Lock()
		server.authorization = append(server.authorization, request.Header.Get("Authorization"))
		server.mu.Unlock()
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"choices":[{"message":{"role":"assistant","content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func (server *modelServer) sawKey(key string) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, header := range server.authorization {
		if strings.Contains(header, key) {
			return true
		}
	}
	return false
}

type writeFixture struct {
	agentEnv
	clock       *writeClock
	sqlite      *sqlite.Store
	org         *orgreport.Service
	snapshots   *snapshotMemory
	analysis    *memoryAnalysisStore
	suggestions *suggestionMemory
	trigger     *fakeRunTrigger
	settings    *sessionanalysis.SettingsService
	settingRows *settingsRows
	model       *modelServer
	adminRead   string
	adminWrite  string
	developer   string
	adminWeb    *http.Cookie
}

// writeFixtureOptions adjust newWriteFixture.
type writeFixtureOptions struct {
	allowWrite bool
	// noModules leaves org reports and session analysis off.
	noModules bool
}

func newWriteFixture(t *testing.T) *writeFixture {
	t.Helper()
	return newWriteFixtureWith(t, writeFixtureOptions{allowWrite: true})
}

func newWriteFixtureWith(t *testing.T, options writeFixtureOptions) *writeFixture {
	t.Helper()
	ctx := context.Background()
	clock := &writeClock{now: orgTestWeek.Add(10 * 24 * time.Hour)}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rules, err := uaguard.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	policies, err := contentpolicy.New(ctx, store, logger)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5b}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	fixture := &writeFixture{clock: clock, sqlite: store, snapshots: &snapshotMemory{}, trigger: &fakeRunTrigger{}, settingRows: &settingsRows{}}
	handlerOptions := Options{AdminToken: testAdminToken, Developer: developerOptions(t, agentTestIdentity, nil), Query: &fakeQuery{healthy: true},
		Rules: rules, Policies: policies, Logger: logger, RetentionDays: 30}
	if !options.noModules {
		orgService, _ := newOrgWriteService(t, clock, fixture.snapshots)
		fixture.org = orgService
		handlerOptions.Org = orgService

		fixture.analysis = &memoryAnalysisStore{cipher: cipher, packs: map[string]storage.SessionPack{}, facets: map[string]storage.SessionFacet{}}
		fixture.analysis.addSession(t, analysisOwnID, testFingerprinter(t).Fingerprint(testDeveloperKey), 7, 42)
		fixture.suggestions = &suggestionMemory{memoryAnalysisStore: fixture.analysis, open: map[int64]string{42: storage.ScopeAll, 43: storage.ScopeAll}}
		query, err := sessionanalysis.NewQueryService(fixture.suggestions, fixture.trigger, cipher, "local-model")
		if err != nil {
			t.Fatal(err)
		}
		fixture.model = newModelServer(t)
		file := analysisFileSection(fixture.model.URL)
		fixture.settings, err = sessionanalysis.NewSettingsService(file, fixture.settingRows, cipher, nopApplier{}, query, logger)
		if err != nil {
			t.Fatal(err)
		}
		handlerOptions.SessionAnalysis = query
		handlerOptions.SessionAnalysisSettings = fixture.settings
	}

	agentStore := agentaccesstest.NewStore()
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: agentStore, AllowWrite: options.allowWrite,
		DeveloperLogins: true, Logger: logger, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	handlerOptions.AgentAccess = service
	handlerValue, err := NewHandler(handlerOptions)
	if err != nil {
		t.Fatal(err)
	}
	fixture.agentEnv = agentEnv{handler: handlerValue.(*managementHandler), service: service, store: agentStore, logs: logs}
	fixture.adminRead = issueAgentAdmin(t, fixture.agentEnv, agentapi.TierRead)
	writer := service
	if !options.allowWrite {
		writer, err = agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: agentStore, AllowWrite: true, DeveloperLogins: true,
			Logger: logger, Now: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.adminWrite = agentaccesstest.IssueAdmin(t, writer, agentapi.TierWrite).Token
	fixture.developer, _ = issueAgentDeveloper(t, fixture.agentEnv)
	fixture.adminWeb = adminSignIn(t, fixture.handler)
	return fixture
}

// analysisFileSection is the configuration file's session analysis section,
// pointing the model at url, with a file key.
func analysisFileSection(url string) config.SessionAnalysisConfig {
	return config.SessionAnalysisConfig{
		Enabled: true, RunAt: "02:00", SessionIdleMinutes: 120, L1SettleHours: 24, MinUserTurns: 2, MinActiveSeconds: 60,
		Pack: config.SessionAnalysisPack{MaxTokens: 6000},
		LLM: config.SessionAnalysisLLM{
			Enabled: true, BaseURL: url + "/v1", Model: "file-model", APIKey: "file-key-0001", StructuredOutput: "json_schema",
			ContextTokens: 16384, DisableThinking: true, MaxOutputTokens: 1500, MaxConcurrency: 1, TimeoutSeconds: 30, MaxSessionsRun: 300,
		},
	}
}

// newOrgWriteService is newOrgTestService with saved settings, snapshots, a
// client vocabulary and a clock past the test week.
func newOrgWriteService(t *testing.T, clock *writeClock, snapshots *snapshotMemory) (*orgreport.Service, *orgMemory) {
	t.Helper()
	_, memory := newOrgTestService(t)
	// The identities newOrgTestService sealed use this key.
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	file := config.OrgReportsConfig{Enabled: true, Timezone: "UTC", WeekStart: "monday", IdleGapSeconds: 180, RankedClients: []string{"codex"}}
	file.Anomaly.MaxConcurrentRoots, file.Anomaly.MaxSingleRequestRoots = 10, 200
	settings, err := orgreport.SettingsFromConfig(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	service, err := orgreport.NewService(context.Background(), orgreport.Options{
		Settings: settings, Repository: memory, Data: memory, Snapshots: snapshots, Cipher: cipher, Now: clock.Now,
		File: file, SavedSettings: &settingsRows{},
		Clients: []orgreport.ClientOption{{Key: "claude-code", Label: "Claude Code"}, {Key: "codex", Label: "Codex"}, {Key: "opencode", Label: "OpenCode"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, memory
}

// serviceWith is an agent service over the fixture's token store and clock
// with its own write switch, as after a restart with another allow_write.
func (fixture *writeFixture) serviceWith(t *testing.T, allowWrite bool) *agentaccess.Service {
	t.Helper()
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: fixture.store, AllowWrite: allowWrite,
		DeveloperLogins: true, Logger: slog.New(slog.NewTextHandler(fixture.logs, nil)), Now: fixture.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// facade calls a facade path with a token; body may be a value to encode.
func (fixture *writeFixture) facade(method, path string, body any, token string) *httptest.ResponseRecorder {
	encoded := ""
	switch typed := body.(type) {
	case nil:
	case string:
		encoded = typed
	default:
		data, _ := json.Marshal(typed)
		encoded = string(data)
	}
	return fixture.do(method, agentapi.PathPrefix+path, encoded, agentCaller{bearer: token},
		agentapi.HeaderCommand, "config.set", agentapi.HeaderCLIVersion, agentapi.LatestVersion)
}

// web calls a management route as the administrator.
func (fixture *writeFixture) web(method, path, body string) *httptest.ResponseRecorder {
	return fixture.do(method, path, body, agentCaller{cookie: fixture.adminWeb})
}

// planResponse is the decoded plan of a successful POST /plans.
type planResponse struct {
	PlanID      string          `json:"plan_id"`
	Op          string          `json:"op"`
	Target      agentPlanTarget `json:"target"`
	Creates     bool            `json:"creates"`
	ChangedKeys []string        `json:"changed_keys"`
	Before      json.RawMessage `json:"before"`
	After       json.RawMessage `json:"after"`
	Effects     []string        `json:"effects"`
	Extras      map[string]any  `json:"extras"`
}

// plan creates a plan and fails the test unless it succeeds.
func (fixture *writeFixture) plan(t *testing.T, body any) planResponse {
	t.Helper()
	response := fixture.facade(http.MethodPost, "/plans", body, fixture.adminWrite)
	if response.Code != http.StatusOK {
		t.Fatalf("plan %v = %d %s", body, response.Code, response.Body.String())
	}
	var plan planResponse
	if err := json.Unmarshal(decodeAgent(t, response).Data, &plan); err != nil || !strings.HasPrefix(plan.PlanID, "pln_") {
		t.Fatalf("plan body = %s", response.Body.String())
	}
	return plan
}

type applyResponse struct {
	Op      string          `json:"op"`
	Target  agentPlanTarget `json:"target"`
	Applied bool            `json:"applied"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result"`
}

// apply executes a plan and fails the test unless it succeeds.
func (fixture *writeFixture) apply(t *testing.T, planID string) applyResponse {
	t.Helper()
	response := fixture.facade(http.MethodPost, "/plans/"+planID+"/apply", nil, fixture.adminWrite)
	if response.Code != http.StatusOK {
		t.Fatalf("apply %s = %d %s", planID, response.Code, response.Body.String())
	}
	var applied applyResponse
	if err := json.Unmarshal(decodeAgent(t, response).Data, &applied); err != nil || !applied.Applied {
		t.Fatalf("apply body = %s", response.Body.String())
	}
	return applied
}

// planAndApply runs a plan through and returns the apply result.
func (fixture *writeFixture) planAndApply(t *testing.T, body any) applyResponse {
	t.Helper()
	return fixture.apply(t, fixture.plan(t, body).PlanID)
}

// show reads GET /config/{kind} as a generic value.
func (fixture *writeFixture) show(t *testing.T, kind string) map[string]any {
	t.Helper()
	response := fixture.facade(http.MethodGet, "/config/"+kind, nil, fixture.adminRead)
	if response.Code != http.StatusOK {
		t.Fatalf("show %s = %d %s", kind, response.Code, response.Body.String())
	}
	var data map[string]any
	if err := json.Unmarshal(decodeAgent(t, response).Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// failure returns the error body of a refused facade call.
func failure(t *testing.T, response *httptest.ResponseRecorder) agentapi.ErrorBody {
	t.Helper()
	decoded := decodeAgent(t, response)
	if decoded.OK || decoded.Error == nil {
		t.Fatalf("expected a failure, got %d %s", response.Code, response.Body.String())
	}
	if response.Code != agentapi.HTTPStatus(decoded.Error.Code) {
		t.Fatalf("%s answered with status %d", decoded.Error.Code, response.Code)
	}
	return *decoded.Error
}

// writeAudits returns the write_* audit rows written so far.
func (fixture *writeFixture) writeAudits() []storage.AgentAuditEntry {
	var rows []storage.AgentAuditEntry
	for _, entry := range fixture.store.Audit() {
		if strings.HasPrefix(entry.Event, "write_") {
			rows = append(rows, entry)
		}
	}
	return rows
}
