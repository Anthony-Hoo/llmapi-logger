package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"
)

// The versioned entries the agent facade uses (doc/features/25-agent-access.md
// section 8.2), against the real store: what the service publishes must be
// what the database holds, a refused write must leave the database alone, and
// an admitted write must report its definitive outcome even when the caller
// cancels, like the web entries do.

func waitQueued(t *testing.T, writer *Store) {
	t.Helper()
	deadline := time.After(time.Second)
	for len(writer.queue) == 0 {
		select {
		case <-deadline:
			t.Fatal("write was not queued")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// heldCall runs write against a held writer, cancels the caller once the
// write is admitted, then releases the writer and returns the outcome.
func heldCall(t *testing.T, writer *Store, write func(context.Context) error) error {
	t.Helper()
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- write(requestCtx) }()
	waitQueued(t, writer)
	cancel()
	return releaseHeld(t, writer, done)
}

func TestAgentUserAgentRuleEntriesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	service, err := uaguard.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	before := service.List()[0]
	disabled := false
	patched, err := service.Patch(ctx, before.ID, before.Version(), uaguard.RulePatch{Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	want := before
	want.Enabled, want.UpdatedAtNS = false, patched.UpdatedAtNS
	persisted, err := store.ListUserAgentRules(ctx)
	if err != nil || !reflect.DeepEqual(patched, want) || !reflect.DeepEqual(persisted, service.List()) || !reflect.DeepEqual(persisted, []uaguard.Rule{want}) {
		t.Fatalf("patched %+v, persisted %+v (%v)", patched, persisted, err)
	}

	// A stale version and a check write nothing.
	if _, err := service.Patch(ctx, before.ID, before.Version(), uaguard.RulePatch{Enabled: &disabled}); !errors.Is(err, uaguard.ErrVersionConflict) {
		t.Fatalf("stale patch = %v", err)
	}
	if err := service.DeleteIfVersion(ctx, before.ID, before.Version()); !errors.Is(err, uaguard.ErrVersionConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	name := "checked"
	if _, err := service.CheckPatch(before.ID, patched.Version(), uaguard.RulePatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.ListUserAgentRules(ctx); !reflect.DeepEqual(again, persisted) {
		t.Fatalf("a refused write or a check changed the database: %+v", again)
	}

	// Admitted writes publish their definitive outcome despite cancellation.
	writer := heldWriter(store)
	held, err := uaguard.New(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := heldCall(t, writer, func(ctx context.Context) error {
		_, err := held.Patch(ctx, before.ID, patched.Version(), uaguard.RulePatch{Enabled: &enabled})
		return err
	}); err != nil {
		t.Fatalf("held patch = %v", err)
	}
	persisted, _ = store.ListUserAgentRules(ctx)
	if !reflect.DeepEqual(persisted, held.List()) || !persisted[0].Enabled {
		t.Fatalf("held patch: database %+v, published %+v", persisted, held.List())
	}

	writer = heldWriter(store)
	held, err = uaguard.New(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	newName, pattern := "new", "^m"
	if err := heldCall(t, writer, func(ctx context.Context) error {
		_, err := held.CreateFromPatch(ctx, uaguard.RulePatch{Name: &newName, Enabled: &enabled, ModelPattern: &pattern, UserAgentPattern: &pattern}, uaguard.CreateOptions{RejectDuplicateName: true})
		return err
	}); err != nil {
		t.Fatalf("held create = %v", err)
	}
	persisted, _ = store.ListUserAgentRules(ctx)
	if !reflect.DeepEqual(persisted, held.List()) || len(persisted) != 2 {
		t.Fatalf("held create: database %+v, published %+v", persisted, held.List())
	}
	var exists *uaguard.AlreadyExistsError
	fresh, _ := uaguard.New(ctx, store)
	if _, err := fresh.CreateFromPatch(ctx, uaguard.RulePatch{Name: &newName, Enabled: &enabled, ModelPattern: &pattern, UserAgentPattern: &pattern}, uaguard.CreateOptions{RejectDuplicateName: true}); !errors.As(err, &exists) || exists.ID != persisted[1].ID {
		t.Fatalf("duplicate = %v", err)
	}

	writer = heldWriter(store)
	held, err = uaguard.New(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	target := held.List()[1]
	if err := heldCall(t, writer, func(ctx context.Context) error {
		return held.DeleteIfVersion(ctx, target.ID, target.Version())
	}); err != nil {
		t.Fatalf("held delete = %v", err)
	}
	persisted, _ = store.ListUserAgentRules(ctx)
	if !reflect.DeepEqual(persisted, held.List()) || len(persisted) != 1 {
		t.Fatalf("held delete: database %+v, published %+v", persisted, held.List())
	}
}

func TestAgentContentPolicyEntriesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	service, err := contentpolicy.New(ctx, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	name, action, enabled := " secrets ", contentpolicy.ActionDryRun, true
	keywords := []string{"Password", "api key"}
	created, err := service.CreateFromPatch(ctx, contentpolicy.RulePatch{Name: &name, Enabled: &enabled, Action: &action, Keywords: &keywords}, contentpolicy.CreateOptions{RejectDuplicateName: true})
	if err != nil {
		t.Fatal(err)
	}
	change := contentpolicy.RuleChange{
		Add:    contentpolicy.RuleListEdit{Keywords: []string{"token", " PASSWORD"}},
		Remove: contentpolicy.RuleListEdit{Keywords: []string{"API KEY"}, ScanScopes: []string{contentpolicy.ScopeSystem}},
	}
	planned, err := service.CheckPatch(created.ID, created.Version(), change)
	if err != nil {
		t.Fatal(err)
	}
	if persisted, _ := store.ListContentPolicyRules(ctx); !reflect.DeepEqual(persisted, []contentpolicy.Rule{created}) {
		t.Fatalf("a check changed the database: %+v", persisted)
	}
	writer := heldWriter(store)
	held, err := contentpolicy.New(ctx, writer, nil)
	if err != nil {
		t.Fatal(err)
	}
	var patched contentpolicy.Rule
	if err := heldCall(t, writer, func(ctx context.Context) error {
		var err error
		patched, err = held.Patch(ctx, created.ID, created.Version(), change)
		return err
	}); err != nil {
		t.Fatalf("held patch = %v", err)
	}
	want := planned.After
	want.UpdatedAtNS = patched.UpdatedAtNS
	persisted, err := store.ListContentPolicyRules(ctx)
	if err != nil || !reflect.DeepEqual(patched, want) || !reflect.DeepEqual(persisted, held.List()) || !reflect.DeepEqual(persisted[0].Keywords, []string{"Password", "token"}) {
		t.Fatalf("patched %+v, planned %+v, persisted %+v (%v)", patched, planned.After, persisted, err)
	}
	if _, err := held.Patch(ctx, created.ID, created.Version(), change); !errors.Is(err, contentpolicy.ErrVersionConflict) {
		t.Fatalf("stale patch = %v", err)
	}
	if err := held.DeleteIfVersion(ctx, created.ID, created.Version()); !errors.Is(err, contentpolicy.ErrVersionConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	if again, _ := store.ListContentPolicyRules(ctx); !reflect.DeepEqual(again, persisted) {
		t.Fatalf("a refused write changed the database: %+v", again)
	}
	var exists *contentpolicy.AlreadyExistsError
	if _, err := held.CheckCreate(contentpolicy.RulePatch{Name: &name, Enabled: &enabled, Action: &action, Keywords: &keywords}, contentpolicy.CreateOptions{RejectDuplicateName: true}); !errors.As(err, &exists) || exists.ID != created.ID {
		t.Fatalf("duplicate = %v", err)
	}
	// The held writer is spent; later writes go through the live store.
	live, err := contentpolicy.New(ctx, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.DeleteIfVersion(ctx, created.ID, patched.Version()); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.ListContentPolicyRules(ctx); len(again) != 0 || len(live.List()) != 0 {
		t.Fatalf("after delete: %+v", again)
	}
}

func agentOrgService(t *testing.T, repository orgreport.Repository, saved orgreport.SettingsStore) *orgreport.Service {
	t.Helper()
	file := config.OrgReportsConfig{Enabled: true, Timezone: "UTC", WeekStart: "monday", IdleGapSeconds: 180, RankedClients: []string{"codex"}}
	file.Anomaly.MaxConcurrentRoots, file.Anomaly.MaxSingleRequestRoots = 10, 200
	settings, err := orgreport.SettingsFromConfig(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	service, err := orgreport.NewService(context.Background(), orgreport.Options{Settings: settings, Repository: repository, File: file, SavedSettings: saved})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestAgentOrgCatalogEntriesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	service := agentOrgService(t, store, store)
	name, enabled := "Platform", true
	group, err := service.CreateGroupFromPatch(ctx, orgreport.GroupPatch{Name: &name, Enabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	projectName, rules := " Demo ", []orgreport.Rule{{Kind: orgreport.RuleRepoName, Pattern: " demo "}}
	project, err := service.CreateProjectFromPatch(ctx, orgreport.ProjectPatch{Name: &projectName, GroupID: orgreport.GroupIDOf(&group.ID), Enabled: &enabled, Rules: &rules})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetMemberIfVersion(ctx, 7, group.ID, 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadOrgCatalog(ctx)
	if err != nil || !reflect.DeepEqual(loaded, service.Catalog().Catalog) || loaded.Projects[0].Name != "Demo" || loaded.Projects[0].Rules[0].Pattern != "demo" {
		t.Fatalf("database %+v, published %+v (%v)", loaded, service.Catalog().Catalog, err)
	}

	change := orgreport.ProjectChange{Add: orgreport.ProjectListEdit{Rules: []orgreport.Rule{{Kind: orgreport.RuleAgentProject, Pattern: "demo-agent"}}}}
	planned, err := service.CheckPatchProject(project.ID, project.Version(), change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckDeleteGroup(group.ID, group.Version()); !errors.Is(err, orgreport.ErrConflict) {
		t.Fatalf("check delete of a group with projects = %v", err)
	}
	if again, _ := store.LoadOrgCatalog(ctx); !reflect.DeepEqual(again, loaded) {
		t.Fatal("a check changed the database")
	}

	writer := heldWriter(store)
	held := agentOrgService(t, writer, writer)
	var patched orgreport.Project
	if err := heldCall(t, writer, func(ctx context.Context) error {
		var err error
		patched, err = held.PatchProject(ctx, project.ID, project.Version(), change)
		return err
	}); err != nil {
		t.Fatalf("held patch = %v", err)
	}
	want := planned.After
	want.UpdatedAtNS = patched.UpdatedAtNS
	loaded, _ = store.LoadOrgCatalog(ctx)
	if !reflect.DeepEqual(patched, want) || !reflect.DeepEqual(loaded, held.Catalog().Catalog) {
		t.Fatalf("patched %+v, planned %+v, database %+v", patched, planned.After, loaded)
	}
	if _, err := held.PatchProject(ctx, project.ID, project.Version(), change); !errors.Is(err, orgreport.ErrVersionConflict) {
		t.Fatalf("stale patch = %v", err)
	}
	if err := held.DeleteProjectIfVersion(ctx, project.ID, project.Version()); !errors.Is(err, orgreport.ErrVersionConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	if again, _ := store.LoadOrgCatalog(ctx); !reflect.DeepEqual(again, loaded) {
		t.Fatal("a refused write changed the database")
	}
	// The held writer is spent; later writes go through the live store.
	live := agentOrgService(t, store, store)
	if err := live.DeleteProjectIfVersion(ctx, project.ID, patched.Version()); err != nil {
		t.Fatal(err)
	}
	if err := live.DeleteMemberIfVersion(ctx, 7, loaded.Members[0].Version()); err != nil {
		t.Fatal(err)
	}
	if err := live.DeleteGroupIfVersion(ctx, group.ID, group.Version()); err != nil {
		t.Fatal(err)
	}
	if loaded, _ = store.LoadOrgCatalog(ctx); len(loaded.Groups)+len(loaded.Projects)+len(loaded.Members) != 0 {
		t.Fatalf("after deletes: %+v", loaded)
	}
}

func TestAgentOrgSettingsEntriesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	service := agentOrgService(t, store, store)
	gap := 60
	if _, err := service.CheckPatchSettings(ctx, 0, orgreport.SettingsChange{Set: orgreport.SettingsPatch{IdleGapSeconds: &gap}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadRuntimeSettings(ctx, storage.SettingsOrgReports); err == nil {
		t.Fatal("a check saved the section")
	}
	saved, err := service.PatchSettings(ctx, 0, orgreport.SettingsChange{Set: orgreport.SettingsPatch{IdleGapSeconds: &gap}})
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.LoadRuntimeSettings(ctx, storage.SettingsOrgReports)
	if err != nil || row.UpdatedAtNS != saved.Version() || !strings.Contains(row.Settings, `"idle_gap_seconds":60`) || !strings.Contains(row.Settings, `"max_concurrent_roots":10`) {
		t.Fatalf("row = %+v (%v)", row, err)
	}
	if _, err := service.PatchSettings(ctx, 0, orgreport.SettingsChange{Set: orgreport.SettingsPatch{IdleGapSeconds: &gap}}); !errors.Is(err, orgreport.ErrVersionConflict) {
		t.Fatalf("stale patch = %v", err)
	}
	if again, _ := store.LoadRuntimeSettings(ctx, storage.SettingsOrgReports); !reflect.DeepEqual(again, row) {
		t.Fatal("a refused write changed the row")
	}
	if _, err := service.ResetSettingsIfVersion(ctx, saved.Version()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadRuntimeSettings(ctx, storage.SettingsOrgReports); err == nil {
		t.Fatal("reset left the row")
	}
}

type agentApplier struct{ keys []string }

func (applier *agentApplier) Apply(configuration config.SessionAnalysisConfig, _ sessionanalysis.Completer) error {
	applier.keys = append(applier.keys, configuration.LLM.APIKey)
	return nil
}

func (*agentApplier) Running() bool { return false }

func TestAgentAnalysisSettingsEntriesAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x52}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	file := config.SessionAnalysisConfig{
		Enabled: true, RunAt: "02:00", SessionIdleMinutes: 120, L1SettleHours: 24, MinUserTurns: 2, MinActiveSeconds: 60,
		Pack: config.SessionAnalysisPack{MaxTokens: 6000},
		LLM: config.SessionAnalysisLLM{
			Enabled: true, BaseURL: "http://127.0.0.1:11434/v1", Model: "file-model", StructuredOutput: "json_schema",
			ContextTokens: 16384, DisableThinking: true, MaxOutputTokens: 1500, MaxConcurrency: 1, TimeoutSeconds: 120, MaxSessionsRun: 300,
		},
	}
	applier := &agentApplier{}
	service, err := sessionanalysis.NewSettingsService(file, store, cipher, applier, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "pg-agent-key-4242"
	keyed, err := service.SetAPIKey(ctx, key)
	if err != nil || keyed.APIKey != sessionanalysis.KeySaved {
		t.Fatalf("set key = %+v, %v", keyed, err)
	}
	concurrency := 2
	if _, err := service.CheckPatch(ctx, keyed.Version(), sessionanalysis.SettingsPatch{LLM: sessionanalysis.LLMPatch{MaxConcurrency: &concurrency}}); err != nil {
		t.Fatal(err)
	}
	row, err := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis)
	if err != nil || row.UpdatedAtNS != keyed.Version() {
		t.Fatalf("a check changed the row: %+v (%v)", row, err)
	}
	patched, err := service.Patch(ctx, keyed.Version(), sessionanalysis.SettingsPatch{LLM: sessionanalysis.LLMPatch{MaxConcurrency: &concurrency}})
	if err != nil || patched.APIKey != sessionanalysis.KeySaved || patched.Settings.LLM.MaxConcurrency != 2 || applier.keys[len(applier.keys)-1] != key {
		t.Fatalf("patched = %+v, %v", patched, err)
	}
	// The key survives the patch in the database, encrypted, and is read back.
	reloaded, err := sessionanalysis.NewSettingsService(file, store, cipher, &agentApplier{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := reloaded.Get(ctx)
	if err != nil || view.APIKey != sessionanalysis.KeySaved || view.Version() != patched.Version() || view.Settings.LLM.MaxConcurrency != 2 {
		t.Fatalf("reloaded = %+v, %v", view, err)
	}
	if effective := sessionanalysis.LoadEffectiveConfig(ctx, file, store, cipher, nil); effective.LLM.APIKey != key {
		t.Fatal("the key did not survive the patch")
	}
	row, _ = store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis)
	if strings.Contains(row.Settings, key) || bytes.Contains(row.SecretEnc, []byte(key)) {
		t.Fatal("the key is stored in clear")
	}
	if _, err := service.Patch(ctx, keyed.Version(), sessionanalysis.SettingsPatch{LLM: sessionanalysis.LLMPatch{MaxConcurrency: &concurrency}}); !errors.Is(err, sessionanalysis.ErrVersionConflict) {
		t.Fatalf("stale patch = %v", err)
	}
	if again, _ := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis); !reflect.DeepEqual(again, row) {
		t.Fatal("a refused write changed the row")
	}
}
