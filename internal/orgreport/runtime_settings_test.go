package orgreport

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/storage"
)

// settingsMemory is an in-memory SettingsStore.
type settingsMemory struct {
	mu   sync.Mutex
	rows map[string]storage.RuntimeSettings
	fail error
}

func (store *settingsMemory) LoadRuntimeSettings(_ context.Context, section string) (storage.RuntimeSettings, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fail != nil {
		return storage.RuntimeSettings{}, store.fail
	}
	row, ok := store.rows[section]
	if !ok {
		return storage.RuntimeSettings{}, sql.ErrNoRows
	}
	return row, nil
}

func (store *settingsMemory) SaveRuntimeSettings(_ context.Context, row storage.RuntimeSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.rows == nil {
		store.rows = map[string]storage.RuntimeSettings{}
	}
	store.rows[row.Section] = row
	return nil
}

func (store *settingsMemory) DeleteRuntimeSettings(_ context.Context, section string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.rows, section)
	return nil
}

// fileOrgSection matches testSettings.
func fileOrgSection() config.OrgReportsConfig {
	section := config.OrgReportsConfig{Enabled: true, Timezone: "UTC", WeekStart: "monday", IdleGapSeconds: 180, RankedClients: []string{"codex", "claude_code"}}
	section.Anomaly.MaxConcurrentRoots, section.Anomaly.MaxSingleRequestRoots = 10, 200
	return section
}

// activeOf returns the ranked active time of one user in the fixture week.
func activeOf(t *testing.T, service *Service, user int64) (time.Duration, bool) {
	t.Helper()
	report, err := service.Weekly(context.Background(), WeeklyQuery{Week: "2026-11-02"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range report.Users {
		if row.UserID == user {
			return time.Duration(row.ActiveNS), report.Frozen
		}
	}
	t.Fatalf("user %d not in the report", user)
	return 0, false
}

func TestOrgSettingsSaveOverridesTheFileAtOnce(t *testing.T) {
	ctx := context.Background()
	fixture := newReportFixture(t)
	store := &settingsMemory{}
	fixture.service.file, fixture.service.saved = fileOrgSection(), store

	initial, err := fixture.service.EditableSettings(ctx)
	if err != nil || initial.Source != SettingsSourceFile || initial.Settings.IdleGapSeconds != 180 || initial.Timezone != "UTC" || initial.WeekStart != "monday" ||
		strings.Join(initial.Settings.RankedClients, ",") != "claude_code,codex" {
		t.Fatalf("initial = %+v, %v", initial, err)
	}
	// User 1 sends three one-minute requests two minutes apart: one block of
	// five minutes with the three-minute idle gap.
	if active, _ := activeOf(t, fixture.service, 1); active != 5*time.Minute {
		t.Fatalf("active with the file's gap = %s", active)
	}

	edited := initial.Settings
	edited.IdleGapSeconds, edited.MaxConcurrentRoots = 30, 3
	edited.RankedClients = []string{" codex ", "", "opencode"}
	saved, err := fixture.service.UpdateSettings(ctx, edited)
	if err != nil || saved.Source != SettingsSourceSaved || saved.Settings.IdleGapSeconds != 30 || saved.File.IdleGapSeconds != 180 ||
		strings.Join(saved.Settings.RankedClients, ",") != "codex,opencode" || saved.UpdatedNS == 0 {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if row := store.rows[storage.SettingsOrgReports]; !strings.Contains(row.Settings, `"idle_gap_seconds":30`) || len(row.SecretEnc) != 0 {
		t.Fatalf("stored row = %+v", row)
	}
	// The live week was cached a moment ago; the change still shows at once:
	// with a 30-second gap the three requests are three separate minutes.
	if active, frozen := activeOf(t, fixture.service, 1); active != 3*time.Minute || frozen {
		t.Fatalf("active with the saved gap = %s frozen=%v", active, frozen)
	}
	public := fixture.service.Settings()
	if public.IdleGapSeconds != 30 || public.MaxConcurrentRoots != 3 || public.Timezone != "UTC" || strings.Join(public.RankedClients, ",") != "codex,opencode" {
		t.Fatalf("public settings = %+v", public)
	}

	// A frozen week keeps its snapshot until it is regenerated.
	if err := fixture.service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatal(err)
	}
	reset, err := fixture.service.ResetSettings(ctx)
	if err != nil || reset.Source != SettingsSourceFile || reset.Settings.IdleGapSeconds != 180 || len(store.rows) != 0 {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
	if active, frozen := activeOf(t, fixture.service, 1); active != 3*time.Minute || !frozen {
		t.Fatalf("frozen week after reset = %s frozen=%v", active, frozen)
	}
	if err := fixture.service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatal(err)
	}
	if active, _ := activeOf(t, fixture.service, 1); active != 5*time.Minute {
		t.Fatalf("regenerated week = %s", active)
	}
}

func TestOrgSettingsRejectWhatTheFileWouldReject(t *testing.T) {
	ctx := context.Background()
	fixture := newReportFixture(t)
	store := &settingsMemory{}
	fixture.service.file, fixture.service.saved = fileOrgSection(), store
	base := editableOf(fileOrgSection())
	cases := map[string]func(*EditableSettings){
		"idle_gap_seconds":         func(edited *EditableSettings) { edited.IdleGapSeconds = 0 },
		"idle_gap_seconds ":        func(edited *EditableSettings) { edited.IdleGapSeconds = 7200 },
		"ranked_clients":           func(edited *EditableSettings) { edited.RankedClients = nil },
		"ranked_clients entry":     func(edited *EditableSettings) { edited.RankedClients = []string{"Codex"} },
		"twice":                    func(edited *EditableSettings) { edited.RankedClients = []string{"codex", "codex"} },
		"max_concurrent_roots":     func(edited *EditableSettings) { edited.MaxConcurrentRoots = 0 },
		"max_single_request_roots": func(edited *EditableSettings) { edited.MaxSingleRequestRoots = -1 },
	}
	for field, change := range cases {
		edited := base
		edited.RankedClients = append([]string{}, base.RankedClients...)
		change(&edited)
		_, err := fixture.service.UpdateSettings(ctx, edited)
		if !errors.Is(err, ErrInvalidSettings) || !strings.Contains(SettingsMessage(err), strings.TrimSpace(field)) {
			t.Errorf("%s: %v (%q)", field, err, SettingsMessage(err))
		}
	}
	if len(store.rows) != 0 || fixture.service.Settings().IdleGapSeconds != 180 {
		t.Fatalf("a rejected change was saved or applied: %d rows, gap %d", len(store.rows), fixture.service.Settings().IdleGapSeconds)
	}
	if SettingsMessage(errors.New("other")) != "" {
		t.Fatal("a foreign error has a settings message")
	}
	// Without a store nothing can be saved.
	bare := newReportFixture(t)
	if _, err := bare.service.UpdateSettings(ctx, base); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("update without a store: %v", err)
	}
	if _, err := bare.service.ResetSettings(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reset without a store: %v", err)
	}
}

// The page can only rank clients a request can be attributed to: a key the
// vocabulary does not know never matches anything.
func TestOrgSettingsOnlySaveVocabularyClients(t *testing.T) {
	ctx := context.Background()
	store := &settingsMemory{}
	// The file lists a key the vocabulary does not have; that is allowed there.
	file := fileOrgSection()
	file.RankedClients = []string{"codex", "homegrown"}
	settings, err := SettingsFromConfig(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	clients := []ClientOption{{Key: "claude_code", Label: "Claude Code"}, {Key: "codex", Label: "Codex"}, {Key: "opencode"}}
	service, err := NewService(ctx, Options{Settings: settings, File: file, SavedSettings: store, Clients: clients})
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.EditableSettings(ctx)
	if err != nil || len(view.Clients) != 3 || view.Clients[0] != (ClientOption{Key: "claude_code", Label: "Claude Code"}) || view.Clients[2].Label != "" ||
		strings.Join(view.Settings.RankedClients, ",") != "codex,homegrown" {
		t.Fatalf("view = %+v, %v", view, err)
	}
	// Saving the file's own list back is refused because of the unknown key.
	_, err = service.UpdateSettings(ctx, view.Settings)
	if !errors.Is(err, ErrInvalidSettings) || !strings.Contains(SettingsMessage(err), `"homegrown" is not a client of the vocabulary`) || len(store.rows) != 0 {
		t.Fatalf("unknown client saved: %v", err)
	}
	edited := view.Settings
	edited.RankedClients = []string{"opencode", "codex"}
	saved, err := service.UpdateSettings(ctx, edited)
	if err != nil || strings.Join(saved.Settings.RankedClients, ",") != "codex,opencode" || len(saved.Clients) != 3 {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	// Without a known vocabulary nothing can be checked, as before.
	open, err := NewService(ctx, Options{Settings: settings, File: file, SavedSettings: &settingsMemory{}})
	if err != nil {
		t.Fatal(err)
	}
	if view, err := open.UpdateSettings(ctx, editableOf(file)); err != nil || len(view.Clients) != 0 || view.Clients == nil {
		t.Fatalf("unchecked save = %+v, %v", view, err)
	}
}

func TestOrgSettingsAreReadBackAtStartup(t *testing.T) {
	ctx := context.Background()
	store := &settingsMemory{rows: map[string]storage.RuntimeSettings{
		storage.SettingsOrgReports: {Section: storage.SettingsOrgReports, UpdatedAtNS: 5,
			Settings: `{"idle_gap_seconds":45,"ranked_clients":["codex"],"max_concurrent_roots":4,"max_single_request_roots":50}`},
	}}
	start := func() *Service {
		t.Helper()
		service, err := NewService(ctx, Options{Settings: testSettings(), File: fileOrgSection(), SavedSettings: store})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	service := start()
	if public := service.Settings(); public.IdleGapSeconds != 45 || public.MaxConcurrentRoots != 4 || len(public.RankedClients) != 1 {
		t.Fatalf("settings after a restart = %+v", public)
	}
	if view, err := service.EditableSettings(ctx); err != nil || view.Source != SettingsSourceSaved || view.UpdatedNS != 5 {
		t.Fatalf("view after a restart = %+v, %v", view, err)
	}
	// A saved section that no longer validates, cannot be parsed or cannot be
	// read is ignored: the service starts on the file.
	for name, row := range map[string]string{
		"invalid": `{"idle_gap_seconds":0,"ranked_clients":["codex"],"max_concurrent_roots":4,"max_single_request_roots":50}`,
		"unknown": `{"idle_gap_seconds":45,"timezone":"Asia/Shanghai"}`,
	} {
		store.rows[storage.SettingsOrgReports] = storage.RuntimeSettings{Section: storage.SettingsOrgReports, Settings: row, UpdatedAtNS: 6}
		ignored := start()
		if public := ignored.Settings(); public.IdleGapSeconds != 180 || len(public.RankedClients) != 2 {
			t.Fatalf("%s saved section applied: %+v", name, public)
		}
		if view, err := ignored.EditableSettings(ctx); err != nil || view.Source != SettingsSourceFile {
			t.Fatalf("%s view = %+v, %v", name, view, err)
		}
	}
	store.fail = errors.New("database unavailable")
	if public := start().Settings(); public.IdleGapSeconds != 180 {
		t.Fatalf("store error applied something: %+v", public)
	}
}
