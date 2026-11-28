package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
)

type fakeAnalysisSettings struct {
	updates []sessionanalysis.SettingsUpdate
	tests   []sessionanalysis.SettingsUpdate
	resets  int
	reads   int
	fail    error
}

func (fake *fakeAnalysisSettings) Get(context.Context) (sessionanalysis.SettingsView, error) {
	fake.reads++
	return sessionanalysis.SettingsView{Source: sessionanalysis.SourceFile, APIKey: sessionanalysis.KeyFile}, nil
}

func (fake *fakeAnalysisSettings) Update(_ context.Context, update sessionanalysis.SettingsUpdate) (sessionanalysis.SettingsView, error) {
	fake.updates = append(fake.updates, update)
	if fake.fail != nil {
		return sessionanalysis.SettingsView{}, fake.fail
	}
	return sessionanalysis.SettingsView{Source: sessionanalysis.SourceSaved, APIKey: sessionanalysis.KeySaved, Settings: update.EditableSettings}, nil
}

func (fake *fakeAnalysisSettings) Reset(context.Context) (sessionanalysis.SettingsView, error) {
	fake.resets++
	return sessionanalysis.SettingsView{Source: sessionanalysis.SourceFile}, nil
}

func (fake *fakeAnalysisSettings) Test(_ context.Context, update sessionanalysis.SettingsUpdate) (sessionanalysis.ProbeResult, error) {
	fake.tests = append(fake.tests, update)
	if fake.fail != nil {
		return sessionanalysis.ProbeResult{}, fake.fail
	}
	return sessionanalysis.ProbeResult{OK: true, HTTPStatus: 200, LatencyMS: 12}, nil
}

func serveBody(handler *managementHandler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != nil {
		request.AddCookie(cookie)
	} else {
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const settingsBody = `{"run_at":"03:30","l1_settle_hours":24,"llm":{"enabled":true,"base_url":"http://127.0.0.1:11434/v1","model":"m","structured_output":"json_schema","context_tokens":16384,"disable_thinking":true,"max_output_tokens":1500,"max_concurrency":4,"timeout_seconds":120,"max_sessions_per_run":300}}`

func TestSessionAnalysisSettingsRoutes(t *testing.T) {
	t.Parallel()
	fake := &fakeAnalysisSettings{}
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil), SessionAnalysisSettings: fake})
	cookie := developerSignIn(t, handler)
	const path, testPath = "/api/v1/settings/session-analysis", "/api/v1/settings/session-analysis/test"

	// Settings are site-wide configuration: a developer session reads nothing.
	for _, call := range [][2]string{{http.MethodGet, path}, {http.MethodPut, path}, {http.MethodDelete, path}, {http.MethodPost, testPath}} {
		if response := serveBody(handler, call[0], call[1], settingsBody, cookie); response.Code != http.StatusForbidden {
			t.Fatalf("developer %s %s = %d", call[0], call[1], response.Code)
		}
	}
	if fake.reads+fake.resets+len(fake.updates)+len(fake.tests) != 0 {
		t.Fatal("a refused request reached the settings service")
	}

	if response := serveBody(handler, http.MethodGet, path, "", nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"api_key":"file"`) {
		t.Fatalf("admin get = %d %s", response.Code, response.Body.String())
	} else {
		assertNoStore(t, response, "settings")
	}
	// Without api_key the key in use is kept; with it, it is replaced.
	if response := serveBody(handler, http.MethodPut, path, settingsBody, nil); response.Code != http.StatusOK || len(fake.updates) != 1 ||
		fake.updates[0].APIKey != nil || fake.updates[0].RunAt != "03:30" || fake.updates[0].LLM.MaxConcurrency != 4 {
		t.Fatalf("admin put = %d %+v", response.Code, fake.updates)
	}
	withKey := strings.TrimSuffix(settingsBody, "}") + `,"api_key":"page-key-1"}`
	response := serveBody(handler, http.MethodPut, path, withKey, nil)
	if response.Code != http.StatusOK || fake.updates[1].APIKey == nil || *fake.updates[1].APIKey != "page-key-1" {
		t.Fatalf("put with a key = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "page-key-1") {
		t.Fatalf("the response echoes the key: %s", response.Body.String())
	}
	cleared := strings.TrimSuffix(settingsBody, "}") + `,"api_key":""}`
	if response := serveBody(handler, http.MethodPut, path, cleared, nil); response.Code != http.StatusOK || fake.updates[2].APIKey == nil || *fake.updates[2].APIKey != "" {
		t.Fatalf("put clearing the key = %d", response.Code)
	}
	if response := serveBody(handler, http.MethodPost, testPath, settingsBody, nil); response.Code != http.StatusOK || len(fake.tests) != 1 ||
		!strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("admin test = %d %s", response.Code, response.Body.String())
	}
	if response := serveBody(handler, http.MethodDelete, path, "", nil); response.Code != http.StatusOK || fake.resets != 1 {
		t.Fatalf("admin reset = %d", response.Code)
	}

	// A rejected change answers 400 with the field message.
	fake.fail = fmt.Errorf("%w: session_analysis.llm.max_concurrency must be between 1 and 64, got 99", sessionanalysis.ErrInvalidSettings)
	for _, call := range [][2]string{{http.MethodPut, path}, {http.MethodPost, testPath}} {
		response := serveBody(handler, call[0], call[1], settingsBody, nil)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "max_concurrency must be between 1 and 64") ||
			strings.Contains(response.Body.String(), "sessionanalysis:") {
			t.Fatalf("%s rejected = %d %s", call[1], response.Code, response.Body.String())
		}
	}
	fake.fail = nil
	seen := len(fake.updates)
	for _, bad := range []string{``, `{`, `{"run_at":"03:30","unknown":1}`, settingsBody + `{}`, `{"llm":{"api_key":"x"}}`} {
		if response := serveBody(handler, http.MethodPut, path, bad, nil); response.Code != http.StatusBadRequest {
			t.Errorf("body %q = %d", bad, response.Code)
		}
	}
	if len(fake.updates) != seen {
		t.Fatal("a malformed body reached the settings service")
	}
	if response := serveBody(handler, http.MethodPost, path, settingsBody, nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST settings = %d", response.Code)
	}
	if response := serveBody(handler, http.MethodGet, testPath, "", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET test = %d", response.Code)
	}
}

// settingsRows is an in-memory store of saved settings. While failLoad is
// set every read fails with it (the reader pool failing, the writer working).
type settingsRows struct {
	mu       sync.Mutex
	rows     map[string]storage.RuntimeSettings
	failLoad error
}

// setFailLoad sets failLoad under the lock.
func (store *settingsRows) setFailLoad(err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.failLoad = err
}

func (store *settingsRows) LoadRuntimeSettings(_ context.Context, section string) (storage.RuntimeSettings, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failLoad != nil {
		return storage.RuntimeSettings{}, store.failLoad
	}
	row, ok := store.rows[section]
	if !ok {
		return storage.RuntimeSettings{}, sql.ErrNoRows
	}
	return row, nil
}

func (store *settingsRows) SaveRuntimeSettings(_ context.Context, row storage.RuntimeSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.rows == nil {
		store.rows = map[string]storage.RuntimeSettings{}
	}
	store.rows[row.Section] = row
	return nil
}

func (store *settingsRows) DeleteRuntimeSettings(_ context.Context, section string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.rows, section)
	return nil
}

func TestOrgReportsSettingsRoutes(t *testing.T) {
	t.Parallel()
	file := config.OrgReportsConfig{Enabled: true, Timezone: "UTC", WeekStart: "monday", IdleGapSeconds: 180, RankedClients: []string{"codex"}}
	file.Anomaly.MaxConcurrentRoots, file.Anomaly.MaxSingleRequestRoots = 10, 200
	settings, err := orgreport.SettingsFromConfig(file, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows := &settingsRows{}
	service, err := orgreport.NewService(context.Background(), orgreport.Options{Settings: settings, File: file, SavedSettings: rows})
	if err != nil {
		t.Fatal(err)
	}
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil), Org: service})
	cookie := developerSignIn(t, handler)
	const path = "/api/v1/settings/org-reports"
	const body = `{"idle_gap_seconds":60,"ranked_clients":["codex","opencode"],"max_concurrent_roots":5,"max_single_request_roots":100}`

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if response := serveBody(handler, method, path, body, cookie); response.Code != http.StatusForbidden {
			t.Fatalf("developer %s = %d", method, response.Code)
		}
	}
	if len(rows.rows) != 0 {
		t.Fatal("a refused request saved settings")
	}
	initial := decodeOrg[orgreport.SettingsView](t, serveBody(handler, http.MethodGet, path, "", nil))
	if initial.Source != orgreport.SettingsSourceFile || initial.Settings.IdleGapSeconds != 180 || initial.Timezone != "UTC" || initial.WeekStart != "monday" {
		t.Fatalf("initial = %+v", initial)
	}
	response := serveBody(handler, http.MethodPut, path, body, nil)
	saved := decodeOrg[orgreport.SettingsView](t, response)
	if response.Code != http.StatusOK || saved.Source != orgreport.SettingsSourceSaved || saved.Settings.IdleGapSeconds != 60 || len(saved.Settings.RankedClients) != 2 || len(rows.rows) != 1 {
		t.Fatalf("saved = %d %+v", response.Code, saved)
	}
	// The read-only settings endpoint shows the values in use.
	if public := decodeOrg[orgreport.PublicSettings](t, serveBody(handler, http.MethodGet, "/api/v1/org/settings", "", nil)); public.IdleGapSeconds != 60 || public.MaxConcurrentRoots != 5 {
		t.Fatalf("public = %+v", public)
	}
	// A rejected change answers 400 with the field message and changes nothing.
	rejected := serveBody(handler, http.MethodPut, path, strings.Replace(body, `"idle_gap_seconds":60`, `"idle_gap_seconds":0`, 1), nil)
	if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), "idle_gap_seconds must be between 1 and 3600") {
		t.Fatalf("rejected = %d %s", rejected.Code, rejected.Body.String())
	}
	for _, bad := range []string{``, `{`, `{"idle_gap_seconds":60,"timezone":"Asia/Shanghai"}`} {
		if response := serveBody(handler, http.MethodPut, path, bad, nil); response.Code != http.StatusBadRequest {
			t.Errorf("body %q = %d", bad, response.Code)
		}
	}
	if view := decodeOrg[orgreport.SettingsView](t, serveBody(handler, http.MethodGet, path, "", nil)); view.Settings.IdleGapSeconds != 60 {
		t.Fatalf("after rejected changes = %+v", view)
	}
	reset := decodeOrg[orgreport.SettingsView](t, serveBody(handler, http.MethodDelete, path, "", nil))
	if reset.Source != orgreport.SettingsSourceFile || reset.Settings.IdleGapSeconds != 180 || len(rows.rows) != 0 {
		t.Fatalf("reset = %+v", reset)
	}
	if response := serveBody(handler, http.MethodPost, path, body, nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", response.Code)
	}
	// Organisation reports off: the route does not exist.
	off := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	if response := serveBody(off, http.MethodGet, path, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("disabled = %d", response.Code)
	}
}

// retrySink records the retry count the capture settings hand to the manager.
type retrySink struct {
	mu     sync.Mutex
	values []int
}

func (sink *retrySink) SetCommitRetries(retries int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.values = append(sink.values, retries)
}

func (sink *retrySink) last() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.values[len(sink.values)-1]
}

func TestCaptureSettingsRoutes(t *testing.T) {
	t.Parallel()
	rows := &settingsRows{}
	sink := &retrySink{}
	service, err := audit.NewCaptureSettings(context.Background(), audit.CaptureSettingsOptions{FileRetries: 3, Store: rows, Manager: sink})
	if err != nil {
		t.Fatal(err)
	}
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil), CaptureSettings: service})
	cookie := developerSignIn(t, handler)
	const path = "/api/v1/settings/audit-capture"

	// Site-wide configuration: a developer session gets the 403 the other
	// settings routes give it, and nothing reaches the service.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if response := serveBody(handler, method, path, `{"commit_retries":1}`, cookie); response.Code != http.StatusForbidden {
			t.Fatalf("developer %s = %d", method, response.Code)
		}
	}
	if len(rows.rows) != 0 || len(sink.values) != 1 {
		t.Fatal("a refused request reached the settings service")
	}

	response := serveBody(handler, http.MethodGet, path, "", nil)
	initial := decodeOrg[audit.CaptureSettingsView](t, response)
	if response.Code != http.StatusOK || initial.Source != audit.CaptureSettingsSourceFile || initial.Settings.CommitRetries != 3 ||
		initial.File.CommitRetries != 3 || initial.WritePath != "unified" || strings.Contains(response.Body.String(), "updated_ns") {
		t.Fatalf("initial = %d %s", response.Code, response.Body.String())
	}
	assertNoStore(t, response, "capture settings")

	response = serveBody(handler, http.MethodPut, path, `{"commit_retries":0}`, nil)
	saved := decodeOrg[audit.CaptureSettingsView](t, response)
	if response.Code != http.StatusOK || saved.Source != audit.CaptureSettingsSourceSaved || saved.Settings.CommitRetries != 0 || saved.UpdatedNS == 0 ||
		len(rows.rows) != 1 || sink.last() != 0 || !strings.Contains(response.Body.String(), `"updated_ns":"`) {
		t.Fatalf("saved = %d %s", response.Code, response.Body.String())
	}
	if view := decodeOrg[audit.CaptureSettingsView](t, serveBody(handler, http.MethodGet, path, "", nil)); view.Source != audit.CaptureSettingsSourceSaved || view.Settings.CommitRetries != 0 {
		t.Fatalf("after save = %+v", view)
	}

	// Out of range: 400 with the field message; nothing changes.
	for _, body := range []string{`{"commit_retries":6}`, `{"commit_retries":-1}`} {
		rejected := serveBody(handler, http.MethodPut, path, body, nil)
		if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), `"invalid_settings"`) ||
			!strings.Contains(rejected.Body.String(), "audit.commit_retries must be between 0 and 5") || strings.Contains(rejected.Body.String(), "audit:") {
			t.Fatalf("%s = %d %s", body, rejected.Code, rejected.Body.String())
		}
	}
	// Malformed: a missing or null field (0 is a valid value, so it is never
	// defaulted), a fraction, a string, an unknown field, trailing data.
	for _, bad := range []string{``, `{`, `{}`, `{"commit_retries":null}`, `{"commit_retries":1.5}`, `{"commit_retries":"2"}`,
		`{"commit_retries":1,"write_path":"legacy"}`, `{"commit_retries":1}{}`} {
		rejected := serveBody(handler, http.MethodPut, path, bad, nil)
		if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), `"invalid_settings"`) {
			t.Errorf("body %q = %d %s", bad, rejected.Code, rejected.Body.String())
		}
	}
	if view := decodeOrg[audit.CaptureSettingsView](t, serveBody(handler, http.MethodGet, path, "", nil)); view.Settings.CommitRetries != 0 || sink.last() != 0 {
		t.Fatalf("after rejected changes = %+v (manager %d)", view, sink.last())
	}

	reset := serveBody(handler, http.MethodDelete, path, "", nil)
	if view := decodeOrg[audit.CaptureSettingsView](t, reset); reset.Code != http.StatusOK || view.Source != audit.CaptureSettingsSourceFile ||
		view.Settings.CommitRetries != 3 || len(rows.rows) != 0 || sink.last() != 3 {
		t.Fatalf("reset = %d %s", reset.Code, reset.Body.String())
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		if response := serveBody(handler, method, path, `{"commit_retries":1}`, nil); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d", method, response.Code)
		}
	}

	// The store cannot be read: the page still reads the file's value, and a
	// write answers 503 and saves nothing.
	rows.setFailLoad(errors.New("transient: reader pool exhausted"))
	if response := serveBody(handler, http.MethodGet, path, "", nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"source":"file"`) {
		t.Fatalf("read during the error = %d %s", response.Code, response.Body.String())
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if response := serveBody(handler, method, path, `{"commit_retries":1}`, nil); response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), "settings_unavailable") || strings.Contains(response.Body.String(), "reader pool") {
			t.Fatalf("%s during the error = %d %s", method, response.Code, response.Body.String())
		}
	}
	rows.setFailLoad(nil)
	if len(rows.rows) != 0 || sink.last() != 3 {
		t.Fatal("a refused write changed something")
	}

	// Not assembled: the route answers 404, and still 405 for other methods.
	off := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	if response := serveBody(off, http.MethodGet, path, "", nil); response.Code != http.StatusNotFound {
		t.Fatalf("not assembled = %d", response.Code)
	}
	if response := serveBody(off, http.MethodPost, path, "", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("not assembled POST = %d", response.Code)
	}
}

func TestSessionAnalysisSettingsReturn404WhenDisabled(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	for _, call := range [][2]string{{http.MethodGet, "/api/v1/settings/session-analysis"}, {http.MethodPost, "/api/v1/settings/session-analysis/test"}} {
		if response := serveBody(handler, call[0], call[1], settingsBody, nil); response.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d", call[0], call[1], response.Code)
		}
	}
}
