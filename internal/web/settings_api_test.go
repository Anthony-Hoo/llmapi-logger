package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/sessionanalysis"
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

func TestSessionAnalysisSettingsReturn404WhenDisabled(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)})
	for _, call := range [][2]string{{http.MethodGet, "/api/v1/settings/session-analysis"}, {http.MethodPost, "/api/v1/settings/session-analysis/test"}} {
		if response := serveBody(handler, call[0], call[1], settingsBody, nil); response.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d", call[0], call[1], response.Code)
		}
	}
}
