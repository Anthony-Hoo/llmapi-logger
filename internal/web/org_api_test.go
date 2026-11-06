package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/orgreport"
)

type fakeOrgReports struct {
	fakeOrgBase
}

type fakeOrgBase struct{}

func (fakeOrgBase) Settings() orgreport.PublicSettings {
	return orgreport.PublicSettings{Timezone: "UTC", WeekStart: "monday", IdleGapSeconds: 180, RankedClients: []string{"codex"}}
}

func orgRequest(t *testing.T, handler http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if cookie != nil {
		request.AddCookie(cookie)
	} else {
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestOrgRoutesAre404WhenDisabled(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil)})
	cookie := developerSignIn(t, handler)
	for _, path := range []string{"/api/v1/org", "/api/v1/org/settings", "/api/v1/org/weekly", "/api/v1/org/me/weekly", "/api/v1/org/groups"} {
		for _, caller := range []*http.Cookie{nil, cookie} {
			response := orgRequest(t, handler, http.MethodGet, path, "", caller)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s (developer=%v) status = %d, want 404", path, caller != nil, response.Code)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s missing no-store", path)
			}
		}
	}
	// The session tells the UI to hide the entry.
	response := orgRequest(t, handler, http.MethodGet, "/api/v1/session", "", nil)
	var session map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session["org_reports_enabled"] != false {
		t.Fatalf("session = %v, want org_reports_enabled false", session)
	}
}

func TestOrgRoutesAreAdministratorOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{
		Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil),
		Org:       &fakeOrgReports{},
	})
	cookie := developerSignIn(t, handler)

	response := orgRequest(t, handler, http.MethodGet, "/api/v1/org/settings", "", nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin settings status = %d headers = %v", response.Code, response.Header())
	}
	var settings orgreport.PublicSettings
	if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil || settings.Timezone != "UTC" {
		t.Fatalf("settings = %+v err = %v", settings, err)
	}

	for _, path := range []string{"/api/v1/org/settings", "/api/v1/org/weekly", "/api/v1/org/groups", "/api/v1/org/unattributed"} {
		response := orgRequest(t, handler, http.MethodGet, path, "", cookie)
		if response.Code != http.StatusForbidden {
			t.Fatalf("developer %s status = %d, want 403", path, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("developer %s missing no-store", path)
		}
	}

	response = orgRequest(t, handler, http.MethodGet, "/api/v1/session", "", cookie)
	var session map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session["org_reports_enabled"] != true {
		t.Fatalf("session = %v, want org_reports_enabled true", session)
	}
}
