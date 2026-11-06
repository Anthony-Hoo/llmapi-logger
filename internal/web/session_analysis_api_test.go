package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

type fakeSessionAnalysis struct {
	scopes    []*query.Scope
	sessions  []sessionanalysis.SessionsQuery
	triggered int
	triggerOK error
}

func (fake *fakeSessionAnalysis) Overview(_ context.Context, from, to int64, scope *query.Scope) (sessionanalysis.OverviewResponse, error) {
	fake.scopes = append(fake.scopes, scope)
	return sessionanalysis.OverviewResponse{FromNS: from, ToNS: to}, nil
}

func (fake *fakeSessionAnalysis) Sessions(_ context.Context, request sessionanalysis.SessionsQuery) (sessionanalysis.SessionsResponse, error) {
	fake.sessions = append(fake.sessions, request)
	fake.scopes = append(fake.scopes, request.Scope)
	return sessionanalysis.SessionsResponse{Items: []sessionanalysis.SessionItem{}}, nil
}

func (fake *fakeSessionAnalysis) TriggerRun() error {
	fake.triggered++
	return fake.triggerOK
}

func newSessionAnalysisHandler(t *testing.T, service SessionAnalysisQuery) (*managementHandler, *http.Cookie) {
	t.Helper()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil), SessionAnalysis: service})
	return handler, developerSignIn(t, handler)
}

func serveAs(handler *managementHandler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	} else {
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSessionAnalysisRoutesReturn404WhenDisabled(t *testing.T) {
	t.Parallel()
	handler, cookie := newSessionAnalysisHandler(t, nil)
	for _, path := range []string{"/api/v1/session-analysis/overview", "/api/v1/session-analysis/sessions", "/api/v1/session-analysis/run"} {
		for _, caller := range []*http.Cookie{nil, cookie} {
			if response := serveAs(handler, http.MethodGet, path, caller); response.Code != http.StatusNotFound {
				t.Errorf("%s: %d", path, response.Code)
			}
		}
	}
}

func TestSessionAnalysisScopeComesFromTheSession(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	window := "?from_ns=1000&to_ns=2000"
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/overview"+window, nil); response.Code != http.StatusOK {
		t.Fatalf("admin overview = %d %s", response.Code, response.Body.String())
	} else {
		assertNoStore(t, response, "overview")
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions"+window+"&flags=loop,unverified&kind=agent&limit=20", cookie); response.Code != http.StatusOK {
		t.Fatalf("developer sessions = %d %s", response.Code, response.Body.String())
	}
	if len(fake.scopes) != 2 || fake.scopes[0] != nil || fake.scopes[1] == nil || len(fake.scopes[1].Fingerprint) == 0 {
		t.Fatalf("scopes = %+v", fake.scopes)
	}
	request := fake.sessions[0]
	if len(request.Flags) != 2 || request.Flags[1] != "unverified" || request.Kind != "agent" || request.Limit != 20 {
		t.Fatalf("query = %+v", request)
	}
	for _, path := range []string{
		"/api/v1/session-analysis/overview",                             // range required
		"/api/v1/session-analysis/overview" + window + "&user=5",        // unknown key
		"/api/v1/session-analysis/sessions" + window + "&limit=0",       // zero limit
		"/api/v1/session-analysis/sessions?from_ns=x&to_ns=2000",        // bad number
		"/api/v1/session-analysis/sessions" + window + "&kind=a&kind=b", // repeated key
	} {
		if response := serveAs(handler, http.MethodGet, path, cookie); response.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, response.Code)
		}
	}
}

func TestSessionAnalysisRunIsAdministratorOnly(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/run", cookie); response.Code != http.StatusForbidden {
		t.Fatalf("developer run = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/run", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET run = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/run", nil); response.Code != http.StatusAccepted || fake.triggered != 1 {
		t.Fatalf("admin run = %d triggered=%d", response.Code, fake.triggered)
	}
	fake.triggerOK = sessionanalysis.ErrRunInProgress
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/run", nil); response.Code != http.StatusConflict {
		t.Fatalf("overlapping run = %d", response.Code)
	}
}
