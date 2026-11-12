package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

type fakeSessionAnalysis struct {
	weeks     []string
	dismissed []int64
	labels    []sessionanalysis.CalibrationLabel
	viewers   []sessionanalysis.Viewer
	scopes    []*query.Scope
	sessions  []sessionanalysis.SessionsQuery
	triggered int
	triggerOK error
	targets   []sessionanalysis.ReportTarget
	users     []*int64
	listings  int
}

func (fake *fakeSessionAnalysis) Overview(_ context.Context, from, to int64, scope *query.Scope, userID *int64) (sessionanalysis.OverviewResponse, error) {
	fake.scopes = append(fake.scopes, scope)
	fake.users = append(fake.users, userID)
	return sessionanalysis.OverviewResponse{FromNS: from, ToNS: to}, nil
}

func (fake *fakeSessionAnalysis) Users(_ context.Context, from, to int64) (sessionanalysis.UsersResponse, error) {
	fake.listings++
	return sessionanalysis.UsersResponse{FromNS: from, ToNS: to, Items: []sessionanalysis.UserTotalsItem{}}, nil
}

func (fake *fakeSessionAnalysis) Sessions(_ context.Context, request sessionanalysis.SessionsQuery) (sessionanalysis.SessionsResponse, error) {
	fake.sessions = append(fake.sessions, request)
	fake.scopes = append(fake.scopes, request.Scope)
	return sessionanalysis.SessionsResponse{Items: []sessionanalysis.SessionItem{}}, nil
}

func (fake *fakeSessionAnalysis) Pack(_ context.Context, id string, scope *query.Scope, viewer sessionanalysis.Viewer) (sessionanalysis.PackResponse, error) {
	fake.scopes = append(fake.scopes, scope)
	fake.viewers = append(fake.viewers, viewer)
	if id == "missing" {
		return sessionanalysis.PackResponse{}, query.ErrNotFound
	}
	return sessionanalysis.PackResponse{SessionID: id, Text: "[会话] 类型=agent"}, nil
}

func (fake *fakeSessionAnalysis) Facet(_ context.Context, id string, scope *query.Scope, viewer sessionanalysis.Viewer) (sessionanalysis.FacetResponse, error) {
	fake.scopes = append(fake.scopes, scope)
	fake.viewers = append(fake.viewers, viewer)
	return sessionanalysis.FacetResponse{SessionID: id, Status: "ok"}, nil
}

func (fake *fakeSessionAnalysis) Calibrate(_ context.Context, labels []sessionanalysis.CalibrationLabel) (sessionanalysis.CalibrationResult, error) {
	fake.labels = append(fake.labels, labels...)
	return sessionanalysis.CalibrationResult{Labels: len(labels)}, nil
}

func (fake *fakeSessionAnalysis) Report(_ context.Context, week string, scope *query.Scope, target sessionanalysis.ReportTarget) (sessionanalysis.ReportResponse, error) {
	fake.scopes = append(fake.scopes, scope)
	fake.weeks = append(fake.weeks, week)
	fake.targets = append(fake.targets, target)
	return sessionanalysis.ReportResponse{Scope: "all"}, nil
}

func (fake *fakeSessionAnalysis) DismissSuggestion(_ context.Context, id int64) error {
	fake.dismissed = append(fake.dismissed, id)
	if id == 404 {
		return query.ErrNotFound
	}
	return nil
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

// Reading per user is for administrators: the listing, and the user selector
// of the overview and the session list.
func TestSessionAnalysisUserRoutesAreAdministratorOnly(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	window := "?from_ns=1000&to_ns=2000"
	for _, path := range []string{
		"/api/v1/session-analysis/users" + window,
		"/api/v1/session-analysis/overview" + window + "&user_id=7",
		"/api/v1/session-analysis/sessions" + window + "&user_id=7",
	} {
		if response := serveAs(handler, http.MethodGet, path, cookie); response.Code != http.StatusForbidden {
			t.Fatalf("developer %s = %d", path, response.Code)
		}
	}
	if fake.listings != 0 || len(fake.users) != 0 || len(fake.sessions) != 0 {
		t.Fatalf("a refused request reached the service: %d %d %d", fake.listings, len(fake.users), len(fake.sessions))
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/users"+window, nil); response.Code != http.StatusOK || fake.listings != 1 {
		t.Fatalf("admin users = %d listings=%d", response.Code, fake.listings)
	} else {
		assertNoStore(t, response, "users")
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/overview"+window+"&user_id=7", nil); response.Code != http.StatusOK ||
		len(fake.users) != 1 || fake.users[0] == nil || *fake.users[0] != 7 {
		t.Fatalf("admin overview of a user = %d %v", response.Code, fake.users)
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions"+window+"&user_id=7", nil); response.Code != http.StatusOK ||
		len(fake.sessions) != 1 || fake.sessions[0].UserID == nil || *fake.sessions[0].UserID != 7 || fake.sessions[0].Scope != nil {
		t.Fatalf("admin sessions of a user = %d %+v", response.Code, fake.sessions)
	}
	// Without the selector nothing is narrowed.
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions"+window, nil); response.Code != http.StatusOK || fake.sessions[1].UserID != nil {
		t.Fatalf("admin sessions = %d %+v", response.Code, fake.sessions)
	}
	for _, path := range []string{
		"/api/v1/session-analysis/users",                              // range required
		"/api/v1/session-analysis/users" + window + "&user_id=7",      // unknown key
		"/api/v1/session-analysis/overview" + window + "&user_id=0",   // not an id
		"/api/v1/session-analysis/sessions" + window + "&user_id=abc", // not a number
	} {
		if response := serveAs(handler, http.MethodGet, path, nil); response.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, response.Code)
		}
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/users"+window, nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST users = %d", response.Code)
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

func TestSessionAnalysisPackRecordsTheViewer(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions/abc/pack", nil); response.Code != http.StatusOK {
		t.Fatalf("admin pack = %d", response.Code)
	} else {
		assertNoStore(t, response, "pack")
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions/abc/pack", cookie); response.Code != http.StatusOK {
		t.Fatalf("developer pack = %d", response.Code)
	}
	if len(fake.viewers) != 2 || fake.viewers[0].Role != "admin" || fake.viewers[1].Role != "developer" || fake.scopes[1] == nil || fake.scopes[0] != nil {
		t.Fatalf("viewers = %+v scopes = %+v", fake.viewers, fake.scopes)
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions/missing/pack", cookie); response.Code != http.StatusNotFound {
		t.Fatalf("missing pack = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/sessions/abc/pack", nil); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST pack = %d", response.Code)
	}
}

func TestSessionAnalysisFacetAndCalibrationRoutes(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/sessions/abc/facet", cookie); response.Code != http.StatusOK {
		t.Fatalf("developer facet = %d", response.Code)
	}
	if len(fake.viewers) != 1 || fake.viewers[0].Role != "developer" || fake.scopes[0] == nil {
		t.Fatalf("facet viewer = %+v", fake.viewers)
	}
	body := `{"labels":[{"session_id":"` + strings.Repeat("a", 64) + `","task_type":"bug_fix"}]}`
	post := func(caller *http.Cookie, payload string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/session-analysis/calibration", strings.NewReader(payload))
		if caller != nil {
			request.AddCookie(caller)
		} else {
			request.Header.Set("Authorization", "Bearer "+testAdminToken)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := post(cookie, body); response.Code != http.StatusForbidden {
		t.Fatalf("developer calibration = %d", response.Code)
	}
	if response := post(nil, body); response.Code != http.StatusOK || len(fake.labels) != 1 || fake.labels[0].TaskType != "bug_fix" {
		t.Fatalf("admin calibration = %d labels=%+v", response.Code, fake.labels)
	}
	if response := post(nil, `{"labels":[],"extra":1}`); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", response.Code)
	}
}

func TestSessionAnalysisReportAndDismissRoutes(t *testing.T) {
	t.Parallel()
	fake := &fakeSessionAnalysis{}
	handler, cookie := newSessionAnalysisHandler(t, fake)
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report?week=previous", cookie); response.Code != http.StatusOK {
		t.Fatalf("developer report = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report", nil); response.Code != http.StatusOK {
		t.Fatalf("admin report = %d", response.Code)
	}
	if len(fake.weeks) != 2 || fake.weeks[0] != "previous" || fake.scopes[0] == nil || fake.scopes[1] != nil {
		t.Fatalf("weeks=%v scopes=%v", fake.weeks, fake.scopes)
	}
	if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report?user=1", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown key = %d", response.Code)
	}
	// Project, group and user reports are for administrators only.
	for _, selector := range []string{"project_id=10", "group_id=3", "user_id=7"} {
		if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report?"+selector, cookie); response.Code != http.StatusForbidden {
			t.Fatalf("developer %s = %d", selector, response.Code)
		}
		if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report?week=previous&"+selector, nil); response.Code != http.StatusOK {
			t.Fatalf("admin %s = %d", selector, response.Code)
		}
	}
	if len(fake.targets) != 5 || fake.targets[0] != (sessionanalysis.ReportTarget{}) ||
		fake.targets[2] != (sessionanalysis.ReportTarget{ProjectID: 10}) || fake.targets[3] != (sessionanalysis.ReportTarget{GroupID: 3}) ||
		fake.targets[4] != (sessionanalysis.ReportTarget{UserID: 7}) {
		t.Fatalf("targets = %+v", fake.targets)
	}
	for _, bad := range []string{"project_id=0", "project_id=-1", "group_id=x", "project_id=1&group_id=2", "project_id=1&project_id=2", "user_id=0", "project_id=1&user_id=2"} {
		if response := serveAs(handler, http.MethodGet, "/api/v1/session-analysis/report?"+bad, nil); response.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d", bad, response.Code)
		}
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/suggestions/7/dismiss", cookie); response.Code != http.StatusForbidden {
		t.Fatalf("developer dismiss = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/suggestions/7/dismiss", nil); response.Code != http.StatusOK || len(fake.dismissed) != 1 {
		t.Fatalf("admin dismiss = %d %v", response.Code, fake.dismissed)
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/suggestions/404/dismiss", nil); response.Code != http.StatusNotFound {
		t.Fatalf("missing dismiss = %d", response.Code)
	}
	if response := serveAs(handler, http.MethodPost, "/api/v1/session-analysis/suggestions/x/dismiss", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("bad id = %d", response.Code)
	}
}
