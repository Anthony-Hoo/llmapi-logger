package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/insights/pricing"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	apiSessionShared  = "agt_aaaaaaaaaaaaaaaaaaaaaaaa"
	apiSessionForeign = "agt_cccccccccccccccccccccccc"
	apiTreeOwn        = "a0a0a0a0a0a0a0a0a0a0a0a0"
	apiTreeForeign    = "b0b0b0b0b0b0b0b0b0b0b0b0"
)

type insightsAPIFixture struct {
	handler *managementHandler
	cookie  *http.Cookie
	base    time.Time
}

func repeated(value byte) []byte { return bytes.Repeat([]byte{value}, sqlite.AnalysisFingerprintSize) }

func seedAPIStep(t *testing.T, store *sqlite.Store, cipher security.Cipher, id string, at time.Time, key []byte, session string, root, node []byte, withDetail bool) {
	t.Helper()
	ctx := context.Background()
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: id, StartedAtNS: at.UnixNano(), RouteID: "openai-chat", Protocol: "openai", ParserName: "openai.chat_completions",
		Method: "POST", Path: "/v1/chat/completions", RequestURIEnc: []byte{1}, Mode: "available", APIKeyFPR: key,
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{
		AuditID: id, EndedAtNS: at.UnixNano() + 1000, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK,
	}); err != nil {
		t.Fatal(err)
	}
	model, role, client := "gpt-4.1", "main", "custom"
	uncached, output := int64(100), int64(10)
	row := sqlite.AnalysisRow{
		AuditID: id, AnalysisVersion: 1, AnalyzedAtNS: at.UnixNano() + 1, Protocol: "openai", Model: &model, StartedAtNS: at.UnixNano(),
		UncachedInput: &uncached, Output: &output, EstSystem: 90, EstUser: 10, AnalysisSessionID: &session,
		AgentClient: &client, AgentRole: &role, AgentRootFPR: root, AgentNodeFPR: node,
	}
	if withDetail {
		plaintext, err := json.Marshal(insights.Detail{Items: []insights.Item{{Index: 0, Category: "system", Kind: "system", Tokens: 90}}, ItemFPRs: []string{"f1"}})
		if err != nil {
			t.Fatal(err)
		}
		aad, err := security.AAD(id, "analysis_detail", "1")
		if err != nil {
			t.Fatal(err)
		}
		if row.DetailEnc, err = cipher.Encrypt(aad, plaintext); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
}

func newInsightsAPIFixture(t *testing.T, enabled bool) *insightsAPIFixture {
	t.Helper()
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	own := testFingerprinter(t).Fingerprint(testDeveloperKey)
	other := bytes.Repeat([]byte{0x77}, len(own))
	seedAPIStep(t, store, cipher, "own-1", base, own, apiSessionShared, repeated(0xa0), repeated(0x11), true)
	seedAPIStep(t, store, cipher, "other-in-shared", base.Add(time.Second), other, apiSessionShared, repeated(0xa0), repeated(0x12), true)
	seedAPIStep(t, store, cipher, "other-only", base.Add(2*time.Second), other, apiSessionForeign, repeated(0xb0), repeated(0x14), true)

	options := Options{Developer: developerOptions(t, newapi.TokenIdentity{}, nil)}
	if enabled {
		prices, err := pricing.Load("")
		if err != nil {
			t.Fatal(err)
		}
		service, err := query.NewInsights(store, cipher, prices)
		if err != nil {
			t.Fatal(err)
		}
		options.Insights = service
	}
	handler := newDeveloperHandler(t, options)
	return &insightsAPIFixture{handler: handler, cookie: developerSignIn(t, handler), base: base}
}

func (fixture *insightsAPIFixture) get(path string, developer bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if developer {
		request.AddCookie(fixture.cookie)
	} else {
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture *insightsAPIFixture) window() string {
	return "from_ns=" + strconv.FormatInt(fixture.base.Add(-time.Hour).UnixNano(), 10) +
		"&to_ns=" + strconv.FormatInt(fixture.base.Add(time.Hour).UnixNano(), 10)
}

func assertNoStore(t *testing.T, response *httptest.ResponseRecorder, path string) {
	t.Helper()
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: Cache-Control = %q", path, got)
	}
}

func TestInsightsRoutesReturn404WhenDisabled(t *testing.T) {
	t.Parallel()
	fixture := newInsightsAPIFixture(t, false)
	for _, path := range []string{
		"/api/v1/insights/overview",
		"/api/v1/insights/sessions",
		"/api/v1/insights/sessions/" + apiSessionShared + "/trend",
		"/api/v1/insights/agent-trees/" + apiTreeOwn,
		"/api/v1/audits/own-1/composition",
	} {
		for _, developer := range []bool{false, true} {
			response := fixture.get(path, developer)
			if response.Code != http.StatusNotFound {
				t.Errorf("%s developer=%v: status = %d", path, developer, response.Code)
			}
			assertNoStore(t, response, path)
		}
	}
}

func TestInsightsEndpointsAreScopedForDevelopers(t *testing.T) {
	t.Parallel()
	fixture := newInsightsAPIFixture(t, true)

	overview := fixture.get("/api/v1/insights/overview?"+fixture.window(), true)
	assertNoStore(t, overview, "overview")
	var overviewBody insights.OverviewResponse
	if overview.Code != http.StatusOK || json.Unmarshal(overview.Body.Bytes(), &overviewBody) != nil {
		t.Fatalf("overview = %d %s", overview.Code, overview.Body.String())
	}
	if overviewBody.Totals.Requests != 1 || overviewBody.Sessions != 1 || overviewBody.Trees != 0 {
		t.Fatalf("developer overview leaked other key rows: %+v", overviewBody)
	}
	admin := fixture.get("/api/v1/insights/overview?"+fixture.window(), false)
	var adminBody insights.OverviewResponse
	if admin.Code != http.StatusOK || json.Unmarshal(admin.Body.Bytes(), &adminBody) != nil || adminBody.Totals.Requests != 3 || adminBody.Sessions != 2 || adminBody.Trees != 1 {
		t.Fatalf("admin overview = %d %s", admin.Code, admin.Body.String())
	}

	sessions := fixture.get("/api/v1/insights/sessions?"+fixture.window(), true)
	assertNoStore(t, sessions, "sessions")
	var sessionsBody insights.SessionsResponse
	if sessions.Code != http.StatusOK || json.Unmarshal(sessions.Body.Bytes(), &sessionsBody) != nil ||
		len(sessionsBody.Items) != 1 || sessionsBody.Items[0].SessionID != apiSessionShared || sessionsBody.Items[0].Steps != 1 || sessionsBody.Items[0].Caller != nil {
		t.Fatalf("developer sessions = %d %s", sessions.Code, sessions.Body.String())
	}
	if !bytes.Contains(sessions.Body.Bytes(), []byte(`"caller":null`)) {
		t.Fatalf("developer card must carry caller:null: %s", sessions.Body.String())
	}

	trend := fixture.get("/api/v1/insights/sessions/"+apiSessionShared+"/trend", true)
	assertNoStore(t, trend, "trend")
	var trendBody insights.TrendResponse
	if trend.Code != http.StatusOK || json.Unmarshal(trend.Body.Bytes(), &trendBody) != nil || len(trendBody.Steps) != 1 || trendBody.Steps[0].AuditID != "own-1" {
		t.Fatalf("developer trend = %d %s", trend.Code, trend.Body.String())
	}
	tree := fixture.get("/api/v1/insights/agent-trees/"+apiTreeOwn, true)
	assertNoStore(t, tree, "tree")
	var treeBody insights.TreeResponse
	if tree.Code != http.StatusOK || json.Unmarshal(tree.Body.Bytes(), &treeBody) != nil || len(treeBody.Nodes) != 1 {
		t.Fatalf("developer tree = %d %s", tree.Code, tree.Body.String())
	}

	for _, path := range []string{
		"/api/v1/insights/sessions/" + apiSessionForeign + "/trend",
		"/api/v1/insights/agent-trees/" + apiTreeForeign,
		"/api/v1/audits/other-only/composition",
		"/api/v1/audits/other-in-shared/composition",
	} {
		response := fixture.get(path, true)
		if response.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d body = %s", path, response.Code, response.Body.String())
		}
		assertNoStore(t, response, path)
	}
	for _, path := range []string{
		"/api/v1/insights/sessions/" + apiSessionForeign + "/trend",
		"/api/v1/insights/agent-trees/" + apiTreeForeign,
	} {
		if response := fixture.get(path, false); response.Code != http.StatusOK {
			t.Errorf("admin %s: status = %d", path, response.Code)
		}
	}
}

func TestInsightsCompositionThroughAuthorizeAudit(t *testing.T) {
	t.Parallel()
	fixture := newInsightsAPIFixture(t, true)
	response := fixture.get("/api/v1/audits/own-1/composition", true)
	assertNoStore(t, response, "composition")
	var body insights.CompositionResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.AuditID != "own-1" || len(body.Items) != 1 || body.Items[0].Summary != "" {
		t.Fatalf("composition = %d %s", response.Code, response.Body.String())
	}
	if body.Anchored == nil || body.Anchored.Sum() != 100 {
		t.Fatalf("anchored = %+v", body.Anchored)
	}
	if missing := fixture.get("/api/v1/audits/no-such-audit/composition", false); missing.Code != http.StatusNotFound {
		t.Fatalf("missing audit status = %d", missing.Code)
	}
	post := httptest.NewRequest(http.MethodPost, "/api/v1/audits/own-1/composition", nil)
	post.Header.Set("Authorization", "Bearer "+testAdminToken)
	postResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", postResponse.Code)
	}
}

func TestInsightsParameterValidation(t *testing.T) {
	t.Parallel()
	fixture := newInsightsAPIFixture(t, true)
	window := fixture.window()
	tooLong := "from_ns=" + strconv.FormatInt(fixture.base.Add(-401*24*time.Hour).UnixNano(), 10) + "&to_ns=" + strconv.FormatInt(fixture.base.UnixNano(), 10)
	cases := []struct {
		path      string
		developer bool
		want      int
	}{
		{"/api/v1/insights/overview?" + window + "&group_by=model&tz_offset_min=480", true, http.StatusOK},
		{"/api/v1/insights/overview?tz_offset_min=-840", false, http.StatusOK},
		{"/api/v1/insights/overview?tz_offset_min=841", false, http.StatusBadRequest},
		{"/api/v1/insights/overview?tz_offset_min=abc", false, http.StatusBadRequest},
		{"/api/v1/insights/overview?" + tooLong, false, http.StatusBadRequest},
		{"/api/v1/insights/overview?from_ns=9&to_ns=3", false, http.StatusBadRequest},
		{"/api/v1/insights/overview?group_by=nope", false, http.StatusBadRequest},
		{"/api/v1/insights/overview?group_by=caller", false, http.StatusOK},
		{"/api/v1/insights/overview?group_by=token", false, http.StatusOK},
		{"/api/v1/insights/overview?group_by=caller", true, http.StatusBadRequest},
		{"/api/v1/insights/overview?group_by=token", true, http.StatusBadRequest},
		{"/api/v1/insights/overview?group_by=client", true, http.StatusOK},
		{"/api/v1/insights/overview?unknown=1", false, http.StatusBadRequest},
		{"/api/v1/insights/overview?group_by=model&group_by=client", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions?" + window + "&limit=100", false, http.StatusOK},
		{"/api/v1/insights/sessions?limit=101", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions?limit=0", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions?limit=x", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions?sort=bogus", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions?sort=tokens", false, http.StatusOK},
		{"/api/v1/insights/sessions?cursor=%25%25", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions/not-a-session/trend", false, http.StatusBadRequest},
		{"/api/v1/insights/sessions/" + apiSessionShared + "/trend?x=1", false, http.StatusBadRequest},
		{"/api/v1/insights/agent-trees/zz", false, http.StatusBadRequest},
		{"/api/v1/insights/agent-trees/" + apiTreeOwn + "/extra", false, http.StatusNotFound},
		{"/api/v1/insights/nothing", false, http.StatusNotFound},
	}
	for _, testCase := range cases {
		response := fixture.get(testCase.path, testCase.developer)
		if response.Code != testCase.want {
			t.Errorf("%s developer=%v: status = %d, want %d (%s)", testCase.path, testCase.developer, response.Code, testCase.want, response.Body.String())
		}
		assertNoStore(t, response, testCase.path)
		if testCase.want == http.StatusBadRequest {
			var body struct {
				Error struct{ Code, Message string }
			}
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Error.Code != "invalid_query" {
				t.Errorf("%s: error body = %s", testCase.path, response.Body.String())
			}
		}
	}
	post := httptest.NewRequest(http.MethodPost, "/api/v1/insights/overview", nil)
	post.Header.Set("Authorization", "Bearer "+testAdminToken)
	postResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", postResponse.Code)
	}
	unauthenticated := httptest.NewRecorder()
	fixture.handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/insights/overview", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
}
