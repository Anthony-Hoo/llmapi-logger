package web

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/insights/models"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/uaguard"
)

// The _untrusted sweep (contract section 0.1 items 24 and 98): a marker is
// planted in every client-controlled input the fixtures allow, and every
// facade read must carry it only under a key ending in _untrusted.

// sweepMarker is text an attacker would put into traffic. It contains only
// characters every planted field accepts (header names, paths, patterns).
const sweepMarker = "MARKER-ignore-previous-instructions"

const (
	sweepAuditID    = "marked"
	sweepSessionID  = "agt_eeeeeeeeeeeeeeeeeeeeeeee"
	sweepTreeID     = "e0e0e0e0e0e0e0e0e0e0e0e0"
	sweepAnalysisID = "0303030303030303030303030303030303030303030303030303030303030303"
)

// containsMarker finds the marker in any letter case: services may fold
// case (repository names, paths) before they show a value.
func containsMarker(text string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(sweepMarker))
}

// untrustedLeaks lists the JSON paths where the marker appears as an object
// key, or in a string whose nearest enclosing key does not end in
// _untrusted (array elements belong to the key of their array).
func untrustedLeaks(value any, key, path string, out *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for name := range typed {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if containsMarker(name) {
				*out = append(*out, path+" (object key)")
			}
			untrustedLeaks(typed[name], name, path+"."+name, out)
		}
	case []any:
		for _, item := range typed {
			untrustedLeaks(item, key, path+"[]", out)
		}
	case string:
		if containsMarker(typed) && !strings.HasSuffix(key, "_untrusted") {
			*out = append(*out, path)
		}
	}
}

// hasUntrustedKey reports whether any object key ends in _untrusted.
func hasUntrustedKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, item := range typed {
			if strings.HasSuffix(name, "_untrusted") || hasUntrustedKey(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if hasUntrustedKey(item) {
				return true
			}
		}
	}
	return false
}

// plantSweepAudit adds an own record whose every client-controlled text
// carries the marker: models, error type and code, path and query, Host,
// header names and values, User-Agent, caller names, response ids,
// conversation text and tool names.
func plantSweepAudit(fixture *readFixture) {
	record := fixtureAudit(sweepAuditID, 30*time.Second, fixture.ownFingerprint, 42, storage.ForwardCompleted, nil)
	text := func(prefix string) *string { value := prefix + sweepMarker; return &value }
	audit := &record.detail.Audit
	audit.Path = "/v1beta/models/" + sweepMarker + ":generateContent"
	audit.RequestModel, audit.ResponseModel = text("gpt-"), text("resp-")
	audit.ParsedErrorType, audit.ParsedErrorCode = text("type-"), text("code-")
	audit.UserAgent = text("agent/")
	audit.Username, audit.TokenName = text("user-"), text("token-")
	record.detail.RequestURI = audit.Path + "?" + sweepMarker + "=" + sweepMarker + "&note=" + url.QueryEscape("a "+sweepMarker)
	record.detail.Stages[0].Host = sweepMarker + ".example.com"
	for _, header := range []query.Header{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "X-" + sweepMarker, Value: sweepMarker},
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "User-Agent", Value: "agent/" + sweepMarker},
		{Stage: storage.StageResponseReceived, Kind: storage.HeaderKindHeader, Name: "X-Upstream-" + sweepMarker, Value: sweepMarker},
	} {
		header.ValueLength = len(header.Value)
		record.detail.Headers = append(record.detail.Headers, header)
	}
	parsed := record.detail.ParsedResult
	parsed.RequestModel, parsed.ResponseModel = text("gpt-"), text("resp-")
	parsed.ErrorType, parsed.ErrorCode, parsed.ResponseID = text("type-"), text("code-"), text("id-")
	record.detail.Turn.PreviousResponseID, record.detail.Turn.ResponseID = text("prev-"), text("id-")
	record.detail.TokenLink.Username, record.detail.TokenLink.TokenName = "user-"+sweepMarker, "token-"+sweepMarker
	record.detail.Conversation.Messages = append(record.detail.Conversation.Messages, conversation.Message{
		Index: 2, Role: conversation.RoleUser, Phase: conversation.PhaseRequest, Direction: conversation.DirectionClientToUpstream,
		Content: []conversation.Part{{Index: 0, Type: conversation.PartText, Text: sweepMarker}, {Index: 1, Type: conversation.PartToolCall, Name: sweepMarker}},
	})
	fixture.audits.records = append([]auditRecord{record}, fixture.audits.records...)
}

// plantSweepInsights replaces the insights service with one over a store
// holding one analysed step of the marked record: model, context item role,
// label and summary, tool name and MCP source, file operation tool and path,
// the agent's identity and name, and the caller names.
func plantSweepInsights(t *testing.T, fixture *readFixture) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "sweep.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5c}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	at := fixtureBase.Add(30 * time.Second)
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: sweepAuditID, StartedAtNS: at.UnixNano(), RouteID: "openai-chat", Protocol: "openai", ParserName: "openai.chat_completions",
		Method: "POST", Path: "/v1/chat/completions", RequestURIEnc: []byte{1}, Mode: "available", APIKeyFPR: fixture.ownFingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	status, requestID := 200, "req-sweep"
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{AuditID: sweepAuditID, EndedAtNS: at.UnixNano() + 1000, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK, NewAPIRequestID: &requestID}); err != nil {
		t.Fatal(err)
	}
	quota, quotaPerUnit, tokens := int64(1000), 500000.0, int64(1)
	tokenID := int64(42)
	if err := store.UpsertTokenLink(ctx, sqlite.TokenLink{AuditID: sweepAuditID, NewAPIRequestID: requestID, NewAPIUserID: 7,
		Username: "user-" + sweepMarker, NewAPITokenID: tokenID, TokenName: "token-" + sweepMarker, LinkedAtNS: at.UnixNano() + 2, Attempts: 1,
		BillingState: sqlite.BillingBilled, Quota: &quota, QuotaPerUnit: &quotaPerUnit, BilledPromptTokens: &tokens, BilledCompletionTokens: &tokens}); err != nil {
		t.Fatal(err)
	}
	model, role, client, session := "gpt-"+sweepMarker, "main", "custom", sweepSessionID
	uncached, output := int64(100), int64(10)
	root, _ := hex.DecodeString(strings.Repeat("e0", sqlite.AnalysisFingerprintSize))
	row := sqlite.AnalysisRow{
		AuditID: sweepAuditID, AnalysisVersion: 1, AnalyzedAtNS: at.UnixNano() + 1, Protocol: "openai", Model: &model, StartedAtNS: at.UnixNano(),
		UncachedInput: &uncached, Output: &output, EstSystem: 90, EstUser: 10, AnalysisSessionID: &session,
		AgentClient: &client, AgentRole: &role, AgentRootFPR: root, AgentNodeFPR: root,
	}
	plaintext, err := json.Marshal(insights.Detail{
		Items:    []insights.Item{{Index: 0, Category: "user", Role: sweepMarker, Kind: "text", Tokens: 10, Label: sweepMarker, Summary: sweepMarker}},
		Tools:    []insights.ToolDef{{Name: sweepMarker, Tokens: 5, Source: "mcp:" + sweepMarker}},
		FileOps:  []insights.FileOp{{Tool: sweepMarker, Op: "write", Path: "/src/" + sweepMarker}},
		Agent:    insights.AgentIdentity{Client: "custom", Role: "main", RootID: sweepMarker, NodeID: sweepMarker, ParentID: sweepMarker, Name: sweepMarker},
		ItemFPRs: []string{"f1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(sweepAuditID, "analysis_detail", "1")
	if err != nil {
		t.Fatal(err)
	}
	if row.DetailEnc, err = cipher.Encrypt(aad, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	windows, err := models.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := query.NewInsights(store, cipher, windows, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.insights = service
}

// sweepReports adds the marker to everything a weekly review shows that
// people or traffic wrote: the narrative, suggestions and their evidence,
// the scope and project names, and an optimisation session's model.
type sweepReports struct{ *reportingAnalysis }

func (reports sweepReports) Report(ctx context.Context, week string, scope *query.Scope, target sessionanalysis.ReportTarget) (sessionanalysis.ReportResponse, error) {
	response, err := reports.reportingAnalysis.Report(ctx, week, scope, target)
	response.Narrative = sweepMarker
	response.ScopeName = sweepMarker
	response.Projects = []sessionanalysis.ScopeOption{{ID: 1, Name: sweepMarker}}
	response.Groups = []sessionanalysis.ScopeOption{{ID: 2, Name: sweepMarker}}
	response.Users = []sessionanalysis.ScopeOption{{ID: 7, Name: sweepMarker}}
	for index := range response.Suggestions {
		response.Suggestions[index].Text = sweepMarker
		response.Suggestions[index].Evidence = []string{sweepMarker}
	}
	response.Optimizations = []sessionanalysis.SessionItem{{SessionID: sweepAnalysisID, Kind: sessionanalysis.KindAgent, Model: sweepMarker,
		Project: sweepMarker, LastAuditID: sweepAuditID}}
	return response, err
}

// plantSweepAnalysis adds an analysed session of the developer whose model,
// pack text and facet texts carry the marker.
func plantSweepAnalysis(t *testing.T, fixture *readFixture) {
	t.Helper()
	store := fixture.analysis
	store.addSession(t, sweepAnalysisID, fixture.ownFingerprint, 7, 42)
	last := len(store.signals) - 1
	store.signals[last].MainModel = sweepMarker
	key, _ := hex.DecodeString(sweepAnalysisID)
	packAAD, err := sessionanalysis.PackAAD(key)
	if err != nil {
		t.Fatal(err)
	}
	pack := store.packs[sweepAnalysisID]
	if pack.PackEnc, err = store.cipher.Encrypt(packAAD, []byte(sweepMarker)); err != nil {
		t.Fatal(err)
	}
	store.packs[sweepAnalysisID] = pack
	facetAAD, err := sessionanalysis.FacetAAD(key)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(map[string]any{"goal": sweepMarker, "instructions": []string{sweepMarker}, "skill_candidate": sweepMarker,
		"evidence": map[string][]string{"goal": {"E1"}, sweepMarker: {"E1"}}})
	facet := store.facets[sweepAnalysisID]
	if facet.TextEnc, err = store.cipher.Encrypt(facetAAD, text); err != nil {
		t.Fatal(err)
	}
	store.facets[sweepAnalysisID] = facet
	fixture.handler.sessionAnalysis = sweepReports{fixture.reports}
}

// plantSweepOrg replaces the org service with one whose group, project,
// project rule and unattributed identity carry the marker.
func plantSweepOrg(t *testing.T, fixture *readFixture) {
	t.Helper()
	ctx := context.Background()
	service, memory := newOrgTestService(t)
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	repoKey, cwdKey := hex.EncodeToString([]byte("sweep-repo")), hex.EncodeToString([]byte("sweep-cwd"))
	memory.identities = append(memory.identities,
		sealIdentity(t, cipher, repoKey, "s0", orgreport.Identity{Source: orgreport.SourceCodexTurnMetadata, Remotes: []string{"git.example.com/team/" + sweepMarker}}),
		sealIdentity(t, cipher, cwdKey, "s1", orgreport.Identity{Source: orgreport.SourceCwd, Cwd: "/home/dev/" + sweepMarker}))
	start := orgTestWeek.Add(11 * time.Hour).UnixNano()
	for index, identity := range []string{repoKey, cwdKey} {
		at := start + int64(index)*int64(time.Minute)
		memory.requests = append(memory.requests, orgreport.Request{AuditID: "s" + string(rune('0'+index)), StartNS: at, EndNS: at + int64(time.Minute),
			UserID: 7, TokenID: 70, Client: "codex", Role: "main", RootKey: "root-sweep", NodeKey: "root-sweep", IdentityKey: identity})
	}
	group, err := service.CreateGroup(ctx, orgreport.GroupInput{Name: "group-" + sweepMarker, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateProject(ctx, orgreport.ProjectInput{Name: "project-" + sweepMarker, GroupID: nil, Enabled: true,
		Rules: []orgreport.Rule{{Kind: "repo_name", Pattern: sweepMarker}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetMember(ctx, 7, group.ID); err != nil {
		t.Fatal(err)
	}
	fixture.handler.org = service
}

// plantSweepConfig gives both rule kinds and the caller directory marked
// names, patterns and keywords.
func plantSweepConfig(t *testing.T, fixture *readFixture) {
	t.Helper()
	rules, err := uaguard.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Create(context.Background(), uaguard.RuleInput{Name: "rule-" + sweepMarker, Enabled: true,
		ModelPattern: "^" + sweepMarker, UserAgentPattern: "^" + sweepMarker}); err != nil {
		t.Fatal(err)
	}
	fixture.handler.rules = rules
	fixture.handler.policies = &fakeContentPolicyRules{items: []contentpolicy.Rule{{ID: 1, Name: "rule-" + sweepMarker, Enabled: true,
		Action: "block", ModelPattern: "^" + sweepMarker, Keywords: []string{sweepMarker}, UpdatedAtNS: 9}}}
	fixture.handler.users = fakeUserCatalog{snapshot: newapi.UserSnapshot{RefreshedAt: fixtureBase, Users: []newapi.User{
		{ID: 7, Username: "user-" + sweepMarker, DisplayName: "display-" + sweepMarker, Group: "group-" + sweepMarker}}}}
}

// TestFacadeReadsMarkTrafficTextUntrusted: for every facade read endpoint
// (and every export kind whose body the facade builds), as administrator and
// as developer, the marker appears only under keys ending in _untrusted, and
// a response with such a key carries the notice. The content exports
// (conversation, request, response, raw-*) are the audited content itself,
// written to a file: they are exempt by design and not swept.
func TestFacadeReadsMarkTrafficTextUntrusted(t *testing.T) {
	fixture := newReadFixture(t)
	plantSweepAudit(fixture)
	plantSweepInsights(t, fixture)
	plantSweepAnalysis(t, fixture)
	plantSweepOrg(t, fixture)
	plantSweepConfig(t, fixture)

	week := orgTestWeek.Format("2006-01-02")
	window := "from=2026-10-10T11:00:00Z&to=2026-10-10T13:00:00Z"
	calls := map[string][]string{
		"requests.list":       {"/requests?collapse=false", "/requests"},
		"requests.get":        {"/requests/" + sweepAuditID, "/requests/" + sweepAuditID + "?headers=all"},
		"requests.export":     {"/requests/" + sweepAuditID + "/export/headers", "/requests/" + sweepAuditID + "/export/timeline-response"},
		"usage.composition":   {"/requests/" + sweepAuditID + "/composition"},
		"usage.overview":      {"/usage/overview?group_by=model&" + window, "/usage/overview?group_by=client&" + window, "/usage/overview?group_by=caller&" + window, "/usage/overview?group_by=token&" + window},
		"usage.sessions":      {"/usage/sessions?" + window},
		"usage.trend":         {"/usage/sessions/" + sweepSessionID + "/trend"},
		"usage.tree":          {"/usage/trees/" + sweepTreeID},
		"weekly.me":           {"/weekly/me"},
		"weekly.report":       {"/weekly/report", "/weekly/report?week=" + week},
		"weekly.trend":        {"/weekly/trend?weeks=2"},
		"weekly.project":      {"/weekly/projects/-1", "/weekly/projects/-2", "/weekly/projects/102"},
		"weekly.unattributed": {"/weekly/unattributed"},
		"analysis.overview":   {"/analysis/overview?" + window},
		"analysis.users":      {"/analysis/users?" + window},
		"analysis.sessions":   {"/analysis/sessions?" + window},
		"analysis.pack":       {"/analysis/sessions/" + sweepAnalysisID + "/pack"},
		"analysis.facet":      {"/analysis/sessions/" + sweepAnalysisID + "/facet"},
		"analysis.report":     {"/analysis/report"},
		"config.show":         {"/config/ua-rule", "/config/content-rule", "/config/org", "/config/weekly-settings", "/config/analysis-settings"},
		"callers.list":        {"/callers"},
		"status":              {"/status"},
	}
	posts := map[string]string{"config.project-preview": `{"group_id":null,"rules":[{"kind":"repo_name","pattern":"` + sweepMarker + `"}]}`}
	for _, endpoint := range agentapi.ReadEndpoints {
		if _, ok := calls[endpoint.ID]; !ok {
			if _, ok := posts[endpoint.ID]; !ok {
				t.Errorf("read endpoint %s is not swept", endpoint.ID)
			}
		}
	}
	// Where the marker must show up at all, so the sweep is not vacuous.
	mustCarry := map[string]bool{
		"/requests?collapse=false": true, "/requests/" + sweepAuditID: true, "/requests/" + sweepAuditID + "/export/headers": true,
		"/requests/" + sweepAuditID + "/composition": true, "/usage/overview?group_by=model&" + window: true,
		"/usage/sessions?" + window: true, "/usage/sessions/" + sweepSessionID + "/trend": true, "/usage/trees/" + sweepTreeID: true,
		"/weekly/projects/102": true, "/weekly/unattributed": true, "/analysis/sessions?" + window: true,
		"/analysis/sessions/" + sweepAnalysisID + "/pack": true, "/analysis/sessions/" + sweepAnalysisID + "/facet": true,
		"/analysis/report": true, "/config/ua-rule": true, "/config/content-rule": true, "/config/org": true, "/callers": true,
	}
	carried := map[string]bool{}
	check := func(label, path string, response []byte, envelope bool) {
		var decoded any
		if err := json.Unmarshal(response, &decoded); err != nil {
			t.Errorf("%s: not JSON: %.200s", label, response)
			return
		}
		var leaks []string
		untrustedLeaks(decoded, "", "", &leaks)
		for _, leak := range leaks {
			t.Errorf("%s: traffic text under a plain key at %s", label, leak)
		}
		if containsMarker(string(response)) {
			carried[path] = true
		}
		if envelope {
			object, _ := decoded.(map[string]any)
			if hasUntrustedKey(object["data"]) && object["notice"] != agentapi.UntrustedNotice {
				t.Errorf("%s: _untrusted fields without the notice", label)
			}
		}
	}
	for _, identity := range []struct {
		name, token string
	}{{"administrator", fixture.adminRead}, {"developer", fixture.developer}} {
		for id, paths := range calls {
			for _, path := range paths {
				response := fixture.facade(http.MethodGet, path, "", identity.token)
				if response.Code != http.StatusOK {
					if identity.name == "administrator" {
						t.Errorf("%s %s = %d %s", identity.name, path, response.Code, response.Body.String())
					}
					continue
				}
				check(identity.name+" "+path, path, response.Body.Bytes(), id != "requests.export")
			}
		}
		for _, body := range posts {
			response := fixture.facade(http.MethodPost, "/config/project-preview", body, identity.token)
			if response.Code == http.StatusOK {
				check(identity.name+" project preview", "/config/project-preview", response.Body.Bytes(), true)
			} else if identity.name == "administrator" {
				t.Errorf("project preview = %d %s", response.Code, response.Body.String())
			}
		}
	}
	for path := range mustCarry {
		if !carried[path] {
			t.Errorf("%s never carried the marker: it was not planted where the sweep expects it", path)
		}
	}
}
