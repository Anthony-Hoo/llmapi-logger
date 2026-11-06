package web

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
)

// orgMemory is an in-memory orgreport.Repository and DataStore.
type orgMemory struct {
	mu         sync.Mutex
	next       int64
	requests   []orgreport.Request
	identities []orgreport.SealedIdentity
}

func (memory *orgMemory) LoadOrgCatalog(context.Context) (orgreport.Catalog, error) {
	return orgreport.Catalog{}, nil
}
func (memory *orgMemory) id() int64 {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.next++
	return memory.next
}
func (memory *orgMemory) CreateProjectGroup(_ context.Context, group orgreport.Group) (orgreport.Group, error) {
	group.ID = memory.id()
	return group, nil
}
func (memory *orgMemory) UpdateProjectGroup(context.Context, orgreport.Group) error { return nil }
func (memory *orgMemory) DeleteProjectGroup(context.Context, int64) error           { return nil }
func (memory *orgMemory) CreateProject(_ context.Context, project orgreport.Project) (orgreport.Project, error) {
	project.ID = memory.id()
	return project, nil
}
func (memory *orgMemory) UpdateProject(context.Context, orgreport.Project) error       { return nil }
func (memory *orgMemory) DeleteProject(context.Context, int64) error                   { return nil }
func (memory *orgMemory) SetGroupMember(context.Context, orgreport.Member) error       { return nil }
func (memory *orgMemory) DeleteGroupMember(context.Context, int64) error               { return nil }
func (memory *orgMemory) SetPrincipalClass(context.Context, orgreport.Principal) error { return nil }
func (memory *orgMemory) DeletePrincipalClass(context.Context, string, int64) error    { return nil }
func (memory *orgMemory) LoadOrgRequests(_ context.Context, fromNS, toNS int64) ([]orgreport.Request, error) {
	out := []orgreport.Request{}
	for _, request := range memory.requests {
		if request.StartNS >= fromNS && request.StartNS < toNS {
			out = append(out, request)
		}
	}
	return out, nil
}
func (memory *orgMemory) LoadOrgIdentities(context.Context, int64, int64) ([]orgreport.SealedIdentity, error) {
	return memory.identities, nil
}

var orgTestWeek = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

func sealIdentity(t *testing.T, cipher security.Cipher, key, auditID string, identity orgreport.Identity) orgreport.SealedIdentity {
	t.Helper()
	aad, err := orgreport.IdentityAAD(auditID, 1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(identity)
	sealed, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return orgreport.SealedIdentity{Key: key, AuditID: auditID, Version: 1, Enc: sealed}
}

// newOrgTestService builds a real service over a synthetic week: user 7
// works 10 minutes in a repository, user 8 in an unconfigured directory.
func newOrgTestService(t *testing.T) (*orgreport.Service, *orgMemory) {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	repoKey, dirKey := hex.EncodeToString([]byte("repo")), hex.EncodeToString([]byte("dir"))
	memory := &orgMemory{next: 100}
	start := orgTestWeek.Add(9 * time.Hour).UnixNano()
	for index := int64(0); index < 5; index++ {
		at := start + index*int64(2*time.Minute)
		memory.requests = append(memory.requests,
			orgreport.Request{AuditID: "a" + string(rune('0'+index)), StartNS: at, EndNS: at + int64(time.Minute), UserID: 7, TokenID: 70,
				Client: "codex", Role: "main", RootKey: "root-7", NodeKey: "root-7", IdentityKey: repoKey, CostUSD: 0.1, Billed: true},
			orgreport.Request{AuditID: "b" + string(rune('0'+index)), StartNS: at, EndNS: at + int64(time.Minute), UserID: 8, TokenID: 80,
				Client: "codex", Role: "main", RootKey: "root-8", NodeKey: "root-8", IdentityKey: dirKey})
	}
	memory.identities = []orgreport.SealedIdentity{
		sealIdentity(t, cipher, repoKey, "a0", orgreport.Identity{Source: orgreport.SourceCodexTurnMetadata, Remotes: []string{"git.example.com/team/demo"}, Roots: []string{"/home/dev/demo"}}),
		sealIdentity(t, cipher, dirKey, "b0", orgreport.Identity{Source: orgreport.SourceCwd, Cwd: "/home/dev/scratch"}),
	}
	settings := orgreport.Settings{
		Location: time.UTC, WeekStart: time.Monday, IdleGap: 180 * time.Second,
		RankedClients: map[string]bool{"codex": true}, MaxConcurrentRoots: 10, MaxSingleRequestRoots: 200,
	}
	service, err := orgreport.NewService(context.Background(), orgreport.Options{
		Settings: settings, Repository: memory, Data: memory, Cipher: cipher,
		Now: func() time.Time { return orgTestWeek.Add(3 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, memory
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

func decodeOrg[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode %q: %v", response.Body.String(), err)
	}
	return value
}

func TestOrgRoutesAre404WhenDisabled(t *testing.T) {
	t.Parallel()
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil)})
	cookie := developerSignIn(t, handler)
	for _, path := range []string{"/api/v1/org", "/api/v1/org/settings", "/api/v1/org/weekly", "/api/v1/org/me/weekly", "/api/v1/org/catalog"} {
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
	session := decodeOrg[map[string]any](t, orgRequest(t, handler, http.MethodGet, "/api/v1/session", "", nil))
	if session["org_reports_enabled"] != false {
		t.Fatalf("session = %v, want org_reports_enabled false", session)
	}
}

func TestOrgRoutesAreAdministratorOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	service, _ := newOrgTestService(t)
	handler := newDeveloperHandler(t, Options{Developer: developerOptions(t, newapi.TokenIdentity{UserID: 7}, nil), Org: service})
	cookie := developerSignIn(t, handler)

	response := orgRequest(t, handler, http.MethodGet, "/api/v1/org/settings", "", nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("admin settings status = %d headers = %v", response.Code, response.Header())
	}
	if settings := decodeOrg[orgreport.PublicSettings](t, response); settings.Timezone != "UTC" {
		t.Fatalf("settings = %+v", settings)
	}
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/org/settings"}, {http.MethodGet, "/api/v1/org/catalog"},
		{http.MethodPost, "/api/v1/org/groups"}, {http.MethodPut, "/api/v1/org/groups/1"}, {http.MethodDelete, "/api/v1/org/groups/1"},
		{http.MethodPost, "/api/v1/org/projects"}, {http.MethodPost, "/api/v1/org/projects/preview"},
		{http.MethodPut, "/api/v1/org/members/7"}, {http.MethodPut, "/api/v1/org/principals/user/7"},
		{http.MethodGet, "/api/v1/org/unattributed"}, {http.MethodGet, "/api/v1/org/weekly"},
		{http.MethodGet, "/api/v1/org/weekly/trend"}, {http.MethodGet, "/api/v1/org/projects/1/weekly"},
	} {
		response := orgRequest(t, handler, endpoint.method, endpoint.path, "{}", cookie)
		if response.Code != http.StatusForbidden || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("developer %s %s status = %d, want 403 no-store", endpoint.method, endpoint.path, response.Code)
		}
	}
	session := decodeOrg[map[string]any](t, orgRequest(t, handler, http.MethodGet, "/api/v1/session", "", cookie))
	if session["org_reports_enabled"] != true {
		t.Fatalf("session = %v, want org_reports_enabled true", session)
	}
}

func TestOrgCatalogAdministration(t *testing.T) {
	t.Parallel()
	service, _ := newOrgTestService(t)
	handler := newDeveloperHandler(t, Options{Org: service})

	response := orgRequest(t, handler, http.MethodPost, "/api/v1/org/groups", `{"name":"Platform","enabled":true}`, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create group = %d %s", response.Code, response.Body.String())
	}
	group := decodeOrg[orgreport.Group](t, response)
	if response := orgRequest(t, handler, http.MethodPost, "/api/v1/org/groups", `{"name":"platform","enabled":true}`, nil); response.Code != http.StatusConflict {
		t.Fatalf("duplicate group = %d", response.Code)
	}
	if response := orgRequest(t, handler, http.MethodPost, "/api/v1/org/groups", `{"name":"x","unknown":1}`, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", response.Code)
	}
	body := `{"name":"Demo","group_id":` + jsonInt(group.ID) + `,"enabled":true,"rules":[{"kind":"repo_url","pattern":"git.example.com/team/*"}]}`
	response = orgRequest(t, handler, http.MethodPost, "/api/v1/org/projects", body, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create project = %d %s", response.Code, response.Body.String())
	}
	project := decodeOrg[orgreport.Project](t, response)
	if response := orgRequest(t, handler, http.MethodPut, "/api/v1/org/projects/"+jsonInt(project.ID), `{"name":"Demo","enabled":true,"rules":[{"kind":"regex","pattern":".*"}]}`, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid rule = %d", response.Code)
	}
	if response := orgRequest(t, handler, http.MethodPut, "/api/v1/org/members/7", `{"group_id":`+jsonInt(group.ID)+`}`, nil); response.Code != http.StatusOK {
		t.Fatalf("set member = %d %s", response.Code, response.Body.String())
	}
	if response := orgRequest(t, handler, http.MethodPut, "/api/v1/org/members/7", `{"group_id":999}`, nil); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown group member = %d", response.Code)
	}
	if response := orgRequest(t, handler, http.MethodPut, "/api/v1/org/principals/token/80", `{"class":"service"}`, nil); response.Code != http.StatusOK {
		t.Fatalf("set principal = %d", response.Code)
	}
	if response := orgRequest(t, handler, http.MethodPut, "/api/v1/org/principals/team/80", `{"class":"service"}`, nil); response.Code != http.StatusNotFound {
		t.Fatalf("unknown principal kind = %d", response.Code)
	}
	if response := orgRequest(t, handler, http.MethodDelete, "/api/v1/org/groups/"+jsonInt(group.ID), "", nil); response.Code != http.StatusConflict {
		t.Fatalf("delete busy group = %d", response.Code)
	}
	catalog := decodeOrg[orgreport.CatalogView](t, orgRequest(t, handler, http.MethodGet, "/api/v1/org/catalog", "", nil))
	if len(catalog.Groups) != 1 || len(catalog.Projects) != 1 || len(catalog.Members) != 1 || len(catalog.Principals) != 1 {
		t.Fatalf("catalog = %+v", catalog)
	}

	// Preview and unattributed see the synthetic week.
	preview := decodeOrg[orgreport.PreviewResult](t, orgRequest(t, handler, http.MethodPost, "/api/v1/org/projects/preview",
		`{"week":"2026-11-02","rules":[{"kind":"repo_name","pattern":"scratch"}]}`, nil))
	if preview.Requests != 5 || preview.Identities != 1 || preview.Users != 1 || preview.Unattributed != 5 {
		t.Fatalf("preview = %+v", preview)
	}
	response = orgRequest(t, handler, http.MethodGet, "/api/v1/org/unattributed?week=2026-11-02&limit=5", "", nil)
	unattributed := decodeOrg[struct {
		Items []orgreport.UnattributedEntry `json:"items"`
	}](t, response)
	if len(unattributed.Items) != 1 || unattributed.Items[0].Value != "/home/dev/scratch" || unattributed.Items[0].DraftRule.Pattern != "scratch" {
		t.Fatalf("unattributed = %+v", unattributed.Items)
	}
	if response := orgRequest(t, handler, http.MethodGet, "/api/v1/org/unattributed?week=2026-11-03", "", nil); response.Code != http.StatusBadRequest {
		t.Fatalf("non-week-start = %d", response.Code)
	}
}

func jsonInt(value int64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
