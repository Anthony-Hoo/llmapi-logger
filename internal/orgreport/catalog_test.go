package orgreport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func groupID(id int64) *int64 { return &id }

func testCatalog() Catalog {
	return Catalog{
		Groups: []Group{{ID: 1, Name: "Platform", Enabled: true}, {ID: 2, Name: "Mobile", Enabled: true}, {ID: 3, Name: "Paused", Enabled: false}},
		Projects: []Project{
			{ID: 10, Name: "Shared Monorepo", Enabled: true, Rules: []Rule{{Kind: RuleRepoURL, Pattern: "git.example.com/shared/*"}}},
			{ID: 11, Name: "Platform Fork", GroupID: groupID(1), Enabled: true, Rules: []Rule{{Kind: RuleRepoURL, Pattern: "git.example.com/shared/monorepo"}}},
			{ID: 12, Name: "Billing", Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "billing"}, {Kind: RuleAgentProject, Pattern: "Billing-Service"}}},
			{ID: 13, Name: "Sandbox", Enabled: true, Rules: []Rule{{Kind: RulePathGlob, Pattern: "/srv/sandbox/**"}}},
			{ID: 14, Name: "Disabled", Enabled: false, Rules: []Rule{{Kind: RuleRepoName, Pattern: "anything"}}},
			{ID: 15, Name: "Paused Group Project", GroupID: groupID(3), Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "paused"}}},
			{ID: 16, Name: "OpenCode App", Enabled: true, Rules: []Rule{{Kind: RuleRepoURL, Pattern: "https://git.example.com/team/app.git"}}},
		},
		Members: []Member{{UserID: 100, GroupID: 1}, {UserID: 200, GroupID: 2}, {UserID: 300, GroupID: 3}},
	}
}

func TestResolvePrefersGroupThenSignalStrength(t *testing.T) {
	compiled, err := Compile(testCatalog())
	if err != nil {
		t.Fatal(err)
	}
	monorepo := Identity{Remotes: []string{"git.example.com/shared/monorepo"}}
	tests := []struct {
		name     string
		identity Identity
		group    int64
		roots    []string
		want     ProjectKey
	}{
		{"group rule beats the global project", monorepo, 1, nil, 11},
		{"other groups use the global project", monorepo, 2, nil, 10},
		{"no group uses the global project", monorepo, 0, nil, 10},
		{"declared beats remote", Identity{Declared: "billing-service", Remotes: []string{"git.example.com/shared/x"}}, 0, nil, 12},
		{"repo name of a remote", Identity{Remotes: []string{"git.example.com/team/billing"}}, 0, nil, 12},
		{"repo name as a path segment of a root", Identity{Roots: []string{"c:/work/billing"}}, 0, nil, 12},
		{"cwd mapped to a known root", Identity{Cwd: "/home/dev/billing/pkg/api"}, 0, []string{"/home/dev/billing"}, 12},
		{"cwd itself contains the name", Identity{Cwd: "/home/dev/billing-tools"}, 0, nil, ProjectUnattributed},
		{"path glob over cwd", Identity{Cwd: "/srv/sandbox/a/b"}, 0, nil, 13},
		{"single star stays in one segment", Identity{Cwd: "/srv/other/a"}, 0, nil, ProjectUnattributed},
		{"disabled projects never match", Identity{Roots: []string{"/x/anything"}}, 0, nil, ProjectUnattributed},
		{"projects of a disabled group never match", Identity{Roots: []string{"/x/paused"}}, 3, nil, ProjectUnattributed},
		{"opencode hash matches a literal repo_url", Identity{ProjectHash: OpenCodeProjectHash("git.example.com/team/app")}, 0, nil, 16},
		{"no signal is no context", Identity{}, 1, nil, ProjectNoContext},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiled.Resolve(test.identity, test.group, test.roots); got != test.want {
				t.Fatalf("Resolve = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCompileRejectsInvalidCatalogs(t *testing.T) {
	tests := map[string]func(*Catalog){
		"unknown rule kind":       func(c *Catalog) { c.Projects[0].Rules = []Rule{{Kind: "regex", Pattern: "x"}} },
		"empty pattern":           func(c *Catalog) { c.Projects[0].Rules = []Rule{{Kind: RuleRepoName, Pattern: " "}} },
		"repo name with slash":    func(c *Catalog) { c.Projects[0].Rules = []Rule{{Kind: RuleRepoName, Pattern: "a/b"}} },
		"padded name":             func(c *Catalog) { c.Groups[0].Name = " Platform" },
		"duplicate group name":    func(c *Catalog) { c.Groups[1].Name = "platform" },
		"duplicate project scope": func(c *Catalog) { c.Projects[1].Name, c.Projects[1].GroupID = "billing", nil },
		"unknown project group":   func(c *Catalog) { c.Projects[1].GroupID = groupID(99) },
		"unknown member group":    func(c *Catalog) { c.Members[0].GroupID = 99 },
		"two groups for one user": func(c *Catalog) { c.Members = append(c.Members, Member{UserID: 100, GroupID: 2}) },
		"bad principal class":     func(c *Catalog) { c.Principals = []Principal{{Kind: PrincipalUser, ID: 1, Class: "robot"}} },
		"bad principal kind":      func(c *Catalog) { c.Principals = []Principal{{Kind: "team", ID: 1, Class: ClassService}} },
		"too many rules": func(c *Catalog) {
			for index := 0; index <= MaxRulesPerProject; index++ {
				c.Projects[0].Rules = append(c.Projects[0].Rules, Rule{Kind: RuleRepoName, Pattern: "x"})
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			catalog := testCatalog().clone()
			mutate(&catalog)
			if _, err := Compile(catalog); err == nil {
				t.Fatal("Compile accepted an invalid catalog")
			}
		})
	}
	// Same project name in two different scopes is fine.
	catalog := testCatalog().clone()
	catalog.Projects[1].Name = "Shared Monorepo"
	if _, err := Compile(catalog); err != nil {
		t.Fatalf("same name in a group and globally: %v", err)
	}
}

func TestPrincipalsFromCatalog(t *testing.T) {
	catalog := testCatalog()
	catalog.Principals = []Principal{{Kind: PrincipalUser, ID: 7, Class: ClassService}, {Kind: PrincipalToken, ID: 70, Class: ClassService}, {Kind: PrincipalToken, ID: 71, Class: ClassHuman}}
	compiled, err := Compile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	principals := compiled.Principals()
	if service, byToken := principals.Service(7, 1); !service || byToken {
		t.Fatal("user-level service")
	}
	if service, byToken := principals.Service(8, 70); !service || !byToken {
		t.Fatal("token-level service")
	}
	if service, _ := principals.Service(7, 71); service {
		t.Fatal("a human token overrides its service user")
	}
	if principals.Groups[100] != 1 || compiled.GroupOf(999) != 0 || compiled.ProjectName(12) != "Billing" {
		t.Fatal("membership")
	}
}

// memoryRepository is an in-memory Repository that can fail on demand.
type memoryRepository struct {
	mu      sync.Mutex
	catalog Catalog
	nextID  int64
	fail    error
	calls   int
}

func (repository *memoryRepository) LoadOrgCatalog(context.Context) (Catalog, error) {
	return repository.catalog.clone(), nil
}

func (repository *memoryRepository) record() error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls++
	return repository.fail
}

func (repository *memoryRepository) CreateProjectGroup(_ context.Context, group Group) (Group, error) {
	if err := repository.record(); err != nil {
		return Group{}, err
	}
	repository.nextID++
	group.ID = repository.nextID
	return group, nil
}
func (repository *memoryRepository) UpdateProjectGroup(context.Context, Group) error {
	return repository.record()
}
func (repository *memoryRepository) DeleteProjectGroup(context.Context, int64) error {
	return repository.record()
}
func (repository *memoryRepository) CreateProject(_ context.Context, project Project) (Project, error) {
	if err := repository.record(); err != nil {
		return Project{}, err
	}
	repository.nextID++
	project.ID = repository.nextID
	return project, nil
}
func (repository *memoryRepository) UpdateProject(context.Context, Project) error {
	return repository.record()
}
func (repository *memoryRepository) DeleteProject(context.Context, int64) error {
	return repository.record()
}
func (repository *memoryRepository) SetGroupMember(context.Context, Member) error {
	return repository.record()
}
func (repository *memoryRepository) DeleteGroupMember(context.Context, int64) error {
	return repository.record()
}
func (repository *memoryRepository) SetPrincipalClass(context.Context, Principal) error {
	return repository.record()
}
func (repository *memoryRepository) DeletePrincipalClass(context.Context, string, int64) error {
	return repository.record()
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	settings := testSettings()
	settings.AdminUserID = 1
	service, err := NewService(context.Background(), Options{Settings: settings, Repository: repository, Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestServiceCRUDPersistsThenSwapsTheSnapshot(t *testing.T) {
	repository := &memoryRepository{nextID: 100}
	service := newTestService(t, repository)
	ctx := context.Background()

	group, err := service.CreateGroup(ctx, GroupInput{Name: "Platform", Enabled: true})
	if err != nil || group.ID != 101 {
		t.Fatalf("group = %+v err = %v", group, err)
	}
	project, err := service.CreateProject(ctx, ProjectInput{Name: "Core", GroupID: &group.ID, Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: " core "}}})
	if err != nil || project.ID != 102 || project.Rules[0].Pattern != "core" {
		t.Fatalf("project = %+v err = %v", project, err)
	}
	if _, err := service.SetMember(ctx, 500, group.ID); err != nil {
		t.Fatal(err)
	}
	if got := service.Compiled().Resolve(Identity{Roots: []string{"/w/core"}}, 101, nil); got != 102 {
		t.Fatalf("resolve after create = %d", got)
	}

	// An invalid rule is rejected before persistence and the snapshot stays.
	calls := repository.calls
	if _, err := service.UpdateProject(ctx, project.ID, ProjectInput{Name: "Core", GroupID: &group.ID, Enabled: true, Rules: []Rule{{Kind: "regex", Pattern: ".*"}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid update = %v", err)
	}
	if repository.calls != calls {
		t.Fatal("an invalid catalog reached the repository")
	}
	if got := service.Compiled().Resolve(Identity{Roots: []string{"/w/core"}}, 101, nil); got != 102 {
		t.Fatal("failed compile replaced the snapshot")
	}

	// A repository failure keeps the old snapshot too.
	repository.fail = errors.New("database down")
	if _, err := service.UpdateProject(ctx, project.ID, ProjectInput{Name: "Core", GroupID: &group.ID, Enabled: false, Rules: project.Rules}); err == nil {
		t.Fatal("repository failure ignored")
	}
	repository.fail = nil
	if got := service.Compiled().Resolve(Identity{Roots: []string{"/w/core"}}, 101, nil); got != 102 {
		t.Fatal("failed persistence replaced the snapshot")
	}

	// A group with projects or members cannot be deleted.
	if err := service.DeleteGroup(ctx, group.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete busy group = %v", err)
	}
	if err := service.DeleteProject(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteMember(ctx, 500); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteGroup(ctx, group.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice = %v", err)
	}

	// The NewAPI administrator is a service candidate until classified.
	if view := service.Catalog(); len(view.ServiceCandidates) != 1 || view.ServiceCandidates[0] != 1 {
		t.Fatalf("candidates = %v", view.ServiceCandidates)
	}
	if _, err := service.SetPrincipal(ctx, PrincipalUser, 1, ClassService); err != nil {
		t.Fatal(err)
	}
	if view := service.Catalog(); len(view.ServiceCandidates) != 0 || len(view.Principals) != 1 {
		t.Fatalf("view = %+v", view)
	}
	if _, err := service.SetPrincipal(ctx, PrincipalUser, 1, "robot"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad class = %v", err)
	}
	if err := service.DeletePrincipal(ctx, PrincipalToken, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing principal = %v", err)
	}
}

func TestServiceWithoutRepositoryIsReadOnly(t *testing.T) {
	service := newTestService(t, nil)
	if _, err := service.CreateGroup(context.Background(), GroupInput{Name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create = %v", err)
	}
}

func TestAttributeInheritsThenResolvesPerUser(t *testing.T) {
	compiled, err := Compile(testCatalog())
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]Identity{
		"mono": {Remotes: []string{"git.example.com/shared/monorepo"}, Roots: []string{"/home/a/monorepo"}},
		"cwd":  {Cwd: "/home/a/monorepo/sub"},
		"chat": {Cwd: "/tmp/scratch"},
	}
	requests := []Request{
		{AuditID: "1", StartNS: 1, UserID: 100, RootKey: "r", NodeKey: "n"},
		{AuditID: "2", StartNS: 2, UserID: 100, RootKey: "r", NodeKey: "n", IdentityKey: "mono"},
		{AuditID: "3", StartNS: 3, UserID: 200, RootKey: "q", NodeKey: "m", IdentityKey: "mono"},
		{AuditID: "4", StartNS: 4, UserID: 100, RootKey: "s", NodeKey: "o", IdentityKey: "cwd"},
		{AuditID: "5", StartNS: 5, UserID: 100, RootKey: "t", NodeKey: "p", IdentityKey: "chat"},
		{AuditID: "6", StartNS: 6, UserID: 100},
		{AuditID: "7", StartNS: 7, UserID: 100, RootKey: "u", IdentityKey: "unknown-key"},
	}
	Attribute(requests, identities, compiled)
	want := []ProjectKey{11, 11, 10, ProjectUnattributed, ProjectUnattributed, ProjectNoContext, ProjectUnattributed}
	for index, request := range requests {
		if request.Project != want[index] {
			t.Errorf("request %s project = %d, want %d", request.AuditID, request.Project, want[index])
		}
	}
	// The cwd below the known monorepo root resolves once a path rule exists.
	catalog := testCatalog()
	catalog.Projects = append(catalog.Projects, Project{ID: 20, Name: "Mono Path", Enabled: true, Rules: []Rule{{Kind: RulePathGlob, Pattern: "/home/*/monorepo"}}})
	withPath, err := Compile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	again := []Request{{AuditID: "1", UserID: 100, RootKey: "r", IdentityKey: "mono"}, {AuditID: "2", UserID: 100, RootKey: "s", IdentityKey: "cwd"}}
	Attribute(again, identities, withPath)
	if again[1].Project != 20 {
		t.Fatalf("cwd to known root = %d", again[1].Project)
	}
}

func TestGlobRulesKeepNonASCIICharacters(t *testing.T) {
	rules, err := CompileRules([]Rule{{Kind: RulePathGlob, Pattern: "/work/项目/**"}, {Kind: RulePathGlob, Pattern: "/work/caf?/x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !MatchRules(rules[:1], Identity{Cwd: "/work/项目/src"}, nil) {
		t.Fatal("a non-ASCII path glob does not match its own directory")
	}
	if MatchRules(rules[:1], Identity{Cwd: "/work/其他/src"}, nil) {
		t.Fatal("a non-ASCII path glob matches another directory")
	}
	// "?" is one character, also when that character takes several bytes.
	if !MatchRules(rules[1:], Identity{Cwd: "/work/café/x"}, nil) {
		t.Fatal("? does not match one multi-byte character")
	}
}

func TestDraftRules(t *testing.T) {
	if rule := draftRule(RuleRepoURL, "git.example.com/a/b"); rule.Kind != RuleRepoURL || rule.Pattern != "git.example.com/a/b" {
		t.Fatalf("remote draft = %+v", rule)
	}
	if rule := draftRule(RulePathGlob, "/home/dev/tool"); rule.Kind != RuleRepoName || rule.Pattern != "tool" {
		t.Fatalf("path draft = %+v", rule)
	}
	rules, err := CompileRules([]Rule{draftRule(RulePathGlob, "/home/dev/tool")})
	if err != nil || !MatchRules(rules, Identity{Cwd: "/home/dev/tool"}, nil) {
		t.Fatalf("draft does not match its own source: %v", err)
	}
}
