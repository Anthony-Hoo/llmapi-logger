package orgreport

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// rowOrgRepository stores the catalog like a database and counts writes.
type rowOrgRepository struct {
	mu      sync.Mutex
	catalog Catalog
	nextID  int64
	writes  int
}

func (repository *rowOrgRepository) LoadOrgCatalog(context.Context) (Catalog, error) {
	return repository.rows(), nil
}

func (repository *rowOrgRepository) rows() Catalog {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.catalog.clone()
}

func (repository *rowOrgRepository) write(change func(*Catalog) error) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	return change(&repository.catalog)
}

func (repository *rowOrgRepository) CreateProjectGroup(_ context.Context, group Group) (Group, error) {
	err := repository.write(func(catalog *Catalog) error {
		repository.nextID++
		group.ID = repository.nextID
		catalog.Groups = append(catalog.Groups, group)
		return nil
	})
	return group, err
}

func (repository *rowOrgRepository) UpdateProjectGroup(_ context.Context, group Group) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Groups {
			if catalog.Groups[index].ID == group.ID {
				catalog.Groups[index] = group
				return nil
			}
		}
		return ErrNotFound
	})
}

func (repository *rowOrgRepository) DeleteProjectGroup(_ context.Context, id int64) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Groups {
			if catalog.Groups[index].ID == id {
				catalog.Groups = append(catalog.Groups[:index], catalog.Groups[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (repository *rowOrgRepository) CreateProject(_ context.Context, project Project) (Project, error) {
	err := repository.write(func(catalog *Catalog) error {
		repository.nextID++
		project.ID = repository.nextID
		catalog.Projects = append(catalog.Projects, cloneProject(project))
		return nil
	})
	return project, err
}

func (repository *rowOrgRepository) UpdateProject(_ context.Context, project Project) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Projects {
			if catalog.Projects[index].ID == project.ID {
				catalog.Projects[index] = cloneProject(project)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (repository *rowOrgRepository) DeleteProject(_ context.Context, id int64) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Projects {
			if catalog.Projects[index].ID == id {
				catalog.Projects = append(catalog.Projects[:index], catalog.Projects[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (repository *rowOrgRepository) SetGroupMember(_ context.Context, member Member) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Members {
			if catalog.Members[index].UserID == member.UserID {
				catalog.Members[index] = member
				return nil
			}
		}
		catalog.Members = append(catalog.Members, member)
		return nil
	})
}

func (repository *rowOrgRepository) DeleteGroupMember(_ context.Context, userID int64) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Members {
			if catalog.Members[index].UserID == userID {
				catalog.Members = append(catalog.Members[:index], catalog.Members[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

func (repository *rowOrgRepository) SetPrincipalClass(_ context.Context, principal Principal) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Principals {
			if catalog.Principals[index].Kind == principal.Kind && catalog.Principals[index].ID == principal.ID {
				catalog.Principals[index] = principal
				return nil
			}
		}
		catalog.Principals = append(catalog.Principals, principal)
		return nil
	})
}

func (repository *rowOrgRepository) DeletePrincipalClass(_ context.Context, kind string, id int64) error {
	return repository.write(func(catalog *Catalog) error {
		for index := range catalog.Principals {
			if catalog.Principals[index].Kind == kind && catalog.Principals[index].ID == id {
				catalog.Principals = append(catalog.Principals[:index], catalog.Principals[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

// agentFixture: groups 1 Platform and 2 Data, project 10 in group 1 with two
// rules, project 11 global, member 7 in group 1, token 70 a service. The
// clock is pinned, so only the version bump separates two writes.
func agentFixture(t *testing.T) (*Service, *rowOrgRepository) {
	t.Helper()
	repository := &rowOrgRepository{nextID: 100, catalog: Catalog{
		Groups: []Group{
			{ID: 1, Name: "Platform", Enabled: true, CreatedAtNS: 5, UpdatedAtNS: 6},
			{ID: 2, Name: "Data", Enabled: false, CreatedAtNS: 5, UpdatedAtNS: 7},
		},
		Projects: []Project{
			{ID: 10, Name: "Demo", GroupID: groupID(1), Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "demo"}, {Kind: RuleRepoURL, Pattern: "https://Git.Example.com/team/demo.git"}}, CreatedAtNS: 5, UpdatedAtNS: 8},
			{ID: 11, Name: "Tools", Enabled: false, Rules: []Rule{{Kind: RulePathGlob, Pattern: "/srv/tools/**"}}, CreatedAtNS: 5, UpdatedAtNS: 9},
		},
		Members:    []Member{{UserID: 7, GroupID: 1, UpdatedAtNS: 10}},
		Principals: []Principal{{Kind: PrincipalToken, ID: 70, Class: ClassService, UpdatedAtNS: 11}},
	}}
	return newTestService(t, repository), repository
}

func jsonFields(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func assertOnlyChanged(t *testing.T, before, after any, changed ...string) {
	t.Helper()
	beforeFields, afterFields := jsonFields(t, before), jsonFields(t, after)
	allowed := map[string]bool{"updated_at_ns": true}
	for _, field := range changed {
		allowed[field] = true
	}
	for field, value := range beforeFields {
		if !allowed[field] && !reflect.DeepEqual(afterFields[field], value) {
			t.Fatalf("%s changed from %v to %v", field, value, afterFields[field])
		}
	}
}

func strp(value string) *string { return &value }
func boolp(value bool) *bool    { return &value }

func projectOf(t *testing.T, service *Service, id int64) Project {
	t.Helper()
	for _, project := range service.Catalog().Projects {
		if project.ID == id {
			return project
		}
	}
	t.Fatalf("project %d missing", id)
	return Project{}
}

func groupOf(t *testing.T, service *Service, id int64) Group {
	t.Helper()
	for _, group := range service.Catalog().Groups {
		if group.ID == id {
			return group
		}
	}
	t.Fatalf("group %d missing", id)
	return Group{}
}

func TestOrgPatchChangesOnlyTheGivenField(t *testing.T) {
	ctx := context.Background()
	service, repository := agentFixture(t)

	group := groupOf(t, service, 1)
	patchedGroup, err := service.PatchGroup(ctx, 1, group.Version(), GroupPatch{Name: strp("  Platform Team ")})
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyChanged(t, group, patchedGroup, "name")
	if patchedGroup.Name != "Platform Team" || !patchedGroup.Enabled || patchedGroup.Version() <= group.Version() {
		t.Fatalf("patched group = %+v", patchedGroup)
	}

	project := projectOf(t, service, 10)
	patched, err := service.PatchProject(ctx, 10, project.Version(), ProjectChange{Set: ProjectPatch{Enabled: boolp(false)}})
	if err != nil {
		t.Fatal(err)
	}
	assertOnlyChanged(t, project, patched, "enabled")
	if patched.Enabled || !reflect.DeepEqual(patched.Rules, project.Rules) || *patched.GroupID != 1 {
		t.Fatalf("patched project = %+v", patched)
	}
	// group_id: absent keeps, null makes the project global.
	global, err := service.PatchProject(ctx, 10, patched.Version(), ProjectChange{Set: ProjectPatch{GroupID: GroupIDOf(nil)}})
	if err != nil || global.GroupID != nil || global.Enabled {
		t.Fatalf("global = %+v, %v", global, err)
	}
	stored := repository.rows()
	if !reflect.DeepEqual(stored.Projects[0], global) || !reflect.DeepEqual(stored.Groups[0], patchedGroup) {
		t.Fatalf("stored %+v / %+v", stored.Projects[0], stored.Groups[0])
	}
	if !reflect.DeepEqual(service.Catalog().Projects[0], global) {
		t.Fatal("snapshot differs from the returned project")
	}
}

func TestOrgStaleVersionsAreRefusedAndNothingChanges(t *testing.T) {
	ctx := context.Background()
	service, repository := agentFixture(t)
	rows, snapshot := repository.rows(), service.current.Load()
	for _, version := range []int64{1, AnyVersion} {
		if _, err := service.PatchGroup(ctx, 1, version, GroupPatch{Enabled: boolp(false)}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("group patch = %v", err)
		}
		if err := service.DeleteGroupIfVersion(ctx, 2, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("group delete = %v", err)
		}
		if _, err := service.PatchProject(ctx, 10, version, ProjectChange{Set: ProjectPatch{Enabled: boolp(false)}}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("project patch = %v", err)
		}
		if err := service.DeleteProjectIfVersion(ctx, 11, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("project delete = %v", err)
		}
		if _, err := service.SetMemberIfVersion(ctx, 7, 2, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("member set = %v", err)
		}
		if err := service.DeleteMemberIfVersion(ctx, 7, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("member delete = %v", err)
		}
		if _, err := service.SetPrincipalIfVersion(ctx, PrincipalToken, 70, ClassHuman, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("principal set = %v", err)
		}
		if err := service.DeletePrincipalIfVersion(ctx, PrincipalToken, 70, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("principal delete = %v", err)
		}
	}
	// 0 means "does not exist yet": refused for an existing member, and a
	// non-zero version is refused for a user without a group.
	if _, err := service.SetMemberIfVersion(ctx, 7, 2, 0); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("member set at 0 = %v", err)
	}
	if _, err := service.SetMemberIfVersion(ctx, 8, 2, 10); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("new member at 10 = %v", err)
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.rows(), rows) || service.current.Load() != snapshot {
		t.Fatal("a refused write changed the database or the snapshot")
	}
	if member, err := service.SetMemberIfVersion(ctx, 8, 2, 0); err != nil || member.GroupID != 2 {
		t.Fatalf("new member = %+v, %v", member, err)
	}
}

func TestOrgChecksMatchTheRealWriteAndChangeNothing(t *testing.T) {
	ctx := context.Background()
	service, repository := agentFixture(t)
	rows, snapshot := repository.rows(), service.current.Load()

	change := ProjectChange{
		Set:    ProjectPatch{Name: strp(" Demo 2 ")},
		Add:    ProjectListEdit{Rules: []Rule{{Kind: RuleAgentProject, Pattern: " demo-agent\n"}}},
		Remove: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: "DEMO"}}},
	}
	planned, err := service.CheckPatchProject(10, 8, change)
	if err != nil {
		t.Fatal(err)
	}
	groupPlan, err := service.CheckPatchGroup(2, AnyVersion, GroupPatch{Enabled: boolp(true)})
	if err != nil {
		t.Fatal(err)
	}
	createPlan, err := service.CheckCreateProject(ProjectPatch{Name: strp(" New "), GroupID: GroupIDOf(groupID(2)), Enabled: boolp(true), Rules: &[]Rule{{Kind: RuleRepoName, Pattern: " new "}}})
	if err != nil {
		t.Fatal(err)
	}
	groupCreatePlan, err := service.CheckCreateGroup(GroupPatch{Name: strp(" Ops "), Enabled: boolp(true)})
	if err != nil {
		t.Fatal(err)
	}
	memberPlan, err := service.CheckSetMember(7, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	principalPlan, err := service.CheckSetPrincipal(PrincipalUser, 9, ClassService, 0)
	if err != nil {
		t.Fatal(err)
	}
	removedProject, err := service.CheckDeleteProject(11, 9)
	if err != nil || removedProject.ID != 11 {
		t.Fatalf("delete plan = %+v, %v", removedProject, err)
	}
	removedMember, err := service.CheckDeleteMember(7, 10)
	if err != nil || removedMember.UserID != 7 {
		t.Fatalf("member delete plan = %+v, %v", removedMember, err)
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.rows(), rows) || service.current.Load() != snapshot || repository.nextID != 100 {
		t.Fatal("a check wrote, published or numbered something")
	}
	if planned.After.UpdatedAtNS != 8 || createPlan.After.ID != 0 || createPlan.After.CreatedAtNS != 0 || groupCreatePlan.After.Name != "Ops" ||
		memberPlan.Before == nil || memberPlan.After.UpdatedAtNS != 10 || principalPlan.Before != nil || principalPlan.After.UpdatedAtNS != 0 {
		t.Fatalf("plans = %+v / %+v / %+v / %+v / %+v", planned, createPlan, groupCreatePlan, memberPlan, principalPlan)
	}
	if want := []Rule{{Kind: RuleRepoURL, Pattern: "https://Git.Example.com/team/demo.git"}, {Kind: RuleAgentProject, Pattern: "demo-agent"}}; !reflect.DeepEqual(planned.After.Rules, want) {
		t.Fatalf("planned rules = %+v", planned.After.Rules)
	}
	if !reflect.DeepEqual(planned.Changed, []string{"name", "rules"}) {
		t.Fatalf("changed = %v", planned.Changed)
	}

	applied, err := service.PatchProject(ctx, 10, 8, change)
	if err != nil {
		t.Fatal(err)
	}
	want := planned.After
	want.UpdatedAtNS = applied.UpdatedAtNS
	if !reflect.DeepEqual(applied, want) {
		t.Fatalf("applied %+v, planned %+v", applied, planned.After)
	}
	appliedGroup, err := service.PatchGroup(ctx, 2, 7, GroupPatch{Enabled: boolp(true)})
	wantGroup := groupPlan.After
	wantGroup.UpdatedAtNS = appliedGroup.UpdatedAtNS
	if err != nil || !reflect.DeepEqual(appliedGroup, wantGroup) {
		t.Fatalf("group applied %+v, planned %+v (%v)", appliedGroup, groupPlan.After, err)
	}
	created, err := service.CreateProjectFromPatch(ctx, ProjectPatch{Name: strp(" New "), GroupID: GroupIDOf(groupID(2)), Enabled: boolp(true), Rules: &[]Rule{{Kind: RuleRepoName, Pattern: " new "}}})
	wantProject := createPlan.After
	wantProject.ID, wantProject.CreatedAtNS, wantProject.UpdatedAtNS = created.ID, created.CreatedAtNS, created.UpdatedAtNS
	if err != nil || !reflect.DeepEqual(created, wantProject) || created.ID != 101 {
		t.Fatalf("created %+v, planned %+v (%v)", created, createPlan.After, err)
	}
	member, err := service.SetMemberIfVersion(ctx, 7, 2, 10)
	if err != nil || member.GroupID != 2 || member.Version() <= 10 {
		t.Fatalf("member = %+v, %v", member, err)
	}
}

func TestOrgProjectRuleEdits(t *testing.T) {
	service, _ := agentFixture(t)
	for _, test := range []struct {
		name   string
		change ProjectChange
		rules  []Rule
		field  string
		reason string
	}{
		{name: "an equivalent rule is already present",
			change: ProjectChange{Add: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoURL, Pattern: " git.example.com/team/demo "}}}},
			rules:  []Rule{{Kind: RuleRepoName, Pattern: "demo"}, {Kind: RuleRepoURL, Pattern: "https://Git.Example.com/team/demo.git"}}},
		{name: "kind is part of the identity",
			change: ProjectChange{Add: ProjectListEdit{Rules: []Rule{{Kind: RuleAgentProject, Pattern: "demo"}}}},
			rules:  []Rule{{Kind: RuleRepoName, Pattern: "demo"}, {Kind: RuleRepoURL, Pattern: "https://Git.Example.com/team/demo.git"}, {Kind: RuleAgentProject, Pattern: "demo"}}},
		{name: "remove by normalised pattern",
			change: ProjectChange{Remove: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoURL, Pattern: "git.example.com/team/demo"}}}},
			rules:  []Rule{{Kind: RuleRepoName, Pattern: "demo"}}},
		{name: "remove everything leaves no rules",
			change: ProjectChange{Set: ProjectPatch{Rules: &[]Rule{}}}, rules: []Rule{}},
		{name: "remove an absent rule",
			change: ProjectChange{Remove: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: "other"}}}}, field: "rules", reason: ReasonNotPresent},
		{name: "set and edit",
			change: ProjectChange{Set: ProjectPatch{Rules: &[]Rule{}}, Add: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: "x"}}}}, field: "rules", reason: ReasonConflictingEdit},
		{name: "add and remove the same rule",
			change: ProjectChange{Add: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: "x"}}}, Remove: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: " X"}}}}, field: "rules", reason: ReasonAddAndRemove},
		{name: "an added invalid rule is reported at its position",
			change: ProjectChange{Add: ProjectListEdit{Rules: []Rule{{Kind: RuleRepoName, Pattern: "team/x"}}}}, field: "rules[2].pattern", reason: ReasonNotASingleName},
		{name: "an unknown kind",
			change: ProjectChange{Set: ProjectPatch{Rules: &[]Rule{{Kind: RuleRepoName, Pattern: "x"}, {Kind: "regex", Pattern: "y"}}}}, field: "rules[1].kind", reason: ReasonInvalidValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			diff, err := service.CheckPatchProject(10, 8, test.change)
			if test.reason != "" {
				var invalid *ValidationError
				if !errors.As(err, &invalid) || invalid.Field != test.field || invalid.Reason != test.reason || invalid.Object != ObjectProject || invalid.ID != 10 || !errors.Is(err, ErrInvalid) {
					t.Fatalf("err = %v (%+v)", err, invalid)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(diff.After.Rules, test.rules) {
				t.Fatalf("rules = %+v", diff.After.Rules)
			}
		})
	}
}

func TestOrgWebEditBetweenCheckAndPatchConflicts(t *testing.T) {
	ctx := context.Background()
	service, repository := agentFixture(t)
	webEdit := func() {
		t.Helper()
		group, project := groupOf(t, service, 1), projectOf(t, service, 10)
		if _, err := service.UpdateGroup(ctx, 1, GroupInput{Name: group.Name, Enabled: group.Enabled}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.UpdateProject(ctx, 10, ProjectInput{Name: project.Name, GroupID: project.GroupID, Enabled: project.Enabled, Rules: project.Rules}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.SetMember(ctx, 7, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := service.SetPrincipal(ctx, PrincipalToken, 70, ClassService); err != nil {
			t.Fatal(err)
		}
	}
	// First web save: every version is now the pinned clock reading, which
	// the second web save below would repeat without the bump.
	webEdit()
	groupPlan, err := service.CheckPatchGroup(1, AnyVersion, GroupPatch{Enabled: boolp(false)})
	if err != nil {
		t.Fatal(err)
	}
	projectPlan, err := service.CheckPatchProject(10, AnyVersion, ProjectChange{Set: ProjectPatch{Enabled: boolp(false)}})
	if err != nil {
		t.Fatal(err)
	}
	memberPlan, err := service.CheckSetMember(7, 2, AnyVersion)
	if err != nil {
		t.Fatal(err)
	}
	principalPlan, err := service.CheckSetPrincipal(PrincipalToken, 70, ClassHuman, AnyVersion)
	if err != nil {
		t.Fatal(err)
	}
	// The web routes resubmit the same values at the same clock reading; the
	// versions still move.
	webEdit()
	rows := repository.rows()
	if _, err := service.PatchGroup(ctx, 1, groupPlan.Before.Version(), GroupPatch{Enabled: boolp(false)}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("group = %v", err)
	}
	if _, err := service.PatchProject(ctx, 10, projectPlan.Before.Version(), ProjectChange{Set: ProjectPatch{Enabled: boolp(false)}}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("project = %v", err)
	}
	if _, err := service.SetMemberIfVersion(ctx, 7, 2, memberPlan.Before.Version()); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("member = %v", err)
	}
	if _, err := service.SetPrincipalIfVersion(ctx, PrincipalToken, 70, ClassHuman, principalPlan.Before.Version()); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("principal = %v", err)
	}
	if !reflect.DeepEqual(repository.rows(), rows) {
		t.Fatal("a refused write changed the database")
	}
}

func TestOrgValidationErrorsNameTheTargetAndKeepTheirText(t *testing.T) {
	ctx := context.Background()
	service, _ := agentFixture(t)

	// Group 1 comes first in the catalog, so Compile meets the clash on
	// group 2; the error still names group 1, the one being changed.
	_, err := service.CheckPatchGroup(1, 6, GroupPatch{Name: strp("data")})
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.Object != ObjectGroup || invalid.ID != 1 || invalid.Field != "name" || invalid.Reason != ReasonDuplicate ||
		!errors.Is(err, ErrConflict) || err.Error() != "orgreport: conflict: duplicate group name" {
		t.Fatalf("duplicate = %v (%+v)", err, invalid)
	}
	if _, err := service.UpdateGroup(ctx, 1, GroupInput{Name: "data", Enabled: true}); err == nil || err.Error() != "orgreport: conflict: duplicate group name" || !errors.Is(err, ErrConflict) {
		t.Fatalf("web duplicate = %v", err)
	}

	_, err = service.CheckDeleteGroup(1, AnyVersion)
	if !errors.As(err, &invalid) || invalid.Reason != ReasonHasProjects || err.Error() != "orgreport: conflict: the group still has projects" || !errors.Is(err, ErrConflict) {
		t.Fatalf("delete with projects = %v", err)
	}
	if err := service.DeleteGroup(ctx, 1); err == nil || err.Error() != "orgreport: conflict: the group still has projects" {
		t.Fatalf("web delete = %v", err)
	}

	_, err = service.CheckCreateProject(ProjectPatch{Name: strp("x"), GroupID: GroupIDOf(groupID(99)), Enabled: boolp(true), Rules: &[]Rule{}})
	if !errors.As(err, &invalid) || invalid.Field != "group_id" || invalid.Reason != ReasonUnknownGroup || invalid.ID != 0 || err.Error() != "orgreport: invalid input: project references an unknown group" {
		t.Fatalf("unknown group = %v (%+v)", err, invalid)
	}
	_, err = service.CheckCreateProject(ProjectPatch{Name: strp("x"), Enabled: boolp(true), Rules: &[]Rule{}})
	if !errors.As(err, &invalid) || invalid.Field != "group_id" || invalid.Reason != ReasonRequired {
		t.Fatalf("missing group_id = %v", err)
	}
	_, err = service.CheckSetPrincipal(PrincipalUser, 5, "robot", 0)
	if !errors.As(err, &invalid) || invalid.Object != ObjectPrincipal || invalid.Kind != PrincipalUser || invalid.Field != "class" || err.Error() != "orgreport: invalid input: invalid principal" {
		t.Fatalf("principal = %v (%+v)", err, invalid)
	}
	// The page trims a name; the service alone rejects the spaces with the
	// generic message, and the error now says why.
	if _, err := service.UpdateProject(ctx, 11, ProjectInput{Name: " Tools ", Enabled: false, Rules: []Rule{}}); !errors.As(err, &invalid) ||
		invalid.Reason != ReasonSurroundingWhitespace || err.Error() != "orgreport: invalid input: name must be 1-128 bytes without surrounding whitespace" {
		t.Fatalf("web name = %v", err)
	}
}

func TestOptionalGroupIDDecoding(t *testing.T) {
	for _, test := range []struct {
		body string
		set  bool
		id   *int64
	}{
		{`{}`, false, nil}, {`{"group_id":null}`, true, nil}, {`{"group_id":4}`, true, groupID(4)},
	} {
		var patch ProjectPatch
		decoder := json.NewDecoder(strings.NewReader(test.body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&patch); err != nil || patch.GroupID.Set != test.set || !reflect.DeepEqual(patch.GroupID.ID, test.id) {
			t.Fatalf("%s = %+v, %v", test.body, patch.GroupID, err)
		}
	}
	var patch ProjectPatch
	decoder := json.NewDecoder(strings.NewReader(`{"owner":1}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&patch) == nil {
		t.Fatal("unknown field accepted")
	}
}

// ---- settings ----

func settingsAgentFixture(t *testing.T) (*Service, *settingsMemory) {
	t.Helper()
	fixture := newReportFixture(t)
	store := &settingsMemory{}
	fixture.service.file, fixture.service.saved = fileOrgSection(), store
	fixture.service.clients = []ClientOption{{Key: "claude_code"}, {Key: "codex"}, {Key: "opencode"}, {Key: "pi"}}
	return fixture.service, store
}

func TestOrgSettingsPatchKeepsOtherFieldsAndVersions(t *testing.T) {
	ctx := context.Background()
	service, store := settingsAgentFixture(t)
	view, _ := service.EditableSettings(ctx)
	if view.Version() != 0 {
		t.Fatalf("file version = %d", view.Version())
	}
	saved, err := service.PatchSettings(ctx, 0, SettingsChange{Set: SettingsPatch{MaxConcurrentRoots: intp(4)}})
	if err != nil {
		t.Fatal(err)
	}
	want := view.Settings
	want.MaxConcurrentRoots = 4
	if !reflect.DeepEqual(saved.Settings, want) || saved.Version() == 0 || saved.Version() != store.rows[storage.SettingsOrgReports].UpdatedAtNS {
		t.Fatalf("saved = %+v", saved)
	}
	again, err := service.PatchSettings(ctx, saved.Version(), SettingsChange{Set: SettingsPatch{IdleGapSeconds: intp(60)}})
	if err != nil || again.Version() <= saved.Version() || again.Settings.MaxConcurrentRoots != 4 || again.Settings.IdleGapSeconds != 60 {
		t.Fatalf("again = %+v, %v", again, err)
	}
	if service.Settings().IdleGapSeconds != 60 {
		t.Fatal("not applied")
	}
}

func intp(value int) *int { return &value }

func TestOrgSettingsStaleVersionAndChecksChangeNothing(t *testing.T) {
	ctx := context.Background()
	service, store := settingsAgentFixture(t)
	diff, err := service.CheckPatchSettings(ctx, 0, SettingsChange{Set: SettingsPatch{IdleGapSeconds: intp(90)}})
	if err != nil || diff.Version != 0 || diff.After.IdleGapSeconds != 90 || !reflect.DeepEqual(diff.Changed, []string{"idle_gap_seconds"}) {
		t.Fatalf("diff = %+v, %v", diff, err)
	}
	if _, err := service.CheckResetSettings(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 0 || service.Settings().IdleGapSeconds != 180 {
		t.Fatal("a check saved or applied")
	}
	// A web save between the check and the patch, with the clock pinned.
	view, _ := service.EditableSettings(ctx)
	first, err := service.UpdateSettings(ctx, view.Settings)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.UpdateSettings(ctx, view.Settings)
	if err != nil || second.Version() == first.Version() {
		t.Fatalf("two web saves share version %d (%v)", first.Version(), err)
	}
	row := store.rows[storage.SettingsOrgReports]
	for _, version := range []int64{0, first.Version(), AnyVersion} {
		if _, err := service.PatchSettings(ctx, version, SettingsChange{Set: SettingsPatch{IdleGapSeconds: intp(90)}}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("patch at %d = %v", version, err)
		}
		if _, err := service.ResetSettingsIfVersion(ctx, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("reset at %d = %v", version, err)
		}
	}
	if !reflect.DeepEqual(store.rows[storage.SettingsOrgReports], row) || service.Settings().IdleGapSeconds != 180 {
		t.Fatal("a refused write changed something")
	}
	if reset, err := service.ResetSettingsIfVersion(ctx, second.Version()); err != nil || reset.Version() != 0 || len(store.rows) != 0 {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
	// After a reset the next save still gets a new version.
	third, err := service.PatchSettings(ctx, 0, SettingsChange{})
	if err != nil || third.Version() <= second.Version() {
		t.Fatalf("after reset = %+v, %v", third, err)
	}
}

func TestOrgSettingsRankedClients(t *testing.T) {
	ctx := context.Background()
	service, store := settingsAgentFixture(t)
	// A stored list with a duplicate, an unsorted order and a key the
	// vocabulary no longer knows.
	store.rows = map[string]storage.RuntimeSettings{storage.SettingsOrgReports: {Section: storage.SettingsOrgReports, UpdatedAtNS: 5,
		Settings: `{"idle_gap_seconds":120,"ranked_clients":["codex","retired","claude_code"],"max_concurrent_roots":10,"max_single_request_roots":200}`}}

	kept, dropped := service.FormRankedClients([]string{"pi", " codex", "codex", "retired", ""})
	if !reflect.DeepEqual(kept, []string{"codex", "pi"}) || !reflect.DeepEqual(dropped, []string{"retired"}) {
		t.Fatalf("form = %v / %v", kept, dropped)
	}

	diff, err := service.CheckPatchSettings(ctx, 5, SettingsChange{Set: SettingsPatch{IdleGapSeconds: intp(60)}})
	if err != nil || !reflect.DeepEqual(diff.After.RankedClients, []string{"claude_code", "codex"}) || !reflect.DeepEqual(diff.DroppedClients, []string{"retired"}) {
		t.Fatalf("drop on load = %+v, %v", diff, err)
	}
	for _, test := range []struct {
		name    string
		change  SettingsChange
		clients []string
		reason  string
	}{
		{name: "add sorts and ignores a present key", change: SettingsChange{Add: SettingsListEdit{RankedClients: []string{"pi", "codex"}}}, clients: []string{"claude_code", "codex", "pi"}},
		{name: "removing the dropped key is not an error", change: SettingsChange{Remove: SettingsListEdit{RankedClients: []string{"retired"}}}, clients: []string{"claude_code", "codex"}},
		{name: "remove", change: SettingsChange{Remove: SettingsListEdit{RankedClients: []string{" codex"}}}, clients: []string{"claude_code"}},
		{name: "set dedupes and sorts", change: SettingsChange{Set: SettingsPatch{RankedClients: &[]string{"pi", "codex", "pi"}}}, clients: []string{"codex", "pi"}},
		{name: "remove absent", change: SettingsChange{Remove: SettingsListEdit{RankedClients: []string{"opencode"}}}, reason: ReasonNotPresent},
		{name: "keys compare exactly", change: SettingsChange{Remove: SettingsListEdit{RankedClients: []string{"CODEX"}}}, reason: ReasonNotPresent},
		{name: "set and edit", change: SettingsChange{Set: SettingsPatch{RankedClients: &[]string{"pi"}}, Add: SettingsListEdit{RankedClients: []string{"codex"}}}, reason: ReasonConflictingEdit},
		{name: "an explicit unknown key is refused, not dropped", change: SettingsChange{Add: SettingsListEdit{RankedClients: []string{"retired2"}}}, reason: ReasonUnknownClient},
		{name: "emptying the list fails validation", change: SettingsChange{Set: SettingsPatch{RankedClients: &[]string{}}}, reason: ReasonInvalidValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			diff, err := service.CheckPatchSettings(ctx, 5, test.change)
			if test.reason != "" {
				var invalid *SettingsError
				if !errors.As(err, &invalid) || invalid.Reason != test.reason || invalid.Field != "ranked_clients" || !errors.Is(err, ErrInvalidSettings) {
					t.Fatalf("err = %v (%+v)", err, invalid)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(diff.After.RankedClients, test.clients) {
				t.Fatalf("clients = %v, %v", diff.After.RankedClients, err)
			}
		})
	}
	saved, err := service.PatchSettings(ctx, 5, SettingsChange{Set: SettingsPatch{IdleGapSeconds: intp(60)}})
	if err != nil || !reflect.DeepEqual(saved.Settings.RankedClients, []string{"claude_code", "codex"}) {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
}

func TestOrgSettingsErrorsNameTheField(t *testing.T) {
	ctx := context.Background()
	service, _ := settingsAgentFixture(t)
	for _, test := range []struct {
		set   SettingsPatch
		field string
	}{
		{SettingsPatch{IdleGapSeconds: intp(0)}, "idle_gap_seconds"},
		{SettingsPatch{MaxConcurrentRoots: intp(0)}, "max_concurrent_roots"},
		{SettingsPatch{MaxSingleRequestRoots: intp(0)}, "max_single_request_roots"},
		{SettingsPatch{RankedClients: &[]string{"Bad Key"}}, "ranked_clients"},
	} {
		_, err := service.CheckPatchSettings(ctx, AnyVersion, SettingsChange{Set: test.set})
		var invalid *SettingsError
		if !errors.As(err, &invalid) || invalid.Field != test.field || SettingsMessage(err) == "" || !strings.HasPrefix(SettingsMessage(err), "org_reports.") {
			t.Fatalf("%+v = %v (%+v)", test.set, err, invalid)
		}
		// The web entry keeps its message.
		view, _ := service.EditableSettings(ctx)
		edited := view.Settings
		if test.set.IdleGapSeconds != nil {
			edited.IdleGapSeconds = *test.set.IdleGapSeconds
		}
		if test.set.MaxConcurrentRoots != nil {
			edited.MaxConcurrentRoots = *test.set.MaxConcurrentRoots
		}
		if test.set.MaxSingleRequestRoots != nil {
			edited.MaxSingleRequestRoots = *test.set.MaxSingleRequestRoots
		}
		if test.set.RankedClients != nil {
			edited.RankedClients = *test.set.RankedClients
		}
		if _, webErr := service.UpdateSettings(ctx, edited); webErr == nil || webErr.Error() != err.Error() {
			t.Fatalf("web = %v, agent = %v", webErr, err)
		}
	}
}

// ---- weeks ----

func TestWeekState(t *testing.T) {
	ctx := context.Background()
	fixture := newReportFixture(t)
	service := fixture.service
	ended, err := service.WeekState(ctx, "2026-11-02")
	if err != nil || !ended.Ended || ended.Frozen || ended.Week != "2026-11-02" || ended.EndNS-ended.StartNS != int64(7*24*time.Hour) {
		t.Fatalf("ended = %+v, %v", ended, err)
	}
	current, err := service.WeekState(ctx, "2026-11-09")
	if err != nil || current.Ended {
		t.Fatalf("current = %+v, %v", current, err)
	}
	if err := service.Regenerate(ctx, "2026-11-09"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Regenerate of the current week = %v", err)
	}
	for _, label := range []string{"", "2026-11-03", "11/02/2026"} {
		if _, err := service.WeekState(ctx, label); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q = %v", label, err)
		}
	}
	saves := fixture.snapshots.saves
	if err := service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatal(err)
	}
	frozen, err := service.WeekState(ctx, "2026-11-02")
	if err != nil || !frozen.Frozen || frozen.FrozenAtNS == 0 || fixture.snapshots.saves != saves+1 {
		t.Fatalf("frozen = %+v, %v", frozen, err)
	}
	if _, err := service.WeekState(ctx, "2026-11-02"); err != nil || fixture.snapshots.saves != saves+1 {
		t.Fatal("WeekState wrote a snapshot")
	}
	service.snapshots = nil
	if _, err := service.WeekState(ctx, "2026-11-02"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("without snapshots = %v", err)
	}
}

// RegenerateIfVersion replaces only the stored state the caller saw; every
// snapshot write is a new version, even at the same clock reading.
func TestRegenerateIfVersion(t *testing.T) {
	ctx := context.Background()
	fixture := newReportFixture(t)
	service := fixture.service
	state, err := service.WeekState(ctx, "2026-11-02")
	if err != nil || state.Version() != 0 {
		t.Fatalf("state = %+v, %v", state, err)
	}
	if err := service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatal(err)
	}
	saves := fixture.snapshots.saves
	if err := service.RegenerateIfVersion(ctx, "2026-11-02", state.Version()); !errors.Is(err, ErrVersionConflict) || fixture.snapshots.saves != saves {
		t.Fatalf("stale version = %v (saves %d -> %d)", err, saves, fixture.snapshots.saves)
	}
	frozen, _ := service.WeekState(ctx, "2026-11-02")
	if err := service.RegenerateIfVersion(ctx, "2026-11-02", frozen.Version()); err != nil {
		t.Fatal(err)
	}
	again, _ := service.WeekState(ctx, "2026-11-02")
	if again.Version() <= frozen.Version() {
		t.Fatalf("versions %d then %d", frozen.Version(), again.Version())
	}
	if err := service.RegenerateIfVersion(ctx, "2026-11-09", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("current week = %v", err)
	}
}

// Contract section 0.1 item 101: a regeneration blocked behind a long freeze
// gives up when its context ends, reports that it never started, and writes
// nothing; once the lock is free it runs.
func TestRegenerateIfVersionGivesUpWaitingForTheSnapshotLock(t *testing.T) {
	fixture := newReportFixture(t)
	service := fixture.service
	// A long freeze of the same week holds its lock.
	unlock, err := service.job.weekLocks.lock(context.Background(), "2026-11-02")
	if err != nil {
		t.Fatal(err)
	}
	saves := fixture.snapshots.saves
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = service.RegenerateIfVersion(ctx, "2026-11-02", 0)
	if !errors.Is(err, ErrNotStarted) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked regeneration = %v", err)
	}
	if fixture.snapshots.saves != saves {
		t.Fatalf("a snapshot was written: saves %d -> %d", saves, fixture.snapshots.saves)
	}
	// The web route's Regenerate gives up the same way.
	if err := service.Regenerate(ctx, "2026-11-02"); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("blocked web regeneration = %v", err)
	}
	unlock()
	if err := service.RegenerateIfVersion(context.Background(), "2026-11-02", 0); err != nil || fixture.snapshots.saves != saves+1 {
		t.Fatalf("after the freeze = %v, saves %d", err, fixture.snapshots.saves)
	}
	// The writers that gave up left no lock entry behind.
	if size := service.job.weekLocks.size(); size != 0 {
		t.Fatalf("lock entries left = %d", size)
	}
}

// Contract section 0.1 item 129: the snapshot lock is per week. A freeze
// holding week A's lock does not delay a regeneration of week B; writers of
// one week still wait for each other, in turn; and no entry outlives its
// last writer, whether it got the lock or gave up waiting.
func TestSnapshotLocksArePerWeek(t *testing.T) {
	fixture := newReportFixture(t)
	service := fixture.service
	holdA, err := service.job.weekLocks.lock(context.Background(), "2026-10-26")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if err := service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatalf("another week behind a held lock = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("another week waited %v", elapsed)
	}
	// A second writer of week A waits until the holder releases.
	done := make(chan error, 1)
	go func() { done <- service.Regenerate(context.Background(), "2026-10-26") }()
	select {
	case err := <-done:
		t.Fatalf("a writer of the held week did not wait: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	holdA()
	holdA() // releasing twice is harmless
	if err := <-done; err != nil {
		t.Fatalf("writer after the release = %v", err)
	}
	// Many writers that give up while one holds the lock leave nothing.
	hold, err := service.job.weekLocks.lock(context.Background(), "2026-10-26")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer stop()
			if err := service.Regenerate(short, "2026-10-26"); !errors.Is(err, ErrNotStarted) {
				t.Errorf("waiter = %v", err)
			}
		}()
	}
	wait.Wait()
	if size := service.job.weekLocks.size(); size != 1 {
		t.Fatalf("entries while one writer holds = %d", size)
	}
	hold()
	if size := service.job.weekLocks.size(); size != 0 {
		t.Fatalf("entries after the last writer = %d", size)
	}
}

func TestOrgSuccessfulDeletesPrincipalsAndGroupCreate(t *testing.T) {
	ctx := context.Background()
	service, repository := agentFixture(t)

	// Principal: check, set, check-delete, delete; the rows and the
	// published catalog agree after each write and a check changes nothing.
	plan, err := service.CheckSetPrincipal(PrincipalUser, 9, ClassService, 0)
	if err != nil || plan.Before != nil || plan.After.Class != ClassService {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	set, err := service.SetPrincipalIfVersion(ctx, PrincipalUser, 9, ClassService, 0)
	if err != nil || set.Version() == 0 {
		t.Fatalf("set = %+v, %v", set, err)
	}
	if !reflect.DeepEqual(repository.rows(), service.Catalog().Catalog) {
		t.Fatal("database and snapshot differ after set")
	}
	rows, snapshot := repository.rows(), service.current.Load()
	removed, err := service.CheckDeletePrincipal(PrincipalUser, 9, set.Version())
	if err != nil || removed != set || !reflect.DeepEqual(repository.rows(), rows) || service.current.Load() != snapshot {
		t.Fatalf("check delete = %+v, %v", removed, err)
	}
	if err := service.DeletePrincipalIfVersion(ctx, PrincipalUser, 9, set.Version()); err != nil {
		t.Fatal(err)
	}
	// Set again at the same clock reading: never the deleted version.
	again, err := service.SetPrincipalIfVersion(ctx, PrincipalUser, 9, ClassService, 0)
	if err != nil || again.Version() == set.Version() {
		t.Fatalf("re-set = %+v (deleted had %d), %v", again, set.Version(), err)
	}
	if err := service.DeletePrincipalIfVersion(ctx, PrincipalUser, 9, set.Version()); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("a plan for the deleted classification applied: %v", err)
	}

	// The same for a membership.
	member, err := service.SetMemberIfVersion(ctx, 8, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteMemberIfVersion(ctx, 8, member.Version()); err != nil {
		t.Fatal(err)
	}
	if again, err := service.SetMember(ctx, 8, 2); err != nil || again.Version() == member.Version() {
		t.Fatalf("re-set member = %+v (deleted had %d), %v", again, member.Version(), err)
	}

	// Successful deletes of a project, the members of a group, the group.
	project := projectOf(t, service, 10)
	if err := service.DeleteProjectIfVersion(ctx, 10, project.Version()); err != nil {
		t.Fatal(err)
	}
	removedMember, err := service.CheckDeleteMember(7, AnyVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteMemberIfVersion(ctx, 7, removedMember.Version()); err != nil {
		t.Fatal(err)
	}
	group := groupOf(t, service, 1)
	if removed, err := service.CheckDeleteGroup(1, group.Version()); err != nil || removed != group {
		t.Fatalf("check delete group = %+v, %v", removed, err)
	}
	if err := service.DeleteGroupIfVersion(ctx, 1, group.Version()); err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateGroupFromPatch(ctx, GroupPatch{Name: strp("  Ops "), Enabled: boolp(false)})
	if err != nil || created.Name != "Ops" || created.Enabled || created.ID != 101 {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if _, err := service.CreateGroupFromPatch(ctx, GroupPatch{Name: strp("ops"), Enabled: boolp(true)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create = %v", err)
	}
	if _, err := service.CreateGroupFromPatch(ctx, GroupPatch{Name: strp("x")}); err == nil {
		t.Fatal("a group without enabled was created")
	}
	final := repository.rows()
	if !reflect.DeepEqual(final, service.Catalog().Catalog) || len(final.Groups) != 2 || len(final.Projects) != 1 {
		t.Fatalf("final database %+v, snapshot %+v", final, service.Catalog().Catalog)
	}
}
