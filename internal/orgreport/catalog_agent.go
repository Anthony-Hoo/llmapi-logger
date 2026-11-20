package orgreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Entry points for callers that edit one field at a time (the agent facade,
// doc/features/25-agent-access.md section 8.2). The web routes replace a
// whole group or project; these merge only the fields given, refuse to write
// over a change made since the caller read the object, and can run every
// check without saving. Writes go through change ("compile the whole
// candidate catalog, persist, publish"); checks run only its validating half
// (candidate), without the lock, and persist, publish, number and stamp
// nothing.
//
// They also do what the management page does in the browser before it
// submits (contract section 4.7): group and project names and rule patterns
// are trimmed.

// AnyVersion makes a Check… entry skip the version comparison. The writing
// entries never accept it, because no object has a negative version.
const AnyVersion int64 = -1

// ErrVersionConflict means the object changed (or appeared, or disappeared)
// since the caller read the version it passed. Nothing was written. It is
// not an ErrConflict, which the web layer maps to its own message.
var ErrVersionConflict = errors.New("orgreport: changed since it was read")

func versionMatches(version, expected int64) bool {
	return expected == AnyVersion || version == expected
}

// keepVersion is the stamp of a check: it allocates no version.
func keepVersion(previous int64) int64 { return previous }

// exact turns AnyVersion into a value no object has.
func exact(version int64) int64 {
	if version < 0 {
		return -2
	}
	return version
}

// Version returns the group's version: its last-modified time in Unix
// nanoseconds. Every write stamps a value above the previous one.
func (group Group) Version() int64 { return group.UpdatedAtNS }

// Version returns the project's version, as Group.Version.
func (project Project) Version() int64 { return project.UpdatedAtNS }

// Version returns the membership's version, as Group.Version. A user without
// a group has version 0.
func (member Member) Version() int64 { return member.UpdatedAtNS }

// Version returns the classification's version, as Group.Version. An
// unclassified principal has version 0.
func (principal Principal) Version() int64 { return principal.UpdatedAtNS }

// GroupPatch names the group fields to change; a nil field keeps its value.
// Decoding into it with DisallowUnknownFields rejects any other field.
type GroupPatch struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

// OptionalGroupID is a project's group_id in a patch, which has three
// states: absent (Set false), null for a global project (Set true, ID nil),
// or a group id. A plain *int64 cannot tell absent from null.
type OptionalGroupID struct {
	Set bool
	ID  *int64
}

// UnmarshalJSON records that the field was present; null means global.
func (value *OptionalGroupID) UnmarshalJSON(data []byte) error {
	value.Set = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		value.ID = nil
		return nil
	}
	var id int64
	if err := json.Unmarshal(data, &id); err != nil {
		return err
	}
	value.ID = &id
	return nil
}

// MarshalJSON writes null or the id; an absent value is written as null too.
func (value OptionalGroupID) MarshalJSON() ([]byte, error) {
	if value.ID == nil {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(*value.ID, 10)), nil
}

// GroupIDOf is the OptionalGroupID that sets id (nil: global).
func GroupIDOf(id *int64) OptionalGroupID {
	if id != nil {
		copied := *id
		id = &copied
	}
	return OptionalGroupID{Set: true, ID: id}
}

// ProjectPatch names the project fields to change; nil (or Set false) keeps
// the value. Rules set to an empty slice saves a project without rules, as
// the page allows.
type ProjectPatch struct {
	Name    *string         `json:"name,omitempty"`
	GroupID OptionalGroupID `json:"group_id"`
	Enabled *bool           `json:"enabled,omitempty"`
	Rules   *[]Rule         `json:"rules,omitempty"`
}

// ProjectListEdit lists rules to add to or remove from a project. Rules
// compare by kind plus the pattern as the matcher normalises it (trimmed;
// lower-cased where matching is case-insensitive; remote URLs and paths
// normalised), so two rules that match exactly the same requests are the
// same rule. Adding a present rule is a no-op; removing an absent one is a
// *ValidationError (ReasonNotPresent).
type ProjectListEdit struct {
	Rules []Rule `json:"rules,omitempty"`
}

// ProjectChange is one project patch. Rules may not be both set and edited.
type ProjectChange struct {
	Set    ProjectPatch
	Add    ProjectListEdit
	Remove ProjectListEdit
}

// GroupDiff is what a group write did or would do. Before is zero for a
// create, After zero for a delete; Changed lists changed JSON field names.
// A check allocates nothing: a planned create has ID 0 and zero timestamps,
// a planned update keeps Before's UpdatedAtNS.
type GroupDiff struct {
	Before  Group    `json:"before"`
	After   Group    `json:"after"`
	Changed []string `json:"changed"`
}

// ProjectDiff is GroupDiff for a project.
type ProjectDiff struct {
	Before  Project  `json:"before"`
	After   Project  `json:"after"`
	Changed []string `json:"changed"`
}

// MemberDiff is what a membership write would do. Before is nil when the
// user had no group; a planned set keeps Before's version (0 when new).
type MemberDiff struct {
	Before *Member `json:"before"`
	After  Member  `json:"after"`
}

// PrincipalDiff is MemberDiff for a classification.
type PrincipalDiff struct {
	Before *Principal `json:"before"`
	After  Principal  `json:"after"`
}

// ---- groups ----

// CheckCreateGroup runs every check CreateGroupFromPatch runs, without
// saving.
func (service *Service) CheckCreateGroup(patch GroupPatch) (GroupDiff, error) {
	if err := service.writable(); err != nil {
		return GroupDiff{}, err
	}
	group, err := newGroup(patch)
	if err != nil {
		return GroupDiff{}, err
	}
	if _, err := service.candidate(func(catalog *Catalog) error {
		catalog.Groups = append(catalog.Groups, group)
		return nil
	}); err != nil {
		return GroupDiff{}, retarget(err, ObjectGroup, 0, "")
	}
	return groupDiff(Group{}, group), nil
}

// CreateGroupFromPatch creates a group; name and enabled are required, so
// the caller does not inherit the form's default by omission.
func (service *Service) CreateGroupFromPatch(ctx context.Context, patch GroupPatch) (Group, error) {
	group, err := newGroup(patch)
	if err != nil {
		return Group{}, err
	}
	created, err := service.CreateGroup(ctx, GroupInput{Name: group.Name, Enabled: group.Enabled})
	return created, retarget(err, ObjectGroup, 0, "")
}

func newGroup(patch GroupPatch) (Group, error) {
	if patch.Name == nil {
		return Group{}, invalidAt(ObjectGroup, 0, "name", ReasonRequired, "name is required")
	}
	if patch.Enabled == nil {
		return Group{}, invalidAt(ObjectGroup, 0, "enabled", ReasonRequired, "enabled is required")
	}
	return Group{Name: strings.TrimSpace(*patch.Name), Enabled: *patch.Enabled}, nil
}

// CheckPatchGroup runs every check PatchGroup runs, without saving.
// expectedVersion may be AnyVersion.
func (service *Service) CheckPatchGroup(id, expectedVersion int64, patch GroupPatch) (GroupDiff, error) {
	if err := service.writable(); err != nil {
		return GroupDiff{}, err
	}
	var before, after Group
	_, err := service.candidate(patchGroupMutation(id, expectedVersion, patch, keepVersion, &before, &after))
	if err != nil {
		return GroupDiff{}, retarget(err, ObjectGroup, id, "")
	}
	return groupDiff(before, after), nil
}

// PatchGroup merges the given fields into group id and saves it, only when
// its version still equals expectedVersion (else ErrVersionConflict, nothing
// written).
func (service *Service) PatchGroup(ctx context.Context, id, expectedVersion int64, patch GroupPatch) (Group, error) {
	var before, after Group
	err := service.change(ctx, patchGroupMutation(id, exact(expectedVersion), patch, service.nextVersion, &before, &after), func(ctx context.Context, _ *Catalog) error {
		return service.repository.UpdateProjectGroup(ctx, after)
	})
	if err != nil {
		return Group{}, retarget(err, ObjectGroup, id, "")
	}
	return after, nil
}

func patchGroupMutation(id, expected int64, patch GroupPatch, stamp func(int64) int64, before, after *Group) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Groups {
			group := &catalog.Groups[index]
			if group.ID != id {
				continue
			}
			if !versionMatches(group.UpdatedAtNS, expected) {
				return ErrVersionConflict
			}
			*before = *group
			if patch.Name != nil {
				group.Name = *patch.Name
			}
			if patch.Enabled != nil {
				group.Enabled = *patch.Enabled
			}
			group.Name = strings.TrimSpace(group.Name)
			group.UpdatedAtNS = max(stamp(group.UpdatedAtNS), group.CreatedAtNS)
			*after = *group
			return nil
		}
		return ErrNotFound
	}
}

// CheckDeleteGroup reports the group DeleteGroupIfVersion would remove,
// including the "no projects and no members" check. expectedVersion may be
// AnyVersion.
func (service *Service) CheckDeleteGroup(id, expectedVersion int64) (Group, error) {
	if err := service.writable(); err != nil {
		return Group{}, err
	}
	var removed Group
	if _, err := service.candidate(deleteGroupMutation(id, expectedVersion, &removed)); err != nil {
		return Group{}, retarget(err, ObjectGroup, id, "")
	}
	return removed, nil
}

// DeleteGroupIfVersion deletes group id only when its version still equals
// expectedVersion.
func (service *Service) DeleteGroupIfVersion(ctx context.Context, id, expectedVersion int64) error {
	err := service.change(ctx, deleteGroupMutation(id, exact(expectedVersion), nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteProjectGroup(ctx, id)
	})
	return retarget(err, ObjectGroup, id, "")
}

func groupDiff(before, after Group) GroupDiff {
	changed := []string{}
	if before.Name != after.Name {
		changed = append(changed, "name")
	}
	if before.Enabled != after.Enabled {
		changed = append(changed, "enabled")
	}
	return GroupDiff{Before: before, After: after, Changed: changed}
}

// ---- projects ----

// FormRules trims every rule pattern as the management page does before it
// submits. The service itself only strips spaces and tabs.
func FormRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, Rule{Kind: rule.Kind, Pattern: strings.TrimSpace(rule.Pattern)})
	}
	return out
}

// CheckCreateProject runs every check CreateProjectFromPatch runs, without
// saving.
func (service *Service) CheckCreateProject(patch ProjectPatch) (ProjectDiff, error) {
	if err := service.writable(); err != nil {
		return ProjectDiff{}, err
	}
	project, err := newProject(patch)
	if err != nil {
		return ProjectDiff{}, err
	}
	if _, err := service.candidate(func(catalog *Catalog) error {
		catalog.Projects = append(catalog.Projects, cloneProject(project))
		return nil
	}); err != nil {
		return ProjectDiff{}, retarget(err, ObjectProject, 0, "")
	}
	return projectDiff(Project{}, project), nil
}

// CreateProjectFromPatch creates a project; name, group_id (null for a
// global project), enabled and rules are required. An empty rules list is
// allowed, as on the page.
func (service *Service) CreateProjectFromPatch(ctx context.Context, patch ProjectPatch) (Project, error) {
	project, err := newProject(patch)
	if err != nil {
		return Project{}, err
	}
	created, err := service.CreateProject(ctx, ProjectInput{Name: project.Name, GroupID: project.GroupID, Enabled: project.Enabled, Rules: project.Rules})
	return created, retarget(err, ObjectProject, 0, "")
}

func newProject(patch ProjectPatch) (Project, error) {
	for _, required := range []struct {
		field   string
		missing bool
	}{
		{"name", patch.Name == nil}, {"group_id", !patch.GroupID.Set}, {"enabled", patch.Enabled == nil}, {"rules", patch.Rules == nil},
	} {
		if required.missing {
			return Project{}, invalidAt(ObjectProject, 0, required.field, ReasonRequired, required.field+" is required")
		}
	}
	project := Project{Name: strings.TrimSpace(*patch.Name), Enabled: *patch.Enabled, Rules: normalizeRules(FormRules(*patch.Rules))}
	if patch.GroupID.ID != nil {
		id := *patch.GroupID.ID
		project.GroupID = &id
	}
	return project, nil
}

// CheckPatchProject runs every check PatchProject runs, without saving.
// expectedVersion may be AnyVersion.
func (service *Service) CheckPatchProject(id, expectedVersion int64, change ProjectChange) (ProjectDiff, error) {
	if err := service.writable(); err != nil {
		return ProjectDiff{}, err
	}
	var before, after Project
	_, err := service.candidate(patchProjectMutation(id, expectedVersion, change, keepVersion, &before, &after))
	if err != nil {
		return ProjectDiff{}, retarget(err, ObjectProject, id, "")
	}
	return projectDiff(before, after), nil
}

// PatchProject merges change into project id and saves it, only when its
// version still equals expectedVersion.
func (service *Service) PatchProject(ctx context.Context, id, expectedVersion int64, change ProjectChange) (Project, error) {
	var before, after Project
	err := service.change(ctx, patchProjectMutation(id, exact(expectedVersion), change, service.nextVersion, &before, &after), func(ctx context.Context, _ *Catalog) error {
		return service.repository.UpdateProject(ctx, after)
	})
	if err != nil {
		return Project{}, retarget(err, ObjectProject, id, "")
	}
	return after, nil
}

func patchProjectMutation(id, expected int64, change ProjectChange, stamp func(int64) int64, before, after *Project) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Projects {
			project := &catalog.Projects[index]
			if project.ID != id {
				continue
			}
			if !versionMatches(project.UpdatedAtNS, expected) {
				return ErrVersionConflict
			}
			*before = cloneProject(*project)
			set := change.Set
			if set.Rules != nil && (len(change.Add.Rules) > 0 || len(change.Remove.Rules) > 0) {
				return invalidAt(ObjectProject, id, "rules", ReasonConflictingEdit, "a list cannot be both replaced and edited")
			}
			if set.Name != nil {
				project.Name = *set.Name
			}
			if set.GroupID.Set {
				project.GroupID = nil
				if set.GroupID.ID != nil {
					groupID := *set.GroupID.ID
					project.GroupID = &groupID
				}
			}
			if set.Enabled != nil {
				project.Enabled = *set.Enabled
			}
			rules := project.Rules
			if set.Rules != nil {
				rules = append([]Rule{}, (*set.Rules)...)
			}
			edited, err := editRules(id, rules, change.Add.Rules, change.Remove.Rules)
			if err != nil {
				return err
			}
			project.Name = strings.TrimSpace(project.Name)
			project.Rules = normalizeRules(FormRules(edited))
			project.UpdatedAtNS = max(stamp(project.UpdatedAtNS), project.CreatedAtNS)
			*after = cloneProject(*project)
			return nil
		}
		return ErrNotFound
	}
}

// ruleKey is the identity of a rule for add and remove: kind plus what the
// compiled rule matches against. A rule that does not compile falls back to
// kind plus the trimmed pattern; validation reports it later.
func ruleKey(rule Rule) string {
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	compiled, err := CompileRules([]Rule{rule})
	if err != nil || len(compiled) != 1 {
		return rule.Kind + "\x00raw\x00" + rule.Pattern
	}
	if compiled[0].glob != nil {
		return rule.Kind + "\x00glob\x00" + compiled[0].glob.String()
	}
	return rule.Kind + "\x00literal\x00" + compiled[0].literal
}

func editRules(id int64, rules, add, remove []Rule) ([]Rule, error) {
	out := append([]Rule{}, rules...)
	adding := map[string]bool{}
	for _, rule := range add {
		adding[ruleKey(rule)] = true
	}
	for _, rule := range remove {
		wanted := ruleKey(rule)
		if adding[wanted] {
			return nil, invalidAt(ObjectProject, id, "rules", ReasonAddAndRemove, "a rule cannot be both added and removed")
		}
		kept := make([]Rule, 0, len(out))
		for _, existing := range out {
			if ruleKey(existing) != wanted {
				kept = append(kept, existing)
			}
		}
		if len(kept) == len(out) {
			return nil, invalidAt(ObjectProject, id, "rules", ReasonNotPresent, "a rule to remove is not in the project")
		}
		out = kept
	}
	for _, rule := range add {
		key, present := ruleKey(rule), false
		for _, existing := range out {
			if ruleKey(existing) == key {
				present = true
				break
			}
		}
		if !present {
			out = append(out, rule)
		}
	}
	return out, nil
}

// CheckDeleteProject reports the project DeleteProjectIfVersion would
// remove. expectedVersion may be AnyVersion.
func (service *Service) CheckDeleteProject(id, expectedVersion int64) (Project, error) {
	if err := service.writable(); err != nil {
		return Project{}, err
	}
	var removed Project
	if _, err := service.candidate(deleteProjectMutation(id, expectedVersion, &removed)); err != nil {
		return Project{}, retarget(err, ObjectProject, id, "")
	}
	return removed, nil
}

// DeleteProjectIfVersion deletes project id only when its version still
// equals expectedVersion.
func (service *Service) DeleteProjectIfVersion(ctx context.Context, id, expectedVersion int64) error {
	err := service.change(ctx, deleteProjectMutation(id, exact(expectedVersion), nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteProject(ctx, id)
	})
	return retarget(err, ObjectProject, id, "")
}

func projectDiff(before, after Project) ProjectDiff {
	changed := []string{}
	if before.Name != after.Name {
		changed = append(changed, "name")
	}
	if (before.GroupID == nil) != (after.GroupID == nil) || (before.GroupID != nil && *before.GroupID != *after.GroupID) {
		changed = append(changed, "group_id")
	}
	if before.Enabled != after.Enabled {
		changed = append(changed, "enabled")
	}
	sameRules := len(before.Rules) == len(after.Rules)
	for index := 0; sameRules && index < len(before.Rules); index++ {
		sameRules = before.Rules[index] == after.Rules[index]
	}
	if !sameRules {
		changed = append(changed, "rules")
	}
	return ProjectDiff{Before: before, After: after, Changed: changed}
}

// ---- members ----

// CheckSetMember runs every check SetMemberIfVersion runs, without saving.
// expectedVersion 0 means "the user has no group yet"; AnyVersion skips the
// comparison.
func (service *Service) CheckSetMember(userID, groupID, expectedVersion int64) (MemberDiff, error) {
	if err := service.writable(); err != nil {
		return MemberDiff{}, err
	}
	member := Member{UserID: userID, GroupID: groupID}
	var previous *Member
	if _, err := service.candidate(setMemberMutation(&member, expectedVersion, keepVersion, &previous)); err != nil {
		return MemberDiff{}, retarget(err, ObjectMember, userID, "")
	}
	member.UpdatedAtNS = 0
	if previous != nil {
		member.UpdatedAtNS = previous.UpdatedAtNS
	}
	return MemberDiff{Before: previous, After: member}, nil
}

// SetMemberIfVersion puts a user into a group only when its membership's
// version still equals expectedVersion; 0 requires that the user has no
// group yet.
func (service *Service) SetMemberIfVersion(ctx context.Context, userID, groupID, expectedVersion int64) (Member, error) {
	member := Member{UserID: userID, GroupID: groupID}
	err := service.change(ctx, setMemberMutation(&member, exact(expectedVersion), service.nextVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.SetGroupMember(ctx, member)
	})
	if err != nil {
		return Member{}, retarget(err, ObjectMember, userID, "")
	}
	return member, nil
}

// CheckDeleteMember reports the membership DeleteMemberIfVersion would
// remove. expectedVersion may be AnyVersion.
func (service *Service) CheckDeleteMember(userID, expectedVersion int64) (Member, error) {
	if err := service.writable(); err != nil {
		return Member{}, err
	}
	var removed Member
	if _, err := service.candidate(deleteMemberMutation(userID, expectedVersion, &removed)); err != nil {
		return Member{}, retarget(err, ObjectMember, userID, "")
	}
	return removed, nil
}

// DeleteMemberIfVersion removes a user from its group only when the
// membership's version still equals expectedVersion.
func (service *Service) DeleteMemberIfVersion(ctx context.Context, userID, expectedVersion int64) error {
	err := service.change(ctx, deleteMemberMutation(userID, exact(expectedVersion), nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteGroupMember(ctx, userID)
	})
	return retarget(err, ObjectMember, userID, "")
}

// ---- principals ----

// CheckSetPrincipal runs every check SetPrincipalIfVersion runs, without
// saving. expectedVersion 0 means "not classified yet"; AnyVersion skips the
// comparison.
func (service *Service) CheckSetPrincipal(kind string, id int64, class string, expectedVersion int64) (PrincipalDiff, error) {
	if err := service.writable(); err != nil {
		return PrincipalDiff{}, err
	}
	principal := Principal{Kind: kind, ID: id, Class: class}
	var previous *Principal
	if _, err := service.candidate(setPrincipalMutation(&principal, expectedVersion, keepVersion, &previous)); err != nil {
		return PrincipalDiff{}, retarget(err, ObjectPrincipal, id, kind)
	}
	principal.UpdatedAtNS = 0
	if previous != nil {
		principal.UpdatedAtNS = previous.UpdatedAtNS
	}
	return PrincipalDiff{Before: previous, After: principal}, nil
}

// SetPrincipalIfVersion classifies a user or token only when the
// classification's version still equals expectedVersion; 0 requires that it
// is not classified yet.
func (service *Service) SetPrincipalIfVersion(ctx context.Context, kind string, id int64, class string, expectedVersion int64) (Principal, error) {
	principal := Principal{Kind: kind, ID: id, Class: class}
	err := service.change(ctx, setPrincipalMutation(&principal, exact(expectedVersion), service.nextVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.SetPrincipalClass(ctx, principal)
	})
	if err != nil {
		return Principal{}, retarget(err, ObjectPrincipal, id, kind)
	}
	return principal, nil
}

// CheckDeletePrincipal reports the classification DeletePrincipalIfVersion
// would remove. expectedVersion may be AnyVersion.
func (service *Service) CheckDeletePrincipal(kind string, id, expectedVersion int64) (Principal, error) {
	if err := service.writable(); err != nil {
		return Principal{}, err
	}
	var removed Principal
	if _, err := service.candidate(deletePrincipalMutation(kind, id, expectedVersion, &removed)); err != nil {
		return Principal{}, retarget(err, ObjectPrincipal, id, kind)
	}
	return removed, nil
}

// DeletePrincipalIfVersion removes a classification only when its version
// still equals expectedVersion.
func (service *Service) DeletePrincipalIfVersion(ctx context.Context, kind string, id, expectedVersion int64) error {
	err := service.change(ctx, deletePrincipalMutation(kind, id, exact(expectedVersion), nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeletePrincipalClass(ctx, kind, id)
	})
	return retarget(err, ObjectPrincipal, id, kind)
}
