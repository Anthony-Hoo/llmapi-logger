package orgreport

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Rule kinds (doc section 4, projects.rules).
const (
	RuleRepoURL      = "repo_url"      // glob over a normalized remote host/org/repo
	RuleRepoName     = "repo_name"     // exact name of a repository or any path segment
	RulePathGlob     = "path_glob"     // glob over a normalized root or working directory
	RuleAgentProject = "agent_project" // equals the declared X-Agent-Project value
)

// Principal kinds.
const (
	PrincipalUser  = "user"
	PrincipalToken = "token"
)

// Limits of administrator input.
const (
	MaxNameBytes        = 128
	MaxRulesPerProject  = 32
	MaxRulePatternBytes = 512
	MaxProjects         = 1000
	MaxGroups           = 200
)

// Group is one project group.
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	CreatedAtNS int64  `json:"created_at_ns"`
	UpdatedAtNS int64  `json:"updated_at_ns"`
}

// Rule is one matching rule of a project.
type Rule struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

// Project is a global project (GroupID nil) or one specific to a group.
type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	GroupID     *int64 `json:"group_id"`
	Enabled     bool   `json:"enabled"`
	Rules       []Rule `json:"rules"`
	CreatedAtNS int64  `json:"created_at_ns"`
	UpdatedAtNS int64  `json:"updated_at_ns"`
}

// Member puts one NewAPI user into one group.
type Member struct {
	UserID      int64 `json:"user_id"`
	GroupID     int64 `json:"group_id"`
	UpdatedAtNS int64 `json:"updated_at_ns"`
}

// Principal classifies one NewAPI user or token as human or service.
type Principal struct {
	Kind        string `json:"kind"`
	ID          int64  `json:"id"`
	Class       string `json:"class"`
	UpdatedAtNS int64  `json:"updated_at_ns"`
}

// Catalog is the complete administrator configuration.
type Catalog struct {
	Groups     []Group     `json:"groups"`
	Projects   []Project   `json:"projects"`
	Members    []Member    `json:"members"`
	Principals []Principal `json:"principals"`
}

func (catalog Catalog) clone() Catalog {
	out := Catalog{
		Groups:     append([]Group{}, catalog.Groups...),
		Projects:   make([]Project, 0, len(catalog.Projects)),
		Members:    append([]Member{}, catalog.Members...),
		Principals: append([]Principal{}, catalog.Principals...),
	}
	for _, project := range catalog.Projects {
		out.Projects = append(out.Projects, cloneProject(project))
	}
	return out
}

func cloneProject(project Project) Project {
	project.Rules = append([]Rule{}, project.Rules...)
	if project.GroupID != nil {
		id := *project.GroupID
		project.GroupID = &id
	}
	return project
}

// compiledRule is a rule ready to match normalized identities.
type compiledRule struct {
	kind    string
	literal string
	glob    *regexp.Regexp
	// hash is the OpenCode project hash of a literal repo_url rule.
	hash string
}

type compiledProject struct {
	project Project
	rules   []compiledRule
}

// Compiled is the immutable request-time form of a Catalog.
type Compiled struct {
	catalog Catalog
	// byGroup lists the enabled projects of each enabled group; global lists
	// the enabled global projects. Both in id order.
	byGroup map[int64][]compiledProject
	global  []compiledProject
	names   map[int64]string
	members map[int64]int64
	users   map[int64]string
	tokens  map[int64]string
	groups  map[int64]Group
}

// Compile validates a whole catalog. Any invalid entry rejects all of it.
func Compile(catalog Catalog) (*Compiled, error) {
	result := &Compiled{
		catalog: catalog.clone(), byGroup: map[int64][]compiledProject{}, names: map[int64]string{},
		members: map[int64]int64{}, users: map[int64]string{}, tokens: map[int64]string{}, groups: map[int64]Group{},
	}
	// Errors are *ValidationError values (validation.go); their text is the
	// one these checks have always produced.
	if len(catalog.Groups) > MaxGroups {
		return nil, invalidAt(ObjectCatalog, 0, "groups", ReasonTooMany, "too many groups or projects")
	}
	if len(catalog.Projects) > MaxProjects {
		return nil, invalidAt(ObjectCatalog, 0, "projects", ReasonTooMany, "too many groups or projects")
	}
	groupNames := map[string]bool{}
	for _, group := range catalog.Groups {
		if group.ID <= 0 {
			return nil, invalidAt(ObjectGroup, group.ID, "id", ReasonInvalidID, "group id must be positive")
		}
		if _, duplicate := result.groups[group.ID]; duplicate {
			return nil, invalidAt(ObjectGroup, group.ID, "id", ReasonDuplicate, "duplicate group id")
		}
		if err := nameError(ObjectGroup, group.ID, group.Name); err != nil {
			return nil, err
		}
		folded := strings.ToLower(group.Name)
		if groupNames[folded] {
			return nil, conflictAt(ObjectGroup, group.ID, "name", ReasonDuplicate, "duplicate group name")
		}
		groupNames[folded] = true
		result.groups[group.ID] = group
	}
	projectNames := map[string]bool{}
	projects := append([]Project{}, catalog.Projects...)
	sort.Slice(projects, func(i, j int) bool { return projects[i].ID < projects[j].ID })
	for index, project := range projects {
		if project.ID <= 0 || (index > 0 && projects[index-1].ID == project.ID) {
			return nil, invalidAt(ObjectProject, project.ID, "id", ReasonInvalidID, "project ids must be positive and unique")
		}
		if err := nameError(ObjectProject, project.ID, project.Name); err != nil {
			return nil, err
		}
		scope := int64(0)
		if project.GroupID != nil {
			scope = *project.GroupID
			if _, ok := result.groups[scope]; !ok {
				return nil, invalidAt(ObjectProject, project.ID, "group_id", ReasonUnknownGroup, "project references an unknown group")
			}
		}
		key := fmt.Sprintf("%d\x00%s", scope, strings.ToLower(project.Name))
		if projectNames[key] {
			return nil, conflictAt(ObjectProject, project.ID, "name", ReasonDuplicate, "duplicate project name in the same scope")
		}
		projectNames[key] = true
		rules, err := CompileRules(project.Rules)
		if err != nil {
			var invalid *ValidationError
			if errors.As(err, &invalid) {
				invalid.Object, invalid.ID = ObjectProject, project.ID
			}
			return nil, err
		}
		result.names[project.ID] = project.Name
		if !project.Enabled {
			continue
		}
		compiled := compiledProject{project: cloneProject(project), rules: rules}
		if project.GroupID == nil {
			result.global = append(result.global, compiled)
		} else if result.groups[scope].Enabled {
			result.byGroup[scope] = append(result.byGroup[scope], compiled)
		}
	}
	for _, member := range catalog.Members {
		if member.UserID <= 0 {
			return nil, invalidAt(ObjectMember, member.UserID, "user_id", ReasonInvalidID, "member user id must be positive")
		}
		if _, ok := result.groups[member.GroupID]; !ok {
			return nil, invalidAt(ObjectMember, member.UserID, "group_id", ReasonUnknownGroup, "member references an unknown group")
		}
		if _, duplicate := result.members[member.UserID]; duplicate {
			return nil, conflictAt(ObjectMember, member.UserID, "user_id", ReasonDuplicate, "a user belongs to one group only")
		}
		result.members[member.UserID] = member.GroupID
	}
	for _, principal := range catalog.Principals {
		if principal.ID <= 0 {
			failure := invalidAt(ObjectPrincipal, principal.ID, "id", ReasonInvalidID, "invalid principal")
			failure.Kind = principal.Kind
			return nil, failure
		}
		if principal.Class != ClassHuman && principal.Class != ClassService {
			failure := invalidAt(ObjectPrincipal, principal.ID, "class", ReasonInvalidValue, "invalid principal")
			failure.Kind = principal.Kind
			return nil, failure
		}
		switch principal.Kind {
		case PrincipalUser:
			result.users[principal.ID] = principal.Class
		case PrincipalToken:
			result.tokens[principal.ID] = principal.Class
		default:
			failure := invalidAt(ObjectPrincipal, principal.ID, "kind", ReasonInvalidValue, "principal kind must be user or token")
			failure.Kind = principal.Kind
			return nil, failure
		}
	}
	return result, nil
}

func validateName(name string) error {
	if strings.TrimSpace(name) != name || name == "" || len(name) > MaxNameBytes || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return fmt.Errorf("%w: name must be 1-%d bytes without surrounding whitespace", ErrInvalid, MaxNameBytes)
	}
	return nil
}

// CompileRules validates and compiles the rules of one project. Its errors
// are *ValidationError values with Object "project", ID 0 and Field
// "rules[i].pattern" / "rules[i].kind" (i indexes rules) or "rules".
func CompileRules(rules []Rule) ([]compiledRule, error) {
	if len(rules) > MaxRulesPerProject {
		return nil, invalidAt(ObjectProject, 0, "rules", ReasonTooMany, fmt.Sprintf("at most %d rules per project", MaxRulesPerProject))
	}
	out := make([]compiledRule, 0, len(rules))
	for index, rule := range rules {
		at := fmt.Sprintf("rules[%d].", index)
		pattern := strings.TrimSpace(rule.Pattern)
		message := fmt.Sprintf("rule pattern must be 1-%d bytes", MaxRulePatternBytes)
		switch {
		case pattern == "":
			return nil, invalidAt(ObjectProject, 0, at+"pattern", ReasonEmpty, message)
		case len(pattern) > MaxRulePatternBytes:
			return nil, invalidAt(ObjectProject, 0, at+"pattern", ReasonTooLong, message)
		case strings.ContainsAny(pattern, "\x00\r\n"):
			return nil, invalidAt(ObjectProject, 0, at+"pattern", ReasonInvalidCharacter, message)
		}
		compiled := compiledRule{kind: rule.Kind}
		switch rule.Kind {
		case RuleRepoURL:
			normalized := NormalizeRemote(pattern)
			if normalized == "" {
				normalized = strings.ToLower(strings.Trim(strings.ReplaceAll(pattern, "\\", "/"), "/"))
				normalized = strings.TrimSuffix(normalized, ".git")
			}
			if hasGlob(normalized) {
				compiled.glob = globRegexp(normalized)
			} else {
				compiled.literal = normalized
				compiled.hash = OpenCodeProjectHash(normalized)
			}
		case RuleRepoName:
			if strings.ContainsAny(pattern, "/\\") {
				return nil, invalidAt(ObjectProject, 0, at+"pattern", ReasonNotASingleName, "repo_name is a single name, not a path")
			}
			compiled.literal = strings.ToLower(pattern)
		case RulePathGlob:
			normalized := NormalizePath(pattern)
			if normalized == "" {
				return nil, invalidAt(ObjectProject, 0, at+"pattern", ReasonInvalidValue, "invalid path_glob")
			}
			compiled.glob = globRegexp(normalized)
		case RuleAgentProject:
			compiled.literal = strings.ToLower(pattern)
		default:
			return nil, invalidAt(ObjectProject, 0, at+"kind", ReasonInvalidValue, "rule kind must be repo_url, repo_name, path_glob or agent_project")
		}
		out = append(out, compiled)
	}
	return out, nil
}

func hasGlob(pattern string) bool { return strings.ContainsAny(pattern, "*?") }

// globRegexp converts a lower-case glob: "**" matches across "/", "*" within
// one segment, "?" one character; everything else is literal. The whole
// value must match. It walks runes, so non-ASCII names stay intact and "?"
// matches one character, not one byte.
func globRegexp(pattern string) *regexp.Regexp {
	var builder strings.Builder
	builder.WriteString("^")
	chars := []rune(pattern)
	for index := 0; index < len(chars); index++ {
		switch char := chars[index]; char {
		case '*':
			if index+1 < len(chars) && chars[index+1] == '*' {
				builder.WriteString(".*")
				index++
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	builder.WriteString("$")
	return regexp.MustCompile(builder.String())
}

func (rule compiledRule) matchValue(value string) bool {
	if value == "" {
		return false
	}
	if rule.glob != nil {
		return rule.glob.MatchString(value)
	}
	return value == rule.literal
}

// tier is one signal strength, strongest first.
type tier int

const (
	tierDeclared tier = iota
	tierRemote
	tierRoot
	tierCwd
)

// matches reports whether the rule matches the identity at one tier.
// resolvedRoot is the cwd mapped to its longest known repository root.
func (rule compiledRule) matches(identity Identity, level tier, resolvedRoot string) bool {
	switch level {
	case tierDeclared:
		return rule.kind == RuleAgentProject && identity.Declared != "" && strings.ToLower(identity.Declared) == rule.literal
	case tierRemote:
		switch rule.kind {
		case RuleRepoURL:
			for _, remote := range identity.Remotes {
				if rule.matchValue(remote) {
					return true
				}
			}
			return rule.hash != "" && identity.ProjectHash == rule.hash
		case RuleRepoName:
			for _, remote := range identity.Remotes {
				if RepoName(remote) == rule.literal {
					return true
				}
			}
		}
		return false
	case tierRoot:
		return rule.matchPaths(identity.Roots)
	case tierCwd:
		paths := []string{resolvedRoot, identity.Cwd}
		return rule.matchPaths(paths)
	}
	return false
}

func (rule compiledRule) matchPaths(paths []string) bool {
	for _, value := range paths {
		if value == "" {
			continue
		}
		switch rule.kind {
		case RulePathGlob:
			if rule.glob.MatchString(value) {
				return true
			}
		case RuleRepoName:
			for _, segment := range strings.Split(value, "/") {
				if segment == rule.literal {
					return true
				}
			}
		}
	}
	return false
}

// Resolve attributes one identity for a user in groupID (0: no group): the
// group's projects first, then the global projects; inside each scope the
// strongest signal tier wins, then the lowest project id. knownRoots are the
// repository roots already seen for the same user.
func (compiled *Compiled) Resolve(identity Identity, groupID int64, knownRoots []string) ProjectKey {
	project, _ := compiled.ResolveLevel(identity, groupID, knownRoots)
	return project
}

// Signal levels a rule can match at, strongest first.
const (
	LevelDeclared = "declared"
	LevelRemote   = "remote"
	LevelRoot     = "root"
	LevelCwd      = "cwd"
)

var levelNames = [...]string{tierDeclared: LevelDeclared, tierRemote: LevelRemote, tierRoot: LevelRoot, tierCwd: LevelCwd}

// LevelRank orders signal levels, strongest first; an unknown level is last.
func LevelRank(level string) int {
	for rank, name := range levelNames {
		if name == level {
			return rank
		}
	}
	return len(levelNames)
}

// ResolveLevel is Resolve that also names the signal level the matching rule
// hit at ("" unless a project matched).
func (compiled *Compiled) ResolveLevel(identity Identity, groupID int64, knownRoots []string) (ProjectKey, string) {
	if identity.Empty() {
		return ProjectNoContext, ""
	}
	resolvedRoot := ""
	if identity.Cwd != "" {
		roots := append(append([]string{}, knownRoots...), identity.Roots...)
		if root := ResolveRoot(identity.Cwd, roots); root != identity.Cwd {
			resolvedRoot = root
		}
	}
	scopes := [][]compiledProject{compiled.byGroup[groupID], compiled.global}
	if groupID == 0 {
		scopes = scopes[1:]
	}
	for _, scope := range scopes {
		for level := tierDeclared; level <= tierCwd; level++ {
			for _, project := range scope {
				for _, rule := range project.rules {
					if rule.matches(identity, level, resolvedRoot) {
						return ProjectKey(project.project.ID), levelNames[level]
					}
				}
			}
		}
	}
	return ProjectUnattributed, ""
}

// IsService reports whether a caller is classified as a service principal; a
// token's class overrides its user's.
func (compiled *Compiled) IsService(userID, tokenID int64) bool {
	if class, ok := compiled.tokens[tokenID]; ok && tokenID > 0 {
		return class == ClassService
	}
	return compiled.users[userID] == ClassService
}

// GroupMembers returns the users of a group, ascending.
func (compiled *Compiled) GroupMembers(groupID int64) []int64 {
	members := make([]int64, 0)
	for user, group := range compiled.members {
		if group == groupID {
			members = append(members, user)
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
	return members
}

// MatchRules reports whether draft rules match an identity at any tier (rule
// hit preview).
func MatchRules(rules []compiledRule, identity Identity, knownRoots []string) bool {
	compiled := &Compiled{global: []compiledProject{{project: Project{ID: 1}, rules: rules}}}
	return compiled.Resolve(identity, 0, knownRoots) == 1
}

// Catalog returns a copy of the compiled catalog.
func (compiled *Compiled) Catalog() Catalog { return compiled.catalog.clone() }

// Principals returns the classification and membership for ComputeWeek.
func (compiled *Compiled) Principals() Principals {
	principals := Principals{UserClass: map[int64]string{}, TokenClass: map[int64]string{}, Groups: map[int64]int64{}}
	for id, class := range compiled.users {
		principals.UserClass[id] = class
	}
	for id, class := range compiled.tokens {
		principals.TokenClass[id] = class
	}
	for user, group := range compiled.members {
		principals.Groups[user] = group
	}
	return principals
}

// GroupOf returns a user's group, 0 when none.
func (compiled *Compiled) GroupOf(userID int64) int64 { return compiled.members[userID] }

// ProjectName returns a project's name, or "" for an unknown id.
func (compiled *Compiled) ProjectName(id int64) string { return compiled.names[id] }

// HasGroup reports whether a group exists.
func (compiled *Compiled) HasGroup(id int64) bool {
	_, ok := compiled.groups[id]
	return ok
}
