package orgreport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/security"
)

// Repository persists the administrator catalog. Create calls return the
// stored row with its database id.
type Repository interface {
	LoadOrgCatalog(ctx context.Context) (Catalog, error)
	CreateProjectGroup(ctx context.Context, group Group) (Group, error)
	UpdateProjectGroup(ctx context.Context, group Group) error
	DeleteProjectGroup(ctx context.Context, id int64) error
	CreateProject(ctx context.Context, project Project) (Project, error)
	UpdateProject(ctx context.Context, project Project) error
	DeleteProject(ctx context.Context, id int64) error
	SetGroupMember(ctx context.Context, member Member) error
	DeleteGroupMember(ctx context.Context, userID int64) error
	SetPrincipalClass(ctx context.Context, principal Principal) error
	DeletePrincipalClass(ctx context.Context, kind string, id int64) error
}

// SealedIdentity is one distinct encrypted identity of a time range.
type SealedIdentity struct {
	Key     string // hex identity fingerprint, equal to Request.IdentityKey
	AuditID string
	Version int
	Enc     []byte
}

// DataStore reads the report inputs of a time range [fromNS, toNS).
type DataStore interface {
	LoadOrgRequests(ctx context.Context, fromNS, toNS int64) ([]Request, error)
	LoadOrgIdentities(ctx context.Context, fromNS, toNS int64) ([]SealedIdentity, error)
}

// Options assembles a Service.
type Options struct {
	Settings   Settings
	Repository Repository
	Data       DataStore
	Snapshots  SnapshotStore
	Cipher     security.Cipher
	Logger     *slog.Logger
	Now        func() time.Time
	// IdentityVersion is the current project identity version
	// (insights.ProjectIdentityVersion); a week freezes only once every
	// audit has it. Zero means 1.
	IdentityVersion int
	// AnalysisProgress tells when the insights backfill has attempted every
	// unanalysed audit of a week (the parser worker). Without it, unanalysed
	// audits hold a week until the freeze deadline.
	AnalysisProgress AnalysisProgress
	// File is the configuration file's section, and SavedSettings where an
	// administrator's changes to it are kept. Both are needed to edit
	// settings at run time; without SavedSettings the file always applies.
	File          config.OrgReportsConfig
	SavedSettings SettingsStore
	// Clients are the clients the insights vocabulary can recognise. The
	// ranked clients an administrator saves must be among them: any other key
	// never matches a request. Empty means unknown, and nothing is checked.
	Clients []ClientOption
}

// Service is the organisation report surface used by the web layer and the
// parser worker's idle cadence.
type Service struct {
	// settings is replaced as a whole when an administrator saves a change;
	// read it through settingsNow.
	settings   atomic.Pointer[Settings]
	file       config.OrgReportsConfig
	saved      SettingsStore
	clients    []ClientOption
	settingsMu sync.Mutex
	// settingsNS is the highest settings version this process has stored or
	// read at startup, guarded by settingsMu; see saveSettings.
	settingsNS int64
	repository Repository
	data       DataStore
	snapshots  SnapshotStore
	cipher     security.Cipher
	logger     *slog.Logger
	now        func() time.Time

	identityVersion int
	progress        AnalysisProgress

	mu      sync.Mutex
	current atomic.Pointer[Compiled]

	job snapshotJob
}

// NewService loads and compiles the persisted catalog. A nil repository is
// accepted for tests and starts empty and read-only.
func NewService(ctx context.Context, options Options) (*Service, error) {
	if options.Settings.Location == nil || options.Settings.IdleGap <= 0 {
		return nil, errors.New("orgreport: settings are incomplete")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.IdentityVersion <= 0 {
		options.IdentityVersion = 1
	}
	service := &Service{
		file: options.File, saved: options.SavedSettings, clients: append([]ClientOption(nil), options.Clients...),
		repository: options.Repository, data: options.Data,
		snapshots: options.Snapshots, cipher: options.Cipher, logger: options.Logger, now: options.Now,
		identityVersion: options.IdentityVersion, progress: options.AnalysisProgress,
	}
	settings := options.Settings
	service.settings.Store(&settings)
	service.loadSavedSettings(ctx)
	catalog := Catalog{}
	if options.Repository != nil {
		loaded, err := options.Repository.LoadOrgCatalog(ctx)
		if err != nil {
			return nil, fmt.Errorf("orgreport: load catalog: %w", err)
		}
		catalog = loaded
	}
	compiled, err := Compile(catalog)
	if err != nil {
		return nil, fmt.Errorf("orgreport: compile persisted catalog: %w", err)
	}
	service.current.Store(compiled)
	return service, nil
}

// settingsNow returns the settings in use. The value is never modified after
// it is stored, its map included.
func (service *Service) settingsNow() Settings {
	return *service.settings.Load()
}

// Settings returns the UI view of the report settings.
func (service *Service) Settings() PublicSettings {
	return service.settingsNow().Public()
}

// Compiled returns the active catalog snapshot.
func (service *Service) Compiled() *Compiled { return service.current.Load() }

// Catalog returns the active catalog.
func (service *Service) Catalog() CatalogView {
	compiled := service.current.Load()
	view := CatalogView{Catalog: compiled.Catalog(), ServiceCandidates: []int64{}}
	if admin := service.settingsNow().AdminUserID; admin > 0 {
		if _, classified := compiled.users[admin]; !classified {
			view.ServiceCandidates = append(view.ServiceCandidates, admin)
		}
	}
	return view
}

// CatalogView is the administrator catalog plus the configured NewAPI
// administrator, proposed as a service principal until classified.
type CatalogView struct {
	Catalog
	ServiceCandidates []int64 `json:"service_candidates"`
}

func (service *Service) writable() error {
	if service == nil || service.repository == nil {
		return ErrUnavailable
	}
	return nil
}

func (service *Service) timestamp() int64 { return service.now().UnixNano() }

// change validates a candidate catalog before persisting anything, persists
// with apply, then publishes the candidate (with any database id apply
// filled in) as the new snapshot. A candidate that does not compile leaves
// both the database and the snapshot untouched.
func (service *Service) change(ctx context.Context, mutate func(*Catalog) error, apply func(context.Context, *Catalog) error) error {
	if err := service.writable(); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("orgreport: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	candidate, err := service.candidate(mutate)
	if err != nil {
		return err
	}
	if err := apply(ctx, &candidate); err != nil {
		return err
	}
	compiled, err := Compile(candidate)
	if err != nil {
		return err
	}
	service.current.Store(compiled)
	return nil
}

// placeholderID is the first id given to rows the database has not numbered
// yet while a candidate catalog is validated.
const placeholderID = int64(1 << 62)

// candidate is the validating half of change: it applies mutate to a copy of
// the published catalog and compiles the result with placeholder ids for
// rows the database has not numbered. It persists and publishes nothing, so
// the check-only entries call it without the lock.
func (service *Service) candidate(mutate func(*Catalog) error) (Catalog, error) {
	candidate := service.current.Load().Catalog()
	if err := mutate(&candidate); err != nil {
		return Catalog{}, err
	}
	probe := candidate.clone()
	next := placeholderID
	for index := range probe.Groups {
		if probe.Groups[index].ID == 0 {
			probe.Groups[index].ID = next
			next++
		}
	}
	for index := range probe.Projects {
		if probe.Projects[index].ID == 0 {
			probe.Projects[index].ID = next
			next++
		}
	}
	if _, err := Compile(probe); err != nil {
		return Catalog{}, err
	}
	return candidate, nil
}

// nextVersion stamps a write of an object whose version was previous: the
// clock, but never a value at or below previous, so two successive writes
// never leave the same version even when the clock repeats a reading.
func (service *Service) nextVersion(previous int64) int64 {
	return max(service.timestamp(), previous+1)
}

// GroupInput is the editable part of a group.
type GroupInput struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// CreateGroup adds a group.
func (service *Service) CreateGroup(ctx context.Context, input GroupInput) (Group, error) {
	now := service.timestamp()
	group := Group{Name: input.Name, Enabled: input.Enabled, CreatedAtNS: now, UpdatedAtNS: now}
	err := service.change(ctx, func(catalog *Catalog) error {
		catalog.Groups = append(catalog.Groups, group)
		return nil
	}, func(ctx context.Context, catalog *Catalog) error {
		stored, err := service.repository.CreateProjectGroup(ctx, group)
		if err != nil {
			return err
		}
		group = stored
		catalog.Groups[len(catalog.Groups)-1] = stored
		return nil
	})
	return group, err
}

// UpdateGroup renames or toggles a group.
func (service *Service) UpdateGroup(ctx context.Context, id int64, input GroupInput) (Group, error) {
	var updated Group
	err := service.change(ctx, func(catalog *Catalog) error {
		for index := range catalog.Groups {
			if catalog.Groups[index].ID == id {
				catalog.Groups[index].Name, catalog.Groups[index].Enabled = input.Name, input.Enabled
				catalog.Groups[index].UpdatedAtNS = max(service.nextVersion(catalog.Groups[index].UpdatedAtNS), catalog.Groups[index].CreatedAtNS)
				updated = catalog.Groups[index]
				return nil
			}
		}
		return ErrNotFound
	}, func(ctx context.Context, _ *Catalog) error {
		return service.repository.UpdateProjectGroup(ctx, updated)
	})
	return updated, err
}

// DeleteGroup removes a group that has no projects and no members.
func (service *Service) DeleteGroup(ctx context.Context, id int64) error {
	return service.change(ctx, deleteGroupMutation(id, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteProjectGroup(ctx, id)
	})
}

// deleteGroupMutation removes group id when it has no projects and no
// members and, unless expected is AnyVersion, when its version is expected.
// removed receives the group.
func deleteGroupMutation(id, expected int64, removed *Group) func(*Catalog) error {
	return func(catalog *Catalog) error {
		index := -1
		for candidate := range catalog.Groups {
			if catalog.Groups[candidate].ID == id {
				index = candidate
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		if !versionMatches(catalog.Groups[index].UpdatedAtNS, expected) {
			return ErrVersionConflict
		}
		for _, project := range catalog.Projects {
			if project.GroupID != nil && *project.GroupID == id {
				return conflictAt(ObjectGroup, id, "", ReasonHasProjects, "the group still has projects")
			}
		}
		for _, member := range catalog.Members {
			if member.GroupID == id {
				return conflictAt(ObjectGroup, id, "", ReasonHasMembers, "the group still has members")
			}
		}
		if removed != nil {
			*removed = catalog.Groups[index]
		}
		catalog.Groups = append(catalog.Groups[:index], catalog.Groups[index+1:]...)
		return nil
	}
}

// ProjectInput is the editable part of a project.
type ProjectInput struct {
	Name    string `json:"name"`
	GroupID *int64 `json:"group_id"`
	Enabled bool   `json:"enabled"`
	Rules   []Rule `json:"rules"`
}

func normalizeRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, Rule{Kind: rule.Kind, Pattern: trimPattern(rule.Pattern)})
	}
	return out
}

func trimPattern(pattern string) string {
	for len(pattern) > 0 && (pattern[0] == ' ' || pattern[0] == '\t') {
		pattern = pattern[1:]
	}
	for len(pattern) > 0 && (pattern[len(pattern)-1] == ' ' || pattern[len(pattern)-1] == '\t') {
		pattern = pattern[:len(pattern)-1]
	}
	return pattern
}

// CreateProject adds a project with its rules.
func (service *Service) CreateProject(ctx context.Context, input ProjectInput) (Project, error) {
	now := service.timestamp()
	project := Project{Name: input.Name, GroupID: input.GroupID, Enabled: input.Enabled, Rules: normalizeRules(input.Rules), CreatedAtNS: now, UpdatedAtNS: now}
	err := service.change(ctx, func(catalog *Catalog) error {
		catalog.Projects = append(catalog.Projects, cloneProject(project))
		return nil
	}, func(ctx context.Context, catalog *Catalog) error {
		stored, err := service.repository.CreateProject(ctx, project)
		if err != nil {
			return err
		}
		project = stored
		catalog.Projects[len(catalog.Projects)-1] = cloneProject(stored)
		return nil
	})
	return project, err
}

// UpdateProject replaces a project's name, scope, state and rules.
func (service *Service) UpdateProject(ctx context.Context, id int64, input ProjectInput) (Project, error) {
	var updated Project
	err := service.change(ctx, func(catalog *Catalog) error {
		for index := range catalog.Projects {
			if catalog.Projects[index].ID == id {
				project := &catalog.Projects[index]
				project.Name, project.GroupID, project.Enabled, project.Rules = input.Name, input.GroupID, input.Enabled, normalizeRules(input.Rules)
				project.UpdatedAtNS = max(service.nextVersion(project.UpdatedAtNS), project.CreatedAtNS)
				updated = cloneProject(*project)
				return nil
			}
		}
		return ErrNotFound
	}, func(ctx context.Context, _ *Catalog) error {
		return service.repository.UpdateProject(ctx, updated)
	})
	return updated, err
}

// DeleteProject removes a project. Frozen weekly snapshots keep its id and
// name.
func (service *Service) DeleteProject(ctx context.Context, id int64) error {
	return service.change(ctx, deleteProjectMutation(id, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteProject(ctx, id)
	})
}

func deleteProjectMutation(id, expected int64, removed *Project) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Projects {
			if catalog.Projects[index].ID == id {
				if !versionMatches(catalog.Projects[index].UpdatedAtNS, expected) {
					return ErrVersionConflict
				}
				if removed != nil {
					*removed = cloneProject(catalog.Projects[index])
				}
				catalog.Projects = append(catalog.Projects[:index], catalog.Projects[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	}
}

// SetMember puts a user into a group, moving it out of any other.
func (service *Service) SetMember(ctx context.Context, userID, groupID int64) (Member, error) {
	member := Member{UserID: userID, GroupID: groupID, UpdatedAtNS: service.timestamp()}
	err := service.change(ctx, setMemberMutation(&member, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.SetGroupMember(ctx, member)
	})
	return member, err
}

// setMemberMutation upserts *member. An existing row's version is never
// reused: member's stamp is raised above it. expected 0 requires that the
// user has no group yet; previous receives the row replaced, if any.
func setMemberMutation(member *Member, expected int64, previous **Member) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Members {
			if catalog.Members[index].UserID == member.UserID {
				existing := catalog.Members[index]
				if !versionMatches(existing.UpdatedAtNS, expected) {
					return ErrVersionConflict
				}
				if previous != nil {
					*previous = &existing
				}
				member.UpdatedAtNS = max(member.UpdatedAtNS, existing.UpdatedAtNS+1)
				catalog.Members[index] = *member
				return nil
			}
		}
		if !versionMatches(0, expected) {
			return ErrVersionConflict
		}
		catalog.Members = append(catalog.Members, *member)
		return nil
	}
}

// DeleteMember removes a user from its group.
func (service *Service) DeleteMember(ctx context.Context, userID int64) error {
	return service.change(ctx, deleteMemberMutation(userID, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeleteGroupMember(ctx, userID)
	})
}

func deleteMemberMutation(userID, expected int64, removed *Member) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Members {
			if catalog.Members[index].UserID == userID {
				if !versionMatches(catalog.Members[index].UpdatedAtNS, expected) {
					return ErrVersionConflict
				}
				if removed != nil {
					*removed = catalog.Members[index]
				}
				catalog.Members = append(catalog.Members[:index], catalog.Members[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	}
}

// SetPrincipal classifies a user or token.
func (service *Service) SetPrincipal(ctx context.Context, kind string, id int64, class string) (Principal, error) {
	principal := Principal{Kind: kind, ID: id, Class: class, UpdatedAtNS: service.timestamp()}
	err := service.change(ctx, setPrincipalMutation(&principal, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.SetPrincipalClass(ctx, principal)
	})
	return principal, err
}

// setPrincipalMutation upserts *principal like setMemberMutation.
func setPrincipalMutation(principal *Principal, expected int64, previous **Principal) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Principals {
			if catalog.Principals[index].Kind == principal.Kind && catalog.Principals[index].ID == principal.ID {
				existing := catalog.Principals[index]
				if !versionMatches(existing.UpdatedAtNS, expected) {
					return ErrVersionConflict
				}
				if previous != nil {
					*previous = &existing
				}
				principal.UpdatedAtNS = max(principal.UpdatedAtNS, existing.UpdatedAtNS+1)
				catalog.Principals[index] = *principal
				return nil
			}
		}
		if !versionMatches(0, expected) {
			return ErrVersionConflict
		}
		catalog.Principals = append(catalog.Principals, *principal)
		return nil
	}
}

// DeletePrincipal removes a classification; the principal is human again.
func (service *Service) DeletePrincipal(ctx context.Context, kind string, id int64) error {
	return service.change(ctx, deletePrincipalMutation(kind, id, AnyVersion, nil), func(ctx context.Context, _ *Catalog) error {
		return service.repository.DeletePrincipalClass(ctx, kind, id)
	})
}

func deletePrincipalMutation(kind string, id, expected int64, removed *Principal) func(*Catalog) error {
	return func(catalog *Catalog) error {
		for index := range catalog.Principals {
			if catalog.Principals[index].Kind == kind && catalog.Principals[index].ID == id {
				if !versionMatches(catalog.Principals[index].UpdatedAtNS, expected) {
					return ErrVersionConflict
				}
				if removed != nil {
					*removed = catalog.Principals[index]
				}
				catalog.Principals = append(catalog.Principals[:index], catalog.Principals[index+1:]...)
				return nil
			}
		}
		return ErrNotFound
	}
}

// IdentityAAD binds an encrypted identity to its audit and row version. The
// insights extractor seals with it and the report service opens with it.
func IdentityAAD(auditID string, version int) ([]byte, error) {
	return security.AAD(auditID, "project_identity", strconv.Itoa(version))
}
