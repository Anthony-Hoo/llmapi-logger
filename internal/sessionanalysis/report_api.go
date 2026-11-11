package sessionanalysis

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// SuggestionItem is one suggestion of the weekly report.
type SuggestionItem struct {
	ID          int64    `json:"id"`
	Kind        string   `json:"kind"`
	Text        string   `json:"text"`
	Sessions    int64    `json:"sessions"`
	Strong      bool     `json:"strong"`
	Status      string   `json:"status"`
	FirstSeenNS int64    `json:"first_seen_ns,string"`
	LastSeenNS  int64    `json:"last_seen_ns,string"`
	Evidence    []string `json:"evidence"`
}

// ReportResponse is GET /api/v1/session-analysis/report.
type ReportResponse struct {
	WeekStartNS     int64            `json:"week_start_ns,string"`
	Scope           string           `json:"scope"`
	Stats           *WeeklyStats     `json:"stats"`
	Previous        *WeeklyStats     `json:"previous"`
	Narrative       string           `json:"narrative"`
	NarrativeSource string           `json:"narrative_source,omitempty"`
	ComputedNS      int64            `json:"computed_ns,string"`
	Suggestions     []SuggestionItem `json:"suggestions"`
	Optimizations   []SessionItem    `json:"optimizations"`
	// Organisation reports only. ScopeID and ScopeName identify the project
	// or group of a 'project' or 'group' report. Projects and Groups list the
	// scopes an administrator can open for this week.
	ScopeID   int64         `json:"scope_id,omitempty"`
	ScopeName string        `json:"scope_name,omitempty"`
	Projects  []ScopeOption `json:"projects,omitempty"`
	Groups    []ScopeOption `json:"groups,omitempty"`
}

// ScopeOption is one project or group with weekly statistics.
type ScopeOption struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ReportTarget selects a project or group report; the zero value is the
// caller's own scope. At most one id is set.
type ReportTarget struct {
	ProjectID int64
	GroupID   int64
}

const maxReportSuggestions = 30

// Report returns the weekly review of the caller's scope: a developer's own
// key, or all keys together for an administrator. With organisation reports
// an administrator can also open one project or one project group. week is
// "current" or "previous"; weeks are cut in the runner's calendar.
func (service *QueryService) Report(ctx context.Context, week string, scope *query.Scope, target ReportTarget) (ReportResponse, error) {
	store, ok := service.store.(ReportStore)
	if !ok {
		return ReportResponse{}, query.ErrNotFound
	}
	start := weekStartOn(service.now(), service.location, service.weekStartsSunday)
	switch week {
	case "", "current":
	case "previous":
		start = start.AddDate(0, 0, -7)
	default:
		return ReportResponse{}, invalid("week must be current or previous")
	}
	selected := allTarget()
	if scope != nil {
		selected = personTarget(storage.ScopeKey{APIKeyFPR: scope.Fingerprint, NewAPITokenID: scope.TokenID})
	}
	scopeID, scopeLabel := int64(0), ""
	if target.ProjectID != 0 || target.GroupID != 0 {
		switch {
		case scope != nil:
			return ReportResponse{}, invalid("a developer session reads its own report only")
		case service.projects == nil:
			return ReportResponse{}, query.ErrNotFound
		case target.ProjectID < 0 || target.GroupID < 0 || (target.ProjectID != 0 && target.GroupID != 0):
			return ReportResponse{}, invalid("select one project or one group")
		case target.ProjectID != 0:
			selected, scopeID = projectTarget(target.ProjectID), target.ProjectID
			scopeLabel = service.projects.ProjectName(target.ProjectID)
		default:
			found := false
			for _, group := range service.projects.ReportGroups() {
				if group.ID == target.GroupID {
					selected, scopeID, scopeLabel, found = groupTarget(group.ID, group.Members), group.ID, group.Name, true
				}
			}
			if !found {
				return ReportResponse{}, query.ErrNotFound
			}
		}
	}
	scopeName, scopeKey, tokenID := selected.scope, selected.key, selected.tokenID
	response := ReportResponse{
		WeekStartNS: start.UnixNano(), Scope: scopeName, ScopeID: scopeID, ScopeName: scopeLabel,
		Suggestions: []SuggestionItem{}, Optimizations: []SessionItem{},
	}
	if scope == nil && service.projects != nil {
		var err error
		if response.Projects, response.Groups, err = service.reportScopes(ctx, store, start.UnixNano()); err != nil {
			return ReportResponse{}, err
		}
	}
	if row, err := store.LoadPeriodStats(ctx, start.UnixNano(), scopeName, scopeKey, tokenID); err == nil {
		var stats WeeklyStats
		if json.Unmarshal([]byte(row.Stats), &stats) == nil {
			response.Stats = &stats
		}
		response.ComputedNS, response.NarrativeSource = row.ComputedAtNS, row.NarrativeSource
		if len(row.NarrativeEnc) != 0 {
			aad, err := NarrativeAAD(row.WeekStartNS, row.Scope, row.ScopeKey)
			if err != nil {
				return ReportResponse{}, query.ErrIntegrity
			}
			plaintext, err := service.cipher.Decrypt(aad, row.NarrativeEnc)
			if err != nil {
				return ReportResponse{}, query.ErrIntegrity
			}
			response.Narrative = string(plaintext)
			clear(plaintext)
		}
	} else if !isNoRows(err) {
		return ReportResponse{}, err
	}
	if row, err := store.LoadPeriodStats(ctx, start.AddDate(0, 0, -7).UnixNano(), scopeName, scopeKey, tokenID); err == nil {
		var stats WeeklyStats
		if json.Unmarshal([]byte(row.Stats), &stats) == nil {
			response.Previous = &stats
		}
	} else if !isNoRows(err) {
		return ReportResponse{}, err
	}
	// A project or group week with too few callers shows counts only: its
	// suggestion texts and its costliest sessions would be one person's. A
	// week without statistics has no caller count and is treated the same.
	limited := selected.shared() && (response.Stats == nil || response.Stats.Limited)
	var suggestions []storage.Suggestion
	if selected.scope != storage.ScopeGroup && !limited {
		// Groups have no suggestions of their own.
		var err error
		if suggestions, err = store.ListSuggestions(ctx, scopeName, scopeKey, tokenID, maxReportSuggestions); err != nil {
			return ReportResponse{}, err
		}
	}
	for _, row := range suggestions {
		aad, err := SuggestionAAD(row.Scope, row.ScopeKey, row.Kind, row.FPR)
		if err != nil {
			return ReportResponse{}, query.ErrIntegrity
		}
		plaintext, err := service.cipher.Decrypt(aad, row.TextEnc)
		if err != nil {
			return ReportResponse{}, query.ErrIntegrity
		}
		item := SuggestionItem{
			ID: row.ID, Kind: row.Kind, Text: string(plaintext), Sessions: row.Support, Strong: row.Support >= strongSupport,
			Status: row.Status, FirstSeenNS: row.FirstSeenNS, LastSeenNS: row.LastSeenNS, Evidence: []string{},
		}
		clear(plaintext)
		_ = json.Unmarshal([]byte(row.Evidence), &item.Evidence)
		response.Suggestions = append(response.Suggestions, item)
	}
	filter := selected.signals(start.UnixNano(), start.AddDate(0, 0, 7).UnixNano())
	filter.Scope = storageScope(scope)
	if limited {
		return response, nil
	}
	seen := map[string]bool{}
	for _, flag := range []string{"loop", "thrash", "unverified"} {
		filter.Flags = []string{flag}
		rows, err := store.TopCostSessions(ctx, filter, 3)
		if err != nil {
			return ReportResponse{}, err
		}
		for _, row := range rows {
			id := hex.EncodeToString(row.SessionKey)
			if !seen[id] {
				seen[id] = true
				response.Optimizations = append(response.Optimizations, service.sessionItem(row))
			}
		}
	}
	return response, nil
}

// SuggestionStore dismisses suggestions.
type SuggestionStore interface {
	DismissSuggestion(ctx context.Context, id int64, scope string, nowNS int64) error
}

// DismissSuggestion marks one all-keys or project suggestion dismissed
// (administrators only; doc 24 section 8.3). Personal suggestions are never
// dismissed here.
func (service *QueryService) DismissSuggestion(ctx context.Context, id int64) error {
	store, ok := service.store.(SuggestionStore)
	if !ok || id <= 0 {
		return query.ErrNotFound
	}
	err := store.DismissSuggestion(ctx, id, storage.ScopeAll, service.now().UnixNano())
	if isNoRows(err) {
		err = store.DismissSuggestion(ctx, id, storage.ScopeProject, service.now().UnixNano())
	}
	if isNoRows(err) {
		return query.ErrNotFound
	}
	return err
}

// reportScopes lists the projects and groups that have statistics for a week.
func (service *QueryService) reportScopes(ctx context.Context, store ReportStore, weekStartNS int64) ([]ScopeOption, []ScopeOption, error) {
	projectKeys, err := store.ListPeriodScopeKeys(ctx, weekStartNS, storage.ScopeProject)
	if err != nil {
		return nil, nil, err
	}
	projects := make([]ScopeOption, 0, len(projectKeys))
	for _, key := range projectKeys {
		if id, ok := storage.IDOfScopeKey(key); ok {
			projects = append(projects, ScopeOption{ID: id, Name: service.projects.ProjectName(id)})
		}
	}
	groupKeys, err := store.ListPeriodScopeKeys(ctx, weekStartNS, storage.ScopeGroup)
	if err != nil {
		return nil, nil, err
	}
	stored := map[int64]bool{}
	for _, key := range groupKeys {
		if id, ok := storage.IDOfScopeKey(key); ok {
			stored[id] = true
		}
	}
	groups := make([]ScopeOption, 0, len(stored))
	for _, group := range service.projects.ReportGroups() {
		if stored[group.ID] {
			groups = append(groups, ScopeOption{ID: group.ID, Name: group.Name})
		}
	}
	return projects, groups, nil
}
