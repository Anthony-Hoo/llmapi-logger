package orgreport

import (
	"context"
	"errors"
	"sort"
)

// Report metrics.
const (
	MetricHours  = "hours"
	MetricTokens = "tokens"
	MetricCost   = "cost"
)

// WeeklyQuery selects one report week.
type WeeklyQuery struct {
	Week    string
	GroupID *int64
	Metric  string
}

// RankedUser is one ranking row; Rank is 1-based within the filtered set.
type RankedUser struct {
	UserRow
	Rank     int     `json:"rank"`
	Coverage float64 `json:"coverage"`
}

// ProjectRef names a project of the week for legends.
type ProjectRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Totals sums the ranked rows of a report.
type Totals struct {
	ActiveNS           int64   `json:"active_ns"`
	Requests           int     `json:"requests"`
	IdentifiedRequests int     `json:"identified_requests"`
	Tokens             Tokens  `json:"tokens"`
	CostUSD            float64 `json:"cost_usd"`
	Users              int     `json:"users"`
}

// WeeklyReport is the response of GET /api/v1/org/weekly.
type WeeklyReport struct {
	Week       string       `json:"week"`
	StartNS    int64        `json:"start_ns"`
	EndNS      int64        `json:"end_ns"`
	Timezone   string       `json:"timezone"`
	Metric     string       `json:"metric"`
	Frozen     bool         `json:"frozen"`
	FrozenAtNS int64        `json:"frozen_at_ns,omitempty"`
	Complete   bool         `json:"complete"`
	Users      []RankedUser `json:"users"`
	Unresolved *UserRow     `json:"unresolved,omitempty"`
	Service    []ServiceRow `json:"service"`
	Projects   []ProjectRef `json:"projects"`
	Totals     Totals       `json:"totals"`
	GroupID    *int64       `json:"group_id"`
}

// weekResult resolves a WeeklyQuery week and returns its result: the frozen
// snapshot for an ended week that has one, a live computation otherwise.
func (service *Service) weekResult(ctx context.Context, label string) (Week, WeekResult, map[int64]string, *WeeklySnapshot, error) {
	week, err := service.resolveWeek(label)
	if err != nil {
		return Week{}, WeekResult{}, nil, nil, err
	}
	if service.snapshots != nil && service.now().After(week.End) {
		snapshot, ok, err := service.snapshots.LoadWeeklySnapshot(ctx, week.Label())
		if err != nil {
			return Week{}, WeekResult{}, nil, nil, err
		}
		if ok {
			return week, snapshot.Result, snapshot.ProjectNames, &snapshot, nil
		}
	}
	result, compiled, err := service.live(ctx, week)
	if err != nil {
		return Week{}, WeekResult{}, nil, nil, err
	}
	return week, result, projectNames(result, compiled), nil, nil
}

func metricValue(row UserRow, metric string) float64 {
	switch metric {
	case MetricTokens:
		return float64(row.Tokens.Total())
	case MetricCost:
		return row.CostUSD
	default:
		return float64(row.ActiveNS)
	}
}

func normalizeMetric(metric string) (string, error) {
	switch metric {
	case "", MetricHours:
		return MetricHours, nil
	case MetricTokens, MetricCost:
		return metric, nil
	}
	return "", errors.Join(ErrInvalid, errors.New("orgreport: metric must be hours, tokens or cost"))
}

// Weekly builds the ranking report of one week.
func (service *Service) Weekly(ctx context.Context, query WeeklyQuery) (WeeklyReport, error) {
	metric, err := normalizeMetric(query.Metric)
	if err != nil {
		return WeeklyReport{}, err
	}
	if query.GroupID != nil && *query.GroupID != 0 && !service.current.Load().HasGroup(*query.GroupID) {
		return WeeklyReport{}, ErrNotFound
	}
	week, result, names, snapshot, err := service.weekResult(ctx, query.Week)
	if err != nil {
		return WeeklyReport{}, err
	}
	report := WeeklyReport{
		Week: week.Label(), StartNS: week.Start.UnixNano(), EndNS: week.End.UnixNano(),
		Timezone: service.settingsNow().Public().Timezone, Metric: metric, GroupID: query.GroupID,
		Users: []RankedUser{}, Service: []ServiceRow{}, Projects: []ProjectRef{},
		Complete: service.now().After(week.End),
	}
	if snapshot != nil {
		report.Frozen, report.FrozenAtNS = true, snapshot.FrozenAtNS
	}
	inGroup := func(group int64) bool {
		return query.GroupID == nil || group == *query.GroupID
	}
	seenProjects := map[int64]bool{}
	for _, row := range result.Users {
		if !inGroup(row.GroupID) {
			continue
		}
		if row.UserID == 0 {
			unresolved := row
			report.Unresolved = &unresolved
			continue
		}
		report.Users = append(report.Users, RankedUser{UserRow: row, Coverage: row.Coverage()})
		for _, cell := range row.Projects {
			if cell.Project > 0 && !seenProjects[int64(cell.Project)] {
				seenProjects[int64(cell.Project)] = true
				report.Projects = append(report.Projects, ProjectRef{ID: int64(cell.Project), Name: names[int64(cell.Project)]})
			}
		}
		report.Totals.ActiveNS += row.ActiveNS
		report.Totals.Requests += row.Requests
		report.Totals.IdentifiedRequests += row.IdentifiedRequests
		report.Totals.Tokens.add(row.Tokens)
		report.Totals.CostUSD += row.CostUSD
	}
	report.Totals.Users = len(report.Users)
	sort.SliceStable(report.Users, func(i, j int) bool {
		left, right := metricValue(report.Users[i].UserRow, metric), metricValue(report.Users[j].UserRow, metric)
		if left != right {
			return left > right
		}
		return report.Users[i].UserID < report.Users[j].UserID
	})
	for index := range report.Users {
		report.Users[index].Rank = index + 1
	}
	sort.Slice(report.Projects, func(i, j int) bool { return report.Projects[i].ID < report.Projects[j].ID })
	if query.GroupID == nil {
		report.Service = result.Service
	} else {
		for _, row := range result.Service {
			if inGroup(service.current.Load().GroupOf(row.UserID)) {
				report.Service = append(report.Service, row)
			}
		}
	}
	return report, nil
}

// TrendWeek is one week of the trend.
type TrendWeek struct {
	Week     string        `json:"week"`
	Frozen   bool          `json:"frozen"`
	ActiveNS int64         `json:"active_ns"`
	Tokens   int64         `json:"tokens"`
	CostUSD  float64       `json:"cost_usd"`
	Users    int           `json:"users"`
	Projects []ProjectCell `json:"projects"`
}

// TrendReport is the response of GET /api/v1/org/weekly/trend.
type TrendReport struct {
	Weeks    []TrendWeek  `json:"weeks"`
	Projects []ProjectRef `json:"projects"`
}

// MaxTrendWeeks bounds a trend request.
const MaxTrendWeeks = 12

// Trend returns the last weeks ending with the current one, oldest first.
func (service *Service) Trend(ctx context.Context, weeks int, groupID *int64) (TrendReport, error) {
	if weeks <= 0 || weeks > MaxTrendWeeks {
		return TrendReport{}, ErrInvalid
	}
	current := service.settingsNow().WeekOf(service.now())
	labels := make([]string, weeks)
	week := current
	for index := weeks - 1; index >= 0; index-- {
		labels[index] = week.Label()
		week = week.Previous()
	}
	report := TrendReport{Weeks: make([]TrendWeek, 0, weeks), Projects: []ProjectRef{}}
	seen := map[int64]bool{}
	for _, label := range labels {
		weekly, err := service.Weekly(ctx, WeeklyQuery{Week: label, GroupID: groupID})
		if err != nil {
			return TrendReport{}, err
		}
		entry := TrendWeek{Week: label, Frozen: weekly.Frozen, ActiveNS: weekly.Totals.ActiveNS, Tokens: weekly.Totals.Tokens.Total(),
			CostUSD: weekly.Totals.CostUSD, Users: weekly.Totals.Users, Projects: []ProjectCell{}}
		byProject := map[ProjectKey]*ProjectCell{}
		for _, user := range weekly.Users {
			for _, cell := range user.Projects {
				total := byProject[cell.Project]
				if total == nil {
					total = &ProjectCell{Project: cell.Project}
					byProject[cell.Project] = total
				}
				total.ActiveNS += cell.ActiveNS
				total.Requests += cell.Requests
				total.Tokens.add(cell.Tokens)
				total.CostUSD += cell.CostUSD
				total.Roots += cell.Roots
			}
		}
		for _, cell := range byProject {
			entry.Projects = append(entry.Projects, *cell)
		}
		sort.Slice(entry.Projects, func(i, j int) bool { return entry.Projects[i].Project < entry.Projects[j].Project })
		for _, project := range weekly.Projects {
			if !seen[project.ID] {
				seen[project.ID] = true
				report.Projects = append(report.Projects, project)
			}
		}
		report.Weeks = append(report.Weeks, entry)
	}
	return report, nil
}

// ProjectContributor is one user's contribution to a project.
type ProjectContributor struct {
	UserID  int64 `json:"user_id"`
	GroupID int64 `json:"group_id"`
	ProjectCell
}

// ProjectReport is the response of GET /api/v1/org/projects/{id}/weekly.
type ProjectReport struct {
	Week         string               `json:"week"`
	Project      ProjectRef           `json:"project"`
	Frozen       bool                 `json:"frozen"`
	Contributors []ProjectContributor `json:"contributors"`
	Total        ProjectCell          `json:"total"`
}

// ProjectWeekly returns the contributors of one project (or of a bucket,
// -1 unattributed and -2 no context) in one week.
func (service *Service) ProjectWeekly(ctx context.Context, projectID int64, label string) (ProjectReport, error) {
	if projectID == 0 || projectID < int64(ProjectNoContext) {
		return ProjectReport{}, ErrNotFound
	}
	week, result, names, snapshot, err := service.weekResult(ctx, label)
	if err != nil {
		return ProjectReport{}, err
	}
	name := names[projectID]
	if name == "" && projectID > 0 {
		name = service.current.Load().ProjectName(projectID)
		if name == "" {
			return ProjectReport{}, ErrNotFound
		}
	}
	report := ProjectReport{Week: week.Label(), Project: ProjectRef{ID: projectID, Name: name}, Frozen: snapshot != nil,
		Contributors: []ProjectContributor{}, Total: ProjectCell{Project: ProjectKey(projectID)}}
	for _, row := range result.Users {
		for _, cell := range row.Projects {
			if int64(cell.Project) != projectID {
				continue
			}
			report.Contributors = append(report.Contributors, ProjectContributor{UserID: row.UserID, GroupID: row.GroupID, ProjectCell: cell})
			report.Total.ActiveNS += cell.ActiveNS
			report.Total.Requests += cell.Requests
			report.Total.Roots += cell.Roots
			report.Total.Tokens.add(cell.Tokens)
			report.Total.CostUSD += cell.CostUSD
		}
	}
	sort.Slice(report.Contributors, func(i, j int) bool {
		if report.Contributors[i].ActiveNS != report.Contributors[j].ActiveNS {
			return report.Contributors[i].ActiveNS > report.Contributors[j].ActiveNS
		}
		return report.Contributors[i].UserID < report.Contributors[j].UserID
	})
	return report, nil
}

// SelfReport is a developer's own current week.
type SelfReport struct {
	Week     string       `json:"week"`
	Timezone string       `json:"timezone"`
	Row      *UserRow     `json:"row"`
	Projects []ProjectRef `json:"projects"`
}

// Self returns the caller's own row of the current week and nothing about
// anyone else. A zero user id (identity unknown) returns an empty report.
func (service *Service) Self(ctx context.Context, userID int64) (SelfReport, error) {
	week := service.settingsNow().WeekOf(service.now())
	report := SelfReport{Week: week.Label(), Timezone: service.settingsNow().Public().Timezone, Projects: []ProjectRef{}}
	if userID <= 0 {
		return report, nil
	}
	result, compiled, err := service.live(ctx, week)
	if err != nil {
		return SelfReport{}, err
	}
	for _, row := range result.Users {
		if row.UserID != userID {
			continue
		}
		own := row
		report.Row = &own
		for _, cell := range row.Projects {
			if cell.Project > 0 {
				report.Projects = append(report.Projects, ProjectRef{ID: int64(cell.Project), Name: compiled.ProjectName(int64(cell.Project))})
			}
		}
	}
	return report, nil
}
