package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/orgreport"
)

// Weekly project reports on the facade (contract section 4.3.4). Durations
// in nanoseconds become seconds (_seconds), project names and unattributed
// values are _untrusted, and frozen is also given as final.

const (
	agentModuleOrgReports = "org_reports"
	agentWeeklyMeAdmin    = "An administrator token has no weekly row of its own; use `llmaudit weekly report` for everybody's rows."
	agentWeeklyMeUnknown  = "This developer token's NewAPI user is unknown, so there is no weekly row to read."
	agentWeeklyMeIdle     = "No activity was recorded for this user in the current week yet."
)

type agentTokens struct {
	Uncached   int64 `json:"uncached"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
	Output     int64 `json:"output"`
}

func agentTokensOf(tokens orgreport.Tokens) agentTokens {
	return agentTokens{Uncached: tokens.Uncached, CacheRead: tokens.CacheRead, CacheWrite: tokens.CacheWrite, Output: tokens.Output}
}

type agentProjectCell struct {
	Project       int64       `json:"project"`
	ActiveSeconds float64     `json:"active_seconds"`
	Roots         int         `json:"roots"`
	Requests      int         `json:"requests"`
	Tokens        agentTokens `json:"tokens"`
	CostUSD       float64     `json:"cost_usd"`
}

func agentProjectCellOf(cell orgreport.ProjectCell) agentProjectCell {
	return agentProjectCell{Project: int64(cell.Project), ActiveSeconds: agentSeconds(cell.ActiveNS), Roots: cell.Roots,
		Requests: cell.Requests, Tokens: agentTokensOf(cell.Tokens), CostUSD: cell.CostUSD}
}

func agentProjectCells(cells []orgreport.ProjectCell) []agentProjectCell {
	out := make([]agentProjectCell, 0, len(cells))
	for _, cell := range cells {
		out = append(out, agentProjectCellOf(cell))
	}
	return out
}

type agentFlag struct {
	Code      string `json:"code"`
	Value     int64  `json:"value"`
	Threshold int64  `json:"threshold,omitempty"`
}

type agentUserRow struct {
	UserID             int64              `json:"user_id"`
	GroupID            int64              `json:"group_id"`
	ActiveSeconds      float64            `json:"active_seconds"`
	OtherActiveSeconds float64            `json:"other_active_seconds"`
	InferredSeconds    float64            `json:"inferred_seconds"`
	Roots              int                `json:"roots"`
	SingleRequestRoots int                `json:"single_request_roots"`
	Requests           int                `json:"requests"`
	IdentifiedRequests int                `json:"identified_requests"`
	BilledRequests     int                `json:"billed_requests"`
	Tokens             agentTokens        `json:"tokens"`
	CostUSD            float64            `json:"cost_usd"`
	PeakConcurrency    int                `json:"peak_concurrency"`
	AvgConcurrency     float64            `json:"avg_concurrency"`
	DailyActiveSeconds []float64          `json:"daily_active_seconds"`
	Projects           []agentProjectCell `json:"projects"`
	Flags              []agentFlag        `json:"flags"`
}

func agentUserRowOf(row orgreport.UserRow) agentUserRow {
	out := agentUserRow{
		UserID: row.UserID, GroupID: row.GroupID, ActiveSeconds: agentSeconds(row.ActiveNS),
		OtherActiveSeconds: agentSeconds(row.OtherActiveNS), InferredSeconds: agentSeconds(row.InferredNS),
		Roots: row.Roots, SingleRequestRoots: row.SingleRequestRoots, Requests: row.Requests,
		IdentifiedRequests: row.IdentifiedRequests, BilledRequests: row.BilledRequests, Tokens: agentTokensOf(row.Tokens),
		CostUSD: row.CostUSD, PeakConcurrency: row.PeakConcurrency, AvgConcurrency: row.AvgConcurrency,
		DailyActiveSeconds: make([]float64, 0, len(row.Daily)), Projects: agentProjectCells(row.Projects),
		Flags: make([]agentFlag, 0, len(row.Flags)),
	}
	for _, day := range row.Daily {
		out.DailyActiveSeconds = append(out.DailyActiveSeconds, agentSeconds(day))
	}
	for _, flag := range row.Flags {
		out.Flags = append(out.Flags, agentFlag{Code: flag.Code, Value: flag.Value, Threshold: flag.Threshold})
	}
	return out
}

type agentProjectRef struct {
	ID            int64  `json:"id"`
	NameUntrusted string `json:"name_untrusted"`
}

func agentProjectRefs(refs []orgreport.ProjectRef) []agentProjectRef {
	out := make([]agentProjectRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, agentProjectRef{ID: ref.ID, NameUntrusted: ref.Name})
	}
	return out
}

type agentSelfReport struct {
	Week     string            `json:"week"`
	Timezone string            `json:"timezone"`
	Row      *agentUserRow     `json:"row"`
	Projects []agentProjectRef `json:"projects"`
}

func (handler *managementHandler) agentOrgReady(writer http.ResponseWriter) bool {
	if handler.org == nil {
		agentModuleDisabled(writer, agentModuleOrgReports)
		return false
	}
	return true
}

// serveAgentWeeklyMe is GET /weekly/me. The user comes from the token's
// identity through the rule the web uses (D7).
func (handler *managementHandler) serveAgentWeeklyMe(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
	defer cancel()
	report, err := handler.org.Self(ctx, selfWeeklyUserID(call.Principal))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	out := agentSelfReport{Week: report.Week, Timezone: report.Timezone, Projects: agentProjectRefs(report.Projects)}
	var actions []string
	if report.Row != nil {
		row := agentUserRowOf(*report.Row)
		out.Row = &row
	} else {
		actions = append(actions, weeklyMeAction(call.Principal))
	}
	// "My week" is always the current, open week, so a developer's row (or
	// its absence so far) can still change; an administrator token or an
	// unknown user has no row at all, and that cannot change (contract
	// section 4.3.4).
	writeAgentRead(writer, out, weeklyFinalMeta(selfWeeklyUserID(call.Principal) == 0), true, actions...)
}

// agentWeek checks a week parameter against the configured first weekday so
// the error can name it (contract section 4.3.4); the service still
// validates the week itself.
func (handler *managementHandler) agentWeek(writer http.ResponseWriter, values url.Values) (string, bool) {
	week := values.Get("week")
	if !values.Has("week") {
		return "", true
	}
	if failure := handler.agentWeekFailure(week, "week"); failure != nil {
		failure.write(writer)
		return "", false
	}
	return week, true
}

// agentWeekFailure is the refusal of a week label that is not a date or not
// the configured first weekday, naming field; nil when the label passes.
func (handler *managementHandler) agentWeekFailure(week, field string) *agentFailure {
	day, err := time.Parse(orgreport.WeekLayout, week)
	if err != nil {
		return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "`" + field + "` must be a YYYY-MM-DD date",
			Details: map[string]any{"field": field, "reason": reasonInvalidFormat}}
	}
	settings := handler.org.Settings()
	first := time.Monday
	if settings.WeekStart == "sunday" {
		first = time.Sunday
	}
	if day.Weekday() != first {
		nearest := day.AddDate(0, 0, -((int(day.Weekday()) - int(first) + 7) % 7))
		return &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "`" + field + "` must be the first day of a report week (a " + settings.WeekStart + "; " + nearest.Format(orgreport.WeekLayout) + " starts the week containing that date)",
			Hint:    "Use --week " + nearest.Format(orgreport.WeekLayout) + ", the start of the week containing that date.",
			Details: map[string]any{"field": field, "reason": reasonNotWeekStart, "week_start": settings.WeekStart}}
	}
	return nil
}

func agentGroupID(values url.Values) (*int64, error) {
	return parseAgentPositiveID(values, "group_id", 0)
}

// agentUnknownOrgObjects explains an empty result read for a project group
// or project the organization catalog does not have (contract section 0.1
// item 119). The web routes answer such a read with an empty result rather
// than an error, so the facade does too, but says that nothing was found
// instead of letting zeros pass for data. Group 0 (ungrouped) always exists.
func (handler *managementHandler) agentUnknownOrgObjects(groupID, projectID *int64) []string {
	if handler.org == nil || (groupID == nil || *groupID == 0) && (projectID == nil || *projectID <= 0) {
		return nil
	}
	catalog := handler.org.Catalog()
	var actions []string
	if groupID != nil && *groupID != 0 {
		found := false
		for _, group := range catalog.Groups {
			found = found || group.ID == *groupID
		}
		if !found {
			actions = append(actions, fmt.Sprintf("No project group with id %d exists, so the result is empty, not a measurement of zero activity; `llmaudit config show --kind org` lists the groups.", *groupID))
		}
	}
	if projectID != nil && *projectID > 0 {
		found := false
		for _, project := range catalog.Projects {
			found = found || project.ID == *projectID
		}
		if !found {
			actions = append(actions, fmt.Sprintf("No project with id %d exists, so the result is empty, not a measurement of zero activity; `llmaudit config show --kind org` lists the projects.", *projectID))
		}
	}
	return actions
}

// errAgentWeekRefused is a week the service refused after the facade's own
// check passed.
var errAgentWeekRefused = argFormat("week", "the first day of a report week, YYYY-MM-DD")

// agentWeeklyMetrics are the metric values of the weekly report.
var agentWeeklyMetrics = []string{orgreport.MetricHours, orgreport.MetricTokens, orgreport.MetricCost}

type agentServiceRow struct {
	UserID        int64       `json:"user_id"`
	TokenID       int64       `json:"token_id"`
	ActiveSeconds float64     `json:"active_seconds"`
	Roots         int         `json:"roots"`
	Requests      int         `json:"requests"`
	Tokens        agentTokens `json:"tokens"`
	CostUSD       float64     `json:"cost_usd"`
}

type agentRankedUser struct {
	agentUserRow
	Rank     int     `json:"rank"`
	Coverage float64 `json:"coverage"`
}

type agentWeeklyTotals struct {
	ActiveSeconds      float64     `json:"active_seconds"`
	Requests           int         `json:"requests"`
	IdentifiedRequests int         `json:"identified_requests"`
	Tokens             agentTokens `json:"tokens"`
	CostUSD            float64     `json:"cost_usd"`
	Users              int         `json:"users"`
}

type agentWeeklyReport struct {
	Week       string            `json:"week"`
	StartAt    *string           `json:"start_at"`
	EndAt      *string           `json:"end_at"`
	Timezone   string            `json:"timezone"`
	Metric     string            `json:"metric"`
	Frozen     bool              `json:"frozen"`
	Final      bool              `json:"final"`
	FrozenAt   *string           `json:"frozen_at"`
	Complete   bool              `json:"complete"`
	Users      []agentRankedUser `json:"users"`
	Unresolved *agentUserRow     `json:"unresolved"`
	Service    []agentServiceRow `json:"service"`
	Projects   []agentProjectRef `json:"projects"`
	Totals     agentWeeklyTotals `json:"totals"`
	GroupID    *int64            `json:"group_id"`
}

func agentWeeklyReportOf(report orgreport.WeeklyReport) agentWeeklyReport {
	out := agentWeeklyReport{
		Week: report.Week, StartAt: agentTime(report.StartNS), EndAt: agentTime(report.EndNS), Timezone: report.Timezone,
		Metric: report.Metric, Frozen: report.Frozen, Final: report.Frozen, FrozenAt: agentTime(report.FrozenAtNS),
		Complete: report.Complete, Users: make([]agentRankedUser, 0, len(report.Users)),
		Service: make([]agentServiceRow, 0, len(report.Service)), Projects: agentProjectRefs(report.Projects),
		Totals: agentWeeklyTotals{
			ActiveSeconds: agentSeconds(report.Totals.ActiveNS), Requests: report.Totals.Requests,
			IdentifiedRequests: report.Totals.IdentifiedRequests, Tokens: agentTokensOf(report.Totals.Tokens),
			CostUSD: report.Totals.CostUSD, Users: report.Totals.Users,
		},
		GroupID: report.GroupID,
	}
	for _, user := range report.Users {
		out.Users = append(out.Users, agentRankedUser{agentUserRow: agentUserRowOf(user.UserRow), Rank: user.Rank, Coverage: user.Coverage})
	}
	if report.Unresolved != nil {
		row := agentUserRowOf(*report.Unresolved)
		out.Unresolved = &row
	}
	for _, row := range report.Service {
		out.Service = append(out.Service, agentServiceRow{UserID: row.UserID, TokenID: row.TokenID, ActiveSeconds: agentSeconds(row.ActiveNS),
			Roots: row.Roots, Requests: row.Requests, Tokens: agentTokensOf(row.Tokens), CostUSD: row.CostUSD})
	}
	return out
}

// serveAgentWeeklyReport is GET /weekly/report (administrators).
func (handler *managementHandler) serveAgentWeeklyReport(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	week, ok := handler.agentWeek(writer, values)
	if !ok {
		return
	}
	groupID, err := agentGroupID(values)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	metric, err := agentClosedValue(values, "metric", agentWeeklyMetrics)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
	defer cancel()
	report, err := handler.org.Weekly(ctx, orgreport.WeeklyQuery{Week: week, GroupID: groupID, Metric: metric})
	if err != nil {
		err = asArgument(err, errAgentWeekRefused)
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentWeeklyReportOf(report), weeklyReportMeta(report), true)
}

// agentIncompleteEvidencePending is the reason a weekly read is not final.
const agentIncompleteEvidencePending = "evidence_pending"

// weeklyReportMeta takes completeness from the report itself.
func weeklyReportMeta(report orgreport.WeeklyReport) agentapi.Meta {
	meta := agentMetaOK()
	if !report.Complete {
		meta.Complete, meta.IncompleteReason = false, agentIncompleteEvidencePending
	}
	return meta
}

// weeklyFinalMeta is the meta of a weekly read whose services give no
// completeness of their own (contract section 0.1 item 95): complete only
// when the data is final, i.e. it comes from a frozen week; data of an open
// week, or of an ended week not frozen yet, can still change.
func weeklyFinalMeta(final bool) agentapi.Meta {
	meta := agentMetaOK()
	if !final {
		meta.Complete, meta.IncompleteReason = false, agentIncompleteEvidencePending
	}
	return meta
}

// agentWeekStates is the optional read of a week's frozen state the
// orgreport service offers (the plans use it too).
type agentWeekStates interface {
	WeekState(ctx context.Context, label string) (orgreport.WeekState, error)
}

// weekFrozen reports whether the week label (empty: the current week) has a
// frozen snapshot. Without a snapshot store no week is ever final.
func (handler *managementHandler) weekFrozen(ctx context.Context, label string) bool {
	states, ok := handler.org.(agentWeekStates)
	if !ok {
		return false
	}
	if label == "" {
		current, err := handler.org.Self(ctx, 0)
		if err != nil {
			return false
		}
		label = current.Week
	}
	state, err := states.WeekState(ctx, label)
	return err == nil && state.Frozen
}

// weeklyMeAction explains an empty "my week" by its cause.
func weeklyMeAction(caller principal) string {
	switch {
	case caller.Role != roleDeveloper:
		return agentWeeklyMeAdmin
	case selfWeeklyUserID(caller) == 0:
		return agentWeeklyMeUnknown
	default:
		return agentWeeklyMeIdle
	}
}

type agentTrendWeek struct {
	Week          string             `json:"week"`
	Frozen        bool               `json:"frozen"`
	Final         bool               `json:"final"`
	ActiveSeconds float64            `json:"active_seconds"`
	Tokens        int64              `json:"tokens"`
	CostUSD       float64            `json:"cost_usd"`
	Users         int                `json:"users"`
	Projects      []agentProjectCell `json:"projects"`
}

type agentWeeklyTrend struct {
	Weeks    []agentTrendWeek  `json:"weeks"`
	Projects []agentProjectRef `json:"projects"`
}

// serveAgentWeeklyTrend is GET /weekly/trend (administrators).
func (handler *managementHandler) serveAgentWeeklyTrend(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	weeks := int64(8)
	if values.Has("weeks") {
		parsed, ok := parseAgentID(values.Get("weeks"), false)
		if !ok || parsed < 1 || parsed > orgreport.MaxTrendWeeks {
			handler.writeAgentServiceFailure(writer, argRange("weeks", 1, orgreport.MaxTrendWeeks), "")
			return
		}
		weeks = parsed
	}
	groupID, err := agentGroupID(values)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
	defer cancel()
	report, err := handler.org.Trend(ctx, int(weeks), groupID)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	out := agentWeeklyTrend{Weeks: make([]agentTrendWeek, 0, len(report.Weeks)), Projects: agentProjectRefs(report.Projects)}
	final := true
	for _, week := range report.Weeks {
		final = final && week.Frozen
		out.Weeks = append(out.Weeks, agentTrendWeek{Week: week.Week, Frozen: week.Frozen, Final: week.Frozen,
			ActiveSeconds: agentSeconds(week.ActiveNS), Tokens: week.Tokens, CostUSD: week.CostUSD, Users: week.Users,
			Projects: agentProjectCells(week.Projects)})
	}
	// A trend is final only when every week in it is.
	writeAgentRead(writer, out, weeklyFinalMeta(final), true)
}

type agentProjectContributor struct {
	UserID  int64 `json:"user_id"`
	GroupID int64 `json:"group_id"`
	agentProjectCell
}

type agentProjectReport struct {
	Week         string                    `json:"week"`
	Project      agentProjectRef           `json:"project"`
	Frozen       bool                      `json:"frozen"`
	Final        bool                      `json:"final"`
	Contributors []agentProjectContributor `json:"contributors"`
	Total        agentProjectCell          `json:"total"`
}

// serveAgentWeeklyProject is GET /weekly/projects/{id} (administrators); id
// may be -1 (unattributed) or -2 (no project context).
func (handler *managementHandler) serveAgentWeeklyProject(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	id, ok := parseAgentID(call.Params["id"], true)
	if !ok {
		handler.writeAgentServiceFailure(writer, argFormat("id", "a project id (ASCII digits), -1 for unattributed or -2 for no project context"), "")
		return
	}
	week, ok := handler.agentWeek(writer, values)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
	defer cancel()
	report, err := handler.org.ProjectWeekly(ctx, id, week)
	if err != nil {
		err = asArgument(err, errAgentWeekRefused)
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	out := agentProjectReport{Week: report.Week, Project: agentProjectRef{ID: report.Project.ID, NameUntrusted: report.Project.Name},
		Frozen: report.Frozen, Final: report.Frozen, Contributors: make([]agentProjectContributor, 0, len(report.Contributors)),
		Total: agentProjectCellOf(report.Total)}
	for _, contributor := range report.Contributors {
		out.Contributors = append(out.Contributors, agentProjectContributor{UserID: contributor.UserID, GroupID: contributor.GroupID,
			agentProjectCell: agentProjectCellOf(contributor.ProjectCell)})
	}
	writeAgentRead(writer, out, weeklyFinalMeta(report.Frozen), true)
}

type agentDraftRule struct {
	Kind             string `json:"kind"`
	PatternUntrusted string `json:"pattern_untrusted"`
}

type agentUnattributedEntry struct {
	Kind           string         `json:"kind"`
	ValueUntrusted string         `json:"value_untrusted"`
	Requests       int            `json:"requests"`
	Users          int            `json:"users"`
	DraftRule      agentDraftRule `json:"draft_rule"`
}

// serveAgentWeeklyUnattributed is GET /weekly/unattributed (administrators).
func (handler *managementHandler) serveAgentWeeklyUnattributed(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	week, ok := handler.agentWeek(writer, values)
	if !ok {
		return
	}
	limit, err := parseAgentLimit(values, 20, 200)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	entries, err := handler.org.Unattributed(ctx, week, limit)
	if err != nil {
		err = asArgument(err, errAgentWeekRefused)
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	items := make([]agentUnattributedEntry, 0, len(entries))
	for _, entry := range entries {
		items = append(items, agentUnattributedEntry{Kind: entry.Kind, ValueUntrusted: entry.Value, Requests: entry.Requests,
			Users: entry.Users, DraftRule: agentDraftRule{Kind: entry.DraftRule.Kind, PatternUntrusted: entry.DraftRule.Pattern}})
	}
	// The entries are always computed live; they are final once the week is
	// frozen.
	writeAgentRead(writer, map[string]any{"items": items}, weeklyFinalMeta(handler.weekFrozen(ctx, week)), true)
}
