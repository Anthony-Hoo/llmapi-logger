package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
)

// Session analysis on the facade (contract section 4.3.5). The scope, the
// administrator-only selectors (D8) and the view-log viewer come from the
// shared access rules; the service applies D9 (work_relevance) and D10.

const (
	agentCursorAnalysisSessions = "analysis-sessions"
	agentModuleSessionAnalysis  = "session_analysis"
)

// Unified states of a session analysis run (contract section 4.1).
const (
	analysisStateRunning   = "running"
	analysisStateNeverRun  = "never_run"
	analysisStateFailed    = "failed"
	analysisStateSucceeded = "succeeded"
)

func (handler *managementHandler) agentAnalysisReady(writer http.ResponseWriter) bool {
	if handler.sessionAnalysis == nil {
		agentModuleDisabled(writer, agentModuleSessionAnalysis)
		return false
	}
	return true
}

// agentAnalysisRange resolves the required time range: from or since must
// be given; to defaults to now.
func (handler *managementHandler) agentAnalysisRange(values url.Values) (int64, int64, error) {
	timeRange, err := parseAgentRange(values, handler.agent.Now())
	if err != nil {
		return 0, 0, err
	}
	if timeRange.FromNS == nil {
		return 0, 0, argError("since")
	}
	to := handler.agent.Now().UnixNano()
	if timeRange.ToNS != nil {
		to = *timeRange.ToNS
	}
	return *timeRange.FromNS, to, nil
}

// agentAnalysisUser reads the administrator-only user_id selector: its value
// first, then the shared role rule (D8).
func agentAnalysisUser(values url.Values, caller principal) (*int64, error) {
	if !values.Has("user_id") {
		return nil, nil
	}
	id, ok := parseAgentID(values.Get("user_id"), false)
	if !ok || id <= 0 {
		return nil, argError("user_id")
	}
	if err := requireAdministratorSelector(caller, true); err != nil {
		return nil, err
	}
	return &id, nil
}

type agentSignalTotals struct {
	Sessions           int64    `json:"sessions"`
	AgentSessions      int64    `json:"agent_sessions"`
	ChatSessions       int64    `json:"chat_sessions"`
	Eligible           int64    `json:"eligible"`
	CostUSD            *float64 `json:"cost_usd"`
	LoopSessions       int64    `json:"loop_sessions"`
	LoopCostUSD        *float64 `json:"loop_cost_usd"`
	ThrashSessions     int64    `json:"thrash_sessions"`
	UnverifiedSessions int64    `json:"unverified_sessions"`
	SessionsWithWrites int64    `json:"sessions_with_writes"`
	FailureSessions    int64    `json:"failure_sessions"`
	Corrections        int64    `json:"corrections"`
	CorrectionSessions int64    `json:"correction_sessions"`
	ErrorPasteSessions int64    `json:"error_paste_sessions"`
	InterruptSessions  int64    `json:"interrupt_sessions"`
	HeavyModelSessions int64    `json:"heavy_model_sessions"`
	DangerSessions     int64    `json:"danger_sessions"`
	SecretSessions     int64    `json:"secret_sessions"`
	CompactionSessions int64    `json:"compaction_sessions"`
	CacheHitRate       *float64 `json:"cache_hit_rate"`
}

func agentSignalTotalsOf(totals sessionanalysis.SignalTotals) agentSignalTotals {
	return agentSignalTotals{
		Sessions: totals.Sessions, AgentSessions: totals.AgentSessions, ChatSessions: totals.ChatSessions,
		Eligible: totals.Eligible, CostUSD: totals.CostUSD, LoopSessions: totals.LoopSessions, LoopCostUSD: totals.LoopCostUSD,
		ThrashSessions: totals.ThrashSessions, UnverifiedSessions: totals.Unverified, SessionsWithWrites: totals.WithWrites,
		FailureSessions: totals.FailureSessions, Corrections: totals.Corrections, CorrectionSessions: totals.CorrectionSess,
		ErrorPasteSessions: totals.ErrorPasteSess, InterruptSessions: totals.InterruptSess, HeavyModelSessions: totals.HeavyModelSess,
		DangerSessions: totals.DangerSessions, SecretSessions: totals.SecretSessions, CompactionSessions: totals.CompactionSess,
		CacheHitRate: totals.CacheHitRate,
	}
}

type agentRunSummary struct {
	StartedAt         *string          `json:"started_at"`
	FinishedAt        *string          `json:"finished_at"`
	Trigger           string           `json:"trigger"`
	Candidates        int64            `json:"candidates"`
	Analyzed          int64            `json:"analyzed"`
	Skipped           int64            `json:"skipped"`
	SkipReasons       map[string]int64 `json:"skip_reasons"`
	FacetsDue         int64            `json:"facets_due"`
	FacetsOK          int64            `json:"facets_ok"`
	FacetsInvalid     int64            `json:"facets_invalid"`
	FacetsFailed      int64            `json:"facets_failed"`
	ModelInputTokens  int64            `json:"model_input_tokens"`
	ModelOutputTokens int64            `json:"model_output_tokens"`
	Error             string           `json:"error,omitempty"`
}

type agentCalibration struct {
	PromptVersion string             `json:"prompt_version"`
	Model         string             `json:"model"`
	Labels        int                `json:"labels"`
	Samples       int64              `json:"samples"`
	Compared      map[string]int64   `json:"compared"`
	Agreement     map[string]float64 `json:"agreement"`
	HiddenFields  []string           `json:"hidden_fields"`
	CreatedAt     *string            `json:"created_at"`
}

type agentAnalysisOverview struct {
	FromAt        *string           `json:"from_at"`
	ToAt          *string           `json:"to_at"`
	Current       agentSignalTotals `json:"current"`
	Previous      agentSignalTotals `json:"previous"`
	LastRun       *agentRunSummary  `json:"last_run"`
	Running       bool              `json:"running"`
	LLMEnabled    bool              `json:"llm_enabled"`
	Model         string            `json:"model,omitempty"`
	PromptVersion string            `json:"prompt_version"`
	Calibration   *agentCalibration `json:"calibration"`
}

func copyCounts[V int64 | float64](counts map[string]V) map[string]V {
	out := make(map[string]V, len(counts))
	for key, value := range counts {
		out[key] = value
	}
	return out
}

func agentRunSummaryOf(run *sessionanalysis.RunSummary) *agentRunSummary {
	if run == nil {
		return nil
	}
	return &agentRunSummary{
		StartedAt: agentTime(run.StartedNS), FinishedAt: agentTime(run.FinishedNS), Trigger: run.Trigger,
		Candidates: run.Candidates, Analyzed: run.Analyzed, Skipped: run.Skipped, SkipReasons: copyCounts(run.SkipReasons),
		FacetsDue: run.FacetsDue, FacetsOK: run.FacetsOK, FacetsInvalid: run.FacetsBad, FacetsFailed: run.FacetsError,
		ModelInputTokens: run.ModelInput, ModelOutputTokens: run.ModelOutput, Error: run.Error,
	}
}

func agentAnalysisOverviewOf(response sessionanalysis.OverviewResponse) agentAnalysisOverview {
	out := agentAnalysisOverview{
		FromAt: agentTime(response.FromNS), ToAt: agentTime(response.ToNS),
		Current: agentSignalTotalsOf(response.Current), Previous: agentSignalTotalsOf(response.Previous),
		Running: response.Running, LLMEnabled: response.LLMEnabled, Model: response.Model, PromptVersion: response.PromptVersion,
	}
	out.LastRun = agentRunSummaryOf(response.LastRun)
	if calibration := response.Calibration; calibration != nil {
		out.Calibration = &agentCalibration{
			PromptVersion: calibration.PromptVersion, Model: calibration.Model, Labels: calibration.Labels,
			Samples: calibration.Samples, Compared: copyCounts(calibration.Compared), Agreement: copyCounts(calibration.Agreement),
			HiddenFields: append([]string{}, calibration.HiddenFields...), CreatedAt: agentTime(calibration.CreatedNS),
		}
	}
	return out
}

// analysisRunMeta maps the run state of an overview (contract section 4.1).
func analysisRunMeta(response sessionanalysis.OverviewResponse) agentapi.Meta {
	meta := agentapi.Meta{Complete: true}
	switch {
	case response.Running:
		meta.State = analysisStateRunning
	case response.LastRun == nil:
		meta.State = analysisStateNeverRun
	case response.LastRun.Error != "":
		meta.State = analysisStateFailed
	default:
		meta.State = analysisStateSucceeded
	}
	if run := response.LastRun; run != nil && run.FacetsError+run.FacetsBad > 0 {
		meta.Complete, meta.IncompleteReason = false, "facets_incomplete"
	}
	return meta
}

// serveAgentAnalysisOverview is GET /analysis/overview.
func (handler *managementHandler) serveAgentAnalysisOverview(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	values, err := agentParams(request, "from", "to", "since", "user_id")
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	from, to, err := handler.agentAnalysisRange(values)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	userID, err := agentAnalysisUser(values, call.Principal)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Overview(ctx, from, to, callerReadScope(call.Principal), userID)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentAnalysisOverviewOf(response), analysisRunMeta(response), false)
}

type agentUserTotals struct {
	UserID *int64            `json:"user_id"`
	LastAt *string           `json:"last_at"`
	Totals agentSignalTotals `json:"totals"`
}

// serveAgentAnalysisUsers is GET /analysis/users (administrators).
func (handler *managementHandler) serveAgentAnalysisUsers(writer http.ResponseWriter, request *http.Request, _ agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	values, err := agentParams(request, "from", "to", "since")
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	from, to, err := handler.agentAnalysisRange(values)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Users(ctx, from, to)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	items := make([]agentUserTotals, 0, len(response.Items))
	for _, item := range response.Items {
		items = append(items, agentUserTotals{UserID: item.UserID, LastAt: agentTime(item.LastNS), Totals: agentSignalTotalsOf(item.Totals)})
	}
	writeAgentRead(writer, map[string]any{"from_at": agentTime(response.FromNS), "to_at": agentTime(response.ToNS), "items": items}, agentMetaOK(), false)
}

type agentAnalysisSession struct {
	SessionID        string           `json:"session_id"`
	TreeID           string           `json:"tree_id,omitempty"`
	TrendSessionID   string           `json:"trend_session_id,omitempty"`
	Kind             string           `json:"kind"`
	Client           string           `json:"client"`
	Model            string           `json:"model"`
	FirstAt          *string          `json:"first_at"`
	LastAt           *string          `json:"last_at"`
	LastAuditID      string           `json:"last_audit_id"`
	Requests         int64            `json:"requests"`
	Subagents        int64            `json:"subagents"`
	UserTurns        int64            `json:"user_turns"`
	ActiveSeconds    int64            `json:"active_seconds"`
	InputTokens      int64            `json:"input_tokens"`
	OutputTokens     int64            `json:"output_tokens"`
	CostUSD          *float64         `json:"cost_usd"`
	ToolCalls        int64            `json:"tool_calls"`
	ToolFailures     int64            `json:"tool_failures"`
	MaxFailureStreak int64            `json:"max_failure_streak"`
	Loops            int64            `json:"loops"`
	MaxLoopLength    int64            `json:"max_loop_length"`
	ThrashFiles      int64            `json:"thrash_files"`
	MaxFileWrites    int64            `json:"max_file_writes"`
	Verified         string           `json:"verified"`
	ErrorPastes      int64            `json:"error_pastes"`
	Interrupts       int64            `json:"interrupts"`
	Corrections      int64            `json:"corrections"`
	Compactions      int64            `json:"compactions"`
	ModelSwitches    int64            `json:"model_switches"`
	LengthStops      int64            `json:"length_stops"`
	UpstreamErrors   int64            `json:"upstream_errors"`
	HeavyModel       bool             `json:"heavy_model"`
	Danger           map[string]int64 `json:"danger"`
	Secrets          map[string]int64 `json:"secrets"`
	Eligible         bool             `json:"eligible"`
	SkipReason       string           `json:"skip_reason,omitempty"`
	FacetStatus      string           `json:"facet_status,omitempty"`
	TaskType         string           `json:"task_type,omitempty"`
	Outcome          string           `json:"outcome,omitempty"`
	Bucket           string           `json:"bucket,omitempty"`
	ProjectID        int64            `json:"project_id,omitempty"`
	ProjectUntrusted string           `json:"project_untrusted,omitempty"`
	UserID           int64            `json:"user_id,omitempty"`
}

func agentAnalysisSessionOf(item sessionanalysis.SessionItem) agentAnalysisSession {
	return agentAnalysisSession{
		SessionID: item.SessionID, TreeID: item.TreeID, TrendSessionID: item.TrendSessionID, Kind: item.Kind,
		Client: item.Client, Model: item.Model, FirstAt: agentTime(item.FirstNS), LastAt: agentTime(item.LastNS),
		LastAuditID: item.LastAuditID, Requests: item.Requests, Subagents: item.Subagents, UserTurns: item.UserTurns,
		ActiveSeconds: item.ActiveSeconds, InputTokens: item.InputTokens, OutputTokens: item.OutputTokens, CostUSD: item.CostUSD,
		ToolCalls: item.ToolCalls, ToolFailures: item.ToolFailures, MaxFailureStreak: item.MaxFailureStreak, Loops: item.Loops,
		MaxLoopLength: item.MaxLoopLength, ThrashFiles: item.ThrashFiles, MaxFileWrites: item.MaxFileWrites,
		Verified: item.Verified, ErrorPastes: item.ErrorPastes, Interrupts: item.Interrupts, Corrections: item.Corrections,
		Compactions: item.Compactions, ModelSwitches: item.ModelSwitches, LengthStops: item.LengthStops,
		UpstreamErrors: item.UpstreamErrors, HeavyModel: item.HeavyModel,
		Danger: copyCounts(item.Danger), Secrets: copyCounts(item.Secrets), Eligible: item.Eligible, SkipReason: item.SkipReason,
		FacetStatus: item.FacetStatus, TaskType: item.TaskType, Outcome: item.Outcome, Bucket: item.Bucket,
		ProjectID: item.ProjectID, ProjectUntrusted: item.Project, UserID: item.UserID,
	}
}

func agentAnalysisSessions(items []sessionanalysis.SessionItem) []agentAnalysisSession {
	out := make([]agentAnalysisSession, 0, len(items))
	for _, item := range items {
		out = append(out, agentAnalysisSessionOf(item))
	}
	return out
}

// serveAgentAnalysisSessions is GET /analysis/sessions.
func (handler *managementHandler) serveAgentAnalysisSessions(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	values, err := agentParams(request, "from", "to", "since", "kind", "flags", "cursor", "limit", "user_id")
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	from, to, err := handler.agentAnalysisRange(values)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	limit, err := parseAgentLimit(values, 50, 200)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	cursor, err := unwrapAgentCursor(agentCursorAnalysisSessions, values.Get("cursor"))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	userID, err := agentAnalysisUser(values, call.Principal)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	sessionsQuery := sessionanalysis.SessionsQuery{FromNS: from, ToNS: to, Kind: values.Get("kind"), Cursor: cursor, Limit: limit,
		Scope: callerReadScope(call.Principal), UserID: userID}
	if flags := values.Get("flags"); flags != "" {
		sessionsQuery.Flags = strings.Split(flags, ",")
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Sessions(ctx, sessionsQuery)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, map[string]any{
		"items":       agentAnalysisSessions(response.Items),
		"next_cursor": wrapAgentCursor(agentCursorAnalysisSessions, response.NextCursor),
	}, agentMetaOK(), true)
}

// recordSensitiveRead writes the sensitive_read audit row of a pack or facet
// read (contract section 3.4); the view log is written by the service.
func (handler *managementHandler) recordSensitiveRead(ctx context.Context, call agentCall, kind string, err error) {
	tokenID := call.Identity.TokenID
	entry := storage.AgentAuditEntry{
		Event: agentaccess.EventSensitiveRead, TokenID: &tokenID, Role: string(call.Identity.Role),
		Command: call.Meta.Command, CLIVersion: call.Meta.CLIVersion,
		ObjectKind: kind, ObjectID: call.Params["id"], Outcome: storage.AgentOutcomeOK,
	}
	if err != nil {
		entry.Outcome, entry.ErrorCode = storage.AgentOutcomeFailed, string(agentErrorCodeOf(err))
	}
	handler.agent.RecordAudit(ctx, entry)
}

type agentPack struct {
	SessionID     string            `json:"session_id"`
	PackID        string            `json:"pack_id"`
	Kind          string            `json:"kind"`
	TextUntrusted string            `json:"text_untrusted"`
	Refs          map[string]string `json:"refs"`
	Tokens        int64             `json:"tokens"`
	Truncated     bool              `json:"truncated"`
	Members       int64             `json:"members"`
	BuiltAt       *string           `json:"built_at"`
	ViewLogged    bool              `json:"view_logged"`
}

// serveAgentAnalysisPack is GET /analysis/sessions/{id}/pack. The service
// writes the view log before it returns content and withholds the content
// when that write fails (D11).
func (handler *managementHandler) serveAgentAnalysisPack(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	if _, err := agentParams(request); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Pack(ctx, call.Params["id"], callerReadScope(call.Principal), analysisViewer(call.Principal, true))
	handler.recordSensitiveRead(ctx, call, "analysis-pack", err)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	refs := make(map[string]string, len(response.Refs))
	for key, value := range response.Refs {
		refs[key] = value
	}
	writeAgentRead(writer, agentPack{
		SessionID: response.SessionID, PackID: response.PackID, Kind: response.Kind, TextUntrusted: response.Text, Refs: refs,
		Tokens: response.Tokens, Truncated: response.Truncated, Members: response.Members, BuiltAt: agentTime(response.BuiltNS),
		ViewLogged: true,
	}, truncatedMeta(response.Truncated), true)
}

type agentFacetItem struct {
	Ref           string `json:"ref"`
	TaskType      string `json:"task_type,omitempty"`
	WorkRelevance string `json:"work_relevance,omitempty"`
}

type agentEvidenceRef struct {
	LabelUntrusted string `json:"label_untrusted"`
	AuditID        string `json:"audit_id,omitempty"`
}

type agentFacet struct {
	SessionID               string                        `json:"session_id"`
	PackID                  string                        `json:"pack_id"`
	Kind                    string                        `json:"kind"`
	Status                  string                        `json:"status"`
	Model                   string                        `json:"model"`
	PromptVersion           string                        `json:"prompt_version"`
	CreatedAt               *string                       `json:"created_at"`
	TaskType                string                        `json:"task_type,omitempty"`
	Outcome                 string                        `json:"outcome,omitempty"`
	Collaboration           string                        `json:"collaboration,omitempty"`
	WorkRelevance           string                        `json:"work_relevance"`
	Friction                []string                      `json:"friction"`
	Items                   []agentFacetItem              `json:"items"`
	InvalidFields           []string                      `json:"invalid_fields"`
	GoalUntrusted           string                        `json:"goal_untrusted,omitempty"`
	InstructionsUntrusted   []string                      `json:"instructions_untrusted"`
	SkillCandidateUntrusted string                        `json:"skill_candidate_untrusted,omitempty"`
	Evidence                map[string][]agentEvidenceRef `json:"evidence"`
	HiddenFields            []string                      `json:"hidden_fields"`
	ViewLogged              bool                          `json:"view_logged"`
}

func agentFacetOf(response sessionanalysis.FacetResponse) agentFacet {
	out := agentFacet{
		SessionID: response.SessionID, PackID: response.PackID, Kind: response.Kind, Status: response.Status,
		Model: response.Model, PromptVersion: response.PromptVersion, CreatedAt: agentTime(response.CreatedNS),
		TaskType: response.TaskType, Outcome: response.Outcome, Collaboration: response.Collaboration,
		WorkRelevance: response.WorkRelevance, Friction: append([]string{}, response.Friction...),
		Items: make([]agentFacetItem, 0, len(response.Items)), InvalidFields: append([]string{}, response.InvalidFields...),
		GoalUntrusted: response.Goal, InstructionsUntrusted: append([]string{}, response.Instructions...),
		SkillCandidateUntrusted: response.SkillCandidate, Evidence: make(map[string][]agentEvidenceRef, len(response.Evidence)),
		HiddenFields: append([]string{}, response.HiddenFields...), ViewLogged: true,
	}
	for _, item := range response.Items {
		out.Items = append(out.Items, agentFacetItem{Ref: item.Ref, TaskType: item.TaskType, WorkRelevance: item.WorkRelevance})
	}
	for field, refs := range response.Evidence {
		converted := make([]agentEvidenceRef, 0, len(refs))
		for _, ref := range refs {
			converted = append(converted, agentEvidenceRef{LabelUntrusted: ref.Label, AuditID: ref.AuditID})
		}
		out.Evidence[field] = converted
	}
	return out
}

// serveAgentAnalysisFacet is GET /analysis/sessions/{id}/facet. The service
// clears work_relevance for anyone but the session's own developer (D9).
func (handler *managementHandler) serveAgentAnalysisFacet(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	if _, err := agentParams(request); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Facet(ctx, call.Params["id"], callerReadScope(call.Principal), analysisViewer(call.Principal, true))
	handler.recordSensitiveRead(ctx, call, "analysis-facet", err)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentFacetOf(response), agentMetaOK(), true)
}

type agentWeeklyStats struct {
	WeekStartAt   *string           `json:"week_start_at"`
	Totals        agentSignalTotals `json:"totals"`
	FacetsOK      int64             `json:"facets_ok"`
	TaskTypes     map[string]int64  `json:"task_types"`
	Outcomes      map[string]int64  `json:"outcomes"`
	Collaboration map[string]int64  `json:"collaboration"`
	Friction      map[string]int64  `json:"friction"`
	Contributors  int64             `json:"contributors,omitempty"`
	Limited       bool              `json:"limited,omitempty"`
}

func agentWeeklyStatsOf(stats *sessionanalysis.WeeklyStats) *agentWeeklyStats {
	if stats == nil {
		return nil
	}
	return &agentWeeklyStats{
		WeekStartAt: agentTime(stats.WeekStartNS), Totals: agentSignalTotalsOf(stats.Totals), FacetsOK: stats.FacetsOK,
		TaskTypes: copyCounts(stats.TaskTypes), Outcomes: copyCounts(stats.Outcomes), Collaboration: copyCounts(stats.Collaboration),
		Friction: copyCounts(stats.Friction), Contributors: stats.Contributors, Limited: stats.Limited,
	}
}

type agentSuggestion struct {
	ID                int64    `json:"id"`
	Kind              string   `json:"kind"`
	TextUntrusted     string   `json:"text_untrusted"`
	Sessions          int64    `json:"sessions"`
	Strong            bool     `json:"strong"`
	Status            string   `json:"status"`
	FirstSeenAt       *string  `json:"first_seen_at"`
	LastSeenAt        *string  `json:"last_seen_at"`
	EvidenceUntrusted []string `json:"evidence_untrusted"`
}

type agentScopeOption struct {
	ID            int64  `json:"id"`
	NameUntrusted string `json:"name_untrusted"`
}

func agentScopeOptions(options []sessionanalysis.ScopeOption) []agentScopeOption {
	if options == nil {
		return nil
	}
	out := make([]agentScopeOption, 0, len(options))
	for _, option := range options {
		out = append(out, agentScopeOption{ID: option.ID, NameUntrusted: option.Name})
	}
	return out
}

type agentAnalysisReport struct {
	WeekStartAt        *string                `json:"week_start_at"`
	Scope              string                 `json:"scope"`
	Stats              *agentWeeklyStats      `json:"stats"`
	Previous           *agentWeeklyStats      `json:"previous"`
	NarrativeUntrusted string                 `json:"narrative_untrusted"`
	NarrativeSource    string                 `json:"narrative_source,omitempty"`
	ComputedAt         *string                `json:"computed_at"`
	Suggestions        []agentSuggestion      `json:"suggestions"`
	Optimizations      []agentAnalysisSession `json:"optimizations"`
	ScopeID            int64                  `json:"scope_id,omitempty"`
	ScopeNameUntrusted string                 `json:"scope_name_untrusted,omitempty"`
	Projects           []agentScopeOption     `json:"projects,omitempty"`
	Groups             []agentScopeOption     `json:"groups,omitempty"`
	Users              []agentScopeOption     `json:"users,omitempty"`
}

func agentAnalysisReportOf(response sessionanalysis.ReportResponse) agentAnalysisReport {
	out := agentAnalysisReport{
		WeekStartAt: agentTime(response.WeekStartNS), Scope: response.Scope,
		Stats: agentWeeklyStatsOf(response.Stats), Previous: agentWeeklyStatsOf(response.Previous),
		NarrativeUntrusted: response.Narrative, NarrativeSource: response.NarrativeSource, ComputedAt: agentTime(response.ComputedNS),
		Suggestions: make([]agentSuggestion, 0, len(response.Suggestions)), Optimizations: agentAnalysisSessions(response.Optimizations),
		ScopeID: response.ScopeID, ScopeNameUntrusted: response.ScopeName,
		Projects: agentScopeOptions(response.Projects), Groups: agentScopeOptions(response.Groups), Users: agentScopeOptions(response.Users),
	}
	for _, suggestion := range response.Suggestions {
		out.Suggestions = append(out.Suggestions, agentSuggestion{
			ID: suggestion.ID, Kind: suggestion.Kind, TextUntrusted: suggestion.Text, Sessions: suggestion.Sessions,
			Strong: suggestion.Strong, Status: suggestion.Status, FirstSeenAt: agentTime(suggestion.FirstSeenNS),
			LastSeenAt: agentTime(suggestion.LastSeenNS), EvidenceUntrusted: append([]string{}, suggestion.Evidence...),
		})
	}
	return out
}

// serveAgentAnalysisReport is GET /analysis/report.
func (handler *managementHandler) serveAgentAnalysisReport(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentAnalysisReady(writer) {
		return
	}
	values, err := agentParams(request, "week", "user_id", "project_id", "group_id")
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	week := values.Get("week")
	if values.Has("week") && week != "current" && week != "previous" {
		handler.writeAgentServiceFailure(writer, argError("week"), "")
		return
	}
	var target sessionanalysis.ReportTarget
	selectors := 0
	for _, selector := range []struct {
		name  string
		field *int64
	}{{"user_id", &target.UserID}, {"project_id", &target.ProjectID}, {"group_id", &target.GroupID}} {
		if !values.Has(selector.name) {
			continue
		}
		id, ok := parseAgentID(values.Get(selector.name), false)
		if !ok || id <= 0 {
			handler.writeAgentServiceFailure(writer, argError(selector.name), "")
			return
		}
		*selector.field = id
		selectors++
	}
	if selectors > 1 {
		handler.writeAgentServiceFailure(writer, argError("user_id"), "")
		return
	}
	if err := requireAdministratorSelector(call.Principal, selectors == 1); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.sessionAnalysis.Report(ctx, week, callerReadScope(call.Principal), target)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	meta := agentMetaOK()
	switch {
	case response.Stats == nil:
		meta.Complete, meta.IncompleteReason = false, "not_computed"
	case response.Stats.Limited:
		meta.Complete, meta.IncompleteReason = false, "below_contributor_minimum"
	}
	writeAgentRead(writer, agentAnalysisReportOf(response), meta, true)
}
