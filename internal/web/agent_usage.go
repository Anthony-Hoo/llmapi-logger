package web

import (
	"context"
	"net/http"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/query"
)

// Usage insights on the facade (contract section 4.3.3). Scope comes from the
// principal exactly as on the web; the insights service applies D5 (no
// caller or token grouping, no session caller for a scoped read) and D6
// (placeholder parents).

const (
	agentCursorUsageSessions = "usage-sessions"
	agentModuleInsights      = "insights"
	agentIncompleteTruncated = "truncated"
)

// agentUsageNotFoundHint lists the three causes the services cannot tell
// apart (D3).
const agentUsageNotFoundHint = "Not found means one of: it does not exist, it is not visible to this identity, or it has not been analysed yet. Do not switch identity or path to retry; analysis may still be pending."

type agentUsageTotals struct {
	Requests         int64    `json:"requests"`
	UncachedInput    int64    `json:"uncached_input"`
	CacheRead        int64    `json:"cache_read"`
	CacheWrite       int64    `json:"cache_write"`
	Output           int64    `json:"output"`
	Reasoning        int64    `json:"reasoning"`
	PromptTotal      int64    `json:"prompt_total"`
	CacheHitRate     *float64 `json:"cache_hit_rate"`
	CostUSD          *float64 `json:"cost_usd"`
	BilledRequests   int64    `json:"billed_requests"`
	UnbilledRequests int64    `json:"unbilled_requests"`
}

func agentUsageTotalsOf(totals insights.UsageTotals) agentUsageTotals {
	return agentUsageTotals{
		Requests: totals.Requests, UncachedInput: totals.UncachedInput, CacheRead: totals.CacheRead,
		CacheWrite: totals.CacheWrite, Output: totals.Output, Reasoning: totals.Reasoning,
		PromptTotal: totals.PromptTotal, CacheHitRate: totals.CacheHitRate, CostUSD: totals.CostUSD,
		BilledRequests: totals.BilledRequests, UnbilledRequests: totals.UnbilledRequests,
	}
}

type agentCategoryValues struct {
	System     int64 `json:"system"`
	Tools      int64 `json:"tools"`
	User       int64 `json:"user"`
	Injected   int64 `json:"injected"`
	Assistant  int64 `json:"assistant"`
	Reasoning  int64 `json:"reasoning"`
	ToolResult int64 `json:"tool_result"`
	Media      int64 `json:"media"`
}

func agentCategoryValuesOf(values insights.CategoryValues) agentCategoryValues {
	return agentCategoryValues{
		System: values.System, Tools: values.Tools, User: values.User, Injected: values.Injected,
		Assistant: values.Assistant, Reasoning: values.Reasoning, ToolResult: values.ToolResult, Media: values.Media,
	}
}

type agentUsage struct {
	UncachedInput *int64 `json:"uncached_input"`
	CacheRead     *int64 `json:"cache_read"`
	CacheWrite    *int64 `json:"cache_write"`
	Output        *int64 `json:"output"`
	Reasoning     *int64 `json:"reasoning"`
}

func agentUsageOf(usage insights.Usage) agentUsage {
	return agentUsage{UncachedInput: usage.UncachedInput, CacheRead: usage.CacheRead, CacheWrite: usage.CacheWrite,
		Output: usage.Output, Reasoning: usage.Reasoning}
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

type agentDailyUsage struct {
	Day   string           `json:"day"`
	Usage agentUsageTotals `json:"usage"`
}

type agentHeatmapDay struct {
	Day      string `json:"day"`
	Requests int64  `json:"requests"`
	Sessions int64  `json:"sessions"`
}

type agentGroupUsage struct {
	Key            string           `json:"key"`
	LabelUntrusted string           `json:"label_untrusted"`
	Usage          agentUsageTotals `json:"usage"`
}

type agentUsageOverview struct {
	FromAt          *string             `json:"from_at"`
	ToAt            *string             `json:"to_at"`
	Totals          agentUsageTotals    `json:"totals"`
	Sessions        int64               `json:"sessions"`
	Trees           int64               `json:"trees"`
	Daily           []agentDailyUsage   `json:"daily"`
	Heatmap         []agentHeatmapDay   `json:"heatmap"`
	GroupBy         string              `json:"group_by"`
	Groups          []agentGroupUsage   `json:"groups"`
	Composition     agentCategoryValues `json:"composition"`
	BillingEnabled  bool                `json:"billing_enabled"`
	ClientLabels    map[string]string   `json:"client_labels,omitempty"`
	BillingComplete bool                `json:"billing_complete"`
	CoverageUnknown bool                `json:"coverage_unknown"`
}

func agentUsageOverviewOf(response insights.OverviewResponse) agentUsageOverview {
	out := agentUsageOverview{
		FromAt: agentTime(response.FromNS), ToAt: agentTime(response.ToNS),
		Totals: agentUsageTotalsOf(response.Totals), Sessions: response.Sessions, Trees: response.Trees,
		Daily: make([]agentDailyUsage, 0, len(response.Daily)), Heatmap: make([]agentHeatmapDay, 0, len(response.Heatmap)),
		GroupBy: response.GroupBy, Groups: make([]agentGroupUsage, 0, len(response.Groups)),
		Composition: agentCategoryValuesOf(response.Mix), BillingEnabled: response.BillingEnabled,
		ClientLabels:    copyLabels(response.ClientLabels),
		BillingComplete: response.Totals.UnbilledRequests == 0, CoverageUnknown: true,
	}
	for _, day := range response.Daily {
		out.Daily = append(out.Daily, agentDailyUsage{Day: day.Day, Usage: agentUsageTotalsOf(day.Usage)})
	}
	for _, day := range response.Heatmap {
		out.Heatmap = append(out.Heatmap, agentHeatmapDay{Day: day.Day, Requests: day.Requests, Sessions: day.Sessions})
	}
	for _, group := range response.Groups {
		out.Groups = append(out.Groups, agentGroupUsage{Key: group.Key, LabelUntrusted: group.Label, Usage: agentUsageTotalsOf(group.Usage)})
	}
	return out
}

const agentCoverageAction = "Totals count analysed records only; the server cannot say how many records are not analysed yet (coverage_unknown)."

func (handler *managementHandler) agentInsightsReady(writer http.ResponseWriter) bool {
	if handler.insights == nil {
		agentModuleDisabled(writer, agentModuleInsights)
		return false
	}
	return true
}

// serveAgentUsageOverview is GET /usage/overview.
func (handler *managementHandler) serveAgentUsageOverview(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentInsightsReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	timeRange, err := parseAgentRange(values, handler.agent.Now())
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	overview := query.OverviewQuery{FromNS: timeRange.FromNS, ToNS: timeRange.ToNS, GroupBy: values.Get("group_by"), Scope: callerReadScope(call.Principal)}
	if values.Has("tz_offset_min") {
		offset, ok := parseAgentID(values.Get("tz_offset_min"), true)
		if !ok || offset < -840 || offset > 840 {
			handler.writeAgentServiceFailure(writer, argError("tz_offset_min"), "")
			return
		}
		overview.TZOffsetMin = int(offset)
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.insights.Overview(ctx, overview)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentUsageOverviewOf(response), agentMetaOK(), true, agentCoverageAction)
}

type agentSessionCaller struct {
	UsernameUntrusted  string `json:"username_untrusted,omitempty"`
	TokenNameUntrusted string `json:"token_name_untrusted,omitempty"`
}

type agentSessionCard struct {
	SessionID       string              `json:"session_id"`
	SessionLink     string              `json:"session_link"`
	TreeID          string              `json:"tree_id,omitempty"`
	Protocol        string              `json:"protocol"`
	Client          string              `json:"client"`
	Role            string              `json:"role"`
	FirstAt         *string             `json:"first_at"`
	LastAt          *string             `json:"last_at"`
	Steps           int64               `json:"steps"`
	Turns           int64               `json:"turns"`
	Models          []string            `json:"models"`
	Usage           agentUsageTotals    `json:"usage"`
	LastComposition agentCategoryValues `json:"last_composition"`
	LastPromptTotal *int64              `json:"last_prompt_total"`
	ContextWindow   *int64              `json:"context_window"`
	Subagents       int64               `json:"subagents"`
	Caller          *agentSessionCaller `json:"caller"`
}

type agentUsageSessions struct {
	Items          []agentSessionCard `json:"items"`
	NextCursor     string             `json:"next_cursor"`
	BillingEnabled bool               `json:"billing_enabled"`
	ClientLabels   map[string]string  `json:"client_labels,omitempty"`
}

func agentUsageSessionsOf(response insights.SessionsResponse) agentUsageSessions {
	out := agentUsageSessions{Items: make([]agentSessionCard, 0, len(response.Items)),
		NextCursor:     wrapAgentCursor(agentCursorUsageSessions, response.NextCursor),
		BillingEnabled: response.BillingEnabled, ClientLabels: copyLabels(response.ClientLabels)}
	for _, card := range response.Items {
		item := agentSessionCard{
			SessionID: card.SessionID, SessionLink: card.SessionLink, TreeID: card.TreeID, Protocol: card.Protocol,
			Client: card.Client, Role: card.Role, FirstAt: agentTime(card.FirstNS), LastAt: agentTime(card.LastNS),
			Steps: card.Steps, Turns: card.Turns, Models: append([]string{}, card.Models...),
			Usage: agentUsageTotalsOf(card.Usage), LastComposition: agentCategoryValuesOf(card.LastEstimate),
			LastPromptTotal: card.LastPrompt, ContextWindow: card.ContextWindow, Subagents: card.Subagents,
		}
		if card.Caller != nil {
			item.Caller = &agentSessionCaller{UsernameUntrusted: card.Caller.Username, TokenNameUntrusted: card.Caller.TokenName}
		}
		out.Items = append(out.Items, item)
	}
	return out
}

// serveAgentUsageSessions is GET /usage/sessions.
func (handler *managementHandler) serveAgentUsageSessions(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentInsightsReady(writer) {
		return
	}
	values, err := agentCallParams(request, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	timeRange, err := parseAgentRange(values, handler.agent.Now())
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	limit, err := parseAgentLimit(values, query.DefaultSessionLimit, query.MaxSessionLimit)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	cursor, err := unwrapAgentCursor(agentCursorUsageSessions, values.Get("cursor"))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.insights.Sessions(ctx, query.SessionsQuery{
		FromNS: timeRange.FromNS, ToNS: timeRange.ToNS, Sort: values.Get("sort"), Cursor: cursor, Limit: limit,
		Scope: callerReadScope(call.Principal),
	})
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	writeAgentRead(writer, agentUsageSessionsOf(response), agentMetaOK(), true)
}

type agentTrendStep struct {
	AuditID       string              `json:"audit_id"`
	StartedAt     *string             `json:"started_at"`
	Turn          int64               `json:"turn"`
	TurnStart     bool                `json:"turn_start"`
	Model         string              `json:"model"`
	Role          string              `json:"role"`
	Estimate      agentCategoryValues `json:"estimate"`
	Usage         agentUsage          `json:"usage"`
	PromptTotal   *int64              `json:"prompt_total"`
	Events        []string            `json:"events"`
	AppendedItems *int64              `json:"appended_items"`
	RemovedItems  *int64              `json:"removed_items"`
	StopReason    string              `json:"stop_reason,omitempty"`
	ResponseKinds []string            `json:"response_kinds"`
	FirstEventMS  *float64            `json:"first_event_ms"`
	GenerationMS  *float64            `json:"generation_ms"`
	ClientGapMS   *float64            `json:"client_gap_ms"`
	CostUSD       *float64            `json:"cost_usd"`
}

type agentTrend struct {
	SessionID     string           `json:"session_id"`
	TreeID        string           `json:"tree_id,omitempty"`
	ContextWindow *int64           `json:"context_window"`
	Truncated     bool             `json:"truncated"`
	Steps         []agentTrendStep `json:"steps"`
}

func agentTrendOf(response insights.TrendResponse) agentTrend {
	out := agentTrend{SessionID: response.SessionID, TreeID: response.TreeID, ContextWindow: response.ContextWindow,
		Truncated: response.Truncated, Steps: make([]agentTrendStep, 0, len(response.Steps))}
	for _, step := range response.Steps {
		out.Steps = append(out.Steps, agentTrendStep{
			AuditID: step.AuditID, StartedAt: agentTime(step.StartedAtNS), Turn: step.Turn, TurnStart: step.TurnStart,
			Model: step.Model, Role: step.Role, Estimate: agentCategoryValuesOf(step.Estimate), Usage: agentUsageOf(step.Usage),
			PromptTotal: step.PromptTotal, Events: append([]string{}, step.Events...),
			AppendedItems: step.AppendedItems, RemovedItems: step.RemovedItems, StopReason: step.StopReason,
			ResponseKinds: append([]string{}, step.ResponseKinds...), FirstEventMS: step.FirstEventMS,
			GenerationMS: step.GenerationMS, ClientGapMS: step.ClientGapMS, CostUSD: step.CostUSD,
		})
	}
	return out
}

func truncatedMeta(truncated bool) agentapi.Meta {
	meta := agentMetaOK()
	if truncated {
		meta.Complete, meta.IncompleteReason = false, agentIncompleteTruncated
	}
	return meta
}

// serveAgentUsageTrend is GET /usage/sessions/{id}/trend.
func (handler *managementHandler) serveAgentUsageTrend(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentInsightsReady(writer) {
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.insights.Trend(ctx, call.Params["id"], callerReadScope(call.Principal))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, agentUsageNotFoundHint)
		return
	}
	writeAgentRead(writer, agentTrendOf(response), truncatedMeta(response.Truncated), false)
}

type agentTreeNode struct {
	NodeID          string              `json:"node_id"`
	ParentNodeID    string              `json:"parent_node_id,omitempty"`
	Visible         bool                `json:"visible"`
	SessionID       string              `json:"session_id,omitempty"`
	Client          string              `json:"client"`
	Role            string              `json:"role"`
	NameUntrusted   string              `json:"name_untrusted,omitempty"`
	FirstAt         *string             `json:"first_at"`
	LastAt          *string             `json:"last_at"`
	Steps           int64               `json:"steps"`
	AuxRequests     int64               `json:"aux_requests"`
	Usage           agentUsageTotals    `json:"usage"`
	LastComposition agentCategoryValues `json:"last_composition"`
	LastPromptTotal *int64              `json:"last_prompt_total"`
	ContextWindow   *int64              `json:"context_window"`
	LinkSource      string              `json:"link_source,omitempty"`
	LinkConfidence  int                 `json:"link_confidence,omitempty"`
}

type agentTree struct {
	TreeID       string            `json:"tree_id"`
	Truncated    bool              `json:"truncated"`
	Nodes        []agentTreeNode   `json:"nodes"`
	ClientLabels map[string]string `json:"client_labels,omitempty"`
}

func agentTreeOf(response insights.TreeResponse) agentTree {
	out := agentTree{TreeID: response.TreeID, Truncated: response.Truncated, Nodes: make([]agentTreeNode, 0, len(response.Nodes)),
		ClientLabels: copyLabels(response.ClientLabels)}
	for _, node := range response.Nodes {
		out.Nodes = append(out.Nodes, agentTreeNode{
			NodeID: node.NodeID, ParentNodeID: node.ParentNodeID, Visible: node.Visible, SessionID: node.SessionID,
			Client: node.Client, Role: node.Role, NameUntrusted: node.Name,
			FirstAt: agentTime(node.FirstNS), LastAt: agentTime(node.LastNS), Steps: node.Steps, AuxRequests: node.AuxRequests,
			Usage: agentUsageTotalsOf(node.Usage), LastComposition: agentCategoryValuesOf(node.LastEstimate),
			LastPromptTotal: node.LastPrompt, ContextWindow: node.ContextWindow,
			LinkSource: node.LinkSource, LinkConfidence: node.LinkConfidence,
		})
	}
	return out
}

// serveAgentUsageTree is GET /usage/trees/{id}.
func (handler *managementHandler) serveAgentUsageTree(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentInsightsReady(writer) {
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	response, err := handler.insights.Tree(ctx, call.Params["id"], callerReadScope(call.Principal))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, agentUsageNotFoundHint)
		return
	}
	writeAgentRead(writer, agentTreeOf(response), truncatedMeta(response.Truncated), true)
}

type agentCompositionItem struct {
	Index            int    `json:"index"`
	Category         string `json:"category"`
	Role             string `json:"role"`
	Kind             string `json:"kind"`
	Tokens           int64  `json:"tokens"`
	LabelUntrusted   string `json:"label_untrusted,omitempty"`
	SummaryUntrusted string `json:"summary_untrusted,omitempty"`
	Change           string `json:"change,omitempty"`
}

type agentToolDef struct {
	NameUntrusted string `json:"name_untrusted"`
	Tokens        int64  `json:"tokens"`
	Source        string `json:"source"`
}

type agentFileOp struct {
	ToolUntrusted string `json:"tool_untrusted"`
	Op            string `json:"op"`
	PathUntrusted string `json:"path_untrusted,omitempty"`
	AddedLines    int    `json:"added_lines,omitempty"`
	RemovedLines  int    `json:"removed_lines,omitempty"`
}

type agentAgentIdentity struct {
	Client            string `json:"client"`
	Role              string `json:"role"`
	RootIDUntrusted   string `json:"root_id_untrusted,omitempty"`
	NodeIDUntrusted   string `json:"node_id_untrusted,omitempty"`
	ParentIDUntrusted string `json:"parent_id_untrusted,omitempty"`
	NameUntrusted     string `json:"name_untrusted,omitempty"`
	LinkSource        string `json:"link_source,omitempty"`
	Confidence        int    `json:"confidence,omitempty"`
}

type agentCompositionDiff struct {
	AddedItems   int64               `json:"added_items"`
	RemovedItems int64               `json:"removed_items"`
	ByCategory   agentCategoryValues `json:"by_category"`
}

type agentComposition struct {
	AuditID         string                 `json:"audit_id"`
	AnalysisVersion int                    `json:"analysis_version"`
	Model           string                 `json:"model"`
	Usage           agentUsage             `json:"usage"`
	PromptTotal     *int64                 `json:"prompt_total"`
	Estimate        agentCategoryValues    `json:"estimate"`
	Anchored        *agentCategoryValues   `json:"anchored"`
	ContextWindow   *int64                 `json:"context_window"`
	Items           []agentCompositionItem `json:"items"`
	Tools           []agentToolDef         `json:"tools"`
	FileOps         []agentFileOp          `json:"file_ops"`
	Agent           agentAgentIdentity     `json:"agent"`
	PreviousAuditID string                 `json:"previous_audit_id,omitempty"`
	Diff            *agentCompositionDiff  `json:"diff"`
	Events          []string               `json:"events"`
	Truncated       bool                   `json:"truncated"`
	ClientLabels    map[string]string      `json:"client_labels,omitempty"`
}

func agentCompositionOf(response insights.CompositionResponse) agentComposition {
	out := agentComposition{
		AuditID: response.AuditID, AnalysisVersion: response.AnalysisVersion, Model: response.Model,
		Usage: agentUsageOf(response.Usage), PromptTotal: response.PromptTotal, Estimate: agentCategoryValuesOf(response.Estimate),
		ContextWindow: response.ContextWindow, Items: make([]agentCompositionItem, 0, len(response.Items)),
		Tools: make([]agentToolDef, 0, len(response.Tools)), FileOps: make([]agentFileOp, 0, len(response.FileOps)),
		Agent: agentAgentIdentity{
			Client: response.Agent.Client, Role: response.Agent.Role, RootIDUntrusted: response.Agent.RootID,
			NodeIDUntrusted: response.Agent.NodeID, ParentIDUntrusted: response.Agent.ParentID, NameUntrusted: response.Agent.Name,
			LinkSource: response.Agent.LinkSource, Confidence: response.Agent.Confidence,
		},
		PreviousAuditID: response.PreviousAuditID, Events: append([]string{}, response.Events...),
		Truncated: response.Truncated, ClientLabels: copyLabels(response.ClientLabels),
	}
	if response.Anchored != nil {
		anchored := agentCategoryValuesOf(*response.Anchored)
		out.Anchored = &anchored
	}
	for _, item := range response.Items {
		out.Items = append(out.Items, agentCompositionItem{Index: item.Index, Category: item.Category, Role: item.Role, Kind: item.Kind,
			Tokens: item.Tokens, LabelUntrusted: item.Label, SummaryUntrusted: item.Summary, Change: item.Change})
	}
	for _, tool := range response.Tools {
		out.Tools = append(out.Tools, agentToolDef{NameUntrusted: tool.Name, Tokens: tool.Tokens, Source: tool.Source})
	}
	for _, op := range response.FileOps {
		out.FileOps = append(out.FileOps, agentFileOp{ToolUntrusted: op.Tool, Op: op.Op, PathUntrusted: op.Path,
			AddedLines: op.AddedLines, RemovedLines: op.RemovedLines})
	}
	if response.Diff != nil {
		out.Diff = &agentCompositionDiff{AddedItems: response.Diff.AddedItems, RemovedItems: response.Diff.RemovedItems,
			ByCategory: agentCategoryValuesOf(response.Diff.ByCategory)}
	}
	return out
}

// serveAgentUsageComposition is GET /requests/{id}/composition. It passes the
// same audit ownership gate as every other per-audit resource.
func (handler *managementHandler) serveAgentUsageComposition(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentInsightsReady(writer) {
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	auditID, err := handler.authorizeAgentAudit(ctx, call)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, agentUsageNotFoundHint)
		return
	}
	response, err := handler.insights.Composition(ctx, auditID, callerReadScope(call.Principal))
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, agentUsageNotFoundHint)
		return
	}
	writeAgentRead(writer, agentCompositionOf(response), truncatedMeta(response.Truncated), true)
}
