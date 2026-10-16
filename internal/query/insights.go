package query

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/insights/pricing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// Insights query limits.
const (
	MaxInsightsRange      = 400 * 24 * time.Hour
	DefaultInsightsRange  = 7 * 24 * time.Hour
	DefaultSessionLimit   = 20
	MaxSessionLimit       = 100
	MaxTrendSteps         = 2000
	MaxTreeNodes          = 40
	HeatmapDays           = 56
	maxTimezoneOffsetMin  = 840
	priceScheduleSlotNS   = int64(pricing.ScheduleGranularityMinutes * time.Minute)
	treeIDHexLength       = 24
	nanosecondsPerSecond  = int64(time.Second)
	secondsPerDay         = int64(24 * 60 * 60)
	insightsCursorVersion = "v1"
)

var (
	sessionIDPattern = regexp.MustCompile(`^(?:agt_[0-9a-f]{24}|ses_[0-9a-f]{24}|conv_[0-9A-Za-z._-]{1,200})$`)
	treeIDPattern    = regexp.MustCompile(`^[0-9a-f]{24}$`)
)

// InsightsStore is the storage surface of the insights service. It is separate
// from Store so the audit list and detail paths do not depend on it.
type InsightsStore interface {
	InsightsUsage(context.Context, sqlite.InsightsFilter, sqlite.InsightsUsageSpec) ([]sqlite.InsightsUsageRow, error)
	InsightsDistinct(context.Context, sqlite.InsightsFilter) (int64, int64, error)
	InsightsDayCounts(context.Context, sqlite.InsightsFilter, int) ([]sqlite.InsightsDayCount, error)
	InsightsSessions(context.Context, sqlite.InsightsFilter, string, *sqlite.InsightsSessionCursor, int) (sqlite.InsightsSessionPage, error)
	InsightsSessionModels(context.Context, sqlite.InsightsFilter) (map[string][]string, error)
	InsightsSubagentCounts(context.Context, sqlite.InsightsFilter) (map[string]int64, error)
	InsightsRealRoots(context.Context, sqlite.InsightsFilter) (map[string]bool, error)
	InsightsTrend(context.Context, sqlite.InsightsFilter, int) ([]sqlite.InsightsTrendRow, bool, error)
	InsightsTurnStartsBefore(context.Context, sqlite.InsightsFilter, int64, string) (int64, error)
	InsightsTree(context.Context, sqlite.InsightsFilter, int) ([]sqlite.InsightsTreeNodeRow, bool, error)
	LoadAnalysis(context.Context, string) (sqlite.AnalysisRow, error)
	QueryAuditScope(context.Context, string) (sqlite.AuditScopeRow, error)
}

// Insights builds the context-insights API responses. Aggregate endpoints read
// plaintext derived columns only; Composition is the single decrypting call.
type Insights struct {
	store  InsightsStore
	cipher security.Cipher
	prices *pricing.Table
	now    func() time.Time
	// trendLimit bounds the steps of one trend; tests lower it.
	trendLimit int
}

// NewInsights constructs the service. prices may be nil, in which case every
// model is unpriced.
func NewInsights(store InsightsStore, cipher security.Cipher, prices *pricing.Table) (*Insights, error) {
	if store == nil {
		return nil, errors.New("query: nil insights store")
	}
	if cipher == nil {
		return nil, errors.New("query: nil cipher")
	}
	return &Insights{store: store, cipher: cipher, prices: prices, now: time.Now, trendLimit: MaxTrendSteps}, nil
}

// OverviewQuery is the validated input of Overview. FromNS and ToNS default to
// the trailing seven days. TZOffsetMin is minutes east of UTC.
type OverviewQuery struct {
	FromNS      *int64
	ToNS        *int64
	GroupBy     string
	TZOffsetMin int
	Scope       *Scope
}

// SessionsQuery is the input of Sessions.
type SessionsQuery struct {
	FromNS *int64
	ToNS   *int64
	Sort   string
	Cursor string
	Limit  int
	Scope  *Scope
}

func (service *Insights) resolveRange(fromNS, toNS *int64) (int64, int64, error) {
	now := service.now().UnixNano()
	to := now
	if toNS != nil {
		to = *toNS
	}
	from := to - int64(DefaultInsightsRange)
	if fromNS != nil {
		from = *fromNS
	}
	if from < 0 || to <= 0 {
		return 0, 0, invalid("time range must not be negative")
	}
	if from >= to {
		return 0, 0, invalid("from_ns must be before to_ns")
	}
	if to-from > int64(MaxInsightsRange) {
		return 0, 0, invalid("time range must not exceed 400 days")
	}
	return from, to, nil
}

func (service *Insights) slotNS() int64 {
	if service.prices.HasSchedules() {
		return priceScheduleSlotNS
	}
	return 0
}

type usageAccumulator struct {
	label  string
	totals insights.UsageTotals
	cost   float64
	priced bool
	mix    sqlite.InsightsMix
}

type usageFold struct {
	order []string
	byKey map[string]*usageAccumulator
}

func (service *Insights) fold(rows []sqlite.InsightsUsageRow) usageFold {
	result := usageFold{byKey: make(map[string]*usageAccumulator)}
	for _, row := range rows {
		accumulator := result.byKey[row.Key]
		if accumulator == nil {
			accumulator = &usageAccumulator{label: row.Label}
			result.byKey[row.Key] = accumulator
			result.order = append(result.order, row.Key)
		}
		accumulator.totals.Requests += row.Requests
		accumulator.totals.UncachedInput += row.UncachedInput
		accumulator.totals.CacheRead += row.CacheRead
		accumulator.totals.CacheWrite += row.CacheWrite
		accumulator.totals.Output += row.Output
		accumulator.totals.Reasoning += row.Reasoning
		accumulator.mix.System += row.Mix.System
		accumulator.mix.Tools += row.Mix.Tools
		accumulator.mix.User += row.Mix.User
		accumulator.mix.Injected += row.Mix.Injected
		accumulator.mix.Assistant += row.Mix.Assistant
		accumulator.mix.Reasoning += row.Mix.Reasoning
		accumulator.mix.ToolResult += row.Mix.ToolResult
		accumulator.mix.Media += row.Mix.Media
		var at time.Time
		if row.SlotNS > 0 {
			at = time.Unix(0, row.SlotNS)
		}
		cost := service.prices.CostTokens(row.Model, at, row.UncachedInput, row.CacheRead, row.CacheWrite, row.Output)
		if cost == nil {
			accumulator.totals.UnpricedRequests += row.Requests
			continue
		}
		accumulator.cost += *cost
		accumulator.priced = true
	}
	return result
}

func (accumulator *usageAccumulator) usage() insights.UsageTotals {
	if accumulator == nil {
		return insights.UsageTotals{}
	}
	totals := accumulator.totals
	totals.PromptTotal = totals.UncachedInput + totals.CacheRead + totals.CacheWrite
	if totals.PromptTotal > 0 {
		rate := float64(totals.CacheRead) / float64(totals.PromptTotal)
		totals.CacheHitRate = &rate
	}
	if accumulator.priced {
		cost := accumulator.cost
		totals.EstimatedCostUSD = &cost
	}
	return totals
}

func roundMix(mix sqlite.InsightsMix) insights.CategoryValues {
	round := func(value float64) int64 { return int64(value + 0.5) }
	return insights.CategoryValues{
		System: round(mix.System), Tools: round(mix.Tools), User: round(mix.User), Injected: round(mix.Injected),
		Assistant: round(mix.Assistant), Reasoning: round(mix.Reasoning), ToolResult: round(mix.ToolResult), Media: round(mix.Media),
	}
}

func (service *Insights) filter(scope *Scope, fromNS, toNS int64) sqlite.InsightsFilter {
	return sqlite.InsightsFilter{FromNS: fromNS, ToNS: toNS, Scope: storageScope(scope)}
}

func validateScope(scope *Scope) error {
	if scope != nil {
		if err := storageScope(scope).Validate(); err != nil {
			return invalid("invalid session scope")
		}
	}
	return nil
}

func localDayIndex(ns int64, tzOffsetMin int) int64 {
	seconds := ns/nanosecondsPerSecond + int64(tzOffsetMin)*60
	index := seconds / secondsPerDay
	if seconds%secondsPerDay < 0 {
		index--
	}
	return index
}

func dayString(index int64) string {
	return time.Unix(index*secondsPerDay, 0).UTC().Format("2006-01-02")
}

func localDayStartNS(index int64, tzOffsetMin int) int64 {
	return (index*secondsPerDay - int64(tzOffsetMin)*60) * nanosecondsPerSecond
}

// Overview aggregates usage, cost, activity and composition over a time range.
func (service *Insights) Overview(ctx context.Context, request OverviewQuery) (insights.OverviewResponse, error) {
	if ctx == nil {
		return insights.OverviewResponse{}, invalid("nil context")
	}
	if err := validateScope(request.Scope); err != nil {
		return insights.OverviewResponse{}, err
	}
	if request.TZOffsetMin < -maxTimezoneOffsetMin || request.TZOffsetMin > maxTimezoneOffsetMin {
		return insights.OverviewResponse{}, invalid("tz_offset_min must be between -840 and 840")
	}
	groupBy := request.GroupBy
	if groupBy == "" {
		groupBy = sqlite.InsightsDimModel
	}
	switch groupBy {
	case sqlite.InsightsDimModel, sqlite.InsightsDimProtocol, sqlite.InsightsDimClient:
	case sqlite.InsightsDimCaller, sqlite.InsightsDimToken:
		if request.Scope != nil {
			return insights.OverviewResponse{}, invalid("group_by is not available to this session")
		}
	default:
		return insights.OverviewResponse{}, invalid("invalid group_by")
	}
	from, to, err := service.resolveRange(request.FromNS, request.ToNS)
	if err != nil {
		return insights.OverviewResponse{}, err
	}
	filter := service.filter(request.Scope, from, to)
	slot := service.slotNS()
	spec := func(dimension string) sqlite.InsightsUsageSpec {
		return sqlite.InsightsUsageSpec{Dimension: dimension, TZOffsetMin: request.TZOffsetMin, SlotNS: slot}
	}

	totalRows, err := service.store.InsightsUsage(ctx, filter, spec(sqlite.InsightsDimTotal))
	if err != nil {
		return insights.OverviewResponse{}, fmt.Errorf("query: insights overview totals: %w", err)
	}
	dayRows, err := service.store.InsightsUsage(ctx, filter, spec(sqlite.InsightsDimDay))
	if err != nil {
		return insights.OverviewResponse{}, fmt.Errorf("query: insights overview days: %w", err)
	}
	groupRows, err := service.store.InsightsUsage(ctx, filter, spec(groupBy))
	if err != nil {
		return insights.OverviewResponse{}, fmt.Errorf("query: insights overview groups: %w", err)
	}
	sessions, trees, err := service.store.InsightsDistinct(ctx, filter)
	if err != nil {
		return insights.OverviewResponse{}, fmt.Errorf("query: insights overview distinct: %w", err)
	}

	response := insights.OverviewResponse{FromNS: from, ToNS: to, Sessions: sessions, Trees: trees, GroupBy: groupBy}
	total := service.fold(totalRows).byKey[""]
	response.Totals = total.usage()
	if total != nil {
		response.Mix = roundMix(total.mix)
	}

	days := service.fold(dayRows)
	firstDay, lastDay := localDayIndex(from, request.TZOffsetMin), localDayIndex(to-1, request.TZOffsetMin)
	response.Daily = make([]insights.DailyUsage, 0, lastDay-firstDay+1)
	for day := firstDay; day <= lastDay; day++ {
		name := dayString(day)
		response.Daily = append(response.Daily, insights.DailyUsage{Day: name, Usage: days.byKey[name].usage()})
	}

	groups := service.fold(groupRows)
	response.Groups = make([]insights.GroupUsage, 0, len(groups.order))
	for _, key := range groups.order {
		accumulator := groups.byKey[key]
		label := accumulator.label
		if label == "" {
			label = key
		}
		response.Groups = append(response.Groups, insights.GroupUsage{Key: key, Label: label, Usage: accumulator.usage()})
	}
	sort.SliceStable(response.Groups, func(i, j int) bool {
		left, right := response.Groups[i].Usage, response.Groups[j].Usage
		if leftTokens, rightTokens := left.PromptTotal+left.Output, right.PromptTotal+right.Output; leftTokens != rightTokens {
			return leftTokens > rightTokens
		}
		return response.Groups[i].Key < response.Groups[j].Key
	})

	// to is an exclusive boundary, so the last day is the one containing to-1.
	endDay := lastDay
	heatmapFrom := localDayStartNS(endDay-(HeatmapDays-1), request.TZOffsetMin)
	heatmapTo := localDayStartNS(endDay+1, request.TZOffsetMin)
	counts, err := service.store.InsightsDayCounts(ctx, service.filter(request.Scope, max(heatmapFrom, 0), heatmapTo), request.TZOffsetMin)
	if err != nil {
		return insights.OverviewResponse{}, fmt.Errorf("query: insights overview heatmap: %w", err)
	}
	byDay := make(map[string]sqlite.InsightsDayCount, len(counts))
	for _, count := range counts {
		byDay[count.Day] = count
	}
	response.Heatmap = make([]insights.HeatmapDay, 0, HeatmapDays)
	for day := endDay - (HeatmapDays - 1); day <= endDay; day++ {
		name := dayString(day)
		count := byDay[name]
		response.Heatmap = append(response.Heatmap, insights.HeatmapDay{Day: name, Requests: count.Requests, Sessions: count.Sessions})
	}
	return response, nil
}

func encodeSessionCursor(sortKey string, cursor sqlite.InsightsSessionCursor) string {
	raw := strings.Join([]string{insightsCursorVersion, sortKey, strconv.FormatInt(cursor.Value, 10), cursor.SessionID}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeSessionCursor(sortKey, encoded string) (*sqlite.InsightsSessionCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > 512 {
		return nil, invalid("invalid cursor")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != insightsCursorVersion || parts[1] != sortKey || !sessionIDPattern.MatchString(parts[3]) {
		return nil, invalid("invalid cursor")
	}
	value, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || value < 0 {
		return nil, invalid("invalid cursor")
	}
	return &sqlite.InsightsSessionCursor{Value: value, SessionID: parts[3]}, nil
}

func estimateValues(estimate sqlite.InsightsEstimate) insights.CategoryValues {
	return insights.CategoryValues{
		System: estimate.System, Tools: estimate.Tools, User: estimate.User, Injected: estimate.Injected,
		Assistant: estimate.Assistant, Reasoning: estimate.Reasoning, ToolResult: estimate.ToolResult, Media: estimate.Media,
	}
}

// displayComposition anchors the estimate to the reported prompt total when one
// exists, and otherwise returns the raw estimate.
func displayComposition(estimate insights.CategoryValues, prompt *int64) insights.CategoryValues {
	if prompt != nil && *prompt > 0 && estimate.Sum() > 0 {
		return insights.Anchor(estimate, *prompt)
	}
	return estimate
}

// isAuxiliaryRole reports compaction, title, review and auxiliary requests,
// which never start a turn.
func isAuxiliaryRole(role string) bool {
	switch role {
	case insights.RoleCompaction, insights.RoleTitle, insights.RoleReview, insights.RoleAuxiliary:
		return true
	}
	return false
}

func treeIDOf(fingerprint []byte) string {
	if len(fingerprint) < treeIDHexLength/2 {
		return ""
	}
	return hex.EncodeToString(fingerprint[:treeIDHexLength/2])
}

// Sessions lists session cards, one per analysis session with in-scope steps in
// the range.
func (service *Insights) Sessions(ctx context.Context, request SessionsQuery) (insights.SessionsResponse, error) {
	if ctx == nil {
		return insights.SessionsResponse{}, invalid("nil context")
	}
	if err := validateScope(request.Scope); err != nil {
		return insights.SessionsResponse{}, err
	}
	sortKey := request.Sort
	if sortKey == "" {
		sortKey = sqlite.InsightsSortRecent
	}
	switch sortKey {
	case sqlite.InsightsSortRecent, sqlite.InsightsSortTokens, sqlite.InsightsSortContext:
	default:
		return insights.SessionsResponse{}, invalid("invalid sort")
	}
	limit := request.Limit
	if limit == 0 {
		limit = DefaultSessionLimit
	}
	if limit < 1 || limit > MaxSessionLimit {
		return insights.SessionsResponse{}, invalid("limit must be between 1 and 100")
	}
	cursor, err := decodeSessionCursor(sortKey, request.Cursor)
	if err != nil {
		return insights.SessionsResponse{}, err
	}
	from, to, err := service.resolveRange(request.FromNS, request.ToNS)
	if err != nil {
		return insights.SessionsResponse{}, err
	}
	filter := service.filter(request.Scope, from, to)
	page, err := service.store.InsightsSessions(ctx, filter, sortKey, cursor, limit)
	if err != nil {
		return insights.SessionsResponse{}, fmt.Errorf("query: insights sessions: %w", err)
	}
	response := insights.SessionsResponse{Items: make([]insights.SessionCard, 0, len(page.Rows))}
	if len(page.Rows) == 0 {
		return response, nil
	}

	ids := make([]string, 0, len(page.Rows))
	var roots [][]byte
	seenRoot := make(map[string]bool)
	for _, row := range page.Rows {
		ids = append(ids, row.SessionID)
		if len(row.Root) != 0 && !seenRoot[string(row.Root)] {
			seenRoot[string(row.Root)] = true
			roots = append(roots, row.Root)
		}
	}
	pageFilter := filter
	pageFilter.SessionIDs = ids
	usageRows, err := service.store.InsightsUsage(ctx, pageFilter, sqlite.InsightsUsageSpec{Dimension: sqlite.InsightsDimSession, SlotNS: service.slotNS()})
	if err != nil {
		return insights.SessionsResponse{}, fmt.Errorf("query: insights session usage: %w", err)
	}
	usage := service.fold(usageRows)
	models, err := service.store.InsightsSessionModels(ctx, pageFilter)
	if err != nil {
		return insights.SessionsResponse{}, fmt.Errorf("query: insights session models: %w", err)
	}
	subagents := map[string]int64{}
	realRoots := map[string]bool{}
	if len(roots) != 0 {
		rootFilter := filter
		rootFilter.RootFPRs = roots
		if realRoots, err = service.store.InsightsRealRoots(ctx, rootFilter); err != nil {
			return insights.SessionsResponse{}, fmt.Errorf("query: insights real trees: %w", err)
		}
		// The tree check above ignores the range, so the count must too or
		// a card could show a tree with zero subagents.
		rootFilter.FromNS, rootFilter.ToNS = 0, 0
		if subagents, err = service.store.InsightsSubagentCounts(ctx, rootFilter); err != nil {
			return insights.SessionsResponse{}, fmt.Errorf("query: insights subagent counts: %w", err)
		}
	}

	for _, row := range page.Rows {
		card := insights.SessionCard{
			SessionID:    row.SessionID,
			SessionLink:  row.Link,
			Protocol:     row.Protocol,
			Client:       row.Client,
			Role:         row.Role,
			FirstNS:      row.FirstNS,
			LastNS:       row.LastNS,
			Steps:        row.Steps,
			Turns:        row.Turns,
			Models:       models[row.SessionID],
			Usage:        usage.byKey[row.SessionID].usage(),
			LastEstimate: displayComposition(estimateValues(row.Estimate), row.LastPrompt),
			LastPrompt:   row.LastPrompt,
		}
		if card.Models == nil {
			card.Models = []string{}
		}
		card.ContextWindow = service.prices.ContextWindow(row.Model)
		if realRoots[string(row.Root)] {
			card.TreeID = treeIDOf(row.Root)
			if row.Role == insights.RoleMain {
				card.Subagents = subagents[string(row.Root)]
			}
		}
		if request.Scope == nil && (row.Username != "" || row.TokenName != "") {
			card.Caller = &insights.SessionCaller{Username: row.Username, TokenName: row.TokenName}
		}
		response.Items = append(response.Items, card)
	}
	if page.HasMore {
		last := page.Rows[len(page.Rows)-1]
		response.NextCursor = encodeSessionCursor(sortKey, sqlite.InsightsSessionCursor{Value: last.SortValue, SessionID: last.SessionID})
	}
	return response, nil
}

var eventNames = []struct {
	bit  int
	name string
}{
	{insights.EventModelSwitch, "model_switch"},
	{insights.EventCompaction, "compaction"},
	{insights.EventPrune, "prune"},
	{insights.EventSystemChanged, "system_changed"},
	{insights.EventToolsChanged, "tools_changed"},
	{insights.EventInjected, "injected"},
}

var kindNames = []struct {
	bit  int
	name string
}{
	{insights.KindThinking, "thinking"},
	{insights.KindToolCall, "tool_call"},
	{insights.KindText, "text"},
}

func bitNames(flags int, names []struct {
	bit  int
	name string
}) []string {
	result := []string{}
	for _, entry := range names {
		if flags&entry.bit != 0 {
			result = append(result, entry.name)
		}
	}
	return result
}

func milliseconds(value *int64) *float64 {
	if value == nil {
		return nil
	}
	converted := float64(*value) / 1e6
	return &converted
}

// Trend returns the step series of one analysis session. A session with no
// in-scope step is reported as not found, whoever owns it.
func (service *Insights) Trend(ctx context.Context, sessionID string, scope *Scope) (insights.TrendResponse, error) {
	if ctx == nil {
		return insights.TrendResponse{}, invalid("nil context")
	}
	if !sessionIDPattern.MatchString(sessionID) {
		return insights.TrendResponse{}, invalid("invalid session_id")
	}
	if err := validateScope(scope); err != nil {
		return insights.TrendResponse{}, err
	}
	filter := sqlite.InsightsFilter{Scope: storageScope(scope), SessionIDs: []string{sessionID}}
	rows, truncated, err := service.store.InsightsTrend(ctx, filter, service.trendLimit)
	if err != nil {
		return insights.TrendResponse{}, fmt.Errorf("query: insights trend: %w", err)
	}
	if len(rows) == 0 {
		return insights.TrendResponse{}, ErrNotFound
	}
	byID := make(map[string]*sqlite.InsightsTrendRow, len(rows))
	for index := range rows {
		byID[rows[index].AuditID] = &rows[index]
	}
	response := insights.TrendResponse{SessionID: sessionID, Truncated: truncated, Steps: make([]insights.TrendStep, 0, len(rows))}
	// A truncated trend starts mid-session; seed the counter with the turns that
	// were left out so numbering stays absolute.
	var turn int64
	if truncated {
		if turn, err = service.store.InsightsTurnStartsBefore(ctx, filter, rows[0].StartedAtNS, rows[0].AuditID); err != nil {
			return insights.TrendResponse{}, fmt.Errorf("query: insights trend turns: %w", err)
		}
	}
	for index := range rows {
		row := &rows[index]
		turnStart := row.TurnStart && !isAuxiliaryRole(row.Role)
		if turnStart {
			turn++
		}
		usage := insights.Usage{
			UncachedInput: row.UncachedInput, CacheRead: row.CacheRead, CacheWrite: row.CacheWrite,
			Output: row.Output, Reasoning: row.Reasoning,
		}
		step := insights.TrendStep{
			AuditID:       row.AuditID,
			StartedAtNS:   row.StartedAtNS,
			Turn:          turn,
			TurnStart:     turnStart,
			Model:         row.Model,
			Role:          row.Role,
			Estimate:      estimateValues(row.Estimate),
			Usage:         usage,
			PromptTotal:   usage.PromptTotal(),
			Events:        bitNames(row.EventFlags, eventNames),
			AppendedItems: row.AppendedItems,
			RemovedItems:  row.RemovedItems,
			StopReason:    row.StopReason,
			ResponseKinds: bitNames(row.RespKinds, kindNames),
			FirstEventMS:  milliseconds(row.FirstEventNS),
			GenerationMS:  milliseconds(row.GenerationNS),
			CostUSD:       service.prices.Cost(usage, row.Model, time.Unix(0, row.StartedAtNS)),
		}
		if previous := byID[row.PrevAuditID]; previous != nil && previous.StopReason == insights.StopToolUse &&
			previous.EndedAtNS != nil && row.StartedAtNS >= *previous.EndedAtNS {
			gap := float64(row.StartedAtNS-*previous.EndedAtNS) / 1e6
			step.ClientGapMS = &gap
		}
		response.Steps = append(response.Steps, step)
	}
	last := rows[len(rows)-1]
	if len(last.Root) != 0 {
		real, err := service.store.InsightsRealRoots(ctx, sqlite.InsightsFilter{Scope: filter.Scope, RootFPRs: [][]byte{last.Root}})
		if err != nil {
			return insights.TrendResponse{}, fmt.Errorf("query: insights real trees: %w", err)
		}
		if real[string(last.Root)] {
			response.TreeID = treeIDOf(last.Root)
		}
	}
	response.ContextWindow = service.prices.ContextWindow(last.Model)
	return response, nil
}

// Tree returns the agent nodes of one tree visible to the caller.
func (service *Insights) Tree(ctx context.Context, treeID string, scope *Scope) (insights.TreeResponse, error) {
	if ctx == nil {
		return insights.TreeResponse{}, invalid("nil context")
	}
	if !treeIDPattern.MatchString(treeID) {
		return insights.TreeResponse{}, invalid("invalid tree_id")
	}
	if err := validateScope(scope); err != nil {
		return insights.TreeResponse{}, err
	}
	prefix, err := hex.DecodeString(treeID)
	if err != nil {
		return insights.TreeResponse{}, invalid("invalid tree_id")
	}
	filter := sqlite.InsightsFilter{Scope: storageScope(scope), RootPrefix: prefix}
	rows, truncated, err := service.store.InsightsTree(ctx, filter, MaxTreeNodes)
	if err != nil {
		return insights.TreeResponse{}, fmt.Errorf("query: insights tree: %w", err)
	}
	if len(rows) == 0 {
		return insights.TreeResponse{}, ErrNotFound
	}
	usageRows, err := service.store.InsightsUsage(ctx, filter, sqlite.InsightsUsageSpec{Dimension: sqlite.InsightsDimNode, SlotNS: service.slotNS()})
	if err != nil {
		return insights.TreeResponse{}, fmt.Errorf("query: insights tree usage: %w", err)
	}
	usage := service.fold(usageRows)

	response := insights.TreeResponse{TreeID: treeID, Truncated: truncated, Nodes: make([]insights.TreeNode, 0, len(rows))}
	known := make(map[string]bool, len(rows))
	for _, row := range rows {
		known[treeIDOf(row.NodeFPR)] = true
	}
	var placeholders []insights.TreeNode
	placeholderSeen := make(map[string]bool)
	for _, row := range rows {
		nodeID := treeIDOf(row.NodeFPR)
		node := insights.TreeNode{
			NodeID:         nodeID,
			ParentNodeID:   treeIDOf(row.ParentFPR),
			Visible:        true,
			SessionID:      row.SessionID,
			Client:         row.Client,
			Role:           row.Role,
			FirstNS:        row.FirstNS,
			LastNS:         row.LastNS,
			Steps:          row.Steps,
			AuxRequests:    row.AuxRequests,
			Usage:          usage.byKey[hex.EncodeToString(row.NodeFPR)].usage(),
			LastEstimate:   displayComposition(estimateValues(row.Estimate), row.LastPrompt),
			LastPrompt:     row.LastPrompt,
			ContextWindow:  service.prices.ContextWindow(row.Model),
			LinkSource:     row.LinkSource,
			LinkConfidence: row.LinkConfidence,
		}
		response.Nodes = append(response.Nodes, node)
		if parent := node.ParentNodeID; parent != "" && parent != nodeID && !known[parent] && !placeholderSeen[parent] {
			placeholderSeen[parent] = true
			placeholders = append(placeholders, insights.TreeNode{NodeID: parent, Visible: false, Client: "unknown", Role: "unknown"})
		}
	}
	response.Nodes = append(response.Nodes, placeholders...)
	return response, nil
}

// allowed reports whether scope may read one audit. A nil scope is an
// administrator.
func (service *Insights) allowed(ctx context.Context, auditID string, scope *Scope) (bool, error) {
	if scope == nil {
		return true, nil
	}
	row, err := service.store.QueryAuditScope(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query: insights authorize: %w", err)
	}
	return storageScope(scope).Allows(row), nil
}

func (service *Insights) decryptDetail(row sqlite.AnalysisRow) (insights.Detail, error) {
	var detail insights.Detail
	if len(row.DetailEnc) == 0 {
		return detail, nil
	}
	aad, err := security.AAD(row.AuditID, "analysis_detail", strconv.Itoa(row.AnalysisVersion))
	if err != nil {
		return insights.Detail{}, ErrIntegrity
	}
	plaintext, err := service.cipher.Decrypt(aad, row.DetailEnc)
	if err != nil {
		return insights.Detail{}, ErrIntegrity
	}
	defer clear(plaintext)
	if err := json.Unmarshal(plaintext, &detail); err != nil {
		return insights.Detail{}, ErrIntegrity
	}
	return detail, nil
}

func rowEstimate(row sqlite.AnalysisRow) insights.CategoryValues {
	return insights.CategoryValues{
		System: row.EstSystem, Tools: row.EstTools, User: row.EstUser, Injected: row.EstInjected,
		Assistant: row.EstAssistant, Reasoning: row.EstReasoning, ToolResult: row.EstToolResult, Media: row.EstMedia,
	}
}

func commonPrefix(left, right []string) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

// Composition decrypts one audit's detail, and its previous step's when that is
// readable in scope, to describe the context items and what changed. Callers
// must have authorized auditID; the scope is re-checked here as a second gate.
func (service *Insights) Composition(ctx context.Context, auditID string, scope *Scope) (insights.CompositionResponse, error) {
	if ctx == nil {
		return insights.CompositionResponse{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return insights.CompositionResponse{}, err
	}
	if err := validateScope(scope); err != nil {
		return insights.CompositionResponse{}, err
	}
	ok, err := service.allowed(ctx, auditID, scope)
	if err != nil {
		return insights.CompositionResponse{}, err
	}
	if !ok {
		return insights.CompositionResponse{}, ErrNotFound
	}
	row, err := service.store.LoadAnalysis(ctx, auditID)
	if errors.Is(err, sql.ErrNoRows) {
		return insights.CompositionResponse{}, ErrNotFound
	}
	if err != nil {
		return insights.CompositionResponse{}, fmt.Errorf("query: insights load analysis: %w", err)
	}
	detail, err := service.decryptDetail(row)
	if err != nil {
		return insights.CompositionResponse{}, err
	}

	model := ""
	if row.Model != nil {
		model = *row.Model
	}
	usage := insights.Usage{
		UncachedInput: row.UncachedInput, CacheRead: row.CacheRead, CacheWrite: row.CacheWrite,
		Output: row.Output, Reasoning: row.Reasoning,
	}
	estimate := rowEstimate(row)
	response := insights.CompositionResponse{
		AuditID:         row.AuditID,
		AnalysisVersion: row.AnalysisVersion,
		Model:           model,
		Usage:           usage,
		PromptTotal:     usage.PromptTotal(),
		Estimate:        estimate,
		ContextWindow:   service.prices.ContextWindow(model),
		Items:           make([]insights.CompositionItem, 0, len(detail.Items)),
		Tools:           detail.Tools,
		FileOps:         detail.FileOps,
		Agent:           detail.Agent,
		Events:          bitNames(row.EventFlags, eventNames),
		Truncated:       detail.Truncated,
	}
	if response.Tools == nil {
		response.Tools = []insights.ToolDef{}
	}
	if response.FileOps == nil {
		response.FileOps = []insights.FileOp{}
	}
	if response.Agent.Client == "" && row.AgentClient != nil {
		response.Agent.Client = *row.AgentClient
	}
	if response.Agent.Role == "" && row.AgentRole != nil {
		response.Agent.Role = *row.AgentRole
	}
	if response.PromptTotal != nil && *response.PromptTotal > 0 && estimate.Sum() > 0 {
		anchored := insights.Anchor(estimate, *response.PromptTotal)
		response.Anchored = &anchored
	}

	var previous *sqlite.AnalysisRow
	var previousDetail insights.Detail
	if row.PrevAuditID != nil && *row.PrevAuditID != "" && *row.PrevAuditID != auditID {
		allowed, err := service.allowed(ctx, *row.PrevAuditID, scope)
		if err != nil {
			return insights.CompositionResponse{}, err
		}
		if allowed {
			candidate, err := service.store.LoadAnalysis(ctx, *row.PrevAuditID)
			switch {
			case err == nil:
				if previousDetail, err = service.decryptDetail(candidate); err != nil {
					return insights.CompositionResponse{}, err
				}
				previous = &candidate
			case errors.Is(err, sql.ErrNoRows):
			default:
				return insights.CompositionResponse{}, fmt.Errorf("query: insights load previous analysis: %w", err)
			}
		}
	}

	common := -1
	if previous != nil && len(detail.ItemFPRs) != 0 && len(previousDetail.ItemFPRs) != 0 {
		common = commonPrefix(detail.ItemFPRs, previousDetail.ItemFPRs)
	}
	for _, item := range detail.Items {
		entry := insights.CompositionItem{Item: item}
		if common >= 0 {
			entry.Change = "kept"
			if item.Index >= common {
				entry.Change = "added"
			}
		}
		response.Items = append(response.Items, entry)
	}
	if previous != nil {
		response.PreviousAuditID = previous.AuditID
		previousEstimate := rowEstimate(*previous)
		diff := insights.CompositionDiff{ByCategory: insights.CategoryValues{
			System: estimate.System - previousEstimate.System, Tools: estimate.Tools - previousEstimate.Tools,
			User: estimate.User - previousEstimate.User, Injected: estimate.Injected - previousEstimate.Injected,
			Assistant: estimate.Assistant - previousEstimate.Assistant, Reasoning: estimate.Reasoning - previousEstimate.Reasoning,
			ToolResult: estimate.ToolResult - previousEstimate.ToolResult, Media: estimate.Media - previousEstimate.Media,
		}}
		switch {
		case common >= 0:
			diff.AddedItems = int64(len(detail.ItemFPRs) - common)
			diff.RemovedItems = int64(len(previousDetail.ItemFPRs) - common)
		default:
			if row.AppendedItems != nil {
				diff.AddedItems = int64(*row.AppendedItems)
			}
			if row.RemovedItems != nil {
				diff.RemovedItems = int64(*row.RemovedItems)
			}
		}
		response.Diff = &diff
	}
	return response, nil
}
