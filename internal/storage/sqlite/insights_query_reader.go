package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The insights read queries aggregate audit_analysis, the derived plaintext
// table of doc/features/20-context-insights.md. They never touch an encrypted
// column. Every query joins audit_records (and token_links, which the developer
// scope rule and the caller/token groupings need) and applies the same
// AuditScope condition as ListAudits to every row it counts, so a session or
// agent tree shared with another API key only exposes the caller's own steps.

// Insights usage groupings.
const (
	InsightsDimTotal    = "total"
	InsightsDimDay      = "day"
	InsightsDimModel    = "model"
	InsightsDimProtocol = "protocol"
	InsightsDimClient   = "client"
	InsightsDimCaller   = "caller"
	InsightsDimToken    = "token"
	InsightsDimSession  = "session"
	InsightsDimNode     = "node"
)

// Session list orderings.
const (
	InsightsSortRecent  = "recent"
	InsightsSortTokens  = "tokens"
	InsightsSortContext = "context"
)

const (
	maxInsightsIDs      = 200
	maxInsightsTrend    = 2000
	maxInsightsSessions = 100
)

// InsightsFilter selects analysis rows. FromNS is inclusive and ToNS exclusive;
// a zero ToNS disables the time condition (single session and tree reads).
type InsightsFilter struct {
	FromNS int64
	ToNS   int64
	Scope  *AuditScope
	// SessionIDs restricts to these analysis sessions.
	SessionIDs []string
	// RootPrefix restricts to agent trees whose root fingerprint starts with it.
	RootPrefix []byte
	// RootFPRs restricts to these full agent root fingerprints.
	RootFPRs [][]byte
}

// InsightsUsageSpec chooses the grouping of InsightsUsage. SlotNS > 0 further
// splits every group into fixed time slots so time-of-day price schedules can
// be applied to aggregates.
type InsightsUsageSpec struct {
	Dimension   string
	TZOffsetMin int
	SlotNS      int64
}

// InsightsMix is the per-category sum of estimates, each row anchored to its own
// reported prompt total when usage exists (raw estimate otherwise).
type InsightsMix struct {
	System, Tools, User, Injected, Assistant, Reasoning, ToolResult, Media float64
}

// InsightsEstimate is one request's raw composition estimate.
type InsightsEstimate struct {
	System, Tools, User, Injected, Assistant, Reasoning, ToolResult, Media int64
}

// InsightsUsageRow is one (group, model, slot) aggregate.
type InsightsUsageRow struct {
	Key, Label, Model string
	SlotNS            int64
	Requests          int64
	UncachedInput     int64
	CacheRead         int64
	CacheWrite        int64
	Output            int64
	Reasoning         int64
	Mix               InsightsMix
}

// InsightsDayCount is the activity of one local calendar day.
type InsightsDayCount struct {
	Day      string
	Requests int64
	Sessions int64
}

const insightsFrom = `
FROM audit_analysis AS x
JOIN audit_records AS a ON a.audit_id = x.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
WHERE 1 = 1`

const (
	insightsPromptSQL = `(COALESCE(x.u_uncached_input, 0) + COALESCE(x.u_cache_read, 0) + COALESCE(x.u_cache_write, 0))`
	insightsHasUsage  = `(x.u_uncached_input IS NOT NULL OR x.u_cache_read IS NOT NULL OR x.u_cache_write IS NOT NULL)`
	insightsEstSumSQL = `(x.est_system + x.est_tools + x.est_user + x.est_injected + x.est_assistant + x.est_reasoning + x.est_tool_result + x.est_media)`
	insightsAnchorSQL = `(CASE WHEN ` + insightsHasUsage + ` AND ` + insightsEstSumSQL + ` > 0 THEN 1.0 * ` +
		insightsPromptSQL + ` / ` + insightsEstSumSQL + ` ELSE 1.0 END)`
	insightsAuxRoles = `('compaction', 'title', 'review', 'auxiliary')`
)

func (filter InsightsFilter) validate() error {
	if filter.FromNS < 0 || filter.ToNS < 0 || (filter.ToNS > 0 && filter.FromNS >= filter.ToNS) {
		return errors.New("sqlite: invalid insights time range")
	}
	if filter.Scope != nil {
		if err := filter.Scope.Validate(); err != nil {
			return err
		}
	}
	if len(filter.SessionIDs) > maxInsightsIDs || len(filter.RootFPRs) > maxInsightsIDs {
		return errors.New("sqlite: too many insights ids")
	}
	return nil
}

// where renders the filter against the aliases x, a and t.
func (filter InsightsFilter) where() (string, []any, error) {
	if err := filter.validate(); err != nil {
		return "", nil, err
	}
	var statement strings.Builder
	arguments := make([]any, 0, 8)
	add := func(condition string, values ...any) {
		statement.WriteString("\n  AND ")
		statement.WriteString(condition)
		arguments = append(arguments, values...)
	}
	if filter.ToNS > 0 {
		add("x.started_at_ns >= ? AND x.started_at_ns < ?", filter.FromNS, filter.ToNS)
	}
	if len(filter.SessionIDs) != 0 {
		values := make([]any, len(filter.SessionIDs))
		for index, id := range filter.SessionIDs {
			values[index] = id
		}
		add("x.analysis_session_id IN ("+placeholders(len(values))+")", values...)
	}
	if len(filter.RootPrefix) != 0 {
		upper := prefixUpperBound(filter.RootPrefix)
		if upper == nil {
			add("x.agent_root_fpr >= ?", filter.RootPrefix)
		} else {
			add("x.agent_root_fpr >= ? AND x.agent_root_fpr < ?", filter.RootPrefix, upper)
		}
	}
	if len(filter.RootFPRs) != 0 {
		values := make([]any, len(filter.RootFPRs))
		for index, root := range filter.RootFPRs {
			values[index] = root
		}
		add("x.agent_root_fpr IN ("+placeholders(len(values))+")", values...)
	}
	if filter.Scope != nil {
		condition, values := filter.Scope.conditionWithAliases("a", "t")
		add(condition, values...)
	}
	return statement.String(), arguments, nil
}

// prefixUpperBound returns the smallest byte string greater than every string
// that starts with prefix, or nil when no such bound exists.
func prefixUpperBound(prefix []byte) []byte {
	upper := cloneBytes(prefix)
	for index := len(upper) - 1; index >= 0; index-- {
		if upper[index] != 0xff {
			upper[index]++
			return upper[:index+1]
		}
	}
	return nil
}

func (store *Store) insightsReady(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return nil
}

func dayExpression(tzOffsetMin int) string {
	return "date(x.started_at_ns / 1000000000 + " + strconv.Itoa(tzOffsetMin*60) + ", 'unixepoch')"
}

// InsightsUsage sums normalized usage per (group, model, slot).
func (store *Store) InsightsUsage(ctx context.Context, filter InsightsFilter, spec InsightsUsageSpec) ([]InsightsUsageRow, error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, err
	}
	if spec.TZOffsetMin < -840 || spec.TZOffsetMin > 840 || spec.SlotNS < 0 {
		return nil, errors.New("sqlite: invalid insights usage spec")
	}
	var key, label string
	switch spec.Dimension {
	case InsightsDimTotal:
		key, label = `''`, `''`
	case InsightsDimDay:
		key = dayExpression(spec.TZOffsetMin)
		label = key
	case InsightsDimModel:
		key, label = `COALESCE(x.model, '')`, `COALESCE(x.model, '')`
	case InsightsDimProtocol:
		key, label = `x.protocol`, `x.protocol`
	case InsightsDimClient:
		key, label = `COALESCE(x.agent_client, 'unknown')`, `COALESCE(x.agent_client, 'unknown')`
	case InsightsDimCaller:
		key, label = `COALESCE(CAST(t.newapi_user_id AS TEXT), '')`, `COALESCE(MAX(t.username), '')`
	case InsightsDimToken:
		key, label = `COALESCE(CAST(t.newapi_token_id AS TEXT), '')`, `COALESCE(MAX(t.token_name), '')`
	case InsightsDimSession:
		key, label = `COALESCE(x.analysis_session_id, '')`, `COALESCE(x.analysis_session_id, '')`
	case InsightsDimNode:
		key, label = `COALESCE(lower(hex(x.agent_node_fpr)), '')`, `COALESCE(lower(hex(x.agent_node_fpr)), '')`
	default:
		return nil, errors.New("sqlite: unknown insights dimension")
	}
	slot := "0"
	if spec.SlotNS > 0 {
		slot = "(x.started_at_ns / " + strconv.FormatInt(spec.SlotNS, 10) + ") * " + strconv.FormatInt(spec.SlotNS, 10)
	}
	where, arguments, err := filter.where()
	if err != nil {
		return nil, err
	}
	statement := `
SELECT ` + key + ` AS grp_key, ` + label + ` AS grp_label, COALESCE(x.model, '') AS grp_model, ` + slot + ` AS grp_slot,
       COUNT(*),
       COALESCE(SUM(x.u_uncached_input), 0), COALESCE(SUM(x.u_cache_read), 0), COALESCE(SUM(x.u_cache_write), 0),
       COALESCE(SUM(x.u_output), 0), COALESCE(SUM(x.u_reasoning), 0),
       SUM(x.est_system * ` + insightsAnchorSQL + `), SUM(x.est_tools * ` + insightsAnchorSQL + `),
       SUM(x.est_user * ` + insightsAnchorSQL + `), SUM(x.est_injected * ` + insightsAnchorSQL + `),
       SUM(x.est_assistant * ` + insightsAnchorSQL + `), SUM(x.est_reasoning * ` + insightsAnchorSQL + `),
       SUM(x.est_tool_result * ` + insightsAnchorSQL + `), SUM(x.est_media * ` + insightsAnchorSQL + `)` +
		insightsFrom + where + `
GROUP BY grp_key, grp_model, grp_slot
ORDER BY grp_key, grp_model, grp_slot`
	rows, err := store.readerDB.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insights usage: %w", err)
	}
	defer rows.Close()
	result := make([]InsightsUsageRow, 0)
	for rows.Next() {
		var row InsightsUsageRow
		if err := rows.Scan(&row.Key, &row.Label, &row.Model, &row.SlotNS, &row.Requests,
			&row.UncachedInput, &row.CacheRead, &row.CacheWrite, &row.Output, &row.Reasoning,
			&row.Mix.System, &row.Mix.Tools, &row.Mix.User, &row.Mix.Injected,
			&row.Mix.Assistant, &row.Mix.Reasoning, &row.Mix.ToolResult, &row.Mix.Media); err != nil {
			return nil, fmt.Errorf("sqlite: scan insights usage: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate insights usage: %w", err)
	}
	return result, nil
}

// InsightsDistinct counts distinct analysis sessions and agent trees.
func (store *Store) InsightsDistinct(ctx context.Context, filter InsightsFilter) (sessions, trees int64, err error) {
	if err := store.insightsReady(ctx); err != nil {
		return 0, 0, err
	}
	where, arguments, err := filter.where()
	if err != nil {
		return 0, 0, err
	}
	err = store.readerDB.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT x.analysis_session_id), COUNT(DISTINCT x.agent_root_fpr)`+insightsFrom+where,
		arguments...).Scan(&sessions, &trees)
	if err != nil {
		return 0, 0, fmt.Errorf("sqlite: insights distinct: %w", err)
	}
	return sessions, trees, nil
}

// InsightsDayCounts returns requests and distinct sessions per local day.
func (store *Store) InsightsDayCounts(ctx context.Context, filter InsightsFilter, tzOffsetMin int) ([]InsightsDayCount, error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, err
	}
	if tzOffsetMin < -840 || tzOffsetMin > 840 {
		return nil, errors.New("sqlite: invalid insights timezone offset")
	}
	where, arguments, err := filter.where()
	if err != nil {
		return nil, err
	}
	rows, err := store.readerDB.QueryContext(ctx,
		`SELECT `+dayExpression(tzOffsetMin)+` AS day, COUNT(*), COUNT(DISTINCT x.analysis_session_id)`+
			insightsFrom+where+` GROUP BY day ORDER BY day`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insights day counts: %w", err)
	}
	defer rows.Close()
	result := make([]InsightsDayCount, 0)
	for rows.Next() {
		var row InsightsDayCount
		if err := rows.Scan(&row.Day, &row.Requests, &row.Sessions); err != nil {
			return nil, fmt.Errorf("sqlite: scan insights day counts: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate insights day counts: %w", err)
	}
	return result, nil
}

// InsightsSessionCursor is the keyset position after the last returned card.
type InsightsSessionCursor struct {
	Value     int64
	SessionID string
}

// InsightsSessionRow is one session aggregate plus the values of its last step.
type InsightsSessionRow struct {
	SessionID  string
	FirstNS    int64
	LastNS     int64
	Steps      int64
	Turns      int64
	Tokens     int64
	SortValue  int64
	Protocol   string
	Model      string
	Client     string
	Role       string
	Link       string
	Root       []byte
	Username   string
	TokenName  string
	LastPrompt *int64
	Estimate   InsightsEstimate
}

// InsightsSessionPage is one keyset page of session cards.
type InsightsSessionPage struct {
	Rows    []InsightsSessionRow
	HasMore bool
}

// InsightsSessions aggregates the in-scope steps of every analysis session that
// has a step in the filter's time range, newest keyset first.
func (store *Store) InsightsSessions(ctx context.Context, filter InsightsFilter, sortKey string, cursor *InsightsSessionCursor, limit int) (InsightsSessionPage, error) {
	if err := store.insightsReady(ctx); err != nil {
		return InsightsSessionPage{}, err
	}
	if limit < 1 || limit > maxInsightsSessions {
		return InsightsSessionPage{}, errors.New("sqlite: insights session limit out of range")
	}
	var sortExpr string
	switch sortKey {
	case InsightsSortRecent:
		sortExpr = "last_ns"
	case InsightsSortTokens:
		sortExpr = "tokens"
	case InsightsSortContext:
		sortExpr = "COALESCE(last_prompt, last_est)"
	default:
		return InsightsSessionPage{}, errors.New("sqlite: unknown insights session sort")
	}
	filter.SessionIDs = nil
	filter.RootPrefix = nil
	filter.RootFPRs = nil
	where, arguments, err := filter.where()
	if err != nil {
		return InsightsSessionPage{}, err
	}
	last := func(column string) string { return "MAX(CASE WHEN rn = 1 THEN " + column + " END)" }
	statement := `
WITH s AS (
  SELECT x.analysis_session_id AS sid, x.started_at_ns AS ts, x.turn_start AS turn_start,
         ` + insightsPromptSQL + ` + COALESCE(x.u_output, 0) AS tokens,
         x.protocol AS protocol, COALESCE(x.model, '') AS model, COALESCE(x.agent_client, 'unknown') AS client,
         COALESCE(x.agent_role, 'main') AS role, COALESCE(x.session_link, '') AS link, x.agent_root_fpr AS root,
         COALESCE(t.username, '') AS username, COALESCE(t.token_name, '') AS token_name,
         CASE WHEN ` + insightsHasUsage + ` THEN ` + insightsPromptSQL + ` END AS prompt,
         x.est_system AS e1, x.est_tools AS e2, x.est_user AS e3, x.est_injected AS e4,
         x.est_assistant AS e5, x.est_reasoning AS e6, x.est_tool_result AS e7, x.est_media AS e8,
         ROW_NUMBER() OVER (PARTITION BY x.analysis_session_id ORDER BY x.started_at_ns DESC, x.audit_id DESC) AS rn` +
		insightsFrom + where + `
    AND x.analysis_session_id IS NOT NULL
), g AS (
  SELECT sid, MIN(ts) AS first_ns, MAX(ts) AS last_ns, COUNT(*) AS steps, SUM(turn_start) AS turns, SUM(tokens) AS tokens,
         ` + last("protocol") + ` AS protocol, ` + last("model") + ` AS model, ` + last("client") + ` AS client,
         ` + last("role") + ` AS role, ` + last("link") + ` AS link, ` + last("root") + ` AS root,
         ` + last("username") + ` AS username, ` + last("token_name") + ` AS token_name,
         ` + last("prompt") + ` AS last_prompt,
         ` + last("e1") + ` AS e1, ` + last("e2") + ` AS e2, ` + last("e3") + ` AS e3, ` + last("e4") + ` AS e4,
         ` + last("e5") + ` AS e5, ` + last("e6") + ` AS e6, ` + last("e7") + ` AS e7, ` + last("e8") + ` AS e8,
         ` + last("e1+e2+e3+e4+e5+e6+e7+e8") + ` AS last_est
  FROM s GROUP BY sid
)
SELECT sid, first_ns, last_ns, steps, turns, tokens, ` + sortExpr + ` AS sort_value,
       protocol, model, client, role, link, root, username, token_name, last_prompt,
       e1, e2, e3, e4, e5, e6, e7, e8
FROM g`
	if cursor != nil {
		statement += `
WHERE (` + sortExpr + ` < ? OR (` + sortExpr + ` = ? AND sid < ?))`
		arguments = append(arguments, cursor.Value, cursor.Value, cursor.SessionID)
	}
	statement += `
ORDER BY sort_value DESC, sid DESC
LIMIT ?`
	arguments = append(arguments, limit+1)

	rows, err := store.readerDB.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return InsightsSessionPage{}, fmt.Errorf("sqlite: insights sessions: %w", err)
	}
	defer rows.Close()
	page := InsightsSessionPage{Rows: make([]InsightsSessionRow, 0, limit)}
	for rows.Next() {
		var row InsightsSessionRow
		var prompt sql.NullInt64
		if err := rows.Scan(&row.SessionID, &row.FirstNS, &row.LastNS, &row.Steps, &row.Turns, &row.Tokens, &row.SortValue,
			&row.Protocol, &row.Model, &row.Client, &row.Role, &row.Link, &row.Root, &row.Username, &row.TokenName, &prompt,
			&row.Estimate.System, &row.Estimate.Tools, &row.Estimate.User, &row.Estimate.Injected,
			&row.Estimate.Assistant, &row.Estimate.Reasoning, &row.Estimate.ToolResult, &row.Estimate.Media); err != nil {
			return InsightsSessionPage{}, fmt.Errorf("sqlite: scan insights sessions: %w", err)
		}
		row.Root = cloneBytes(row.Root)
		row.LastPrompt = nullInt64Pointer(prompt)
		if len(page.Rows) == limit {
			page.HasMore = true
			break
		}
		page.Rows = append(page.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return InsightsSessionPage{}, fmt.Errorf("sqlite: iterate insights sessions: %w", err)
	}
	return page, nil
}

// InsightsSessionModels lists the models used by the filter's sessions, most
// used first, keyed by session id.
func (store *Store) InsightsSessionModels(ctx context.Context, filter InsightsFilter) (map[string][]string, error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, err
	}
	if len(filter.SessionIDs) == 0 {
		return map[string][]string{}, nil
	}
	where, arguments, err := filter.where()
	if err != nil {
		return nil, err
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT x.analysis_session_id, COALESCE(x.model, '')`+insightsFrom+where+`
GROUP BY x.analysis_session_id, COALESCE(x.model, '')
ORDER BY x.analysis_session_id, COUNT(*) DESC, COALESCE(x.model, '')`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insights session models: %w", err)
	}
	defer rows.Close()
	result := make(map[string][]string)
	for rows.Next() {
		var session, model string
		if err := rows.Scan(&session, &model); err != nil {
			return nil, fmt.Errorf("sqlite: scan insights session models: %w", err)
		}
		if model != "" {
			result[session] = append(result[session], model)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate insights session models: %w", err)
	}
	return result, nil
}

// InsightsSubagentCounts counts distinct subagent nodes per agent root, keyed by
// the raw root fingerprint bytes. filter.RootFPRs selects the roots.
func (store *Store) InsightsSubagentCounts(ctx context.Context, filter InsightsFilter) (map[string]int64, error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, err
	}
	if len(filter.RootFPRs) == 0 {
		return map[string]int64{}, nil
	}
	where, arguments, err := filter.where()
	if err != nil {
		return nil, err
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT x.agent_root_fpr, COUNT(DISTINCT x.agent_node_fpr)`+insightsFrom+where+`
  AND x.agent_role = 'subagent' AND x.agent_node_fpr IS NOT NULL
GROUP BY x.agent_root_fpr`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insights subagent counts: %w", err)
	}
	defer rows.Close()
	result := make(map[string]int64)
	for rows.Next() {
		var root []byte
		var count int64
		if err := rows.Scan(&root, &count); err != nil {
			return nil, fmt.Errorf("sqlite: scan insights subagent counts: %w", err)
		}
		result[string(root)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate insights subagent counts: %w", err)
	}
	return result, nil
}

// InsightsTrendRow is one request of a session trend.
type InsightsTrendRow struct {
	AuditID       string
	StartedAtNS   int64
	EndedAtNS     *int64
	Protocol      string
	Model         string
	Role          string
	Root          []byte
	Estimate      InsightsEstimate
	UncachedInput *int64
	CacheRead     *int64
	CacheWrite    *int64
	Output        *int64
	Reasoning     *int64
	TurnStart     bool
	EventFlags    int
	AppendedItems *int64
	RemovedItems  *int64
	StopReason    string
	RespKinds     int
	FirstEventNS  *int64
	GenerationNS  *int64
	PrevAuditID   string
}

// InsightsTrend returns the most recent in-scope steps of filter.SessionIDs[0]
// in ascending time order, at most limit (<= 2000). truncated reports older
// steps that were left out.
func (store *Store) InsightsTrend(ctx context.Context, filter InsightsFilter, limit int) (rows []InsightsTrendRow, truncated bool, err error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, false, err
	}
	if limit < 1 || limit > maxInsightsTrend {
		return nil, false, errors.New("sqlite: insights trend limit out of range")
	}
	if len(filter.SessionIDs) != 1 {
		return nil, false, errors.New("sqlite: insights trend needs exactly one session")
	}
	filter.FromNS, filter.ToNS = 0, 0
	where, arguments, err := filter.where()
	if err != nil {
		return nil, false, err
	}
	arguments = append(arguments, limit+1)
	cursor, err := store.readerDB.QueryContext(ctx, `
SELECT x.audit_id, x.started_at_ns, a.ended_at_ns, x.protocol, COALESCE(x.model, ''), COALESCE(x.agent_role, 'main'),
       x.agent_root_fpr,
       x.est_system, x.est_tools, x.est_user, x.est_injected, x.est_assistant, x.est_reasoning, x.est_tool_result, x.est_media,
       x.u_uncached_input, x.u_cache_read, x.u_cache_write, x.u_output, x.u_reasoning,
       x.turn_start, x.event_flags, x.appended_items, x.removed_items, COALESCE(x.stop_reason, ''), x.resp_kinds,
       x.first_event_ns, x.generation_ns, COALESCE(x.prev_audit_id, '')`+insightsFrom+where+`
ORDER BY x.started_at_ns DESC, x.audit_id DESC
LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("sqlite: insights trend: %w", err)
	}
	defer cursor.Close()
	for cursor.Next() {
		var row InsightsTrendRow
		var ended, uncached, cacheRead, cacheWrite, output, reasoning, appended, removed, firstEvent, generation sql.NullInt64
		var turnStart int
		if err := cursor.Scan(&row.AuditID, &row.StartedAtNS, &ended, &row.Protocol, &row.Model, &row.Role, &row.Root,
			&row.Estimate.System, &row.Estimate.Tools, &row.Estimate.User, &row.Estimate.Injected,
			&row.Estimate.Assistant, &row.Estimate.Reasoning, &row.Estimate.ToolResult, &row.Estimate.Media,
			&uncached, &cacheRead, &cacheWrite, &output, &reasoning,
			&turnStart, &row.EventFlags, &appended, &removed, &row.StopReason, &row.RespKinds,
			&firstEvent, &generation, &row.PrevAuditID); err != nil {
			return nil, false, fmt.Errorf("sqlite: scan insights trend: %w", err)
		}
		row.Root = cloneBytes(row.Root)
		row.EndedAtNS = nullInt64Pointer(ended)
		row.UncachedInput, row.CacheRead, row.CacheWrite = nullInt64Pointer(uncached), nullInt64Pointer(cacheRead), nullInt64Pointer(cacheWrite)
		row.Output, row.Reasoning = nullInt64Pointer(output), nullInt64Pointer(reasoning)
		row.TurnStart = turnStart != 0
		row.AppendedItems, row.RemovedItems = nullInt64Pointer(appended), nullInt64Pointer(removed)
		row.FirstEventNS, row.GenerationNS = nullInt64Pointer(firstEvent), nullInt64Pointer(generation)
		if len(rows) == limit {
			truncated = true
			break
		}
		rows = append(rows, row)
	}
	if err := cursor.Err(); err != nil {
		return nil, false, fmt.Errorf("sqlite: iterate insights trend: %w", err)
	}
	for left, right := 0, len(rows)-1; left < right; left, right = left+1, right-1 {
		rows[left], rows[right] = rows[right], rows[left]
	}
	return rows, truncated, nil
}

// InsightsTreeNodeRow is one agent of a tree. Steps excludes auxiliary
// requests, which are counted in AuxRequests; the last-step values come from
// the node's latest non-auxiliary request when it has one.
type InsightsTreeNodeRow struct {
	NodeFPR        []byte
	ParentFPR      []byte
	FirstNS        int64
	LastNS         int64
	Steps          int64
	AuxRequests    int64
	Role           string
	Client         string
	Model          string
	SessionID      string
	LinkSource     string
	LinkConfidence int
	LastPrompt     *int64
	Estimate       InsightsEstimate
}

// InsightsTree returns the in-scope nodes of the agent trees matching
// filter.RootPrefix, oldest first, at most maxNodes; truncated reports more.
func (store *Store) InsightsTree(ctx context.Context, filter InsightsFilter, maxNodes int) (rows []InsightsTreeNodeRow, truncated bool, err error) {
	if err := store.insightsReady(ctx); err != nil {
		return nil, false, err
	}
	if maxNodes < 1 || maxNodes > 200 {
		return nil, false, errors.New("sqlite: insights tree size out of range")
	}
	if len(filter.RootPrefix) == 0 {
		return nil, false, errors.New("sqlite: insights tree needs a root prefix")
	}
	filter.FromNS, filter.ToNS = 0, 0
	filter.SessionIDs, filter.RootFPRs = nil, nil
	where, arguments, err := filter.where()
	if err != nil {
		return nil, false, err
	}
	arguments = append(arguments, maxNodes+1)
	last := func(column string) string { return "MAX(CASE WHEN rn = 1 THEN " + column + " END)" }
	cursor, err := store.readerDB.QueryContext(ctx, `
WITH s AS (
  SELECT x.agent_node_fpr AS node, x.agent_parent_fpr AS parent, x.started_at_ns AS ts,
         COALESCE(x.agent_role, 'main') AS role,
         CASE WHEN x.agent_role IN `+insightsAuxRoles+` THEN 1 ELSE 0 END AS aux,
         COALESCE(x.agent_client, 'unknown') AS client, COALESCE(x.model, '') AS model,
         COALESCE(x.analysis_session_id, '') AS sid, COALESCE(x.agent_link_source, '') AS link,
         COALESCE(x.agent_link_confidence, 0) AS confidence,
         CASE WHEN `+insightsHasUsage+` THEN `+insightsPromptSQL+` END AS prompt,
         x.est_system AS e1, x.est_tools AS e2, x.est_user AS e3, x.est_injected AS e4,
         x.est_assistant AS e5, x.est_reasoning AS e6, x.est_tool_result AS e7, x.est_media AS e8,
         ROW_NUMBER() OVER (PARTITION BY x.agent_node_fpr ORDER BY
           CASE WHEN x.agent_role IN `+insightsAuxRoles+` THEN 1 ELSE 0 END, x.started_at_ns DESC, x.audit_id DESC) AS rn`+
		insightsFrom+where+`
    AND x.agent_node_fpr IS NOT NULL
), g AS (
  SELECT node, MAX(parent) AS parent, MIN(ts) AS first_ns, MAX(ts) AS last_ns,
         SUM(1 - aux) AS steps, SUM(aux) AS aux_requests,
         `+last("role")+` AS role, `+last("client")+` AS client, `+last("model")+` AS model,
         `+last("sid")+` AS sid, `+last("link")+` AS link, `+last("confidence")+` AS confidence,
         `+last("prompt")+` AS last_prompt,
         `+last("e1")+` AS e1, `+last("e2")+` AS e2, `+last("e3")+` AS e3, `+last("e4")+` AS e4,
         `+last("e5")+` AS e5, `+last("e6")+` AS e6, `+last("e7")+` AS e7, `+last("e8")+` AS e8
  FROM s GROUP BY node
)
SELECT node, parent, first_ns, last_ns, steps, aux_requests, role, client, model, sid, link, confidence, last_prompt,
       e1, e2, e3, e4, e5, e6, e7, e8
FROM g
ORDER BY first_ns, node
LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, fmt.Errorf("sqlite: insights tree: %w", err)
	}
	defer cursor.Close()
	for cursor.Next() {
		var row InsightsTreeNodeRow
		var prompt sql.NullInt64
		if err := cursor.Scan(&row.NodeFPR, &row.ParentFPR, &row.FirstNS, &row.LastNS, &row.Steps, &row.AuxRequests,
			&row.Role, &row.Client, &row.Model, &row.SessionID, &row.LinkSource, &row.LinkConfidence, &prompt,
			&row.Estimate.System, &row.Estimate.Tools, &row.Estimate.User, &row.Estimate.Injected,
			&row.Estimate.Assistant, &row.Estimate.Reasoning, &row.Estimate.ToolResult, &row.Estimate.Media); err != nil {
			return nil, false, fmt.Errorf("sqlite: scan insights tree: %w", err)
		}
		row.NodeFPR, row.ParentFPR = cloneBytes(row.NodeFPR), cloneBytes(row.ParentFPR)
		row.LastPrompt = nullInt64Pointer(prompt)
		if len(rows) == maxNodes {
			truncated = true
			break
		}
		rows = append(rows, row)
	}
	if err := cursor.Err(); err != nil {
		return nil, false, fmt.Errorf("sqlite: iterate insights tree: %w", err)
	}
	return rows, truncated, nil
}
