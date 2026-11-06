package sessionanalysis

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// JSON contract of the session analysis management API. The web frontend
// mirrors these shapes in src/types.ts. Responses never carry who a session
// belongs to: an administrator sees anonymous rows, a developer only their own.

// SignalTotals summarizes the sessions of one period.
type SignalTotals struct {
	Sessions        int64    `json:"sessions"`
	AgentSessions   int64    `json:"agent_sessions"`
	ChatSessions    int64    `json:"chat_sessions"`
	Eligible        int64    `json:"eligible"`
	CostUSD         *float64 `json:"cost_usd"`
	LoopSessions    int64    `json:"loop_sessions"`
	LoopCostUSD     *float64 `json:"loop_cost_usd"`
	ThrashSessions  int64    `json:"thrash_sessions"`
	Unverified      int64    `json:"unverified_sessions"`
	WithWrites      int64    `json:"sessions_with_writes"`
	FailureSessions int64    `json:"failure_sessions"`
	Corrections     int64    `json:"corrections"`
	CorrectionSess  int64    `json:"correction_sessions"`
	ErrorPasteSess  int64    `json:"error_paste_sessions"`
	InterruptSess   int64    `json:"interrupt_sessions"`
	HeavyModelSess  int64    `json:"heavy_model_sessions"`
	DangerSessions  int64    `json:"danger_sessions"`
	SecretSessions  int64    `json:"secret_sessions"`
	CompactionSess  int64    `json:"compaction_sessions"`
	CacheHitRate    *float64 `json:"cache_hit_rate"`
}

// RunSummary is the latest batch run.
type RunSummary struct {
	StartedNS   int64            `json:"started_ns,string"`
	FinishedNS  int64            `json:"finished_ns,string"`
	Trigger     string           `json:"trigger"`
	Candidates  int64            `json:"candidates"`
	Analyzed    int64            `json:"analyzed"`
	Skipped     int64            `json:"skipped"`
	SkipReasons map[string]int64 `json:"skip_reasons"`
	Error       string           `json:"error,omitempty"`
}

// OverviewResponse is GET /api/v1/session-analysis/overview.
type OverviewResponse struct {
	FromNS   int64        `json:"from_ns,string"`
	ToNS     int64        `json:"to_ns,string"`
	Current  SignalTotals `json:"current"`
	Previous SignalTotals `json:"previous"`
	LastRun  *RunSummary  `json:"last_run,omitempty"`
	Running  bool         `json:"running"`
	// LLMEnabled reports whether facets are produced (S2); packs and signals
	// work without it.
	LLMEnabled bool `json:"llm_enabled"`
}

// SessionItem is one row of GET /api/v1/session-analysis/sessions.
type SessionItem struct {
	SessionID        string           `json:"session_id"`
	TreeID           string           `json:"tree_id,omitempty"`
	TrendSessionID   string           `json:"trend_session_id,omitempty"`
	Kind             string           `json:"kind"`
	Client           string           `json:"client"`
	Model            string           `json:"model"`
	FirstNS          int64            `json:"first_ns,string"`
	LastNS           int64            `json:"last_ns,string"`
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
}

// SessionsResponse is one keyset page.
type SessionsResponse struct {
	Items      []SessionItem `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// SessionsQuery selects one page.
type SessionsQuery struct {
	FromNS int64
	ToNS   int64
	Kind   string
	Flags  []string
	Cursor string
	Limit  int
	Scope  *query.Scope
}

// QueryStore is the read surface of the management API.
type QueryStore interface {
	ListSessionSignals(ctx context.Context, filter storage.SessionSignalFilter, cursor storage.SessionSignalCursor, limit int) (storage.SessionSignalPage, error)
	SessionSignalTotals(ctx context.Context, filter storage.SessionSignalFilter) (storage.SessionSignalTotals, error)
	LatestSessionAnalysisRun(ctx context.Context) (storage.SessionAnalysisRun, error)
}

// Trigger starts a manual batch run.
type Trigger interface {
	TriggerNow() error
	Running() bool
}

// QueryService serves the management API.
type QueryService struct {
	store      QueryStore
	trigger    Trigger
	llmEnabled bool
}

// Default and maximum page sizes and range of the management API.
const (
	defaultPageSize = 50
	maxPageSize     = 200
	maxRange        = 400 * 24 * time.Hour
)

var validFlags = map[string]bool{
	"loop": true, "thrash": true, "unverified": true, "failures": true, "corrections": true,
	"error_paste": true, "interrupt": true, "heavy_model": true, "danger": true, "secret": true, "compaction": true,
}

// NewQueryService assembles the management read service. trigger may be nil.
func NewQueryService(store QueryStore, trigger Trigger, llmEnabled bool) (*QueryService, error) {
	if store == nil {
		return nil, errors.New("sessionanalysis: nil query store")
	}
	return &QueryService{store: store, trigger: trigger, llmEnabled: llmEnabled}, nil
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", query.ErrInvalidQuery, message)
}

func storageScope(scope *query.Scope) *storage.AuditScope {
	if scope == nil {
		return nil
	}
	return &storage.AuditScope{Fingerprint: scope.Fingerprint, TokenID: scope.TokenID}
}

func validRange(fromNS, toNS int64) error {
	if fromNS <= 0 || toNS <= fromNS || time.Duration(toNS-fromNS) > maxRange {
		return invalid("invalid time range")
	}
	return nil
}

// Overview returns the totals of [fromNS, toNS) and of the equally long period
// before it.
func (service *QueryService) Overview(ctx context.Context, fromNS, toNS int64, scope *query.Scope) (OverviewResponse, error) {
	if err := validRange(fromNS, toNS); err != nil {
		return OverviewResponse{}, err
	}
	filter := storage.SessionSignalFilter{FromNS: fromNS, ToNS: toNS, Scope: storageScope(scope)}
	current, err := service.store.SessionSignalTotals(ctx, filter)
	if err != nil {
		return OverviewResponse{}, err
	}
	filter.FromNS, filter.ToNS = fromNS-(toNS-fromNS), fromNS
	previous, err := service.store.SessionSignalTotals(ctx, filter)
	if err != nil {
		return OverviewResponse{}, err
	}
	response := OverviewResponse{
		FromNS: fromNS, ToNS: toNS,
		Current: mapTotals(current), Previous: mapTotals(previous),
		LLMEnabled: service.llmEnabled,
	}
	if service.trigger != nil {
		response.Running = service.trigger.Running()
	}
	run, err := service.store.LatestSessionAnalysisRun(ctx)
	if err == nil {
		summary := RunSummary{
			StartedNS: run.StartedAtNS, FinishedNS: run.FinishedAtNS, Trigger: run.Trigger,
			Candidates: run.Candidates, Analyzed: run.Analyzed, Skipped: run.Skipped, Error: run.ErrorCategory,
			SkipReasons: map[string]int64{},
		}
		_ = json.Unmarshal([]byte(run.SkipReasons), &summary.SkipReasons)
		response.LastRun = &summary
	} else if !errors.Is(err, sql.ErrNoRows) {
		return OverviewResponse{}, err
	}
	return response, nil
}

func mapTotals(totals storage.SessionSignalTotals) SignalTotals {
	out := SignalTotals{
		Sessions: totals.Sessions, AgentSessions: totals.AgentSessions, ChatSessions: totals.ChatSessions,
		Eligible: totals.Eligible, LoopSessions: totals.LoopSessions, ThrashSessions: totals.ThrashSessions,
		Unverified: totals.Unverified, WithWrites: totals.WithWrites, FailureSessions: totals.FailureSessions,
		Corrections: totals.Corrections, CorrectionSess: totals.CorrectionSess, ErrorPasteSess: totals.ErrorPasteSess,
		InterruptSess: totals.InterruptSess, HeavyModelSess: totals.HeavyModelSess, DangerSessions: totals.DangerSessions,
		SecretSessions: totals.SecretSessions, CompactionSess: totals.CompactionSess,
	}
	if totals.BilledSessions > 0 {
		cost, loopCost := totals.CostUSD, totals.LoopCostUSD
		out.CostUSD, out.LoopCostUSD = &cost, &loopCost
	}
	if totals.InputTokens > 0 {
		rate := float64(totals.CacheReadTokens) / float64(totals.InputTokens)
		out.CacheHitRate = &rate
	}
	return out
}

// Sessions returns one page of session signal rows.
func (service *QueryService) Sessions(ctx context.Context, request SessionsQuery) (SessionsResponse, error) {
	if err := validRange(request.FromNS, request.ToNS); err != nil {
		return SessionsResponse{}, err
	}
	if request.Limit == 0 {
		request.Limit = defaultPageSize
	}
	if request.Limit < 1 || request.Limit > maxPageSize {
		return SessionsResponse{}, invalid("invalid limit")
	}
	if request.Kind != "" && request.Kind != KindAgent && request.Kind != KindChat {
		return SessionsResponse{}, invalid("invalid kind")
	}
	for _, flag := range request.Flags {
		if !validFlags[flag] {
			return SessionsResponse{}, invalid("invalid flag")
		}
	}
	cursor, err := decodeCursor(request.Cursor)
	if err != nil {
		return SessionsResponse{}, err
	}
	page, err := service.store.ListSessionSignals(ctx, storage.SessionSignalFilter{
		FromNS: request.FromNS, ToNS: request.ToNS, Kind: request.Kind, Flags: request.Flags, Scope: storageScope(request.Scope),
	}, cursor, request.Limit)
	if err != nil {
		return SessionsResponse{}, err
	}
	response := SessionsResponse{Items: make([]SessionItem, 0, len(page.Rows))}
	for _, row := range page.Rows {
		response.Items = append(response.Items, mapSession(row))
	}
	if page.HasMore && len(page.Rows) != 0 {
		last := page.Rows[len(page.Rows)-1]
		response.NextCursor = encodeCursor(last.LastNS, last.SessionKey)
	}
	return response, nil
}

// TriggerRun starts a manual batch run (administrators only; the web layer
// enforces the role).
func (service *QueryService) TriggerRun() error {
	if service.trigger == nil {
		return errors.New("sessionanalysis: runner unavailable")
	}
	return service.trigger.TriggerNow()
}

func mapSession(row storage.SessionSignals) SessionItem {
	item := SessionItem{
		SessionID: hex.EncodeToString(row.SessionKey), TrendSessionID: row.MainSessionID,
		Kind: row.Kind, Client: row.Client, Model: row.MainModel,
		FirstNS: row.FirstNS, LastNS: row.LastNS, LastAuditID: row.LastAuditID,
		Requests: row.Requests, Subagents: row.Subagents, UserTurns: row.UserTurns,
		ActiveSeconds: row.ActiveNS / int64(time.Second), InputTokens: row.InputTokens, OutputTokens: row.OutputTokens,
		CostUSD: row.CostUSD, ToolCalls: row.ToolCalls, ToolFailures: row.ToolFailures, MaxFailureStreak: row.MaxFailureStreak,
		Loops: row.Loops, MaxLoopLength: row.MaxLoopLength, ThrashFiles: row.ThrashFiles, MaxFileWrites: row.MaxFileWrites,
		Verified: row.Verified, ErrorPastes: row.ErrorPastes, Interrupts: row.Interrupts, Corrections: row.Corrections,
		Compactions: row.Compactions, ModelSwitches: row.ModelSwitches, LengthStops: row.LengthStops,
		UpstreamErrors: row.UpstreamErrors, HeavyModel: row.HeavyModel,
		Danger: decodeCounts(row.DangerCounts), Secrets: decodeCounts(row.SecretCounts),
		Eligible: row.Eligible, SkipReason: row.SkipReason,
	}
	if row.Kind == KindAgent && len(row.SessionKey) >= 12 {
		item.TreeID = hex.EncodeToString(row.SessionKey[:12])
	}
	return item
}

func decodeCounts(encoded string) map[string]int64 {
	counts := map[string]int64{}
	_ = json.Unmarshal([]byte(encoded), &counts)
	return counts
}

func encodeCursor(lastNS int64, key []byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(lastNS, 10) + ":" + hex.EncodeToString(key)))
}

func decodeCursor(cursor string) (storage.SessionSignalCursor, error) {
	if cursor == "" {
		return storage.SessionSignalCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return storage.SessionSignalCursor{}, invalid("invalid cursor")
	}
	lastText, keyText, ok := strings.Cut(string(decoded), ":")
	lastNS, parseErr := strconv.ParseInt(lastText, 10, 64)
	key, keyErr := hex.DecodeString(keyText)
	if !ok || parseErr != nil || keyErr != nil || len(key) != 32 || lastNS <= 0 {
		return storage.SessionSignalCursor{}, invalid("invalid cursor")
	}
	return storage.SessionSignalCursor{BeforeLastNS: lastNS, BeforeKey: key}, nil
}

// ParseSessionID decodes the 64-hex session id of the API.
func ParseSessionID(id string) ([]byte, error) {
	if len(id) != 64 {
		return nil, invalid("invalid session id")
	}
	key, err := hex.DecodeString(id)
	if err != nil {
		return nil, invalid("invalid session id")
	}
	return key, nil
}
