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
}

const maxReportSuggestions = 30

// Report returns the weekly review of the caller's scope: a developer's own
// key, or all keys together for an administrator. week is "current" or
// "previous" (weeks start on Monday in the server's time zone).
func (service *QueryService) Report(ctx context.Context, week string, scope *query.Scope) (ReportResponse, error) {
	store, ok := service.store.(ReportStore)
	if !ok {
		return ReportResponse{}, query.ErrNotFound
	}
	start := WeekStart(service.now(), service.location)
	switch week {
	case "", "current":
	case "previous":
		start = start.AddDate(0, 0, -7)
	default:
		return ReportResponse{}, invalid("week must be current or previous")
	}
	scopeName, scopeKey := storage.ScopeAll, storage.AllScopeKey
	var tokenID *int64
	if scope != nil {
		scopeName, scopeKey, tokenID = storage.ScopePerson, scope.Fingerprint, scope.TokenID
	}
	response := ReportResponse{WeekStartNS: start.UnixNano(), Scope: scopeName, Suggestions: []SuggestionItem{}, Optimizations: []SessionItem{}}
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
	suggestions, err := store.ListSuggestions(ctx, scopeName, scopeKey, tokenID, maxReportSuggestions)
	if err != nil {
		return ReportResponse{}, err
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
	filter := storage.SessionSignalFilter{FromNS: start.UnixNano(), ToNS: start.AddDate(0, 0, 7).UnixNano(), Scope: storageScope(scope)}
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
				response.Optimizations = append(response.Optimizations, mapSession(row))
			}
		}
	}
	return response, nil
}

// SuggestionStore dismisses suggestions.
type SuggestionStore interface {
	DismissSuggestion(ctx context.Context, id int64, scope string, nowNS int64) error
}

// DismissSuggestion marks one all-keys suggestion dismissed (administrators
// only; doc 24 section 8.3). Personal suggestions are never dismissed here.
func (service *QueryService) DismissSuggestion(ctx context.Context, id int64) error {
	store, ok := service.store.(SuggestionStore)
	if !ok || id <= 0 {
		return query.ErrNotFound
	}
	err := store.DismissSuggestion(ctx, id, storage.ScopeAll, service.now().UnixNano())
	if isNoRows(err) {
		return query.ErrNotFound
	}
	return err
}
