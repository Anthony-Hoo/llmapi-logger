package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/query"
)

// InsightsQuery is the context-insights surface consumed by the HTTP handlers.
// A nil InsightsQuery (insights.enabled: false) makes every insights route 404.
type InsightsQuery interface {
	Overview(context.Context, query.OverviewQuery) (insights.OverviewResponse, error)
	Sessions(context.Context, query.SessionsQuery) (insights.SessionsResponse, error)
	Trend(context.Context, string, *query.Scope) (insights.TrendResponse, error)
	Tree(context.Context, string, *query.Scope) (insights.TreeResponse, error)
	Composition(context.Context, string, *query.Scope) (insights.CompositionResponse, error)
}

const insightsPathPrefix = "/api/v1/insights/"

func (handler *managementHandler) insightsDisabled(writer http.ResponseWriter) bool {
	if handler.insights == nil {
		writeError(writer, http.StatusNotFound, "not_found", "context insights are not enabled")
		return true
	}
	return false
}

// serveInsights is reachable by administrators and developers alike; every
// response is built from the caller's scope, never from query parameters.
func (handler *managementHandler) serveInsights(writer http.ResponseWriter, request *http.Request) {
	if handler.insightsDisabled(writer) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, insightsPathPrefix), "/")
	switch {
	case len(parts) == 1 && parts[0] == "overview":
		handler.serveInsightsOverview(writer, request)
	case len(parts) == 1 && parts[0] == "sessions":
		handler.serveInsightsSessions(writer, request)
	case len(parts) == 3 && parts[0] == "sessions" && parts[2] == "trend":
		handler.serveInsightsTrend(writer, request, parts[1])
	case len(parts) == 2 && parts[0] == "agent-trees":
		handler.serveInsightsTree(writer, request, parts[1])
	default:
		http.NotFound(writer, request)
	}
}

func (handler *managementHandler) insightsContext(request *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(request.Context(), queryTimeout)
}

// parseInsightsValues rejects unknown and repeated query keys.
func parseInsightsValues(values url.Values, allowed ...string) error {
	permitted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		permitted[key] = true
	}
	for key, entries := range values {
		if !permitted[key] || len(entries) != 1 {
			return fmt.Errorf("invalid query key %q", key)
		}
	}
	return nil
}

func (handler *managementHandler) serveInsightsOverview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	values := request.URL.Query()
	if err := parseInsightsValues(values, "from_ns", "to_ns", "group_by", "tz_offset_min"); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	fromNS, fromErr := optionalInt64(values, "from_ns")
	toNS, toErr := optionalInt64(values, "to_ns")
	offset, offsetErr := optionalInt(values, "tz_offset_min")
	if fromErr != nil || toErr != nil || offsetErr != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	insightsQuery := query.OverviewQuery{
		FromNS:  fromNS,
		ToNS:    toNS,
		GroupBy: values.Get("group_by"),
		Scope:   handler.sessionScope(request),
	}
	if offset != nil {
		insightsQuery.TZOffsetMin = *offset
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.insights.Overview(ctx, insightsQuery)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveInsightsSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	values := request.URL.Query()
	if err := parseInsightsValues(values, "from_ns", "to_ns", "sort", "cursor", "limit"); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	fromNS, fromErr := optionalInt64(values, "from_ns")
	toNS, toErr := optionalInt64(values, "to_ns")
	limit, limitErr := optionalInt(values, "limit")
	if fromErr != nil || toErr != nil || limitErr != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	insightsQuery := query.SessionsQuery{
		FromNS: fromNS,
		ToNS:   toNS,
		Sort:   values.Get("sort"),
		Cursor: values.Get("cursor"),
		Scope:  handler.sessionScope(request),
	}
	if limit != nil {
		insightsQuery.Limit = *limit
		if *limit == 0 {
			writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
			return
		}
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.insights.Sessions(ctx, insightsQuery)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveInsightsTrend(writer http.ResponseWriter, request *http.Request, sessionID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if err := parseInsightsValues(request.URL.Query()); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.insights.Trend(ctx, sessionID, handler.sessionScope(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveInsightsTree(writer http.ResponseWriter, request *http.Request, treeID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if err := parseInsightsValues(request.URL.Query()); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.insights.Tree(ctx, treeID, handler.sessionScope(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

// serveComposition runs behind authorizeAudit like the rest of the audit
// resource family.
func (handler *managementHandler) serveComposition(writer http.ResponseWriter, request *http.Request, auditID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if handler.insightsDisabled(writer) {
		return
	}
	if err := parseInsightsValues(request.URL.Query()); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid insights query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.insights.Composition(ctx, auditID, handler.sessionScope(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}
