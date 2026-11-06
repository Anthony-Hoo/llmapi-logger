package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

// SessionAnalysisQuery is the session analysis surface
// (doc/features/24-session-analysis.md). Nil makes every route 404.
type SessionAnalysisQuery interface {
	Overview(context.Context, int64, int64, *query.Scope) (sessionanalysis.OverviewResponse, error)
	Sessions(context.Context, sessionanalysis.SessionsQuery) (sessionanalysis.SessionsResponse, error)
	TriggerRun() error
	Pack(context.Context, string, *query.Scope, sessionanalysis.Viewer) (sessionanalysis.PackResponse, error)
	Facet(context.Context, string, *query.Scope, sessionanalysis.Viewer) (sessionanalysis.FacetResponse, error)
	Calibrate(context.Context, []sessionanalysis.CalibrationLabel) (sessionanalysis.CalibrationResult, error)
	Report(context.Context, string, *query.Scope) (sessionanalysis.ReportResponse, error)
	DismissSuggestion(context.Context, int64) error
}

const sessionAnalysisPathPrefix = "/api/v1/session-analysis/"

// serveSessionAnalysis is reachable by administrators and developers; reads
// are built from the caller's scope, and only the run trigger is
// administrator-only.
func (handler *managementHandler) serveSessionAnalysis(writer http.ResponseWriter, request *http.Request) {
	if handler.sessionAnalysis == nil {
		writeError(writer, http.StatusNotFound, "not_found", "session analysis is not enabled")
		return
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, sessionAnalysisPathPrefix), "/")
	switch {
	case len(parts) == 1 && parts[0] == "overview":
		handler.serveSessionAnalysisOverview(writer, request)
	case len(parts) == 1 && parts[0] == "sessions":
		handler.serveSessionAnalysisSessions(writer, request)
	case len(parts) == 1 && parts[0] == "run":
		handler.serveSessionAnalysisRun(writer, request)
	case len(parts) == 3 && parts[0] == "sessions" && parts[2] == "pack":
		handler.serveSessionAnalysisPack(writer, request, parts[1])
	case len(parts) == 3 && parts[0] == "sessions" && parts[2] == "facet":
		handler.serveSessionAnalysisFacet(writer, request, parts[1])
	case len(parts) == 1 && parts[0] == "calibration":
		handler.serveSessionAnalysisCalibration(writer, request)
	case len(parts) == 1 && parts[0] == "report":
		handler.serveSessionAnalysisReport(writer, request)
	case len(parts) == 3 && parts[0] == "suggestions" && parts[2] == "dismiss":
		handler.serveSessionAnalysisDismiss(writer, request, parts[1])
	default:
		http.NotFound(writer, request)
	}
}

func (handler *managementHandler) serveSessionAnalysisOverview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	values := request.URL.Query()
	if err := parseInsightsValues(values, "from_ns", "to_ns"); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	fromNS, fromErr := optionalInt64(values, "from_ns")
	toNS, toErr := optionalInt64(values, "to_ns")
	if fromErr != nil || toErr != nil || fromNS == nil || toNS == nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.sessionAnalysis.Overview(ctx, *fromNS, *toNS, handler.sessionScope(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveSessionAnalysisSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	values := request.URL.Query()
	if err := parseInsightsValues(values, "from_ns", "to_ns", "kind", "flags", "cursor", "limit"); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	fromNS, fromErr := optionalInt64(values, "from_ns")
	toNS, toErr := optionalInt64(values, "to_ns")
	limit, limitErr := optionalInt(values, "limit")
	if fromErr != nil || toErr != nil || limitErr != nil || fromNS == nil || toNS == nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	sessionsQuery := sessionanalysis.SessionsQuery{
		FromNS: *fromNS, ToNS: *toNS, Kind: values.Get("kind"), Cursor: values.Get("cursor"),
		Scope: handler.sessionScope(request),
	}
	if flags := values.Get("flags"); flags != "" {
		sessionsQuery.Flags = strings.Split(flags, ",")
	}
	if limit != nil {
		if *limit == 0 {
			writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
			return
		}
		sessionsQuery.Limit = *limit
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.sessionAnalysis.Sessions(ctx, sessionsQuery)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveSessionAnalysisRun(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !handler.requireAdmin(writer, request) {
		return
	}
	if err := handler.sessionAnalysis.TriggerRun(); err != nil {
		if errors.Is(err, sessionanalysis.ErrRunInProgress) {
			writeError(writer, http.StatusConflict, "run_in_progress", "a session analysis run is already in progress")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "session_analysis_unavailable", "session analysis runner is unavailable")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{"status": "started"})
}

// sessionViewer describes the caller for the analysis view log.
func (handler *managementHandler) sessionViewer(request *http.Request) sessionanalysis.Viewer {
	caller, ok := principalFrom(request.Context())
	if !ok || caller.Role != roleDeveloper {
		return sessionanalysis.Viewer{Role: "admin"}
	}
	viewer := sessionanalysis.Viewer{Role: "developer", TokenID: caller.Identity.TokenID}
	if caller.Identity.UserID != 0 {
		userID := caller.Identity.UserID
		viewer.UserID = &userID
	}
	return viewer
}

// serveSessionAnalysisPack returns the decrypted input pack of one session;
// every successful read is written to the analysis view log first.
func (handler *managementHandler) serveSessionAnalysisPack(writer http.ResponseWriter, request *http.Request, sessionID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if err := parseInsightsValues(request.URL.Query()); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.sessionAnalysis.Pack(ctx, sessionID, handler.sessionScope(request), handler.sessionViewer(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *managementHandler) serveSessionAnalysisFacet(writer http.ResponseWriter, request *http.Request, sessionID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if err := parseInsightsValues(request.URL.Query()); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.sessionAnalysis.Facet(ctx, sessionID, handler.sessionScope(request), handler.sessionViewer(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

// maxCalibrationBodyBytes bounds one calibration upload (1000 labels).
const maxCalibrationBodyBytes = 512 << 10

// serveSessionAnalysisCalibration compares administrator-supplied labels with
// the stored facets (doc 24 section 7.3) and records the agreement.
func (handler *managementHandler) serveSessionAnalysisCalibration(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !handler.requireAdmin(writer, request) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxCalibrationBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		Labels []sessionanalysis.CalibrationLabel `json:"labels"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_calibration", "invalid calibration labels")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	result, err := handler.sessionAnalysis.Calibrate(ctx, body.Labels)
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// serveSessionAnalysisReport returns the weekly review of the caller's own
// scope: a developer's key, or all keys for an administrator.
func (handler *managementHandler) serveSessionAnalysisReport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	values := request.URL.Query()
	if err := parseInsightsValues(values, "week"); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid session analysis query")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	response, err := handler.sessionAnalysis.Report(ctx, values.Get("week"), handler.sessionScope(request))
	if err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

// serveSessionAnalysisDismiss dismisses one all-keys suggestion.
func (handler *managementHandler) serveSessionAnalysisDismiss(writer http.ResponseWriter, request *http.Request, idText string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !handler.requireAdmin(writer, request) {
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid suggestion id")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	if err := handler.sessionAnalysis.DismissSuggestion(ctx, id); err != nil {
		handler.writeQueryError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "dismissed"})
}
