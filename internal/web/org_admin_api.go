package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"llmapi-logger/internal/orgreport"
)

// maxOrgBodyBytes bounds one administrator request body (a project carries
// at most 32 rules of 512 bytes).
const maxOrgBodyBytes = 64 << 10

// serveOrgAdmin serves the administrator-only org routes; requireAdmin has
// already run.
func (handler *managementHandler) serveOrgAdmin(writer http.ResponseWriter, request *http.Request, parts []string) {
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	switch {
	case len(parts) == 1 && parts[0] == "catalog":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, handler.org.Catalog())
	case len(parts) == 1 && parts[0] == "groups":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		var input orgreport.GroupInput
		if !decodeOrgBody(writer, request, &input) {
			return
		}
		group, err := handler.org.CreateGroup(ctx, input)
		handler.writeOrgResult(writer, http.StatusCreated, group, err)
	case len(parts) == 2 && parts[0] == "groups":
		id, ok := orgID(writer, request, parts[1])
		if !ok {
			return
		}
		switch request.Method {
		case http.MethodPut:
			var input orgreport.GroupInput
			if !decodeOrgBody(writer, request, &input) {
				return
			}
			group, err := handler.org.UpdateGroup(ctx, id, input)
			handler.writeOrgResult(writer, http.StatusOK, group, err)
		case http.MethodDelete:
			handler.writeOrgResult(writer, http.StatusNoContent, nil, handler.org.DeleteGroup(ctx, id))
		default:
			methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
		}
	case len(parts) == 1 && parts[0] == "projects":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		var input orgreport.ProjectInput
		if !decodeOrgBody(writer, request, &input) {
			return
		}
		project, err := handler.org.CreateProject(ctx, input)
		handler.writeOrgResult(writer, http.StatusCreated, project, err)
	case len(parts) == 2 && parts[0] == "projects" && parts[1] == "preview":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		var input orgreport.PreviewInput
		if !decodeOrgBody(writer, request, &input) {
			return
		}
		result, err := handler.org.Preview(ctx, input)
		handler.writeOrgResult(writer, http.StatusOK, result, err)
	case len(parts) == 2 && parts[0] == "projects":
		id, ok := orgID(writer, request, parts[1])
		if !ok {
			return
		}
		switch request.Method {
		case http.MethodPut:
			var input orgreport.ProjectInput
			if !decodeOrgBody(writer, request, &input) {
				return
			}
			project, err := handler.org.UpdateProject(ctx, id, input)
			handler.writeOrgResult(writer, http.StatusOK, project, err)
		case http.MethodDelete:
			handler.writeOrgResult(writer, http.StatusNoContent, nil, handler.org.DeleteProject(ctx, id))
		default:
			methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
		}
	case len(parts) == 2 && parts[0] == "members":
		userID, ok := orgID(writer, request, parts[1])
		if !ok {
			return
		}
		switch request.Method {
		case http.MethodPut:
			var input struct {
				GroupID int64 `json:"group_id"`
			}
			if !decodeOrgBody(writer, request, &input) {
				return
			}
			member, err := handler.org.SetMember(ctx, userID, input.GroupID)
			handler.writeOrgResult(writer, http.StatusOK, member, err)
		case http.MethodDelete:
			handler.writeOrgResult(writer, http.StatusNoContent, nil, handler.org.DeleteMember(ctx, userID))
		default:
			methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
		}
	case len(parts) == 3 && parts[0] == "principals" && (parts[1] == orgreport.PrincipalUser || parts[1] == orgreport.PrincipalToken):
		id, ok := orgID(writer, request, parts[2])
		if !ok {
			return
		}
		switch request.Method {
		case http.MethodPut:
			var input struct {
				Class string `json:"class"`
			}
			if !decodeOrgBody(writer, request, &input) {
				return
			}
			principal, err := handler.org.SetPrincipal(ctx, parts[1], id, input.Class)
			handler.writeOrgResult(writer, http.StatusOK, principal, err)
		case http.MethodDelete:
			handler.writeOrgResult(writer, http.StatusNoContent, nil, handler.org.DeletePrincipal(ctx, parts[1], id))
		default:
			methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
		}
	case len(parts) == 1 && parts[0] == "unattributed":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		values := request.URL.Query()
		if err := parseInsightsValues(values, "week", "limit"); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_query", "invalid org query")
			return
		}
		limit := 20
		if values.Has("limit") {
			parsed, err := parseInt(values.Get("limit"))
			if err != nil {
				writeError(writer, http.StatusBadRequest, "invalid_query", "invalid org query")
				return
			}
			limit = parsed
		}
		entries, err := handler.org.Unattributed(ctx, values.Get("week"), limit)
		handler.writeOrgResult(writer, http.StatusOK, map[string]any{"items": entries}, err)
	default:
		handler.serveOrgReport(writer, request, parts)
	}
}

func orgID(writer http.ResponseWriter, request *http.Request, text string) (int64, bool) {
	id, err := strconv.ParseInt(text, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(writer, request)
		return 0, false
	}
	return id, true
}

// decodeOrgBody accepts exactly one JSON object with known fields.
func decodeOrgBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxOrgBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_input", "invalid organisation report input")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_input", "invalid organisation report input")
		return false
	}
	return true
}

// writeOrgResult maps domain errors to stable codes; it never echoes input.
func (handler *managementHandler) writeOrgResult(writer http.ResponseWriter, status int, value any, err error) {
	switch {
	case err == nil:
		if status == http.StatusNoContent {
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(writer, status, value)
	case errors.Is(err, orgreport.ErrInvalid):
		writeError(writer, http.StatusBadRequest, "invalid_input", "invalid organisation report input")
	case errors.Is(err, orgreport.ErrConflict):
		writeError(writer, http.StatusConflict, "conflict", "the change conflicts with existing groups, projects or members")
	case errors.Is(err, orgreport.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "organisation report entry not found")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusServiceUnavailable, "org_timeout", "organisation report request timed out")
	case errors.Is(err, context.Canceled):
		return
	default:
		handler.logger.Warn("org report request failed", "error_code", "org_unavailable")
		writeError(writer, http.StatusServiceUnavailable, "org_unavailable", "organisation reports are unavailable")
	}
}

// serveOrgReport serves the administrator report routes.
func (handler *managementHandler) serveOrgReport(writer http.ResponseWriter, request *http.Request, parts []string) {
	values := request.URL.Query()
	invalid := func() {
		writeError(writer, http.StatusBadRequest, "invalid_query", "invalid org query")
	}
	groupID, err := optionalInt64(values, "group_id")
	if err != nil || (groupID != nil && *groupID < 0) {
		invalid()
		return
	}
	switch {
	case len(parts) == 1 && parts[0] == "weekly":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		if parseInsightsValues(values, "week", "group_id", "metric") != nil {
			invalid()
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
		defer cancel()
		report, err := handler.org.Weekly(ctx, orgreport.WeeklyQuery{Week: values.Get("week"), GroupID: groupID, Metric: values.Get("metric")})
		handler.writeOrgResult(writer, http.StatusOK, report, err)
	case len(parts) == 2 && parts[0] == "weekly" && parts[1] == "trend":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		if parseInsightsValues(values, "weeks", "group_id") != nil {
			invalid()
			return
		}
		weeks := 8
		if values.Has("weeks") {
			parsed, err := parseInt(values.Get("weeks"))
			if err != nil {
				invalid()
				return
			}
			weeks = parsed
		}
		ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
		defer cancel()
		report, err := handler.org.Trend(ctx, weeks, groupID)
		handler.writeOrgResult(writer, http.StatusOK, report, err)
	case len(parts) == 2 && parts[0] == "weekly" && parts[1] == "regenerate":
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, http.MethodPost)
			return
		}
		if parseInsightsValues(values, "week") != nil || values.Get("week") == "" {
			invalid()
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), orgRegenerateTimeout)
		defer cancel()
		handler.writeOrgResult(writer, http.StatusNoContent, nil, handler.org.Regenerate(ctx, values.Get("week")))
	case len(parts) == 3 && parts[0] == "projects" && parts[2] == "weekly":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		if parseInsightsValues(values, "week") != nil {
			invalid()
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), orgReportTimeout)
		defer cancel()
		report, err := handler.org.ProjectWeekly(ctx, id, values.Get("week"))
		handler.writeOrgResult(writer, http.StatusOK, report, err)
	default:
		http.NotFound(writer, request)
	}
}

// A report week loads every analysed request of the week plus margins; it
// gets more time than an ordinary query. Regeneration also writes.
const (
	orgReportTimeout     = 30 * time.Second
	orgRegenerateTimeout = 2 * time.Minute
)
