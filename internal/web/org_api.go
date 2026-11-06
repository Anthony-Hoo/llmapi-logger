package web

import (
	"net/http"
	"strings"

	"llmapi-logger/internal/orgreport"
)

// OrgReports is the optional organisation report surface
// (doc/features/23-org-project-reports.md). A nil OrgReports
// (org_reports.enabled: false) makes every /api/v1/org route 404 for every
// caller, so a personal deployment exposes nothing new.
type OrgReports interface {
	Settings() orgreport.PublicSettings
}

const (
	orgPath       = "/api/v1/org"
	orgPathPrefix = "/api/v1/org/"
	// orgSelfPath is the only org route a developer session may read: the
	// caller's own row for the current week.
	orgSelfPath = "/api/v1/org/me/weekly"
)

func isOrgPath(path string) bool {
	return path == orgPath || strings.HasPrefix(path, orgPathPrefix)
}

// serveOrg dispatches before requireAdmin so that the disabled feature answers
// 404 to everyone and a developer gets 403 rather than 404 for routes that do
// exist.
func (handler *managementHandler) serveOrg(writer http.ResponseWriter, request *http.Request) {
	if handler.org == nil {
		writeError(writer, http.StatusNotFound, "not_found", "organisation reports are not enabled")
		return
	}
	if request.URL.Path == orgSelfPath {
		handler.serveOrgSelf(writer, request)
		return
	}
	if !handler.requireAdmin(writer, request) {
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(request.URL.Path, orgPath), "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "settings":
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, handler.org.Settings())
	default:
		handler.serveOrgAdmin(writer, request, parts)
	}
}

// serveOrgSelf answers the caller's own weekly row.
func (handler *managementHandler) serveOrgSelf(writer http.ResponseWriter, request *http.Request) {
	http.NotFound(writer, request)
}

// serveOrgAdmin serves the administrator-only org routes.
func (handler *managementHandler) serveOrgAdmin(writer http.ResponseWriter, request *http.Request, _ []string) {
	http.NotFound(writer, request)
}
