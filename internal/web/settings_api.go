package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
)

// SessionAnalysisSettings is the settings an administrator saves from the
// management UI for session analysis (doc 24 section 4). Nil makes the routes
// 404.
type SessionAnalysisSettings interface {
	Get(context.Context) (sessionanalysis.SettingsView, error)
	Update(context.Context, sessionanalysis.SettingsUpdate) (sessionanalysis.SettingsView, error)
	Reset(context.Context) (sessionanalysis.SettingsView, error)
	Test(context.Context, sessionanalysis.SettingsUpdate) (sessionanalysis.ProbeResult, error)
}

const (
	sessionAnalysisSettingsPath     = "/api/v1/settings/session-analysis"
	sessionAnalysisSettingsTestPath = sessionAnalysisSettingsPath + "/test"
	// maxSettingsBodyBytes bounds one settings body; the largest field is the
	// API key.
	maxSettingsBodyBytes = 16 << 10
)

// serveSessionAnalysisSettings reads, saves and resets the saved section. The
// caller is an administrator: serveProtected checks the role first.
func (handler *managementHandler) serveSessionAnalysisSettings(writer http.ResponseWriter, request *http.Request) {
	if handler.sessionAnalysisSettings == nil {
		writeError(writer, http.StatusNotFound, "not_found", "session analysis is not enabled")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	switch request.Method {
	case http.MethodGet:
		view, err := handler.sessionAnalysisSettings.Get(ctx)
		handler.writeSettingsResult(writer, view, err)
	case http.MethodPut:
		update, ok := decodeSettingsBody(writer, request)
		if !ok {
			return
		}
		view, err := handler.sessionAnalysisSettings.Update(ctx, update)
		handler.writeSettingsResult(writer, view, err)
	case http.MethodDelete:
		view, err := handler.sessionAnalysisSettings.Reset(ctx)
		handler.writeSettingsResult(writer, view, err)
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodPut, http.MethodDelete)
	}
}

// serveSessionAnalysisSettingsTest validates an unsaved change and sends one
// synthetic request to the model endpoint it names.
func (handler *managementHandler) serveSessionAnalysisSettingsTest(writer http.ResponseWriter, request *http.Request) {
	if handler.sessionAnalysisSettings == nil {
		writeError(writer, http.StatusNotFound, "not_found", "session analysis is not enabled")
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	update, ok := decodeSettingsBody(writer, request)
	if !ok {
		return
	}
	// The probe has its own timeout, longer than a query's.
	result, err := handler.sessionAnalysisSettings.Test(request.Context(), update)
	handler.writeSettingsResult(writer, result, err)
}

// orgReportsSettingsPath is the saved section of the weekly report.
const orgReportsSettingsPath = "/api/v1/settings/org-reports"

// serveOrgReportsSettings reads, saves and resets the weekly report settings
// an administrator can change (doc 23 section 3). serveProtected has checked
// the role.
func (handler *managementHandler) serveOrgReportsSettings(writer http.ResponseWriter, request *http.Request) {
	if handler.org == nil {
		writeError(writer, http.StatusNotFound, "not_found", "organisation reports are not enabled")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	var view orgreport.SettingsView
	var err error
	switch request.Method {
	case http.MethodGet:
		view, err = handler.org.EditableSettings(ctx)
	case http.MethodPut:
		var edited orgreport.EditableSettings
		if !decodeOrgBody(writer, request, &edited) {
			return
		}
		view, err = handler.org.UpdateSettings(ctx, edited)
	case http.MethodDelete:
		view, err = handler.org.ResetSettings(ctx)
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodPut, http.MethodDelete)
		return
	}
	switch {
	case err == nil:
		writeJSON(writer, http.StatusOK, view)
	case errors.Is(err, orgreport.ErrInvalidSettings):
		writeError(writer, http.StatusBadRequest, "invalid_settings", orgreport.SettingsMessage(err))
	default:
		handler.writeOrgResult(writer, http.StatusOK, nil, err)
	}
}

// CaptureSettings is the audit capture setting an administrator saves from
// the management UI: the retry count of the unified path's final commit
// (design H.3). Nil makes GET, PUT and DELETE answer 404.
type CaptureSettings interface {
	Get(context.Context) (audit.CaptureSettingsView, error)
	Update(context.Context, audit.CaptureEditableSettings) (audit.CaptureSettingsView, error)
	Reset(context.Context) (audit.CaptureSettingsView, error)
}

// captureSettingsPath is the saved section of the capture write path.
const captureSettingsPath = "/api/v1/settings/audit-capture"

// serveCaptureSettings reads, saves and resets the capture setting.
// serveProtected has checked the role. The method is checked first, so an
// unknown method answers 405 whether or not the service is assembled.
func (handler *managementHandler) serveCaptureSettings(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodPut, http.MethodDelete:
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodPut, http.MethodDelete)
		return
	}
	if handler.captureSettings == nil {
		writeError(writer, http.StatusNotFound, "not_found", "audit capture settings are not available")
		return
	}
	ctx, cancel := handler.insightsContext(request)
	defer cancel()
	var view audit.CaptureSettingsView
	var err error
	switch request.Method {
	case http.MethodGet:
		view, err = handler.captureSettings.Get(ctx)
	case http.MethodPut:
		edited, ok := decodeCaptureSettingsBody(writer, request)
		if !ok {
			return
		}
		view, err = handler.captureSettings.Update(ctx, edited)
	case http.MethodDelete:
		view, err = handler.captureSettings.Reset(ctx)
	}
	switch {
	case err == nil:
		writeJSON(writer, http.StatusOK, view)
	case errors.Is(err, audit.ErrInvalidSettings):
		writeError(writer, http.StatusBadRequest, "invalid_settings", audit.SettingsMessage(err))
	case errors.Is(err, audit.ErrSettingsUnavailable):
		// The saved section could not be read; nothing was written.
		writeError(writer, http.StatusServiceUnavailable, "settings_unavailable", "saved settings could not be read; nothing was saved")
	case errors.Is(err, context.Canceled):
		return
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusServiceUnavailable, "settings_timeout", "settings request timed out")
	default:
		handler.logger.Warn("audit capture settings request failed", "error_code", "settings_unavailable")
		writeError(writer, http.StatusServiceUnavailable, "settings_unavailable", "audit capture settings are unavailable")
	}
}

// decodeCaptureSettingsBody accepts exactly {"commit_retries": n} with n an
// integer. A missing or null field is refused: 0 is a valid value, so a
// default would silently switch the retries off.
func decodeCaptureSettingsBody(writer http.ResponseWriter, request *http.Request) (audit.CaptureEditableSettings, bool) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxSettingsBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		CommitRetries *int `json:"commit_retries"`
	}
	var trailing any
	if err := decoder.Decode(&body); err != nil || body.CommitRetries == nil || !errors.Is(decoder.Decode(&trailing), io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_settings", "invalid settings body: commit_retries must be an integer")
		return audit.CaptureEditableSettings{}, false
	}
	return audit.CaptureEditableSettings{CommitRetries: *body.CommitRetries}, true
}

func decodeSettingsBody(writer http.ResponseWriter, request *http.Request) (sessionanalysis.SettingsUpdate, bool) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxSettingsBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var update sessionanalysis.SettingsUpdate
	if err := decoder.Decode(&update); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_settings", "invalid settings body")
		return sessionanalysis.SettingsUpdate{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_settings", "invalid settings body")
		return sessionanalysis.SettingsUpdate{}, false
	}
	return update, true
}

// writeSettingsResult answers 400 with the validator's field message, which
// names a field and its limits and never a secret.
func (handler *managementHandler) writeSettingsResult(writer http.ResponseWriter, value any, err error) {
	switch {
	case err == nil:
		writeJSON(writer, http.StatusOK, value)
	case errors.Is(err, sessionanalysis.ErrInvalidSettings):
		writeError(writer, http.StatusBadRequest, "invalid_settings", sessionanalysis.SettingsMessage(err))
	default:
		handler.writeQueryError(writer, err)
	}
}
