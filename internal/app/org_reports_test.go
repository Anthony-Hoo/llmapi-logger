package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrgReportsAreUnassembledWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	application, err := newSQLiteTest(insightsTestConfig(t, upstream.URL, true, ""), logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	if application.orgReports != nil {
		t.Fatal("disabled org_reports assembled a service")
	}
	if application.parserWorker.HasIdleTasks() {
		t.Fatal("disabled org_reports registered parser idle work")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/org/settings", nil)
	request.Header.Set("Authorization", "Bearer app-test-admin-token")
	response := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled org route status = %d, want 404", response.Code)
	}
}

func TestEnabledOrgReportsRefuseAStoreWithoutOrgSupport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	configuration := insightsTestConfig(t, upstream.URL, true, "")
	configuration.NewAPI.AccessToken = "placeholder-token"
	configuration.NewAPI.UserID = 1
	configuration.OrgReports.Enabled = true
	application, err := newSQLiteTest(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if application != nil {
		_ = application.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "org reports") {
		t.Fatalf("New with the legacy test store = %v, want an org reports error", err)
	}
}
