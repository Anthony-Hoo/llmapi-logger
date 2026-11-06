package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
