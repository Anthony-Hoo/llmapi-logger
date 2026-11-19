package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentAccessIsUnassembledWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	application, err := newSQLiteTest(insightsTestConfig(t, upstream.URL, true, ""), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	for _, path := range []string{"/api/agent/v1/whoami", "/api/agent/v1/token"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer app-test-admin-token")
		response := httptest.NewRecorder()
		application.adminServer.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "FEATURE_DISABLED") {
			t.Fatalf("disabled %s = %d %s", path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-access/tokens", nil)
	request.Header.Set("Authorization", "Bearer app-test-admin-token")
	response := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled web-side route = %d", response.Code)
	}
}

func TestEnabledAgentAccessRefusesAStoreWithoutAgentSupport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	configuration := insightsTestConfig(t, upstream.URL, true, "")
	configuration.AgentAccess.Enabled = true
	application, err := newSQLiteTest(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if application != nil {
		_ = application.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "agent access") {
		t.Fatalf("New with the legacy test store = %v, want an agent access error", err)
	}
}
