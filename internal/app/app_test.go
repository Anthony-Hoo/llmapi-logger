package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"llmapi-logger/internal/config"
)

func TestNewAssemblesDataPlaneHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("created"))
	}))
	defer upstream.Close()

	configuration := config.Default()
	configuration.NewAPIURL = upstream.URL
	configuration.Routes = []config.RouteConfig{{
		ID:     "chat",
		Method: http.MethodPost,
		Path:   "/v1/chat/completions",
		Match:  "exact",
		Parser: "openai.chat_completions",
	}}
	application, err := New(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new application: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	response := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusCreated)
	}
	if response.Body.String() != "created" {
		t.Fatalf("body = %q, want created", response.Body.String())
	}
}
