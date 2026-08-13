package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/routing"
)

func TestDataPlaneHandlerAdversarialPathDispatch(t *testing.T) {
	matcher, err := routing.Compile([]config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
	})
	if err != nil {
		t.Fatalf("compile routes: %v", err)
	}
	handler := newDataPlaneHandler(
		matcher,
		http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusTeapot)
		}),
		http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}),
	)

	deepSlash := encodePathPercents("/v1/chat%2Fcompletions", 7)
	tests := []struct {
		name       string
		request    *http.Request
		wantStatus int
	}{
		{
			name:       "models passthrough",
			request:    httptest.NewRequest(http.MethodGet, "http://audit-proxy/v1/models", http.NoBody),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "trailing slash API passthrough",
			request:    httptest.NewRequest(http.MethodGet, "http://audit-proxy/api/user/", http.NoBody),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "absolute form models passthrough",
			request:    httptest.NewRequest(http.MethodGet, "http://client.example/v1/models?group=all", http.NoBody),
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "absolute form audited route",
			request:    httptest.NewRequest(http.MethodPost, "http://client.example/v1/chat/completions", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "wrong method exact route",
			request:    httptest.NewRequest(http.MethodGet, "http://audit-proxy/v1/chat/completions", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "case variant exact route",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy/V1/CHAT/COMPLETIONS", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "exact route descendant",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions/child", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "exact route trailing slash",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions/", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "consistent encoded RawPath",
			request:    &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/v1/chat/completions", RawPath: "/v1/chat/%63ompletions"}},
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "deep encoded slash",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy"+deepSlash, http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "template family near miss",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1beta/models/a+b:generateContent", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "template route trailing slash",
			request:    httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1beta/models/gemini:generateContent/", http.NoBody),
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "opaque absolute URI fails closed",
			request:    &http.Request{Method: http.MethodPost, URL: &url.URL{Scheme: "http", Opaque: "//client.example/v1/chat/completions"}},
			wantStatus: http.StatusTeapot,
		},
		{
			name: "inconsistent protected RawPath is ignored with models Path",
			request: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Path: "/v1/models", RawPath: "/v1/chat/%63ompletions"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "inconsistent models RawPath cannot hide protected Path",
			request: &http.Request{
				Method: http.MethodPost,
				URL:    &url.URL{Path: "/v1/chat/completions", RawPath: "/v1/%6dodels"},
			},
			wantStatus: http.StatusTeapot,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; effective path=%q", response.Code, test.wantStatus, test.request.URL.EscapedPath())
			}
		})
	}
}

func encodePathPercents(value string, depth int) string {
	for range depth {
		encoded := make([]byte, 0, len(value)+8)
		for index := 0; index < len(value); index++ {
			if value[index] == '%' {
				encoded = append(encoded, '%', '2', '5')
				continue
			}
			encoded = append(encoded, value[index])
		}
		value = string(encoded)
	}
	return value
}
