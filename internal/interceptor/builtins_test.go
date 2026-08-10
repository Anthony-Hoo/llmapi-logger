package interceptor

import (
	"bytes"
	"net/http"
	"testing"

	"llmapi-logger/internal/config"
)

func TestRequireCredentialAcceptedSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers http.Header
		query   string
		allowed bool
	}{
		{name: "authorization", headers: http.Header{"Authorization": {"Bearer token"}}, allowed: true},
		{name: "authorization-case-insensitive", headers: http.Header{"Authorization": {"bEaReR token"}}, allowed: true},
		{name: "authorization-second-value", headers: http.Header{"Authorization": {"Basic value", "Bearer token"}}, allowed: true},
		{name: "x-api-key", headers: http.Header{"X-Api-Key": {" token "}}, allowed: true},
		{name: "x-goog-api-key", headers: http.Header{"X-Goog-Api-Key": {"token"}}, allowed: true},
		{name: "gemini-query-key", query: "key=token", allowed: true},
		{name: "gemini-query-second-value", query: "key=&key=token", allowed: true},
		{name: "missing"},
		{name: "empty-authorization", headers: http.Header{"Authorization": {"Bearer   "}}},
		{name: "wrong-scheme", headers: http.Header{"Authorization": {"Basic token"}}},
		{name: "bearer-extra-fields", headers: http.Header{"Authorization": {"Bearer one two"}}},
		{name: "empty-api-keys", headers: http.Header{"X-Api-Key": {" "}, "X-Goog-Api-Key": {"\t"}}, query: "key="},
	}

	engine, err := NewEngine(
		map[string]config.InterceptorConfig{"credential": {Type: "require_credential"}},
		[]config.RouteConfig{testRoute("route", "credential")},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := newRequest(t, nil)
			request.Header = test.headers.Clone()
			request.URL.RawQuery = test.query
			result := engine.Evaluate(request.Context(), request, testMatch("route", "credential"))
			if result.Allowed != test.allowed {
				t.Fatalf("Allowed = %v, want %v; result=%+v", result.Allowed, test.allowed, result)
			}
			if !test.allowed && (result.StatusCode != http.StatusUnauthorized || result.BlockedBy != "credential" || result.BlockCode != "credential_required" || result.Internal != nil) {
				t.Fatalf("unexpected rejection: %+v", result)
			}
		})
	}
}

func TestBuiltinConfigurationIsStrict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		definition config.InterceptorConfig
	}{
		{name: "credential-unknown-field", definition: config.InterceptorConfig{Type: "require_credential", Config: map[string]any{"extra": true}}},
		{name: "body-missing-limit", definition: config.InterceptorConfig{Type: "max_body_bytes"}},
		{name: "body-unknown-field", definition: config.InterceptorConfig{Type: "max_body_bytes", Config: map[string]any{"max_bytes": MinBodyBytes, "extra": true}}},
		{name: "body-string-limit", definition: config.InterceptorConfig{Type: "max_body_bytes", Config: map[string]any{"max_bytes": "1048576"}}},
		{name: "body-fractional-limit", definition: config.InterceptorConfig{Type: "max_body_bytes", Config: map[string]any{"max_bytes": float64(MinBodyBytes) + 0.5}}},
		{name: "body-below-min", definition: config.InterceptorConfig{Type: "max_body_bytes", Config: map[string]any{"max_bytes": MinBodyBytes - 1}}},
		{name: "body-above-max", definition: config.InterceptorConfig{Type: "max_body_bytes", Config: map[string]any{"max_bytes": MaxBodyBytes + 1}}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEngine(map[string]config.InterceptorConfig{"guard": test.definition}, []config.RouteConfig{testRoute("route", "guard")}); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestBodyViewReadersAreIndependent(t *testing.T) {
	t.Parallel()

	view := BodyView{data: []byte("abcdef")}
	first := view.Open()
	second := view.Open()
	buffer := make([]byte, 2)
	if _, err := first.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, []byte("ab")) {
		t.Fatalf("first reader returned %q", buffer)
	}
	buffer = make([]byte, 3)
	if _, err := second.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, []byte("abc")) {
		t.Fatalf("second reader did not start at beginning: %q", buffer)
	}
	if view.Len() != 6 {
		t.Fatalf("Len = %d, want 6", view.Len())
	}
}

func TestRegistryRejectsInvalidAndDuplicateRegistrations(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	factory := func(string, map[string]any) (Interceptor, error) { return testInterceptor{}, nil }
	if err := registry.Register("", factory); err == nil {
		t.Fatal("expected empty type error")
	}
	if err := registry.Register("valid", nil); err == nil {
		t.Fatal("expected nil factory error")
	}
	if err := registry.Register("valid", factory); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("valid", factory); err == nil {
		t.Fatal("expected duplicate registration error")
	}
	var nilRegistry *Registry
	if err := nilRegistry.Register("valid", factory); err == nil {
		t.Fatal("expected nil registry error")
	}
}
