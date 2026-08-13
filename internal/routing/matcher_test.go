package routing

import (
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/config"
)

func TestMatcherExact(t *testing.T) {
	matcher := mustCompile(t, []config.RouteConfig{{
		ID:           "responses",
		Method:       "POST",
		Path:         "/v1/responses",
		Match:        "exact",
		Parser:       "openai.responses",
		Interceptors: []string{"auth"},
	}})

	got, ok := matcher.Match("POST", "/v1/responses")
	if !ok {
		t.Fatal("Match() ok = false")
	}
	want := Match{
		RouteID:        "responses",
		Parser:         "openai.responses",
		InterceptorIDs: []string{"auth"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match() = %#v, want %#v", got, want)
	}

	for _, request := range []struct{ method, path string }{
		{"GET", "/v1/responses"},
		{"post", "/v1/responses"},
		{"POST", "/v1/responses/"},
		{"POST", "/v1/responses?stream=true"},
		{"POST", "/v1/other"},
	} {
		if _, ok := matcher.Match(request.method, request.path); ok {
			t.Errorf("Match(%q, %q) ok = true", request.method, request.path)
		}
	}
}

func TestMatcherTemplate(t *testing.T) {
	matcher := mustCompile(t, []config.RouteConfig{{
		ID:           "gemini-generate",
		Method:       "POST",
		Path:         "/v1beta/models/{model}:generateContent",
		Match:        "template",
		Parser:       "gemini.generate_content",
		Interceptors: []string{"auth", "limit"},
	}})

	got, ok := matcher.Match("POST", "/v1beta/models/gemini-2.5_flash:generateContent")
	if !ok {
		t.Fatal("Match() ok = false")
	}
	if got.RouteID != "gemini-generate" || got.Parser != "gemini.generate_content" {
		t.Fatalf("Match() = %#v", got)
	}
	if !reflect.DeepEqual(got.PathParams, map[string]string{"model": "gemini-2.5_flash"}) {
		t.Fatalf("PathParams = %#v", got.PathParams)
	}
	if !reflect.DeepEqual(got.InterceptorIDs, []string{"auth", "limit"}) {
		t.Fatalf("InterceptorIDs = %#v", got.InterceptorIDs)
	}

	invalid := []string{
		"/v1beta/models/:generateContent",
		"/v1beta/models/a+b:generateContent",
		"/v1beta/models/a%2Fb:generateContent",
		"/v1beta/models/a%5cb:generateContent",
		"/v1beta/models/a/b:generateContent",
		"/v1beta/models/a:streamGenerateContent",
	}
	for _, path := range invalid {
		if _, ok := matcher.Match("POST", path); ok {
			t.Errorf("Match(POST, %q) ok = true", path)
		}
	}
}

func TestMatcherRejectsUnsafeEscapedPaths(t *testing.T) {
	matcher := mustCompile(t, []config.RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x"}})
	paths := []string{
		"",
		"v1/x",
		"/v1/x/",
		"/v1//x",
		"/v1/./x",
		"/v1/../x",
		"/v1/%2e%2e/x",
		"/v1%2Fx",
		"/v1%2fx",
		"/v1%5Cx",
		"/v1\\x",
		"/v1/%zz/x",
	}
	for _, path := range paths {
		if _, ok := matcher.Match("POST", path); ok {
			t.Errorf("Match(POST, %q) ok = true", path)
		}
	}
}

func TestMatcherAllowsOnlyUnrelatedPathsToUsePassthrough(t *testing.T) {
	matcher := mustCompile(t, []config.RouteConfig{
		{ID: "responses", Method: "POST", Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "gemini", Method: "POST", Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
	})

	allowed := []string{
		"/v1/models",
		"/v1/models/",
		"/v1beta/models",
		"/api/status",
		"/api/user/",
		"/api/log/",
		"/api/option/",
		"/v1/responses-old",
	}
	for _, path := range allowed {
		if !matcher.AllowsPassthrough(path) {
			t.Errorf("AllowsPassthrough(%q) = false, want true", path)
		}
	}

	protected := []string{
		"/v1/responses",
		"/v1/%72esponses",
		"/v1/%2572esponses",
		"/v1/responses/child",
		"/v1/responses/",
		"/v1//responses",
		"/v1/./responses",
		"/v1beta/models/gemini-2.5:generateContent",
		"/v1beta/%6dodels/gemini-2.5:generateContent",
		"/v1beta/models/a+b:generateContent",
		"/v1beta/models/a%2Fb:generateContent",
		"/v1beta/models/gemini-2.5:countTokens",
	}
	for _, path := range protected {
		if matcher.AllowsPassthrough(path) {
			t.Errorf("AllowsPassthrough(%q) = true, want false", path)
		}
	}
}

func TestMatcherRejectsAdversarialMultiEncodedPassthroughVariants(t *testing.T) {
	matcher := mustCompile(t, []config.RouteConfig{
		{ID: "chat", Method: "POST", Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "gemini", Method: "POST", Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
	})

	protected := []string{
		"/V1/CHAT/COMPLETIONS",
		"/V1/CHAT/COMPLETIONS/child",
		"/V1BETA/MODELS/gemini:generateContent",
		encodePercents("/v1/chat%2Fcompletions", 6),
		encodePercents("/v1/chat%2fcompletions", 6),
		encodePercents("/v1/chat%5Ccompletions", 6),
		encodePercents("/v1/chat%5ccompletions", 6),
		encodePercents("/v1/ignored/%2E%2E/chat/completions", 6),
		encodePercents("/v1/ignored/%2e%2e/chat/completions", 6),
		encodePercents("/v1/chat/completions%2Fchild", 6),
		encodePercents("/v1beta/%6Dodels/a+b:generateContent", 6),
		encodePercents("/v1/chat%2Fcompletions", maxPathUnescapeDepth+1),
		"/v1/models%25zz",
	}
	for _, path := range protected {
		if matcher.AllowsPassthrough(path) {
			t.Errorf("AllowsPassthrough(%q) = true for adversarial path", path)
		}
	}

	for _, path := range []string{"/v1/models", "/v1/%6Dodels", "/v1/%256Dodels"} {
		if !matcher.AllowsPassthrough(path) {
			t.Errorf("AllowsPassthrough(%q) = false for models path", path)
		}
	}
}

func TestCompileRejectsInvalidAndOverlappingRoutes(t *testing.T) {
	base := config.RouteConfig{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x"}
	tests := map[string][]config.RouteConfig{
		"unknown match": {withRoute(base, func(route *config.RouteConfig) { route.Match = "prefix" })},
		"bad template":  {withRoute(base, func(route *config.RouteConfig) { route.Match = "template" })},
		"duplicate":     {base, withRoute(base, func(route *config.RouteConfig) { route.ID = "y" })},
		"overlap": {
			{ID: "exact", Method: "POST", Path: "/models/gemini:generateContent", Match: "exact", Parser: "x"},
			{ID: "template", Method: "POST", Path: "/models/{model}:generateContent", Match: "template", Parser: "x"},
		},
	}
	for name, routes := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(routes); err == nil {
				t.Fatal("Compile() error = nil")
			}
		})
	}
}

func TestCompileAllowsDistinctMethodsAndTemplateVerbs(t *testing.T) {
	routes := []config.RouteConfig{
		{ID: "post", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x"},
		{ID: "get", Method: "GET", Path: "/v1/x", Match: "exact", Parser: "x"},
		{ID: "generate", Method: "POST", Path: "/models/{model}:generateContent", Match: "template", Parser: "x"},
		{ID: "stream", Method: "POST", Path: "/models/{model}:streamGenerateContent", Match: "template", Parser: "x"},
	}
	matcher := mustCompile(t, routes)
	for method, path := range map[string]string{
		"GET":  "/v1/x",
		"POST": "/models/gemini:streamGenerateContent",
	} {
		if _, ok := matcher.Match(method, path); !ok {
			t.Errorf("Match(%q, %q) ok = false", method, path)
		}
	}
}

func TestMatcherDoesNotExposeMutableInterceptorSlice(t *testing.T) {
	routes := []config.RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x", Interceptors: []string{"auth"}}}
	matcher := mustCompile(t, routes)
	routes[0].Interceptors[0] = "changed-before-match"

	first, ok := matcher.Match("POST", "/v1/x")
	if !ok {
		t.Fatal("first Match() ok = false")
	}
	first.InterceptorIDs[0] = "changed-after-match"
	second, ok := matcher.Match("POST", "/v1/x")
	if !ok || !reflect.DeepEqual(second.InterceptorIDs, []string{"auth"}) {
		t.Fatalf("second Match() = %#v, %v", second, ok)
	}
}

func TestNilMatcherDoesNotMatch(t *testing.T) {
	var matcher *Matcher
	if _, ok := matcher.Match("POST", "/v1/x"); ok {
		t.Fatal("nil Matcher.Match() ok = true")
	}
	if matcher.AllowsPassthrough("/v1/models") {
		t.Fatal("nil Matcher.AllowsPassthrough() = true")
	}
}

func mustCompile(t *testing.T, routes []config.RouteConfig) *Matcher {
	t.Helper()
	matcher, err := Compile(routes)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return matcher
}

func withRoute(route config.RouteConfig, mutate func(*config.RouteConfig)) config.RouteConfig {
	mutate(&route)
	return route
}

func encodePercents(value string, depth int) string {
	for range depth {
		value = strings.ReplaceAll(value, "%", "%25")
	}
	return value
}
