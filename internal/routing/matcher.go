// Package routing compiles the explicitly configured LLM API whitelist into
// an immutable request matcher.
package routing

import (
	"fmt"
	"net/url"
	"strings"

	"llmapi-logger/internal/config"
)

const modelPlaceholder = "{model}"

// Match describes the enabled route and the immutable execution metadata that
// callers need after a successful whitelist match.
type Match struct {
	RouteID        string
	Parser         string
	InterceptorIDs []string
	PathParams     map[string]string
}

type compiledRoute struct {
	routeID        string
	parser         string
	interceptorIDs []string
	prefix         string
	suffix         string
}

// Matcher is immutable after Compile and safe for concurrent use.
type Matcher struct {
	exact     map[string]compiledRoute
	templates map[string][]compiledRoute
}

// Compile validates and compiles an explicit route whitelist.
func Compile(routes []config.RouteConfig) (*Matcher, error) {
	if err := config.ValidateRouteDefinitions(routes); err != nil {
		return nil, fmt.Errorf("compile routes: %w", err)
	}

	matcher := &Matcher{
		exact:     make(map[string]compiledRoute, len(routes)),
		templates: make(map[string][]compiledRoute),
	}
	for _, route := range routes {
		compiled := compiledRoute{
			routeID:        route.ID,
			parser:         route.Parser,
			interceptorIDs: append([]string(nil), route.Interceptors...),
		}
		if route.Match == "exact" {
			matcher.exact[routeKey(route.Method, route.Path)] = compiled
			continue
		}

		placeholder := strings.Index(route.Path, modelPlaceholder)
		compiled.prefix = route.Path[:placeholder]
		compiled.suffix = route.Path[placeholder+len(modelPlaceholder):]
		matcher.templates[route.Method] = append(matcher.templates[route.Method], compiled)
	}
	return matcher, nil
}

// Match applies method and EscapedPath matching. Unsafe or non-canonical path
// forms fail closed before any configured route is considered.
func (matcher *Matcher) Match(method, escapedPath string) (Match, bool) {
	if matcher == nil || !safeEscapedPath(escapedPath) {
		return Match{}, false
	}
	if route, ok := matcher.exact[routeKey(method, escapedPath)]; ok {
		return makeMatch(route, nil), true
	}
	for _, route := range matcher.templates[method] {
		model, ok := matchTemplate(route, escapedPath)
		if !ok {
			continue
		}
		return makeMatch(route, map[string]string{"model": model}), true
	}
	return Match{}, false
}

func routeKey(method, path string) string {
	return method + "\x00" + path
}

func makeMatch(route compiledRoute, pathParams map[string]string) Match {
	return Match{
		RouteID:        route.routeID,
		Parser:         route.parser,
		InterceptorIDs: append([]string(nil), route.interceptorIDs...),
		PathParams:     pathParams,
	}
}

func matchTemplate(route compiledRoute, escapedPath string) (string, bool) {
	if !strings.HasPrefix(escapedPath, route.prefix) || !strings.HasSuffix(escapedPath, route.suffix) {
		return "", false
	}
	modelEnd := len(escapedPath) - len(route.suffix)
	if modelEnd < len(route.prefix) {
		return "", false
	}
	model := escapedPath[len(route.prefix):modelEnd]
	if !validModel(model) {
		return "", false
	}
	return model, true
}

func safeEscapedPath(escapedPath string) bool {
	if escapedPath == "" || !strings.HasPrefix(escapedPath, "/") {
		return false
	}
	if escapedPath != "/" && strings.HasSuffix(escapedPath, "/") {
		return false
	}
	if strings.Contains(escapedPath, "//") || strings.ContainsRune(escapedPath, '\\') {
		return false
	}
	if strings.ContainsAny(escapedPath, "?#") {
		return false
	}
	lower := strings.ToLower(escapedPath)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return false
	}
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil || strings.ContainsRune(decoded, '\\') {
		return false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validModel(model string) bool {
	if model == "" {
		return false
	}
	for _, char := range model {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
