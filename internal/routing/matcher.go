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

const maxPathUnescapeDepth = 16

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
	exact                 map[string]compiledRoute
	templates             map[string][]compiledRoute
	protectedExactPaths   []string
	protectedPathPrefixes []string
}

// Compile validates and compiles an explicit route whitelist.
func Compile(routes []config.RouteConfig) (*Matcher, error) {
	if err := config.ValidateRouteDefinitions(routes); err != nil {
		return nil, fmt.Errorf("compile routes: %w", err)
	}

	matcher := &Matcher{
		exact:                 make(map[string]compiledRoute, len(routes)),
		templates:             make(map[string][]compiledRoute),
		protectedExactPaths:   make([]string, 0, len(routes)),
		protectedPathPrefixes: make([]string, 0, len(routes)),
	}
	for _, route := range routes {
		compiled := compiledRoute{
			routeID:        route.ID,
			parser:         route.Parser,
			interceptorIDs: append([]string(nil), route.Interceptors...),
		}
		if route.Match == "exact" {
			matcher.exact[routeKey(route.Method, route.Path)] = compiled
			matcher.protectedExactPaths = append(matcher.protectedExactPaths, fullyUnescape(route.Path))
			continue
		}

		placeholder := strings.Index(route.Path, modelPlaceholder)
		compiled.prefix = route.Path[:placeholder]
		compiled.suffix = route.Path[placeholder+len(modelPlaceholder):]
		matcher.templates[route.Method] = append(matcher.templates[route.Method], compiled)
		matcher.protectedPathPrefixes = append(matcher.protectedPathPrefixes, fullyUnescape(compiled.prefix))
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

// AllowsPassthrough reports whether a request that did not Match can safely
// use the non-audited NewAPI fallback. Configured exact paths, descendants of
// exact paths, template route families, and their encoded equivalents remain
// protected regardless of method. Unsafe path forms fail closed globally.
func (matcher *Matcher) AllowsPassthrough(escapedPath string) bool {
	if matcher == nil || !safeEscapedPath(escapedPath) {
		return false
	}

	forms, complete := unescapedPathForms(escapedPath)
	if !complete {
		return false
	}
	for _, candidate := range forms {
		if unsafePathForm(candidate) {
			return false
		}
		for _, protected := range matcher.protectedExactPaths {
			if strings.EqualFold(candidate, protected) || protected != "/" && hasFoldedPrefix(candidate, protected+"/") {
				return false
			}
		}
		for _, prefix := range matcher.protectedPathPrefixes {
			if hasFoldedPrefix(candidate, prefix) {
				return false
			}
		}
	}
	return true
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

func unescapedPathForms(escapedPath string) ([]string, bool) {
	forms := []string{escapedPath}
	current := escapedPath
	for range maxPathUnescapeDepth {
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return forms, false
		}
		if decoded == current {
			return forms, true
		}
		forms = append(forms, decoded)
		current = decoded
	}
	return forms, false
}

func fullyUnescape(escapedPath string) string {
	forms, _ := unescapedPathForms(escapedPath)
	return forms[len(forms)-1]
}

func unsafePathForm(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return true
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		return true
	}
	if strings.Contains(path, "//") || strings.ContainsRune(path, '\\') || strings.ContainsAny(path, "?#") {
		return true
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func hasFoldedPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
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
