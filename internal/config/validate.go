package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const modelPlaceholder = "{model}"

type routePattern struct {
	method  string
	exact   bool
	path    string
	prefix  string
	suffix  string
	routeID string
}

// Validate applies the configuration checks used by both startup and a
// validate-config command.
func Validate(cfg Config) error {
	listen, err := validateListenAddress("listen", cfg.Listen)
	if err != nil {
		return err
	}
	adminListen, err := validateListenAddress("admin_listen", cfg.AdminListen)
	if err != nil {
		return err
	}
	if listen == adminListen {
		return errors.New("listen and admin_listen must be different")
	}

	if err := validateNewAPIURL(cfg.NewAPIURL); err != nil {
		return err
	}
	if err := validateNewAPIProxyURL(cfg.NewAPIProxyURL); err != nil {
		return err
	}
	if cfg.Mode != "available" && cfg.Mode != "strict" {
		return fmt.Errorf("mode must be available or strict, got %q", cfg.Mode)
	}
	if err := validateDataPath("db_path", cfg.DBPath); err != nil {
		return err
	}
	if err := validateDataPath("key_path", cfg.KeyPath); err != nil {
		return err
	}
	if cfg.AdminToken == "" || strings.IndexFunc(cfg.AdminToken, unicode.IsSpace) >= 0 {
		return errors.New("admin_token must not be empty or contain whitespace")
	}
	if cfg.RetentionDays < 0 || cfg.RetentionDays > 3650 {
		return fmt.Errorf("retention_days must be 0 or between 1 and 3650, got %d", cfg.RetentionDays)
	}
	if cfg.NewAPITokenDBPath != "" {
		if err := validateDataPath("newapi_token_db_path", cfg.NewAPITokenDBPath); err != nil {
			return err
		}
	}
	if err := validateInterceptors(cfg.Interceptors); err != nil {
		return err
	}
	if err := validateRoutes(cfg.Routes, cfg.Interceptors, true); err != nil {
		return err
	}
	return nil
}

// ValidateRouteDefinitions validates route grammar, IDs, and overlap without
// requiring the interceptor definitions. routing.Compile uses this to keep
// programmatically assembled routes subject to the same boundary checks.
func ValidateRouteDefinitions(routes []RouteConfig) error {
	return validateRoutes(routes, nil, false)
}

func validateListenAddress(name, value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%s must be a non-empty host:port address", name)
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("%s must be a valid host:port address: %w", name, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%s has invalid port %q", name, portText)
	}
	canonicalHost, err := canonicalHost(host, true)
	if err != nil {
		return "", fmt.Errorf("%s has invalid host %q: %w", name, host, err)
	}
	if canonicalHost == "" || canonicalHost == "0.0.0.0" || canonicalHost == "::" {
		canonicalHost = "*"
	}
	return net.JoinHostPort(canonicalHost, strconv.Itoa(port)), nil
}

func validateNewAPIURL(value string) error {
	return validateHTTPURL("newapi_url", value)
}

func validateNewAPIProxyURL(value string) error {
	if value == "" {
		return nil
	}
	return validateHTTPURL("newapi_proxy_url", value)
}

func validateHTTPURL(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not be empty or contain surrounding whitespace", name)
	}
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s scheme must be http or https, got %q", name, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return fmt.Errorf("%s must contain an http(s) host", name)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo", name)
	}
	if u.Path != "" || u.RawPath != "" {
		return fmt.Errorf("%s must not contain a path", name)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%s must not contain a query", name)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%s must not contain a fragment", name)
	}

	hostname := u.Hostname()
	if _, err := canonicalHost(hostname, false); err != nil {
		return fmt.Errorf("%s has invalid host %q: %w", name, hostname, err)
	}
	if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("%s has an empty port", name)
	}
	if portText := u.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s has invalid port %q", name, portText)
		}
	}
	return nil
}

func canonicalHost(host string, allowEmpty bool) (string, error) {
	if host == "" {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("host is empty")
	}

	addressText := host
	zone := ""
	if percent := strings.LastIndexByte(addressText, '%'); percent >= 0 {
		zone = addressText[percent+1:]
		addressText = addressText[:percent]
		if zone == "" {
			return "", errors.New("IPv6 zone is empty")
		}
	}
	if address, err := netip.ParseAddr(addressText); err == nil {
		canonical := address.String()
		if zone != "" {
			if !address.Is6() {
				return "", errors.New("zone is only valid for IPv6")
			}
			canonical += "%" + zone
		}
		return canonical, nil
	}
	if zone != "" {
		return "", errors.New("invalid IPv6 address")
	}
	if !validHostname(host) {
		return "", errors.New("invalid DNS name")
	}
	return strings.ToLower(host), nil
}

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validateDataPath(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not be empty", name)
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return fmt.Errorf("%s must name a file", name)
	}
	if info, err := os.Stat(value); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s must name a file, got directory %q", name, value)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect %s: %w", name, err)
	}

	parent := filepath.Dir(cleaned)
	for {
		info, err := os.Stat(parent)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("parent of %s is not a directory: %q", name, parent)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect parent of %s: %w", name, err)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return fmt.Errorf("%s has no existing parent directory", name)
		}
		parent = next
	}
}

func validateInterceptors(interceptors map[string]InterceptorConfig) error {
	for id, interceptor := range interceptors {
		if strings.TrimSpace(id) == "" {
			return errors.New("interceptor id must not be empty")
		}
		if strings.TrimSpace(interceptor.Type) != interceptor.Type || interceptor.Type == "" {
			return fmt.Errorf("interceptor %q type must not be empty", id)
		}
	}
	return nil
}

func validateRoutes(routes []RouteConfig, interceptors map[string]InterceptorConfig, checkReferences bool) error {
	ids := make(map[string]struct{}, len(routes))
	patterns := make([]routePattern, 0, len(routes))
	for index, route := range routes {
		if strings.TrimSpace(route.ID) == "" {
			return fmt.Errorf("route %d id must not be empty", index)
		}
		if _, exists := ids[route.ID]; exists {
			return fmt.Errorf("duplicate route id %q", route.ID)
		}
		ids[route.ID] = struct{}{}
		if route.Parser == "" || strings.TrimSpace(route.Parser) != route.Parser {
			return fmt.Errorf("route %q parser must not be empty", route.ID)
		}
		pattern, err := parseRoutePattern(route)
		if err != nil {
			return fmt.Errorf("route %q: %w", route.ID, err)
		}
		for _, previous := range patterns {
			if patternsOverlap(previous, pattern) {
				return fmt.Errorf("routes %q and %q overlap for method %s", previous.routeID, route.ID, route.Method)
			}
		}
		patterns = append(patterns, pattern)

		referenced := make(map[string]struct{}, len(route.Interceptors))
		for _, interceptorID := range route.Interceptors {
			if _, duplicate := referenced[interceptorID]; duplicate {
				return fmt.Errorf("route %q references interceptor %q more than once", route.ID, interceptorID)
			}
			referenced[interceptorID] = struct{}{}
			if checkReferences {
				if _, ok := interceptors[interceptorID]; !ok {
					return fmt.Errorf("route %q references unknown interceptor %q", route.ID, interceptorID)
				}
			}
		}
	}
	return nil
}

func parseRoutePattern(route RouteConfig) (routePattern, error) {
	if !validMethod(route.Method) {
		return routePattern{}, fmt.Errorf("method %q must be an uppercase HTTP token", route.Method)
	}
	if err := validateRoutePath(route.Path); err != nil {
		return routePattern{}, err
	}

	pattern := routePattern{method: route.Method, path: route.Path, routeID: route.ID}
	switch route.Match {
	case "exact":
		if strings.ContainsAny(route.Path, "{}") {
			return routePattern{}, errors.New("exact path must not contain placeholders")
		}
		pattern.exact = true
		return pattern, nil
	case "template":
		if strings.Count(route.Path, modelPlaceholder) != 1 {
			return routePattern{}, errors.New("template path must contain exactly one {model} placeholder")
		}
		withoutModel := strings.Replace(route.Path, modelPlaceholder, "", 1)
		if strings.ContainsAny(withoutModel, "{}") {
			return routePattern{}, errors.New("template path contains an unsupported placeholder")
		}
		placeholder := strings.Index(route.Path, modelPlaceholder)
		pattern.prefix = route.Path[:placeholder]
		pattern.suffix = route.Path[placeholder+len(modelPlaceholder):]
		if !strings.HasSuffix(pattern.prefix, "/") {
			return routePattern{}, errors.New("{model} must begin a path segment")
		}
		if strings.Contains(pattern.suffix, "/") {
			return routePattern{}, errors.New("{model} must not span path segments")
		}
		if pattern.suffix != "" && !strings.HasPrefix(pattern.suffix, ":") {
			return routePattern{}, errors.New("text after {model} must be an optional colon verb")
		}
		return pattern, nil
	default:
		return routePattern{}, fmt.Errorf("match must be exact or template, got %q", route.Match)
	}
}

func validateRoutePath(routePath string) error {
	if routePath == "" || !strings.HasPrefix(routePath, "/") {
		return errors.New("path must be absolute")
	}
	if routePath != "/" && strings.HasSuffix(routePath, "/") {
		return errors.New("path must not have a trailing slash")
	}
	if strings.Contains(routePath, "//") {
		return errors.New("path must not contain an empty segment")
	}
	if strings.ContainsRune(routePath, '\\') {
		return errors.New("path must not contain a backslash")
	}
	if strings.ContainsAny(routePath, "?#") {
		return errors.New("path must not contain a query or fragment")
	}
	for _, char := range routePath {
		if unicode.IsControl(char) || unicode.IsSpace(char) {
			return errors.New("path must not contain whitespace or control characters")
		}
	}
	lower := strings.ToLower(routePath)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return errors.New("path must not contain an encoded slash or backslash")
	}
	decodedForCheck := strings.ReplaceAll(routePath, modelPlaceholder, "model")
	decodedForCheck, err := url.PathUnescape(decodedForCheck)
	if err != nil {
		return fmt.Errorf("path has invalid escaping: %w", err)
	}
	if strings.ContainsRune(decodedForCheck, '\\') || hasDotSegment(decodedForCheck) {
		return errors.New("path must not contain a backslash or dot segment")
	}
	return nil
}

func validMethod(method string) bool {
	if method == "" || method != strings.ToUpper(method) {
		return false
	}
	for _, char := range method {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return false
	}
	return true
}

func hasDotSegment(decodedPath string) bool {
	for _, segment := range strings.Split(decodedPath, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func patternsOverlap(left, right routePattern) bool {
	if left.method != right.method {
		return false
	}
	if left.exact && right.exact {
		return left.path == right.path
	}
	if left.exact {
		return templateMatches(right, left.path)
	}
	if right.exact {
		return templateMatches(left, right.path)
	}
	return left.prefix == right.prefix && left.suffix == right.suffix
}

func templateMatches(pattern routePattern, escapedPath string) bool {
	if !strings.HasPrefix(escapedPath, pattern.prefix) || !strings.HasSuffix(escapedPath, pattern.suffix) {
		return false
	}
	modelEnd := len(escapedPath) - len(pattern.suffix)
	if modelEnd < len(pattern.prefix) {
		return false
	}
	return validModel(escapedPath[len(pattern.prefix):modelEnd])
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
