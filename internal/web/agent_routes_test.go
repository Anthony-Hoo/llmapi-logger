package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// The route table test of contract section 4.8. The management routes are
// dispatched by hand-written switch code, so there is no router to read
// them from. agentapi.WebRoutes plus agentapi.WebRouteExceptions is the
// canonical list, and this test holds it to the code from three sides:
//
//  1. every row resolves: its facade endpoints are registered, or the row
//     is marked pending (and a pending row whose endpoints all exist fails,
//     so the marker is removed when phase 4 lands);
//  2. every row is served by the real handler with every module enabled
//     (not the plain-text 404 of an unknown path, not 405), and every
//     method a row does not list is refused with 405 or 404;
//  3. the handler source is parsed and every route path constant or
//     literal, and every path segment the dispatch code compares against,
//     must appear in the canonical list.
//
// It does not catch a route whose path is assembled at run time from
// something other than constants and literals, or a segment matched by a
// function other than ==, switch or strings.HasPrefix on a constant.

// notRoutes are management path literals that are not routes.
var notRoutes = map[string]string{
	"/metrics": "authenticated by protectedPath but served by no handler; answers 404",
}

// notSegments are values compared against a variable named parts that are
// not path segments.
var notSegments = map[string]string{
	"v2": "auth.go: the version field of a session cookie",
}

var routeSamples = map[string]string{
	"/api/v1/audits/{id}":                      "own-1",
	"/api/v1/insights/sessions/{id}":           apiSessionShared,
	"/api/v1/insights/agent-trees/{id}":        apiTreeOwn,
	"/api/v1/session-analysis/sessions/{id}":   analysisOwnID,
	"/api/v1/org/principals/{kind}":            "user",
	"/api/v1/org/members/{user_id}":            "7",
	"/ui/{path}":                               "index.html",
	"/api/v1/audits/{id}/raw/{side}":           "request",
	"/api/v1/audits/{id}/reconstructed/{side}": "request",
	"/api/v1/audits/{id}/timeline/{side}":      "request",
}

// samplePath substitutes a sample value for every {param} of path.
func samplePath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if !strings.HasPrefix(segment, "{") {
			continue
		}
		prefix := strings.Join(segments[:index+1], "/")
		value, ok := routeSamples[prefix]
		if !ok {
			value = "1"
		}
		segments[index] = value
	}
	return strings.Join(segments, "/")
}

type canonicalRoute struct {
	method, path string
}

func canonicalRoutes() []canonicalRoute {
	var routes []canonicalRoute
	for _, route := range agentapi.WebRoutes {
		routes = append(routes, canonicalRoute{route.Method, route.Path})
	}
	for _, route := range agentapi.WebRouteExceptions {
		routes = append(routes, canonicalRoute{route.Method, route.Path})
	}
	return routes
}

func TestWebRouteTableResolves(t *testing.T) {
	registered := map[string]bool{}
	for _, endpoint := range agentapi.Endpoints {
		registered[endpoint.ID] = true
	}
	referenced := map[string]bool{}
	seen := map[string]bool{}
	for _, route := range agentapi.WebRoutes {
		key := route.Method + " " + route.Path
		if seen[key] {
			t.Errorf("%s is listed twice", key)
		}
		seen[key] = true
		if len(route.Endpoints) == 0 || len(route.Commands) == 0 {
			t.Errorf("%s maps to nothing", key)
		}
		missing := 0
		for _, id := range route.Endpoints {
			referenced[id] = true
			if !registered[id] {
				missing++
			}
		}
		switch {
		case !route.Pending && missing > 0:
			t.Errorf("%s points at unregistered endpoints %v", key, route.Endpoints)
		case route.Pending && missing == 0:
			t.Errorf("%s is marked pending but all of %v are registered: remove the marker", key, route.Endpoints)
		}
	}
	for _, exception := range agentapi.WebRouteExceptions {
		if seen[exception.Method+" "+exception.Path] || exception.Reason == "" {
			t.Errorf("exception %s %s overlaps the table or has no reason", exception.Method, exception.Path)
		}
	}
	for _, id := range agentapi.FacadeOnlyEndpoints {
		referenced[id] = true
	}
	for _, endpoint := range agentapi.Endpoints {
		if !referenced[endpoint.ID] {
			t.Errorf("facade endpoint %s is in no row of the route table", endpoint.ID)
		}
	}
}

// isPlainNotFound is http.NotFound: the answer to a path no handler serves.
func isPlainNotFound(response *httptest.ResponseRecorder) bool {
	return response.Code == http.StatusNotFound && strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain")
}

func TestWebRouteTableMatchesTheHandler(t *testing.T) {
	fixture := newReadFixture(t)
	listed := map[string]map[string]bool{}
	for _, route := range canonicalRoutes() {
		if listed[route.path] == nil {
			listed[route.path] = map[string]bool{}
		}
		listed[route.path][route.method] = true
		response := fixture.do(route.method, samplePath(route.path), "{}", agentCaller{bearer: testAdminToken})
		if isPlainNotFound(response) || response.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s (%s) is not served: %d %s", route.method, route.path, samplePath(route.path), response.Code, response.Body.String())
		}
	}
	for path, methods := range listed {
		if path == "/" || path == "/ui" || strings.HasPrefix(path, "/ui/") {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if methods[method] {
				continue
			}
			response := fixture.do(method, samplePath(path), "{}", agentCaller{bearer: testAdminToken})
			if response.Code != http.StatusMethodNotAllowed && !isPlainNotFound(response) {
				t.Errorf("%s %s answers %d but is not in the route table", method, path, response.Code)
			}
		}
	}
}

// routeSource is what the dispatch code of internal/web names: path
// constants and literals, and the segments it compares path parts against.
type routeSource struct {
	paths    map[string]string
	segments map[string]string
}

func scanRouteSource(t *testing.T) routeSource {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fileSet, name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
	}
	// String constants, including ones built from other constants.
	constants := map[string]string{}
	var value func(ast.Expr) (string, bool)
	value = func(expr ast.Expr) (string, bool) {
		switch typed := expr.(type) {
		case *ast.BasicLit:
			if typed.Kind != token.STRING {
				return "", false
			}
			text, err := strconv.Unquote(typed.Value)
			return text, err == nil
		case *ast.Ident:
			text, ok := constants[typed.Name]
			return text, ok
		case *ast.BinaryExpr:
			left, leftOK := value(typed.X)
			right, rightOK := value(typed.Y)
			return left + right, leftOK && rightOK && typed.Op == token.ADD
		case *ast.ParenExpr:
			return value(typed.X)
		}
		return "", false
	}
	for range 3 {
		for _, file := range parsed {
			for _, decl := range file.Decls {
				general, ok := decl.(*ast.GenDecl)
				if !ok || general.Tok != token.CONST {
					continue
				}
				for _, spec := range general.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					for index, name := range valueSpec.Names {
						if index < len(valueSpec.Values) {
							if text, ok := value(valueSpec.Values[index]); ok {
								constants[name.Name] = text
							}
						}
					}
				}
			}
		}
	}
	result := routeSource{paths: map[string]string{}, segments: map[string]string{}}
	managementPath := func(text string) bool {
		return text == "/" || text == "/healthz" || text == "/readyz" || text == "/metrics" || text == "/ui" ||
			strings.HasPrefix(text, "/ui/") || text == "/api/v1" || strings.HasPrefix(text, "/api/v1/")
	}
	for name, text := range constants {
		if managementPath(text) {
			result.paths[text] = "const " + name
		}
	}
	isPartIndex := func(expr ast.Expr) bool {
		index, ok := expr.(*ast.IndexExpr)
		if !ok {
			return false
		}
		ident, ok := index.X.(*ast.Ident)
		return ok && ident.Name == "parts"
	}
	for _, file := range parsed {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				if text, ok := value(typed); ok && managementPath(text) {
					result.paths[text] = fileSet.Position(typed.Pos()).String()
				}
			case *ast.BinaryExpr:
				if typed.Op == token.EQL && isPartIndex(typed.X) {
					if text, ok := value(typed.Y); ok {
						result.segments[text] = fileSet.Position(typed.Pos()).String()
					}
				}
			case *ast.SwitchStmt:
				if typed.Tag != nil && isPartIndex(typed.Tag) {
					for _, clause := range typed.Body.List {
						for _, expr := range clause.(*ast.CaseClause).List {
							if text, ok := value(expr); ok {
								result.segments[text] = fileSet.Position(expr.Pos()).String()
							}
						}
					}
				}
			}
			return true
		})
	}
	return result
}

// coveredPath reports whether path names a canonical route or a prefix of
// one, segment by segment; a {param} segment matches any value.
func coveredPath(path string, routes []canonicalRoute) bool {
	wanted := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if path == "/" {
		wanted = []string{""}
	}
	for _, route := range routes {
		segments := strings.Split(route.path, "/")
		if route.path == "/" {
			segments = []string{""}
		}
		if len(wanted) > len(segments) {
			continue
		}
		matched := true
		for index, segment := range wanted {
			if segments[index] != segment && !strings.HasPrefix(segments[index], "{") {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func TestWebRouteTableCoversTheDispatchCode(t *testing.T) {
	source := scanRouteSource(t)
	routes := canonicalRoutes()
	if len(source.paths) < 10 || len(source.segments) < 10 {
		t.Fatalf("the scan found too little (%d paths, %d segments); it is probably broken", len(source.paths), len(source.segments))
	}
	var paths []string
	for path := range source.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if _, ok := notRoutes[path]; ok {
			continue
		}
		if !coveredPath(path, routes) {
			t.Errorf("%s (%s) is in the dispatch code but not in agentapi.WebRoutes or WebRouteExceptions", path, source.paths[path])
		}
	}
	known := map[string]bool{}
	for _, route := range routes {
		for _, segment := range strings.Split(route.path, "/") {
			known[segment] = true
		}
	}
	for segment, position := range source.segments {
		if _, ok := notSegments[segment]; !ok && !known[segment] {
			t.Errorf("path segment %q (%s) is dispatched on but appears in no route of the table", segment, position)
		}
	}
	// The scan sees the routes this module added, so it is not vacuous.
	for _, path := range []string{"/api/v1/agent-access/authorizations", "/api/v1/settings/session-analysis/test", "/api/v1/org/me/weekly"} {
		if _, ok := source.paths[path]; !ok {
			t.Errorf("scan missed %s", path)
		}
	}
	for _, segment := range []string{"composition", "pack", "dismiss", "preview", "unattributed"} {
		if _, ok := source.segments[segment]; !ok {
			t.Errorf("scan missed segment %s", segment)
		}
	}
}
