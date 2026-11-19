// Package agentcli is the llmaudit command-line client of the agent facade
// (doc/features/25-agent-access-contract.md section 6). cmd/llmaudit only
// calls Main; everything else lives here so that other packages' tests can
// import it.
//
// It depends on the standard library and internal/agentapi only.
package agentcli

import (
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/agentapi"
)

// Version is this client's version. It is sent in X-Llmaudit-Version and must
// always parse as MAJOR.MINOR.PATCH: the server refuses an unparsable one
// with CLIENT_TOO_OLD.
var Version = agentapi.LatestVersion

const defaultTimeout = 15 * time.Second

type flagKind int

const (
	stringFlag flagKind = iota
	boolFlag
	listFlag // repeatable
)

// flagSpec is one command flag. Query, PathParam and Body say where its value
// goes; Routes() is derived from them, and the request builder only sends
// what they declare.
type flagSpec struct {
	Name  string
	Kind  flagKind
	Value string // placeholder shown in help, e.g. "<duration>"
	Help  string

	Query      string // query parameter it sets
	QueryValue string // value sent for a set bool flag
	PathParam  string // path segment it fills
	Body       string // request body field it feeds
	Required   bool
	// Default is sent when the flag is absent (only --tz-offset-min).
	Default func(*Env) string
}

// argSpec is one positional argument.
type argSpec struct {
	Name      string
	Help      string
	PathParam string
	Body      string
}

// routeSpec is one facade endpoint a command may call. Path is relative to
// agentapi.PathPrefix with {name} segments, the same shape as
// agentapi.Endpoint.Pattern.
type routeSpec struct {
	Method string
	Path   string
	// Body lists the body fields the command sets itself (not from flags or
	// arguments), such as op or code_verifier.
	Body []string
	// Meta marks a read result: the envelope must carry all three meta fields.
	Meta bool
	// Raw marks an export: the success body is the content, not an envelope.
	Raw bool
}

// commandSpec is one command. The parser, the help text, the request builder
// and Routes() all read the same spec.
type commandSpec struct {
	Path        []string
	Summary     string
	Description string
	// Fields is printed as it is, after the description.
	Fields  string
	Args    []argSpec
	Flags   []flagSpec
	Routes  []routeSpec
	Timeout time.Duration
	// Wait is an interactive wait before the request (login's browser or
	// pasted code), with WaitFor saying what is waited for; help prints it.
	Wait    time.Duration
	WaitFor string
	// StateFlags are flags the command needs in some local state, such as
	// login's --server before anything is saved. A command written into a
	// hint cannot know that state, so CheckCommand requires them.
	StateFlags []string
	Examples   []string
	// Select picks the route; nil means Routes[0].
	Select func(*invocation) (*routeSpec, error)
	Run    func(*invocation) (*result, error)
}

func (spec *commandSpec) name() string { return strings.Join(spec.Path, " ") }

// header is the X-Llmaudit-Command value, e.g. "requests.list".
func (spec *commandSpec) header() string { return strings.Join(spec.Path, ".") }

func (spec *commandSpec) flag(name string) *flagSpec {
	for index := range spec.Flags {
		if spec.Flags[index].Name == name {
			return &spec.Flags[index]
		}
	}
	return nil
}

func (spec *commandSpec) timeout() time.Duration {
	if spec.Timeout > 0 {
		return spec.Timeout
	}
	return defaultTimeout
}

// Route is one endpoint a command can call, with every query parameter and
// body field the command can send to it. Path is relative to
// agentapi.PathPrefix and uses {name} segments like agentapi.Endpoint.
// Body names a nested field as "args.week".
type Route struct {
	Command string
	Method  string
	Path    string
	Query   []string
	Body    []string
}

// Routes lists, for every command, the endpoints it calls. It is generated
// from the command table the parser and the request builder use, so it cannot
// drift from what the commands really send.
func Routes() []Route {
	var routes []Route
	for _, spec := range allCommands() {
		for index := range spec.Routes {
			routes = append(routes, spec.route(&spec.Routes[index]))
		}
	}
	return routes
}

func (spec *commandSpec) route(route *routeSpec) Route {
	query := map[string]struct{}{}
	body := map[string]struct{}{}
	for _, field := range route.Body {
		body[field] = struct{}{}
	}
	if route.Method != "GET" && route.Method != "DELETE" {
		for _, flag := range spec.Flags {
			if flag.Body != "" {
				body[flag.Body] = struct{}{}
			}
		}
		for _, arg := range spec.Args {
			if arg.Body != "" {
				body[arg.Body] = struct{}{}
			}
		}
	}
	for _, flag := range spec.Flags {
		if flag.Query != "" {
			query[flag.Query] = struct{}{}
		}
	}
	return Route{Command: spec.name(), Method: route.Method, Path: route.Path, Query: sortedKeys(query), Body: sortedKeys(body)}
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
