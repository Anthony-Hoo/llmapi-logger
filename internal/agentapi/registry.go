package agentapi

import "strings"

// Access says which identities may call an endpoint (contract section 2.1).
type Access string

const (
	// AccessAny admits administrators and developers; a developer is always
	// confined to their scope by the handler's service call.
	AccessAny Access = "any"
	// AccessAdmin admits administrators only.
	AccessAdmin Access = "admin"
	// AccessAnonymous needs no token: only the code exchange and the signed
	// package download.
	AccessAnonymous Access = "anonymous"
)

// Tier is a token tier and an endpoint's required tier.
type Tier string

const (
	TierRead  Tier = "read"
	TierWrite Tier = "write"
)

// Valid reports whether tier is one of the two tiers.
func (tier Tier) Valid() bool {
	return tier == TierRead || tier == TierWrite
}

// Role is the identity an agent token resolves to.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleDeveloper Role = "developer"
)

// Endpoint is one registered facade endpoint. Pattern is relative to
// PathPrefix; a segment written {name} matches one non-empty path segment.
// The dispatcher checks Access and Tier before the handler runs, and a path
// that matches no endpoint is NOT_FOUND.
type Endpoint struct {
	// ID names the endpoint; the server binds its handler by ID.
	ID      string
	Method  string
	Pattern string
	Access  Access
	Tier    Tier
}

// EndpointDownload is the signed package download of contract section 5:
// anonymous, fetched by the install prompt rather than by a command. The
// signature in the path is what authorizes it.
const EndpointDownload = "packages.download"

// Endpoints is the facade registry. Each phase appends its endpoints here
// together with the server handler bound to the same ID.
var Endpoints = append(append([]Endpoint{
	{ID: "token.exchange", Method: "POST", Pattern: "/token", Access: AccessAnonymous, Tier: TierRead},
	{ID: "whoami", Method: "GET", Pattern: "/whoami", Access: AccessAny, Tier: TierRead},
	{ID: "logout", Method: "POST", Pattern: "/logout", Access: AccessAny, Tier: TierRead},
	{ID: EndpointDownload, Method: "GET", Pattern: "/dl/{signature}/{file}", Access: AccessAnonymous, Tier: TierRead},
}, ReadEndpoints...), WriteEndpoints...)

// Registry resolves request paths against a list of endpoints.
type Registry struct {
	endpoints []Endpoint
}

// NewRegistry copies endpoints into a registry.
func NewRegistry(endpoints []Endpoint) *Registry {
	return &Registry{endpoints: append([]Endpoint(nil), endpoints...)}
}

// Endpoints returns a copy of the registered endpoints.
func (registry *Registry) Endpoints() []Endpoint {
	return append([]Endpoint(nil), registry.endpoints...)
}

// Match finds the endpoint for method and a full request path (including
// PathPrefix) and returns its path parameters. A path that matches with
// another method is not a match: the facade answers both as NOT_FOUND.
func (registry *Registry) Match(method, path string) (Endpoint, map[string]string, bool) {
	if registry == nil || !strings.HasPrefix(path, PathPrefix+"/") {
		return Endpoint{}, nil, false
	}
	segments := strings.Split(strings.TrimPrefix(path, PathPrefix), "/")[1:]
	for _, endpoint := range registry.endpoints {
		if endpoint.Method != method {
			continue
		}
		if params, ok := matchPattern(endpoint.Pattern, segments); ok {
			return endpoint, params, true
		}
	}
	return Endpoint{}, nil, false
}

func matchPattern(pattern string, segments []string) (map[string]string, bool) {
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	if len(parts) != len(segments) {
		return nil, false
	}
	var params map[string]string
	for index, part := range parts {
		segment := segments[index]
		if segment == "" {
			return nil, false
		}
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if params == nil {
				params = make(map[string]string)
			}
			params[part[1:len(part)-1]] = segment
			continue
		}
		if part != segment {
			return nil, false
		}
	}
	return params, true
}
