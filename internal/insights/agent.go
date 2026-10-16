package insights

import (
	"net/http"
	"strings"
)

// Agent fingerprint domains. Node, parent and root tags share DomainAgent over
// client ‖ 0x00 ‖ raw id, so a parent id and the node id it names produce the
// same tag. DomainAgentSynthetic tags agents that have no client id at all
// (content-matched parents and children), over their analysis_session_id.
const (
	DomainAgent          = "insights/agent"
	DomainAgentSynthetic = "insights/agent-synthetic"
)

// ClientUnknown is the client of a request no vocabulary rule recognises.
const ClientUnknown = "unknown"

const (
	// maxAgentIDBytes bounds every raw id read from a header or body path;
	// longer values are ignored rather than truncated, so two ids sharing a
	// long prefix can never collapse into one node.
	maxAgentIDBytes = 256
	// maxAgentNameBytes bounds the display-only agent name (doc section 11).
	maxAgentNameBytes = 64
	// agentLinkConfidenceExact is the confidence of header and body links.
	agentLinkConfidenceExact = 100
)

// AgentFPR returns the keyed tag of one raw agent id of a client.
func AgentFPR(fp Fingerprinter, client, rawID string) []byte {
	return fp.Fingerprint(DomainAgent, []byte(client+"\x00"+rawID))
}

// SyntheticAgentFPR returns the node tag of an agent that carries no client
// id, derived from its analysis_session_id. Readers resolve a parent tag that
// matches no agent_node_fpr by recomputing this over candidate session ids.
func SyntheticAgentFPR(fp Fingerprinter, sessionID string) []byte {
	return fp.Fingerprint(DomainAgentSynthetic, []byte(sessionID))
}

// IdentifyAgent reads the agent identity a request declares about itself
// (doc/features/20-context-insights.md sections 5.8 and 11). It never looks at
// other audits: root inheritance and content matching belong to the linker.
//
// Client detection tries User-Agent prefixes of every client in priority order
// first and only then the detect headers, because some clients send another
// client's marker header (OpenCode under ChatGPT auth sends originator).
//
// A nil vocab means the built-in vocabulary.
func IdentifyAgent(input Input, vocab *Vocabulary) AgentIdentity {
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	identity := AgentIdentity{Client: detectClient(input.Headers, vocab)}
	rule, known := vocab.Clients[identity.Client]
	if !known {
		identity.Client = ClientUnknown
		identity.Role = firstNonEmpty(SideRequestRole(input, vocab), RoleMain)
		return identity
	}

	headers := input.Headers
	identity.RootID = headerID(headers, rule.RootHeaders, maxAgentIDBytes)
	identity.NodeID = headerID(headers, rule.NodeHeaders, maxAgentIDBytes)
	identity.ParentID = headerID(headers, rule.ParentHeaders, maxAgentIDBytes)
	identity.Name = headerID(headers, rule.NameHeaders, maxAgentNameBytes)
	parentSource := ""
	if identity.ParentID != "" {
		parentSource = LinkHeader
	} else if parent := bodyID(input.Request, rule.ParentBodyPaths); parent != "" {
		identity.ParentID, parentSource = parent, LinkBody
	}
	nodeFromHeader := identity.NodeID != ""
	if !nodeFromHeader && rule.NodeFallback == "root" && identity.RootID != "" {
		// The main agent's node is the session root (Claude Code without
		// x-claude-code-agent-id).
		identity.NodeID = identity.RootID
	}
	if nodeFromHeader && identity.ParentID == "" && rule.ParentFallback == "root" && identity.RootID != "" {
		// A named agent without a parent header was spawned by the main agent.
		identity.ParentID, parentSource = identity.RootID, LinkHeader
	}
	if identity.ParentID != "" && identity.ParentID == identity.NodeID {
		// A node is never its own parent, whichever header produced the loop.
		identity.ParentID, parentSource = "", ""
	}

	identity.Role = headerRole(headers, rule.RoleHeaders)
	if identity.Role == "" {
		identity.Role = SideRequestRole(input, vocab)
	}
	if identity.Role == "" {
		identity.Role = RoleMain
		if identity.ParentID != "" {
			identity.Role = RoleSubagent
		}
	}

	switch {
	case parentSource != "":
		identity.LinkSource = parentSource
	case identity.NodeID != "":
		identity.LinkSource = LinkHeader
	}
	if identity.LinkSource != "" {
		identity.Confidence = agentLinkConfidenceExact
	}
	return identity
}

// detectClient returns the first client whose User-Agent prefix matches, else
// the first whose detect headers match, else "".
func detectClient(headers http.Header, vocab *Vocabulary) string {
	if len(headers) == 0 {
		return ""
	}
	ordered := vocab.OrderedClients()
	userAgent := strings.ToLower(strings.TrimSpace(headers.Get("User-Agent")))
	if userAgent != "" {
		for _, name := range ordered {
			for _, prefix := range vocab.Clients[name].Detect.UserAgentPrefixes {
				if strings.HasPrefix(userAgent, prefix) {
					return name
				}
			}
		}
	}
	for _, name := range ordered {
		detect := vocab.Clients[name].Detect
		for _, header := range detect.HeadersPresent {
			if firstHeaderValue(headers, header) != "" {
				return name
			}
		}
		for header, want := range detect.HeadersEqual {
			for _, value := range headers.Values(header) {
				if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
					return name
				}
			}
		}
	}
	return ""
}

func firstHeaderValue(headers http.Header, name string) string {
	for _, value := range headers.Values(name) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// headerID returns the first non-empty value of the listed headers that fits
// within limit bytes. Oversized values are skipped, not truncated.
func headerID(headers http.Header, names []string, limit int) string {
	for _, name := range names {
		for _, value := range headers.Values(name) {
			if trimmed := strings.TrimSpace(value); trimmed != "" && len(trimmed) <= limit {
				return trimmed
			}
		}
	}
	return ""
}

// bodyID resolves dot-separated paths against the request JSON object and
// returns the first string value within the id bound.
func bodyID(request []byte, paths []string) string {
	if len(paths) == 0 || len(request) == 0 {
		return ""
	}
	value, err := decodeJSON(request)
	if err != nil {
		return ""
	}
	root := asMap(value)
	for _, path := range paths {
		current := any(root)
		for _, key := range strings.Split(path, ".") {
			current = asMap(current)[key]
		}
		if text, ok := current.(string); ok {
			if trimmed := strings.TrimSpace(text); trimmed != "" && len(trimmed) <= maxAgentIDBytes {
				return trimmed
			}
		}
	}
	return ""
}

func headerRole(headers http.Header, roleHeaders []RoleHeader) string {
	for _, roleHeader := range roleHeaders {
		for _, value := range headers.Values(roleHeader.Header) {
			if role, ok := roleHeader.Values[strings.ToLower(strings.TrimSpace(value))]; ok {
				return role
			}
		}
	}
	return ""
}

// auxiliaryRole reports whether role is a side request attached to a node
// rather than a tree node itself.
func auxiliaryRole(role string) bool {
	switch role {
	case RoleCompaction, RoleTitle, RoleReview, RoleAuxiliary:
		return true
	}
	return false
}
