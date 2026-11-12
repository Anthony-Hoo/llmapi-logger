package orgreport

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Identity sources, strongest first (doc section 5.1). Source names the
// strongest signal an identity carries.
const (
	SourceDeclared          = "declared"            // X-Agent-Project
	SourceCodexTurnMetadata = "codex_turn_metadata" // Codex workspaces: remotes and repo roots
	SourceAgentHeader       = "agent_header"        // OpenCode x-opencode-project hash
	SourceRoot              = "root"                // repository root from a client text block
	SourceCwd               = "cwd"                 // working directory only
	SourceNone              = "none"
)

// Identity is the plaintext project identity of one request. It only ever
// exists in memory: storage keeps keyed fingerprints and the encrypted JSON.
type Identity struct {
	Source string `json:"source"`
	// Declared is the project name a client declared explicitly.
	Declared string `json:"declared,omitempty"`
	// Remotes are normalized "host/org/repo" remotes, origin first.
	Remotes []string `json:"remotes,omitempty"`
	// ProjectHash is OpenCode's x-opencode-project value (lower-case hex).
	ProjectHash string `json:"project_hash,omitempty"`
	// Roots are normalized repository roots; Cwd is the normalized working
	// directory, which may lie below a root.
	Roots []string `json:"roots,omitempty"`
	Cwd   string   `json:"cwd,omitempty"`
}

// Empty reports an identity without any signal.
func (identity Identity) Empty() bool {
	return identity.Declared == "" && len(identity.Remotes) == 0 && identity.ProjectHash == "" &&
		len(identity.Roots) == 0 && identity.Cwd == ""
}

// HasPath reports whether the identity has any repository or path signal, the
// difference between the unattributed and the no-context bucket.
func (identity Identity) HasPath() bool { return !identity.Empty() }

// Finish fills Source from the strongest signal and sorts nothing else: the
// order of Remotes and Roots is meaningful.
func (identity *Identity) Finish() {
	switch {
	case identity.Declared != "":
		identity.Source = SourceDeclared
	case len(identity.Remotes) != 0:
		identity.Source = SourceCodexTurnMetadata
	case identity.ProjectHash != "":
		identity.Source = SourceAgentHeader
	case len(identity.Roots) != 0:
		identity.Source = SourceRoot
	case identity.Cwd != "":
		identity.Source = SourceCwd
	default:
		identity.Source = SourceNone
	}
}

// Canonical returns the JSON that keys the identity: equal identities give
// equal bytes.
func (identity Identity) Canonical() []byte {
	encoded, _ := json.Marshal(identity)
	return encoded
}

const maxIdentityValueBytes = 2048

// NormalizeRemote turns a git remote into lower-case "host/org/repo":
// git@host:org/repo.git, ssh://git@host:22/org/repo, https://user@host:443/org/repo.git
// and git://host/org/repo all normalize alike. Anything that is not a
// network remote (a local path, file://, an empty string) returns "".
func NormalizeRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" || len(remote) > maxIdentityValueBytes {
		return ""
	}
	var host, path string
	if strings.Contains(remote, "://") {
		parsed, err := url.Parse(remote)
		if err != nil || parsed.Scheme == "file" || parsed.Hostname() == "" {
			return ""
		}
		host, path = parsed.Hostname(), parsed.Path
	} else {
		// scp form: [user@]host:path, where the host part has no slash.
		colon := strings.Index(remote, ":")
		if colon <= 0 || strings.Contains(remote[:colon], "/") || strings.HasPrefix(remote[colon+1:], "\\") {
			return ""
		}
		host = remote[:colon]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		path = remote[colon+1:]
		if len(host) == 1 {
			// "C:\repo" or "C:/repo" is a Windows drive, not a host.
			return ""
		}
	}
	path = strings.Trim(strings.ReplaceAll(path, "\\", "/"), "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.Trim(path, "/")
	if host == "" || path == "" {
		return ""
	}
	return strings.ToLower(host + "/" + path)
}

// NormalizePath converts a native path to the comparison form: forward
// slashes, lower case, no trailing slash, no surrounding quotes or spaces.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "\"'`")
	path = strings.TrimSpace(path)
	if path == "" || len(path) > maxIdentityValueBytes || strings.ContainsAny(path, "\x00\r\n") {
		return ""
	}
	path = strings.ReplaceAll(path, "\\", "/")
	for strings.Contains(path, "//") && !strings.HasPrefix(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return strings.ToLower(path)
}

// OpenCodeProjectHash is the value OpenCode v2 sends in x-opencode-project
// for a repository with an origin remote: sha1("git-remote:" + remote).
// Whether OpenCode normalizes the remote exactly like NormalizeRemote is an
// open item (doc section 11).
func OpenCodeProjectHash(normalizedRemote string) string {
	sum := sha1.Sum([]byte("git-remote:" + normalizedRemote))
	return hex.EncodeToString(sum[:])
}

// RepoName returns the last path segment of a normalized remote or path.
func RepoName(normalized string) string {
	normalized = strings.TrimRight(normalized, "/")
	if index := strings.LastIndex(normalized, "/"); index >= 0 {
		return normalized[index+1:]
	}
	return normalized
}

// ResolveRoot maps a working directory to the longest known repository root
// that contains it, or returns the directory itself (doc section 5.2).
func ResolveRoot(cwd string, knownRoots []string) string {
	best := ""
	for _, root := range knownRoots {
		if root == "" {
			continue
		}
		if cwd == root || strings.HasPrefix(cwd, strings.TrimRight(root, "/")+"/") {
			if len(root) > len(best) {
				best = root
			}
		}
	}
	if best == "" {
		return cwd
	}
	return best
}

// AddRemote appends a normalized remote once.
func (identity *Identity) AddRemote(raw string) {
	if normalized := NormalizeRemote(raw); normalized != "" && !contains(identity.Remotes, normalized) {
		identity.Remotes = append(identity.Remotes, normalized)
	}
}

// AddRoot appends a normalized root once.
func (identity *Identity) AddRoot(raw string) {
	if normalized := NormalizePath(raw); normalized != "" && !contains(identity.Roots, normalized) {
		identity.Roots = append(identity.Roots, normalized)
	}
}

// SortedRoots returns the roots sorted, for display.
func (identity Identity) SortedRoots() []string {
	roots := append([]string(nil), identity.Roots...)
	sort.Strings(roots)
	return roots
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
