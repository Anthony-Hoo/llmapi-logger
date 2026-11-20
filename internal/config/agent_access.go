package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// AgentAccessConfig controls the optional agent access module
// (doc/features/25-agent-access.md): a token-authenticated facade under
// /api/agent/ for a local command-line client. It is off by default; while
// off no facade route, no web-side agent-access route and no in-memory state
// exist. The whole section may be omitted.
type AgentAccessConfig struct {
	Enabled bool `yaml:"enabled"`
	// AllowWrite lets the confirmation page issue read-write tokens and lets
	// such tokens reach the write endpoints. Read endpoints ignore it.
	AllowWrite bool `yaml:"allow_write"`
	// PublicURL is the address written into install prompts. Empty means the
	// address the user is currently browsing.
	PublicURL string `yaml:"public_url"`
}

// validateAgentAccess checks the agent_access section. Like the other
// optional sections a disabled one is not inspected, so a stale value never
// blocks a deployment that does not use the feature.
func validateAgentAccess(cfg Config) error {
	agent := cfg.AgentAccess
	if !agent.Enabled {
		return nil
	}
	if agent.PublicURL != "" {
		if err := validatePublicURL(agent.PublicURL); err != nil {
			return err
		}
	}
	return nil
}

// maxPublicURLLength is the install prompt's limit for the server URL.
const maxPublicURLLength = 2048

// publicURLChar is the install prompt's character set for the server URL:
// letters, digits and - . _ ~ : / % [ ].
func publicURLChar(char byte) bool {
	switch {
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		return true
	default:
		return strings.IndexByte("-._~:/%[]", char) >= 0
	}
}

// validatePublicURL accepts an http(s) address with a host and, unlike the
// upstream URLs, an optional path: the management plane may be published
// below a prefix by a reverse proxy. Userinfo, a query and a fragment are
// rejected because they would end up verbatim in a prompt an agent executes,
// and so is every character outside publicURLChar (contract section 8.1).
func validatePublicURL(value string) error {
	const name = "agent_access.public_url"
	if strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%s must not contain whitespace", name)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must not contain control characters", name)
	}
	// The install prompt writes this address into shell commands inside
	// double quotes (internal/agentdist cleanServerURL), and refuses any
	// character a shell could interpret there. The same rule here makes a
	// value the prompt would refuse a startup error instead of a failing
	// install-links request.
	if len(value) > maxPublicURLLength {
		return fmt.Errorf("%s is longer than %d characters", name, maxPublicURLLength)
	}
	for index := 0; index < len(value); index++ {
		if !publicURLChar(value[index]) {
			return fmt.Errorf("%s may contain only ASCII letters, digits and - . _ ~ : / %% [ ]", name)
		}
	}
	u, err := url.Parse(value)
	if err != nil {
		return errors.New(name + " is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s scheme must be http or https, got %q", name, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%s must contain an http(s) host", name)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo", name)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%s must not contain a query", name)
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return fmt.Errorf("%s must not contain a fragment", name)
	}
	if _, err := canonicalHost(u.Hostname(), false); err != nil {
		return fmt.Errorf("%s has an invalid host", name)
	}
	if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("%s has an empty port", name)
	}
	if port := u.Port(); port != "" {
		number := 0
		for _, char := range port {
			if char < '0' || char > '9' {
				return fmt.Errorf("%s has an invalid port", name)
			}
			number = number*10 + int(char-'0')
			if number > 65535 {
				return fmt.Errorf("%s has an invalid port", name)
			}
		}
		if number < 1 {
			return fmt.Errorf("%s has an invalid port", name)
		}
	}
	return nil
}
