package security

import (
	"net/http"
	"net/url"
	"strings"
)

const bearerPrefix = "Bearer "

// The inbound credential transports accepted by the OpenAI, Anthropic and
// Gemini routes proxied to NewAPI. HasCredential and ExtractCredential both
// enumerate exactly this list, so a new transport only has to be added here for
// the require_credential interceptor and the audit fingerprint to stay aligned.
//
// The two functions differ on purpose. HasCredential answers "did the client
// present something that looks like a credential", which is the admission check
// the interceptor has always made and which requires the Bearer scheme on
// Authorization. ExtractCredential answers "which key would NewAPI resolve this
// request to", which also accepts a bare Authorization value because NewAPI
// does.

// HasCredential reports whether the request carries a credential in any
// accepted transport. It is the presence check behind the require_credential
// interceptor and does not look at the credential value.
func HasCredential(header http.Header, query url.Values) bool {
	if header != nil {
		for _, value := range header.Values("Authorization") {
			if bearerCredential(value) != "" {
				return true
			}
		}
		if hasNonBlank(header.Values("X-Api-Key")) || hasNonBlank(header.Values("X-Goog-Api-Key")) {
			return true
		}
	}
	return query != nil && hasNonBlank(query["key"])
}

// ExtractCredential returns the raw credential NewAPI would authenticate the
// request with, or an empty string when the request carries none. Transports
// are consulted in the order NewAPI itself resolves them.
func ExtractCredential(header http.Header, query url.Values) string {
	if header != nil {
		for _, value := range header.Values("Authorization") {
			if credential := authorizationCredential(value); credential != "" {
				return credential
			}
		}
		for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
			if credential := firstNonBlank(header.Values(name)); credential != "" {
				return credential
			}
		}
	}
	if query != nil {
		return firstNonBlank(query["key"])
	}
	return ""
}

// NormalizeNewAPIKey reduces a credential to the canonical NewAPI token key,
// mirroring NewAPI's own TokenAuthReadOnly middleware: strip the Bearer scheme,
// strip the "sk-" prefix, then keep the segment before the first dash. NewAPI
// treats "sk-abc-suffix" and "sk-abc" as the same token, so both must reduce to
// the same value or one key would fail to match its own records.
//
// An empty result means the request carries no usable key.
func NormalizeNewAPIKey(raw string) string {
	// The scheme is matched before the value is fully trimmed so that a header
	// carrying only "Bearer " reduces to nothing rather than to the scheme name.
	key := strings.TrimLeft(raw, " \t")
	if len(key) >= len(bearerPrefix) && strings.EqualFold(key[:len(bearerPrefix)], bearerPrefix) {
		key = key[len(bearerPrefix):]
	}
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "sk-")
	if segment, _, found := strings.Cut(key, "-"); found {
		key = segment
	}
	return key
}

// bearerCredential returns the token of a well-formed Bearer header and an
// empty string for anything else, including other authentication schemes.
func bearerCredential(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

// authorizationCredential accepts both "Bearer <key>" and a bare key, because
// NewAPI accepts both. Any other authentication scheme is ignored so that a
// Basic or Negotiate credential is never mistaken for an API key.
func authorizationCredential(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.ContainsAny(trimmed, " \t") {
		return bearerCredential(trimmed)
	}
	return trimmed
}

func firstNonBlank(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func hasNonBlank(values []string) bool {
	return firstNonBlank(values) != ""
}
