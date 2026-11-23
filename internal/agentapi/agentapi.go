// Package agentapi holds what the agent facade (/api/agent/v1) and the
// llmaudit command-line client share: the response envelope, the one table of
// error codes with their HTTP status and exit code, the endpoint registry,
// header names, version negotiation and the credential masking rule
// (doc/features/25-agent-access-contract.md).
//
// It depends on the standard library only, because the command-line client
// must build without any other server package.
package agentapi

// PathPrefix is the facade prefix; every facade path below is relative to it.
const PathPrefix = "/api/agent/v1"

// Header names (contract section 2.1).
const (
	// HeaderCLIVersion carries the client's version. It is used for audit and
	// version negotiation, never for authentication.
	HeaderCLIVersion = "X-Llmaudit-Version"
	// HeaderCommand carries the client's command name (for example
	// "requests.list"). It is recorded, never trusted.
	HeaderCommand = "X-Llmaudit-Command"
	// HeaderLatest and HeaderMin are on every facade response.
	HeaderLatest = "X-Agent-Api-Latest"
	HeaderMin    = "X-Agent-Api-Min"
)

// TokenPrefix starts every agent token; the rest is 43 URL-safe characters
// (32 random bytes, unpadded base64url).
const (
	TokenPrefix       = "lla_"
	TokenRandomBytes  = 32
	TokenEncodedChars = 43
	TokenLength       = len(TokenPrefix) + TokenEncodedChars
)

// ValidTokenFormat reports whether value has the exact token shape. It says
// nothing about whether the token exists.
func ValidTokenFormat(value string) bool {
	if len(value) != TokenLength || value[:len(TokenPrefix)] != TokenPrefix {
		return false
	}
	return base64URLChars(value[len(TokenPrefix):])
}

func base64URLChars(value string) bool {
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-', char == '_':
		default:
			return false
		}
	}
	return true
}
