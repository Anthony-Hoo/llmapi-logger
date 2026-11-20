package agentapi

import (
	"strings"
	"unicode/utf8"
)

// OmittedCredential is the value_omitted reason of a masked value.
const OmittedCredential = "credential"

// MaskedValue is a Header or query parameter value as the facade outputs it:
// either ValueUntrusted or ValueOmitted is set, and Length is always the byte
// length of the original value.
type MaskedValue struct {
	ValueUntrusted *string `json:"value_untrusted,omitempty"`
	ValueOmitted   string  `json:"value_omitted,omitempty"`
	Length         int     `json:"length"`
}

// credentialNames are matched exactly, case-insensitively (rule 1).
var credentialNames = map[string]struct{}{
	"authorization": {}, "proxy-authorization": {}, "cookie": {}, "set-cookie": {},
	"x-api-key": {}, "x-goog-api-key": {}, "api-key": {}, "key": {},
}

// credentialNameParts are matched as substrings of the lower-cased name
// (rule 2). The list is narrow on purpose: names with "session" or "tokens"
// (X-Agent-Session-Id, usage and rate-limit headers) are not credentials.
var credentialNameParts = []string{
	"secret", "password", "passwd", "credential", "signature", "api-key", "apikey", "api_key",
}

// credentialValuePrefixes are matched case-insensitively after leading
// whitespace (rule 3).
var credentialValuePrefixes = []string{"bearer ", "basic ", "sk-", "lla_"}

// IsCredential applies the masking rule of contract section 4.3.2 to one
// name and value. It is shared by the server and the command-line client.
func IsCredential(name, value string) bool {
	lowerName := strings.ToLower(name)
	if _, ok := credentialNames[lowerName]; ok {
		return true
	}
	if lowerName == "token" || strings.HasSuffix(lowerName, "-token") || strings.HasSuffix(lowerName, "_token") {
		return true
	}
	for _, part := range credentialNameParts {
		if strings.Contains(lowerName, part) {
			return true
		}
	}
	trimmed := strings.TrimLeft(value, " \t\r\n\v\f")
	for _, prefix := range credentialValuePrefixes {
		if len(trimmed) >= len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// MaskValue returns the output form of one value. A value that is not valid
// UTF-8 is still passed through as Go replaces invalid bytes when encoding
// JSON; the length is that of the original bytes.
func MaskValue(name, value string) MaskedValue {
	masked := MaskedValue{Length: len(value)}
	if IsCredential(name, value) {
		masked.ValueOmitted = OmittedCredential
		return masked
	}
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	masked.ValueUntrusted = &value
	return masked
}
