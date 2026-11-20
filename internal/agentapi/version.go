package agentapi

import (
	"strconv"
	"strings"
)

// LatestVersion is the newest llmaudit version this server knows, and
// MinVersion the oldest it still serves. Both go out on every facade
// response; a client below MinVersion gets CLIENT_TOO_OLD.
const (
	LatestVersion = "0.1.0"
	MinVersion    = "0.1.0"
)

// ParseVersion parses MAJOR.MINOR.PATCH with an optional pre-release or build
// suffix after '-' or '+', which is ignored for ordering.
func ParseVersion(value string) ([3]int, bool) {
	var parsed [3]int
	if cut := strings.IndexAny(value, "-+"); cut >= 0 {
		value = value[:cut]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return parsed, false
	}
	for index, part := range parts {
		if part == "" || len(part) > 6 {
			return parsed, false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return parsed, false
			}
		}
		number, err := strconv.Atoi(part)
		if err != nil {
			return parsed, false
		}
		parsed[index] = number
	}
	return parsed, true
}

// CompareVersions orders two parsed versions: -1, 0 or 1.
func CompareVersions(left, right [3]int) int {
	for index := range left {
		switch {
		case left[index] < right[index]:
			return -1
		case left[index] > right[index]:
			return 1
		}
	}
	return 0
}

// ClientTooOld reports whether a client version header must be refused. An
// absent header is not refused (the header is informative, not a credential);
// a present one that does not parse is, because it cannot be shown to be new
// enough.
func ClientTooOld(header string) bool {
	if header == "" {
		return false
	}
	version, ok := ParseVersion(header)
	if !ok {
		return true
	}
	minimum, _ := ParseVersion(MinVersion)
	return CompareVersions(version, minimum) < 0
}
