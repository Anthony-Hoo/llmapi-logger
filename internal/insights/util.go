package insights

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// This package deliberately does not import internal/parser: the parser worker
// calls the analyzer, so the dependency must point the other way.

const summaryRunes = 160

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func asMap(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func asSlice(value any) []any {
	result, _ := value.([]any)
	return result
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	}
	return ""
}

func asInt64(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	if err != nil {
		floating, ferr := number.Float64()
		if ferr != nil || floating < 0 {
			return 0, false
		}
		return int64(floating), true
	}
	return parsed, true
}

// pick returns the first present key of an object (several spellings for
// camelCase and snake_case variants).
func pick(object map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := object[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func pickMap(object map[string]any, keys ...string) map[string]any {
	return asMap(pick(object, keys...))
}

func pickString(object map[string]any, keys ...string) string {
	return asString(pick(object, keys...))
}

// firstString returns the first non-empty string value among keys.
func firstString(object map[string]any, keys []string) string {
	for _, key := range keys {
		if value := asString(object[key]); value != "" {
			return value
		}
	}
	return ""
}

// canonicalJSON re-encodes a decoded value with sorted object keys, so equal
// content serializes identically regardless of the client's key order.
func canonicalJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}

func jsonString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if value == nil {
		return ""
	}
	return string(canonicalJSON(value))
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// summarize collapses whitespace and keeps the first 160 runes.
func summarize(text string) string {
	if len(text) > 4*summaryRunes*2 {
		text = text[:4*summaryRunes*2]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	collapsed := strings.Join(strings.Fields(text), " ")
	if utf8.RuneCountInString(collapsed) <= summaryRunes {
		return collapsed
	}
	runes := []rune(collapsed)
	return string(runes[:summaryRunes])
}

// lineCount counts lines of a text block: empty is 0, a trailing newline does
// not add a line.
func lineCount(text string) int {
	if text == "" {
		return 0
	}
	count := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		count++
	}
	return count
}
