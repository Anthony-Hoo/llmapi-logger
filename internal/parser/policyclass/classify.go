// Package policyclass derives one stable, protocol-neutral classification for
// an upstream policy rejection from an already-decoded provider error envelope.
//
// The package is intentionally dependency-free beyond the standard library:
// protocol parsers import it, so importing internal/parser (or protocolutil)
// here would create an import cycle. It only inspects structured error fields;
// it never scans response content or stores the provider message.
package policyclass

import (
	"encoding/json"
	"strings"
)

// Stable upstream policy classes persisted in parsed_results. They are part of
// the public query contract, so values never change once shipped.
const (
	ClassCyberPolicy        = "cyber_policy"
	ClassMisalignmentPolicy = "misalignment_policy"
	ClassContentPolicy      = "content_policy"
	ClassContentFilter      = "content_filter"
	ClassModerationBlocked  = "moderation_blocked"
	ClassSafetyPolicy       = "safety_policy"
)

// precedence orders classes from most to least specific. Explicit provider
// policy codes outrank generic content filters, and safety_policy is the
// message-only fallback used when no more specific code is available.
var precedence = map[string]int{
	ClassCyberPolicy:        6,
	ClassMisalignmentPolicy: 5,
	ClassContentPolicy:      4,
	ClassContentFilter:      3,
	ClassModerationBlocked:  2,
	ClassSafetyPolicy:       1,
}

var cyberPhrases = []string{
	"flagged for possible cybersecurity risk",
	"high-risk cyber activity",
	"cyber policy",
	"cybersecurity risk",
}

var misalignmentPhrases = []string{
	"misalignment policy",
	"misalignment",
}

var contentPhrases = []string{
	"content policy",
	"policy violation",
}

var safetyPhrases = []string{
	"not allowed by our safety system",
	"flagged by our safety system",
	"safety system",
	"flagged",
}

// Classify returns the stable class for one provider error object. The caller
// passes the decoded "error" object itself, not the root response envelope.
//
// Explicit identifiers are inspected first in this order: code, type,
// innererror/inner_error.code, codex_error_info. The message is consulted only
// when none of those identifiers maps to a class, and only exact, known
// phrases count. An unrecognized envelope returns "".
func Classify(errorObject map[string]any) string {
	if errorObject == nil {
		return ""
	}
	for _, identifier := range errorIdentifiers(errorObject) {
		if class := classifyIdentifier(identifier); class != "" {
			return class
		}
	}
	return classifyMessage(stringValue(errorObject["message"]))
}

// Merge combines a class already derived for one result with a later one from
// another parse path. Empty values are ignored, a more specific class replaces
// a less specific one, and equal precedence keeps the existing class so a
// nested error object never overwrites an earlier, equally specific finding.
func Merge(current, next string) string {
	if next == "" {
		return current
	}
	if current == "" || precedence[next] > precedence[current] {
		return next
	}
	return current
}

// errorIdentifiers returns the structured classification candidates in
// priority order. Empty entries are harmless and skipped by the caller.
func errorIdentifiers(errorObject map[string]any) []string {
	identifiers := make([]string, 0, 8)
	identifiers = append(identifiers, stringValue(errorObject["code"]), stringValue(errorObject["type"]))
	for _, key := range []string{"innererror", "inner_error", "innerError"} {
		if inner := mapValue(errorObject[key]); inner != nil {
			identifiers = append(identifiers, stringValue(inner["code"]))
			continue
		}
		identifiers = append(identifiers, stringValue(errorObject[key]))
	}
	if info := mapValue(errorObject["codex_error_info"]); info != nil {
		identifiers = append(identifiers, stringValue(info["code"]), stringValue(info["type"]))
	} else {
		identifiers = append(identifiers, stringValue(errorObject["codex_error_info"]))
	}
	return identifiers
}

func classifyIdentifier(identifier string) string {
	switch strings.ToLower(strings.TrimSpace(identifier)) {
	case "cyber_policy", "cyber", "cybersecurity":
		return ClassCyberPolicy
	case "misalignment_policy", "misalignment_policy_violation", "misalignment":
		return ClassMisalignmentPolicy
	case "content_policy", "content_policy_violation":
		return ClassContentPolicy
	case "content_filter", "contentfilter", "responsibleaipolicyviolation":
		return ClassContentFilter
	case "moderation_blocked", "moderation":
		return ClassModerationBlocked
	case "safety_policy", "safety":
		return ClassSafetyPolicy
	default:
		return ""
	}
}

func classifyMessage(message string) string {
	normalized := strings.ToLower(strings.TrimSpace(message))
	if normalized == "" {
		return ""
	}
	for _, phrase := range cyberPhrases {
		if strings.Contains(normalized, phrase) {
			return ClassCyberPolicy
		}
	}
	for _, phrase := range misalignmentPhrases {
		if strings.Contains(normalized, phrase) {
			return ClassMisalignmentPolicy
		}
	}
	for _, phrase := range contentPhrases {
		if strings.Contains(normalized, phrase) {
			return ClassContentPolicy
		}
	}
	for _, phrase := range safetyPhrases {
		if strings.Contains(normalized, phrase) {
			return ClassSafetyPolicy
		}
	}
	return ""
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}
