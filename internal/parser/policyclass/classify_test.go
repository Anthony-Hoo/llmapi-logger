package policyclass

import (
	"encoding/json"
	"testing"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		errorObject map[string]any
		want        string
	}{
		{
			name:        "nil envelope",
			errorObject: nil,
			want:        "",
		},
		{
			name:        "empty envelope",
			errorObject: map[string]any{},
			want:        "",
		},
		{
			name:        "cyber policy code",
			errorObject: map[string]any{"code": "cyber_policy", "type": "invalid_request_error", "message": "private detail"},
			want:        ClassCyberPolicy,
		},
		{
			name:        "cyber policy code mixed case",
			errorObject: map[string]any{"code": "Cyber_Policy"},
			want:        ClassCyberPolicy,
		},
		{
			name:        "cyber message flagged for possible risk",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "Your request was flagged for possible cybersecurity risk."},
			want:        ClassCyberPolicy,
		},
		{
			name:        "cyber message high risk cyber activity",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "This request describes high-risk cyber activity."},
			want:        ClassCyberPolicy,
		},
		{
			name:        "cyber message cyber policy",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "Rejected under our cyber policy."},
			want:        ClassCyberPolicy,
		},
		{
			name:        "cyber message cybersecurity risk",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "Blocked because of cybersecurity risk."},
			want:        ClassCyberPolicy,
		},
		{
			name:        "misalignment policy code",
			errorObject: map[string]any{"code": "misalignment_policy_violation", "message": "private detail"},
			want:        ClassMisalignmentPolicy,
		},
		{
			name:        "misalignment message",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "The response was blocked for misalignment with the stated task."},
			want:        ClassMisalignmentPolicy,
		},
		{
			name:        "content policy violation code",
			errorObject: map[string]any{"code": "content_policy_violation"},
			want:        ClassContentPolicy,
		},
		{
			name:        "content policy message",
			errorObject: map[string]any{"message": "This request violates our content policy."},
			want:        ClassContentPolicy,
		},
		{
			name:        "generic policy violation message",
			errorObject: map[string]any{"message": "Request rejected: policy violation detected."},
			want:        ClassContentPolicy,
		},
		{
			name:        "content filter code",
			errorObject: map[string]any{"code": "content_filter"},
			want:        ClassContentFilter,
		},
		{
			name:        "azure responsible ai innererror",
			errorObject: map[string]any{"code": "content_filter", "innererror": map[string]any{"code": "ResponsibleAIPolicyViolation"}},
			want:        ClassContentFilter,
		},
		{
			name:        "azure innererror only",
			errorObject: map[string]any{"type": "invalid_request_error", "innererror": map[string]any{"code": "ResponsibleAIPolicyViolation"}},
			want:        ClassContentFilter,
		},
		{
			name:        "inner error snake case",
			errorObject: map[string]any{"inner_error": map[string]any{"code": "ResponsibleAIPolicyViolation"}},
			want:        ClassContentFilter,
		},
		{
			name:        "azure innererror string value",
			errorObject: map[string]any{"innererror": "ResponsibleAIPolicyViolation"},
			want:        ClassContentFilter,
		},
		{
			name:        "moderation blocked code",
			errorObject: map[string]any{"code": "moderation_blocked"},
			want:        ClassModerationBlocked,
		},
		{
			name:        "safety policy message",
			errorObject: map[string]any{"type": "invalid_request_error", "message": "Your prompt is not allowed by our safety system."},
			want:        ClassSafetyPolicy,
		},
		{
			name:        "generic flagged message falls back to safety",
			errorObject: map[string]any{"message": "The request was flagged."},
			want:        ClassSafetyPolicy,
		},
		{
			name:        "safety policy code",
			errorObject: map[string]any{"code": "safety_policy"},
			want:        ClassSafetyPolicy,
		},
		{
			name:        "type maps when code is generic",
			errorObject: map[string]any{"code": "invalid_request_error", "type": "content_filter"},
			want:        ClassContentFilter,
		},
		{
			name:        "code outranks message phrase",
			errorObject: map[string]any{"code": "moderation_blocked", "message": "flagged for possible cybersecurity risk"},
			want:        ClassModerationBlocked,
		},
		{
			name:        "codex error info cyber",
			errorObject: map[string]any{"type": "invalid_request_error", "codex_error_info": "cyber_policy"},
			want:        ClassCyberPolicy,
		},
		{
			name:        "codex error info object",
			errorObject: map[string]any{"codex_error_info": map[string]any{"code": "cyber_policy"}},
			want:        ClassCyberPolicy,
		},
		{
			name:        "unknown error code",
			errorObject: map[string]any{"code": "server_error", "type": "api_error", "message": "upstream failed"},
			want:        "",
		},
		{
			name:        "numeric code is not a class",
			errorObject: map[string]any{"code": json.Number("400"), "message": "INVALID_ARGUMENT"},
			want:        "",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := Classify(test.errorObject); got != test.want {
				t.Fatalf("Classify(%v) = %q, want %q", test.errorObject, got, test.want)
			}
		})
	}
}

func TestClassifyDoesNotInspectUnrelatedFields(t *testing.T) {
	t.Parallel()

	// Only the error envelope is inspected: class-like strings in other fields
	// must not produce a classification.
	errorObject := map[string]any{
		"code":    "invalid_request_error",
		"message": "request failed",
		"detail":  "cyber_policy",
		"status":  "content_filter",
		"choices": []any{map[string]any{"text": "misalignment_policy"}},
	}
	if got := Classify(errorObject); got != "" {
		t.Fatalf("Classify() = %q, want empty", got)
	}
}

func TestMergeKeepsMostSpecificClass(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		current string
		next    string
		want    string
	}{
		{name: "empty current", current: "", next: ClassCyberPolicy, want: ClassCyberPolicy},
		{name: "empty next", current: ClassCyberPolicy, next: "", want: ClassCyberPolicy},
		{name: "both empty", current: "", next: "", want: ""},
		{name: "specific replaces safety fallback", current: ClassSafetyPolicy, next: ClassCyberPolicy, want: ClassCyberPolicy},
		{name: "safety fallback cannot replace specific", current: ClassContentFilter, next: ClassSafetyPolicy, want: ClassContentFilter},
		{name: "equal precedence keeps existing", current: ClassCyberPolicy, next: ClassContentFilter, want: ClassCyberPolicy},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := Merge(test.current, test.next); got != test.want {
				t.Fatalf("Merge(%q, %q) = %q, want %q", test.current, test.next, got, test.want)
			}
		})
	}
}
