package security

import (
	"net/http"
	"net/url"
	"testing"
)

func TestNormalizeNewAPIKeyMatchesNewAPITokenResolution(t *testing.T) {
	// NewAPI reduces a credential to the segment before the first dash after
	// dropping the Bearer scheme and the "sk-" prefix. Every spelling of the
	// same token must therefore normalize identically.
	sameToken := []string{
		"sk-abc123",
		"sk-abc123-channelsuffix",
		"Bearer sk-abc123",
		"bearer sk-abc123-channelsuffix",
		"  sk-abc123  ",
		"abc123",
	}
	for _, raw := range sameToken {
		if got := NormalizeNewAPIKey(raw); got != "abc123" {
			t.Fatalf("NormalizeNewAPIKey(%q) = %q, want %q", raw, got, "abc123")
		}
	}

	for _, raw := range []string{"", "   ", "sk-", "Bearer "} {
		if got := NormalizeNewAPIKey(raw); got != "" {
			t.Fatalf("NormalizeNewAPIKey(%q) = %q, want empty", raw, got)
		}
	}

	if got := NormalizeNewAPIKey("sk-other"); got == "abc123" {
		t.Fatal("distinct keys must not normalize to the same value")
	}
}

func TestExtractCredentialCoversEveryTransport(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		query  url.Values
		want   string
	}{
		{
			name:   "authorization bearer",
			header: http.Header{"Authorization": []string{"Bearer sk-abc123"}},
			want:   "sk-abc123",
		},
		{
			name:   "authorization bare value",
			header: http.Header{"Authorization": []string{"sk-abc123"}},
			want:   "sk-abc123",
		},
		{
			name:   "anthropic header",
			header: http.Header{"X-Api-Key": []string{"sk-abc123"}},
			want:   "sk-abc123",
		},
		{
			name:   "gemini header",
			header: http.Header{"X-Goog-Api-Key": []string{"sk-abc123"}},
			want:   "sk-abc123",
		},
		{
			name:  "gemini query parameter",
			query: url.Values{"key": []string{"sk-abc123"}},
			want:  "sk-abc123",
		},
		{
			name:   "authorization wins over other transports",
			header: http.Header{"Authorization": []string{"Bearer sk-abc123"}, "X-Api-Key": []string{"sk-other"}},
			want:   "sk-abc123",
		},
		{
			name:   "other authentication schemes are ignored",
			header: http.Header{"Authorization": []string{"Basic dXNlcjpwYXNzd29yZA=="}},
			want:   "",
		},
		{
			name: "no credential",
			want: "",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ExtractCredential(testCase.header, testCase.query); got != testCase.want {
				t.Fatalf("ExtractCredential() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestHasCredentialKeepsInterceptorAdmissionSemantics(t *testing.T) {
	// The require_credential interceptor has always demanded the Bearer scheme
	// on Authorization while accepting any non-empty value in the other
	// transports. Sharing the transport list with ExtractCredential must not
	// loosen that.
	allowed := []struct {
		header http.Header
		query  url.Values
	}{
		{header: http.Header{"Authorization": []string{"Bearer sk-abc123"}}},
		{header: http.Header{"Authorization": []string{"bearer sk-abc123"}}},
		{header: http.Header{"X-Api-Key": []string{"sk-abc123"}}},
		{header: http.Header{"X-Goog-Api-Key": []string{"sk-abc123"}}},
		{query: url.Values{"key": []string{"sk-abc123"}}},
	}
	for index, testCase := range allowed {
		if !HasCredential(testCase.header, testCase.query) {
			t.Fatalf("case %d: HasCredential() = false, want true", index)
		}
	}

	rejected := []struct {
		header http.Header
		query  url.Values
	}{
		{},
		{header: http.Header{"Authorization": []string{""}}},
		{header: http.Header{"Authorization": []string{"Bearer"}}},
		{header: http.Header{"Authorization": []string{"Basic dXNlcjpwYXNz"}}},
		{header: http.Header{"Authorization": []string{"sk-abc123"}}},
		{header: http.Header{"X-Api-Key": []string{"   "}}},
		{query: url.Values{"key": []string{""}}},
	}
	for index, testCase := range rejected {
		if HasCredential(testCase.header, testCase.query) {
			t.Fatalf("case %d: HasCredential() = true, want false", index)
		}
	}
}
