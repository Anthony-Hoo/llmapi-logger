package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestListFiltersAndMapsUpstreamErrorClass(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	parsedErrorType := "invalid_request_error"
	parsedErrorCode := "content_policy_violation"
	upstreamErrorClass := "content_policy"
	rows := []sqlite.AuditListRow{{
		AuditID: "audit-upstream-class", StartedAtNS: 3,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseError,
		ParsedErrorType: &parsedErrorType, ParsedErrorCode: &parsedErrorCode, UpstreamErrorClass: &upstreamErrorClass,
	}}
	var gotFilter sqlite.AuditQueryFilter
	var gotCalls int
	store := &fakeStore{healthy: true, listFunc: func(filter sqlite.AuditQueryFilter, _ sqlite.AuditQueryCursor, _ int) (sqlite.AuditListPage, error) {
		gotCalls++
		gotFilter = filter
		return sqlite.AuditListPage{Rows: rows}, nil
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), Filter{
		UpstreamErrorClass:    upstreamErrorClass,
		CollapseConversations: true,
	}, Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if gotCalls != 1 || gotFilter.UpstreamErrorClass != upstreamErrorClass {
		t.Fatalf("storage filter = %+v, calls = %d", gotFilter, gotCalls)
	}
	// A row filter must disable storage-side conversation collapse so every
	// matching turn stays visible.
	if gotFilter.CollapseConversations {
		t.Fatalf("upstream class filter kept collapse enabled: %+v", gotFilter)
	}
	if len(page.Items) != 1 {
		t.Fatalf("mapped items = %+v", page.Items)
	}
	item := page.Items[0]
	if item.ParsedErrorType == nil || *item.ParsedErrorType != parsedErrorType ||
		item.ParsedErrorCode == nil || *item.ParsedErrorCode != parsedErrorCode ||
		item.UpstreamErrorClass == nil || *item.UpstreamErrorClass != upstreamErrorClass {
		t.Fatalf("mapped parsed error projection = %+v", item)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"parsed_error_type":"invalid_request_error"`,
		`"parsed_error_code":"content_policy_violation"`,
		`"upstream_error_class":"content_policy"`,
	} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("list JSON %s lacks %s", encoded, field)
		}
	}
}

func TestGetMapsUpstreamErrorClass(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-detail-upstream-class"
	requestAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestAAD, []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	upstreamErrorClass := "cyber_policy"
	store := &fakeStore{healthy: true, detail: sqlite.AuditQueryDetail{
		Audit:         sqlite.AuditListRow{AuditID: auditID, StartedAtNS: 1},
		RequestURIEnc: requestURIEnc,
		ParsedResult: &sqlite.ParsedResultSummary{
			ParserName: "openai.chat_completions", ParserVersion: "2", Status: sqlite.ParseError,
			UpstreamErrorClass: &upstreamErrorClass, ParsedAtNS: 2,
		},
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Get(context.Background(), auditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if detail.ParsedResult == nil || detail.ParsedResult.UpstreamErrorClass == nil ||
		*detail.ParsedResult.UpstreamErrorClass != upstreamErrorClass {
		t.Fatalf("detail parsed result = %+v", detail.ParsedResult)
	}
	encoded, err := json.Marshal(detail.ParsedResult)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"upstream_error_class":"cyber_policy"`)) {
		t.Fatalf("parsed result JSON = %s", encoded)
	}
}

func TestListRejectsUnstableUpstreamErrorClass(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	for _, class := range []string{
		"Content_Policy",        // uppercase is not a stable code
		"1content",              // must start with a letter
		"content-policy",        // hyphen is not allowed
		"content policy",        // whitespace is not allowed
		"content.policy",        // punctuation is not allowed
		strings.Repeat("a", 65), // longer than 64 characters
	} {
		class := class
		t.Run(class, func(t *testing.T) {
			called := false
			store := &fakeStore{healthy: true, listFunc: func(sqlite.AuditQueryFilter, sqlite.AuditQueryCursor, int) (sqlite.AuditListPage, error) {
				called = true
				return sqlite.AuditListPage{}, nil
			}}
			service, err := New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			_, listErr := service.List(context.Background(), Filter{UpstreamErrorClass: class}, Cursor{}, 10)
			if !errors.Is(listErr, ErrInvalidQuery) {
				t.Fatalf("List(%q) error = %v, want ErrInvalidQuery", class, listErr)
			}
			if called {
				t.Fatalf("invalid upstream_error_class %q reached storage", class)
			}
		})
	}
	for _, class := range []string{
		"content_policy",
		"a",
		"a" + strings.Repeat("0", 63), // 64 characters is the maximum
	} {
		class := class
		t.Run("valid_"+class, func(t *testing.T) {
			store := &fakeStore{healthy: true}
			service, err := New(store, cipher)
			if err != nil {
				t.Fatal(err)
			}
			if _, listErr := service.List(context.Background(), Filter{UpstreamErrorClass: class}, Cursor{}, 10); listErr != nil {
				t.Fatalf("List(%q) error = %v, want accepted stable code", class, listErr)
			}
		})
	}
}
