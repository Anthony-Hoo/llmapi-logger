package query

import (
	"context"
	"testing"

	"llmapi-logger/internal/storage/sqlite"
)

func TestEveryRowFilterDisablesStorageCollapse(t *testing.T) {
	t.Parallel()
	ns, id, code := int64(10), int64(1), 503
	for name, filter := range map[string]Filter{
		"from": {FromNS: &ns}, "to": {ToNS: &ns},
		"protocol": {Protocol: "openai"}, "path": {Path: "/v1/responses"},
		"model": {Model: "model-example"}, "user agent": {UserAgent: "client"},
		"status code": {StatusCode: &code}, "status class": {StatusClass: "5xx"},
		"forward":    {ForwardStatus: sqlite.ForwardCompleted},
		"blocked by": {BlockedBy: "guard"}, "block code": {BlockCode: "blocked"},
		"capture": {CaptureStatus: sqlite.CapturePartial},
		"user id": {NewAPIUserID: &id}, "username": {Username: "example-user"},
		"token id": {NewAPITokenID: &id}, "token name": {TokenName: "example-token"},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			store := &fakeStore{listFunc: func(got sqlite.AuditQueryFilter, _ sqlite.AuditQueryCursor, _ int) (sqlite.AuditListPage, error) {
				called = true
				if got.CollapseConversations {
					t.Fatal("row filter was combined with SQL collapse")
				}
				return sqlite.AuditListPage{}, nil
			}}
			service, err := New(store, testCipher(t))
			if err != nil {
				t.Fatal(err)
			}
			filter.CollapseConversations = true
			if _, err := service.List(context.Background(), filter, Cursor{}, 10); err != nil || !called {
				t.Fatalf("list called=%v error=%v", called, err)
			}
		})
	}
}
