package web

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"llmapi-logger/internal/query"
)

// detailLikeService is the fixture's audits with Get behaving as the real
// query.Service.Get: it does not fill the User-Agent (only List reads it).
type detailLikeService struct{ *scopedAudits }

func (audits detailLikeService) Get(ctx context.Context, auditID string, scope *query.Scope) (query.Detail, error) {
	detail, err := audits.scopedAudits.Get(ctx, auditID, scope)
	detail.Audit.UserAgent = nil
	return detail, err
}

// TestRequestDetailAgreesWithTheList: every field the list item and the
// detail share has the same value for the same record (user agent, model,
// status, state, caller, conversation, block fields and the rest), and a
// field that has a value is never null in the detail.
func TestRequestDetailAgreesWithTheList(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.handler.query = detailLikeService{fixture.audits}
	for _, token := range []string{fixture.adminRead, fixture.developer} {
		list := readData(t, fixture.facade(http.MethodGet, "/requests?collapse=false", "", token))
		items, _ := list["items"].([]any)
		if len(items) == 0 {
			t.Fatal("empty list")
		}
		for _, raw := range items {
			item := raw.(map[string]any)
			id := item["audit_id"].(string)
			detail := readData(t, fixture.facade(http.MethodGet, "/requests/"+id, "", token))
			for key, want := range item {
				got, present := detail[key]
				if !present {
					t.Errorf("%s: the detail lacks %s", id, key)
					continue
				}
				if !reflect.DeepEqual(got, want) {
					wantJSON, _ := json.Marshal(want)
					gotJSON, _ := json.Marshal(got)
					t.Errorf("%s %s: list %s, detail %s", id, key, wantJSON, gotJSON)
				}
			}
			if detail["user_agent_untrusted"] == nil {
				t.Errorf("%s: the detail's user agent is null although the record has one", id)
			}
		}
	}
}
