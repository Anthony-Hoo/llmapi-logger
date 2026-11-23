package web

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
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

// A credential-shaped User-Agent is null in the list and in the detail, as the
// headers view omits it by the same rule (contract section 0.1 item 174).
func TestRequestUserAgentIsMaskedLikeItsHeader(t *testing.T) {
	fixture := newReadFixture(t)
	fixture.handler.query = detailLikeService{fixture.audits}
	const credential = "Bearer sk-example-not-a-real-key"
	found := false
	for index := range fixture.audits.records {
		record := &fixture.audits.records[index]
		if record.detail.Audit.AuditID != "own-1" {
			continue
		}
		found = true
		value := credential
		record.detail.Audit.UserAgent = &value
		for headerIndex := range record.detail.Headers {
			if header := &record.detail.Headers[headerIndex]; strings.EqualFold(header.Name, "user-agent") {
				header.Value = credential
			}
		}
	}
	if !found {
		t.Fatal("fixture record own-1 missing")
	}
	list := readData(t, fixture.facade(http.MethodGet, "/requests?collapse=false", "", fixture.adminRead))
	for _, raw := range list["items"].([]any) {
		item := raw.(map[string]any)
		switch item["audit_id"] {
		case "own-1":
			if value, present := item["user_agent_untrusted"]; !present || value != nil {
				t.Errorf("list user agent of a credential-shaped value = %v (present %v)", value, present)
			}
		default:
			// A normal User-Agent is still output.
			if item["user_agent_untrusted"] == nil {
				t.Errorf("%s: normal user agent dropped", item["audit_id"])
			}
		}
	}
	response := fixture.facade(http.MethodGet, "/requests/own-1?headers=all", "", fixture.adminRead)
	detail := readData(t, response)
	if value, present := detail["user_agent_untrusted"]; !present || value != nil {
		t.Errorf("detail user agent of a credential-shaped value = %v (present %v)", value, present)
	}
	if strings.Contains(response.Body.String(), "sk-example") {
		t.Errorf("the detail carries the credential: %s", response.Body.String())
	}
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
