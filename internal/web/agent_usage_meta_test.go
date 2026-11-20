package web

import (
	"net/http"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The usage overview is never called complete while the server cannot say
// how many records are not analysed yet (coverage_unknown), and
// billing_complete is false only while some request's billing can still
// change: requests that failed and will never be billed are final.
func TestAgentUsageOverviewCompleteness(t *testing.T) {
	fixture := newReadFixture(t)
	body := decodeAgent(t, fixture.facade(http.MethodGet, "/usage/overview?"+fixtureWindow, "", fixture.adminRead))
	data := readData(t, fixture.facade(http.MethodGet, "/usage/overview?"+fixtureWindow, "", fixture.adminRead))
	if body.Meta == nil || body.Meta.Complete || body.Meta.IncompleteReason != agentIncompleteCoverage || data["coverage_unknown"] != true {
		t.Fatalf("overview meta %+v, coverage_unknown %v", body.Meta, data["coverage_unknown"])
	}

	settled := agentUsageOverviewOf(insights.OverviewResponse{Totals: insights.UsageTotals{Requests: 3, BilledRequests: 1, UnbilledRequests: 2}})
	if !settled.BillingComplete {
		t.Fatal("two final unbilled requests made billing_complete false")
	}
	waiting := agentUsageOverviewOf(insights.OverviewResponse{Totals: insights.UsageTotals{Requests: 3, BilledRequests: 1, UnbilledRequests: 2, PendingBillingRequests: 1}})
	if waiting.BillingComplete {
		t.Fatal("a request whose billing is pending left billing_complete true")
	}
	for _, test := range []struct {
		data   agentUsageOverview
		reason string
	}{
		{agentUsageOverview{CoverageUnknown: true, BillingComplete: true}, agentIncompleteCoverage},
		{agentUsageOverview{CoverageUnknown: false, BillingComplete: false}, agentIncompleteBilling},
		{agentUsageOverview{CoverageUnknown: false, BillingComplete: true}, ""},
	} {
		if meta := usageOverviewMeta(test.data); meta.Complete != (test.reason == "") || meta.IncompleteReason != test.reason {
			t.Errorf("%+v: meta %+v", test.data, meta)
		}
	}
}

// billing_final of a record follows the same rule as billing_complete: only
// an unchecked token link is unsettled.
func TestAgentBillingFinalFollowsTheTokenLink(t *testing.T) {
	for _, test := range []struct {
		name   string
		detail query.Detail
		final  bool
	}{
		{"billed", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingBilled}}, true},
		{"unbilled", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingUnbilled}}, true},
		{"unchecked", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingUnchecked}}, false},
		{"no request id", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerNone}}, true},
		{"caller pending", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerPending}}, true},
		{"caller unresolved", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerUnresolved}}, true},
	} {
		if got := agentBillingFinal(test.detail); got != test.final {
			t.Errorf("%s: billing_final %v, want %v", test.name, got, test.final)
		}
	}
}

// Every usage session card and trend carries the tree_id that `usage tree`
// accepts, a lone agent without sub-agents included, and every emitted id
// resolves for the same identity.
func TestAgentEverySessionCardHasAUsableTreeID(t *testing.T) {
	fixture := newReadFixture(t)
	for name, token := range map[string]string{"admin": fixture.adminRead, "developer": fixture.developer} {
		items, _ := readData(t, fixture.facade(http.MethodGet, "/usage/sessions?"+fixtureWindow, "", token))["items"].([]any)
		if len(items) == 0 {
			t.Fatalf("%s: no session cards", name)
		}
		lone := 0
		for _, item := range items {
			card := item.(map[string]any)
			tree, _ := card["tree_id"].(string)
			if tree == "" {
				t.Errorf("%s: card %v has no tree_id", name, card["session_id"])
				continue
			}
			if card["subagents"] == float64(0) {
				lone++
			}
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/usage/trees/"+tree, "", token)); code != "" {
				t.Errorf("%s: usage tree %s of card %v = %s", name, tree, card["session_id"], code)
			}
			trend := readData(t, fixture.facade(http.MethodGet, "/usage/sessions/"+card["session_id"].(string)+"/trend", "", token))
			if trend["tree_id"] != tree {
				t.Errorf("%s: trend of %v has tree_id %v, the card %s", name, card["session_id"], trend["tree_id"], tree)
			}
		}
		if lone == 0 {
			t.Errorf("%s: the fixture has no card without sub-agents, so the rule is not exercised", name)
		}
	}
}
