package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The usage overview's meta.complete carries information: whether every
// record is analysed cannot be determined through this interface, so it is
// not a reason of meta (a flag false on every call says nothing); it stays
// the data field coverage_unknown with its next_actions sentence, and
// meta.complete is false exactly while billing is pending (billing_pending).
// billing_complete is false only while some request's billing can still
// change: requests that failed and will never be billed are final.
func TestAgentUsageOverviewCompleteness(t *testing.T) {
	fixture := newReadFixture(t)
	for _, token := range []string{fixture.adminRead, fixture.developer} {
		response := fixture.facade(http.MethodGet, "/usage/overview?"+fixtureWindow, "", token)
		body := decodeAgent(t, response)
		data := readData(t, response)
		// Every fixture request is billed, so the overview is complete.
		if body.Meta == nil || !body.Meta.Complete || body.Meta.IncompleteReason != "" || data["coverage_unknown"] != true || data["billing_complete"] != true {
			t.Fatalf("overview meta %+v, data coverage_unknown %v billing_complete %v", body.Meta, data["coverage_unknown"], data["billing_complete"])
		}
		if len(body.NextActions) != 1 || !strings.Contains(body.NextActions[0], "analysed records only") || !strings.Contains(body.NextActions[0], "cannot be checked") {
			t.Fatalf("next_actions %v", body.NextActions)
		}
	}

	// A request whose billing is still being backfilled makes the overview
	// incomplete through the endpoint: billing_pending, billing_complete
	// false. The stores refuse to write a new unchecked link (only migration
	// 009 left such links), so the real service's answer is taken and one
	// pending request added to it, as the service reports such a link
	// (TestInsightsPendingBillingCountsOnlyUnsettledRequests).
	fixture.handler.insights = pendingBilling{InsightsQuery: fixture.handler.insights}
	for _, token := range []string{fixture.adminRead, fixture.developer} {
		response := fixture.facade(http.MethodGet, "/usage/overview?"+fixtureWindow, "", token)
		body := decodeAgent(t, response)
		data := readData(t, response)
		if body.Meta == nil || body.Meta.Complete || body.Meta.IncompleteReason != agentIncompleteBilling || data["billing_complete"] != false {
			t.Fatalf("overview with pending billing: meta %+v, billing_complete %v", body.Meta, data["billing_complete"])
		}
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
		{agentUsageOverview{CoverageUnknown: true, BillingComplete: true}, ""},
		{agentUsageOverview{CoverageUnknown: true, BillingComplete: false}, agentIncompleteBilling},
		{agentUsageOverview{CoverageUnknown: false, BillingComplete: false}, agentIncompleteBilling},
		{agentUsageOverview{CoverageUnknown: false, BillingComplete: true}, ""},
		{waiting, agentIncompleteBilling},
		{settled, ""},
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

// Contract section 0.1 item 157: every agent row of `analysis sessions` has
// a tree_id (a stored session always has its 32-byte root), and `usage tree`
// answers it for the same identity.
func TestAgentEveryAnalysisAgentRowHasAUsableTreeID(t *testing.T) {
	fixture := newReadFixture(t)
	for name, token := range map[string]string{"admin": fixture.adminRead, "developer": fixture.developer} {
		items, _ := readData(t, fixture.facade(http.MethodGet, "/analysis/sessions?"+fixtureWindow, "", token))["items"].([]any)
		if len(items) == 0 {
			t.Fatalf("%s: no analysis sessions", name)
		}
		for _, item := range items {
			row := item.(map[string]any)
			if row["kind"] != "agent" {
				continue
			}
			tree, _ := row["tree_id"].(string)
			if tree == "" {
				t.Errorf("%s: agent row %v has no tree_id", name, row["session_id"])
				continue
			}
			if code := facadeOutcome(t, fixture.facade(http.MethodGet, "/usage/trees/"+tree, "", token)); code != "" {
				t.Errorf("%s: usage tree %s of analysis row %v = %s", name, tree, row["session_id"], code)
			}
		}
	}
}

// pendingBilling is the real insights service whose overview reports one
// request more whose billing is pending.
type pendingBilling struct {
	InsightsQuery
}

func (service pendingBilling) Overview(ctx context.Context, request query.OverviewQuery) (insights.OverviewResponse, error) {
	response, err := service.InsightsQuery.Overview(ctx, request)
	response.Totals.PendingBillingRequests++
	return response, err
}
