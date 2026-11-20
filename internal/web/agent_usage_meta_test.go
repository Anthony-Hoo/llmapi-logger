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

// billing_final of a record follows the same rule as billing_complete: a
// record without a token link is final only once its caller lookup is over.
func TestAgentBillingFinalWaitsForTheCallerLookup(t *testing.T) {
	for _, test := range []struct {
		name   string
		detail query.Detail
		final  bool
	}{
		{"billed", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingBilled}}, true},
		{"unbilled", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingUnbilled}}, true},
		{"unchecked", query.Detail{TokenLink: &query.TokenLink{BillingState: storage.BillingUnchecked}}, false},
		{"no request id", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerNone}}, true},
		{"caller pending", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerPending}}, false},
		{"caller unresolved", query.Detail{Audit: query.AuditSummary{CallerStatus: storage.CallerUnresolved}}, true},
	} {
		if got := agentBillingFinal(test.detail); got != test.final {
			t.Errorf("%s: billing_final %v, want %v", test.name, got, test.final)
		}
	}
}
