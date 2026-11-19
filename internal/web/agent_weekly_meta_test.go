package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestWeeklyReadsAreCompleteOnlyWhenFinal: the weekly reads whose services
// give no completeness of their own report complete=false (reason
// evidence_pending, as /weekly/report) while the week they cover is open or
// not frozen yet, and complete=true once it is frozen; a trend is complete
// only when every week in it is.
func TestWeeklyReadsAreCompleteOnlyWhenFinal(t *testing.T) {
	fixture := newWriteFixture(t)
	ended := orgTestWeek.Format("2006-01-02")
	meta := func(path, token string) (bool, string, bool) {
		t.Helper()
		response := fixture.facade(http.MethodGet, path, nil, token)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", path, response.Code, response.Body.String())
		}
		var envelope struct {
			Data struct {
				Final *bool `json:"final"`
			} `json:"data"`
			Meta struct {
				Complete bool   `json:"complete"`
				Reason   string `json:"incomplete_reason"`
			} `json:"meta"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		final := envelope.Data.Final != nil && *envelope.Data.Final
		return envelope.Meta.Complete, envelope.Meta.Reason, final
	}
	expect := func(path, token string, complete bool) {
		t.Helper()
		got, reason, final := meta(path, token)
		if got != complete || (!complete && reason != agentIncompleteEvidencePending) || (complete && reason != "") {
			t.Errorf("%s: complete=%v reason=%q, want complete=%v", path, got, reason, complete)
		}
		if final && !got {
			t.Errorf("%s: final data reported incomplete", path)
		}
	}
	// The current week is open: nothing about it is final.
	for _, path := range []string{"/weekly/projects/-1", "/weekly/projects/-2", "/weekly/unattributed", "/weekly/trend?weeks=2", "/weekly/report"} {
		expect(path, fixture.adminRead, false)
	}
	// The ended week before it is not frozen yet: the report counts it
	// complete (its evidence is in), the reads that only become final with
	// the snapshot do not.
	expect("/weekly/report?week="+ended, fixture.adminRead, true)
	for _, path := range []string{"/weekly/projects/-1?week=" + ended, "/weekly/projects/-2?week=" + ended, "/weekly/unattributed?week=" + ended} {
		expect(path, fixture.adminRead, false)
	}
	// Frozen: final and complete.
	if err := fixture.org.Regenerate(context.Background(), ended); err != nil {
		t.Fatal(err)
	}
	fixture.org.WaitSnapshots()
	for _, path := range []string{"/weekly/report?week=" + ended, "/weekly/projects/-1?week=" + ended, "/weekly/projects/-2?week=" + ended, "/weekly/unattributed?week=" + ended} {
		expect(path, fixture.adminRead, true)
	}
	// A trend that includes the open week stays incomplete.
	expect("/weekly/trend?weeks=2", fixture.adminRead, false)
	// My week: the developer's row is of the open week; an administrator has
	// no row, so nothing can change.
	expect("/weekly/me", fixture.developer, false)
	expect("/weekly/me", fixture.adminRead, true)
}
