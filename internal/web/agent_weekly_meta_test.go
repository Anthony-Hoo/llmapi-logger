package web

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
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
	// the snapshot do not. The unattributed list is a live view computed
	// with the current rules, never the snapshot, so it is complete once the
	// week has ended (contract section 0.1 item 146).
	expect("/weekly/report?week="+ended, fixture.adminRead, true)
	expect("/weekly/unattributed?week="+ended, fixture.adminRead, true)
	for _, path := range []string{"/weekly/projects/-1?week=" + ended, "/weekly/projects/-2?week=" + ended} {
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

// manyUnattributed answers Unattributed with count entries, at most the
// limit asked for, as the service does.
type manyUnattributed struct {
	OrgReports
	count int
}

func (org manyUnattributed) Unattributed(_ context.Context, _ string, limit int) ([]orgreport.UnattributedEntry, error) {
	entries := []orgreport.UnattributedEntry{}
	for index := 0; index < org.count && index < limit; index++ {
		entries = append(entries, orgreport.UnattributedEntry{Kind: "repo_name", Value: "repo-" + strconv.Itoa(index), Requests: 1, Users: 1})
	}
	return entries, nil
}

// weekly unattributed says when --limit cut the list: meta.complete false
// with truncated, data.truncated, and a next action besides the one that
// says the list is computed with the current rules; a list that fits is not
// called truncated, and a full page at the server's maximum is called
// possibly cut.
func TestAgentWeeklyUnattributedSaysWhenTheLimitCutIt(t *testing.T) {
	fixture := newReadFixture(t)
	original := fixture.handler.org
	defer func() { fixture.handler.org = original }()
	for _, test := range []struct {
		count, limit, items int
		truncated           bool
	}{
		{5, 3, 3, true}, {3, 3, 3, false}, {2, 20, 2, false}, {250, 200, 200, true}, {199, 200, 199, false},
	} {
		fixture.handler.org = manyUnattributed{OrgReports: original, count: test.count}
		response := fixture.facade(http.MethodGet, "/weekly/unattributed?limit="+strconv.Itoa(test.limit), "", fixture.adminRead)
		body := decodeAgent(t, response)
		data := readData(t, response)
		items, _ := data["items"].([]any)
		if len(items) != test.items || data["truncated"] != test.truncated || body.Meta == nil ||
			(body.Meta.IncompleteReason == agentIncompleteTruncated) != test.truncated || (len(body.NextActions) > 1) != test.truncated {
			t.Errorf("%d entries, limit %d: %s", test.count, test.limit, response.Body.String())
		}
	}
}

// weekly unattributed is a live view: it is computed with the current
// project rules even for a frozen week, so a rule added after the freeze
// changes it while the frozen snapshot (weekly project -1) does not. Its
// meta never claims more than is known (the week has ended, the list was
// not cut), and data, next_actions and the Skill say that it can differ
// from the snapshot.
func TestWeeklyUnattributedIsALiveView(t *testing.T) {
	fixture := newWriteFixture(t)
	ctx := context.Background()
	service, memory := newOrgWriteService(t, fixture.clock, fixture.snapshots)
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	repoKey := hex.EncodeToString([]byte("live-view-repo"))
	memory.identities = append(memory.identities,
		sealIdentity(t, cipher, repoKey, "lv0", orgreport.Identity{Source: orgreport.SourceCodexTurnMetadata, Remotes: []string{"git.example.com/team/live-view-repo"}}))
	at := orgTestWeek.Add(30 * time.Hour).UnixNano()
	memory.requests = append(memory.requests, orgreport.Request{AuditID: "lv0", StartNS: at, EndNS: at + int64(time.Minute),
		UserID: 7, TokenID: 70, Client: "codex", Role: "main", RootKey: "root-lv", NodeKey: "root-lv", IdentityKey: repoKey})
	fixture.handler.org = service
	week := orgTestWeek.Format("2006-01-02")
	if err := service.Regenerate(ctx, week); err != nil {
		t.Fatal(err)
	}
	service.WaitSnapshots()
	type read struct {
		data    map[string]any
		meta    agentapi.Meta
		actions []string
	}
	get := func(path string) read {
		t.Helper()
		response := fixture.facade(http.MethodGet, path, nil, fixture.adminRead)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", path, response.Code, response.Body.String())
		}
		var envelope struct {
			Data    map[string]any `json:"data"`
			Meta    agentapi.Meta  `json:"meta"`
			Actions []string       `json:"next_actions"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		return read{envelope.Data, envelope.Meta, envelope.Actions}
	}
	before := get("/weekly/unattributed?week=" + week)
	snapshotBefore := get("/weekly/projects/-1?week=" + week)
	if before.data["computed_with"] != agentComputedWithCurrentRules || before.data["week_frozen"] != true ||
		!before.meta.Complete || before.meta.State == "final" {
		t.Fatalf("frozen week's unattributed list: data %v meta %+v", before.data, before.meta)
	}
	if len(before.actions) != 1 || !strings.Contains(before.actions[0], "frozen snapshot") || !strings.Contains(before.actions[0], "llmaudit weekly project -1") {
		t.Fatalf("next_actions %v", before.actions)
	}
	items, _ := before.data["items"].([]any)
	var rule map[string]any
	for _, raw := range items {
		if item := raw.(map[string]any); strings.HasSuffix(toText(item["value_untrusted"]), "/live-view-repo") {
			rule, _ = item["draft_rule"].(map[string]any)
		}
	}
	if rule == nil {
		t.Fatalf("no unattributed entry for the repository: %v", items)
	}
	if _, err := service.CreateProject(ctx, orgreport.ProjectInput{Name: "live-view-project", Enabled: true,
		Rules: []orgreport.Rule{{Kind: rule["kind"].(string), Pattern: rule["pattern_untrusted"].(string)}}}); err != nil {
		t.Fatal(err)
	}
	after := get("/weekly/unattributed?week=" + week)
	snapshotAfter := get("/weekly/projects/-1?week=" + week)
	afterItems, _ := after.data["items"].([]any)
	for _, raw := range afterItems {
		if strings.HasSuffix(toText(raw.(map[string]any)["value_untrusted"]), "/live-view-repo") {
			t.Fatal("the new rule did not move the entry out of the live list")
		}
	}
	if !reflect.DeepEqual(snapshotBefore.data, snapshotAfter.data) {
		t.Fatalf("the frozen snapshot moved: %v -> %v", snapshotBefore.data, snapshotAfter.data)
	}
}

// frozenTrend answers Trend with the weeks given, as the service would for
// weeks in those states.
type frozenTrend struct {
	OrgReports
	frozen []bool
}

func (org frozenTrend) Trend(context.Context, int, *int64) (orgreport.TrendReport, error) {
	report := orgreport.TrendReport{Projects: []orgreport.ProjectRef{}}
	for index, frozen := range org.frozen {
		report.Weeks = append(report.Weeks, orgreport.TrendWeek{Week: orgTestWeek.AddDate(0, 0, 7*index).Format("2006-01-02"), Frozen: frozen, Projects: []orgreport.ProjectCell{}})
	}
	return report, nil
}

// A trend is complete exactly when every week in it is final (frozen): a
// trend of closed, frozen weeks only is complete, one week that is not
// frozen makes it incomplete. The service's own trend always ends with the
// current week, so through it the trend is incomplete.
func TestWeeklyTrendIsCompleteOnlyOverFrozenWeeks(t *testing.T) {
	fixture := newReadFixture(t)
	original := fixture.handler.org
	defer func() { fixture.handler.org = original }()
	for _, test := range []struct {
		frozen   []bool
		complete bool
	}{
		{[]bool{true, true, true}, true}, {[]bool{true}, true}, {[]bool{true, false}, false}, {[]bool{false, true}, false},
	} {
		fixture.handler.org = frozenTrend{OrgReports: original, frozen: test.frozen}
		body := decodeAgent(t, fixture.facade(http.MethodGet, "/weekly/trend?weeks="+strconv.Itoa(len(test.frozen)), "", fixture.adminRead))
		if body.Meta == nil || body.Meta.Complete != test.complete || (!test.complete && body.Meta.IncompleteReason != agentIncompleteEvidencePending) {
			t.Errorf("frozen %v: meta %+v", test.frozen, body.Meta)
		}
	}
	fixture.handler.org = original
	if body := decodeAgent(t, fixture.facade(http.MethodGet, "/weekly/trend?weeks=2", "", fixture.adminRead)); body.Meta == nil || body.Meta.Complete {
		t.Errorf("the service's trend, which includes the current week: meta %+v", body.Meta)
	}
}
func toText(value any) string {
	text, _ := value.(string)
	return text
}
