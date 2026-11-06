package orgreport

import (
	"testing"
	"time"
)

var testWeekStart = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

func testSettings() Settings {
	return Settings{
		Location: time.UTC, WeekStart: time.Monday, IdleGap: 180 * time.Second,
		RankedClients:      map[string]bool{"codex": true, "claude_code": true},
		MaxConcurrentRoots: 10, MaxSingleRequestRoots: 200,
	}
}

// at returns ns at offset seconds after the test week start.
func at(seconds int64) int64 { return testWeekStart.UnixNano() + seconds*sec }

func req(id string, user int64, root string, start, end int64, project ProjectKey) Request {
	return Request{AuditID: id, UserID: user, TokenID: 100 + user, Client: "codex", Role: "main",
		RootKey: root, NodeKey: root, StartNS: at(start), EndNS: at(end), Project: project, IdentityKey: "id"}
}

func compute(t *testing.T, requests []Request, principals Principals, mutate ...func(*Settings)) WeekResult {
	t.Helper()
	settings := testSettings()
	for _, change := range mutate {
		change(&settings)
	}
	return ComputeWeek(WeekInput{
		Week:     Week{Start: testWeekStart, End: testWeekStart.AddDate(0, 0, 7)},
		Settings: settings, Requests: requests, Principals: principals,
	})
}

func userRow(t *testing.T, result WeekResult, user int64) UserRow {
	t.Helper()
	for _, row := range result.Users {
		if row.UserID == user {
			return row
		}
	}
	t.Fatalf("no row for user %d in %+v", user, result.Users)
	return UserRow{}
}

func cell(row UserRow, project ProjectKey) ProjectCell {
	for _, item := range row.Projects {
		if item.Project == project {
			return item
		}
	}
	return ProjectCell{}
}

func TestParallelRootsAreSummed(t *testing.T) {
	result := compute(t, []Request{
		req("a", 1, "root-1", 100, 160, 1),
		req("b", 1, "root-2", 100, 160, 1),
		req("c", 1, "root-3", 130, 190, 2),
	}, Principals{})
	row := userRow(t, result, 1)
	if row.ActiveNS != 180*sec {
		t.Fatalf("active = %d, want three parallel 60 s roots summed (180 s)", row.ActiveNS/sec)
	}
	if row.Roots != 3 || row.PeakConcurrency != 3 || row.SingleRequestRoots != 3 {
		t.Fatalf("roots=%d peak=%d single=%d", row.Roots, row.PeakConcurrency, row.SingleRequestRoots)
	}
	// Union is 100..190 = 90 s; sum 180 s; average 2.
	if row.AvgConcurrency != 2 {
		t.Fatalf("average concurrency = %v, want 2", row.AvgConcurrency)
	}
	if cell(row, 1).ActiveNS != 120*sec || cell(row, 2).ActiveNS != 60*sec {
		t.Fatalf("projects = %+v", row.Projects)
	}
}

func TestSubAgentsAreUnionedIntoTheirRoot(t *testing.T) {
	parent := req("p1", 1, "root", 0, 100, 1)
	child := req("c1", 1, "root", 20, 80, 1)
	child.NodeKey, child.Role = "child", "subagent"
	late := req("c2", 1, "root", 150, 200, 1)
	late.NodeKey, late.Role = "child", "subagent"
	row := userRow(t, compute(t, []Request{parent, child, late}, Principals{}), 1)
	if row.ActiveNS != 200*sec || row.Roots != 1 || row.PeakConcurrency != 1 {
		t.Fatalf("active=%d roots=%d peak=%d, want one 200 s root", row.ActiveNS/sec, row.Roots, row.PeakConcurrency)
	}
	if row.SingleRequestRoots != 0 {
		t.Fatal("a multi-request root counted as single-request")
	}
}

func TestIdleGapBoundaryInsideARoot(t *testing.T) {
	merged := userRow(t, compute(t, []Request{req("a", 1, "r", 0, 10, 1), req("b", 1, "r", 190, 200, 1)}, Principals{}), 1)
	if merged.ActiveNS != 200*sec {
		t.Fatalf("gap of exactly 180 s: active = %d s, want 200 (merged)", merged.ActiveNS/sec)
	}
	split := userRow(t, compute(t, []Request{req("a", 1, "r", 0, 10, 1), req("b", 1, "r", 191, 201, 1)}, Principals{}), 1)
	if split.ActiveNS != 20*sec {
		t.Fatalf("gap of 181 s: active = %d s, want 20 (two blocks)", split.ActiveNS/sec)
	}
}

func TestSingleRequestUsesItsRealDuration(t *testing.T) {
	row := userRow(t, compute(t, []Request{req("a", 1, "r", 50, 64, 1)}, Principals{}), 1)
	if row.ActiveNS != 14*sec || cell(row, 1).ActiveNS != 14*sec || row.SingleRequestRoots != 1 {
		t.Fatalf("row = %+v", row)
	}
}

func TestBlocksAreSplitAcrossMidnightAndWeekBoundaries(t *testing.T) {
	// A block from Monday 23:50 to Tuesday 00:20 (two requests 30 min apart
	// would split, so chain them every two minutes).
	var requests []Request
	for index := int64(0); index <= 15; index++ {
		start := 24*3600 - 600 + index*120
		requests = append(requests, req("m"+string(rune('a'+index)), 1, "r", start, start+120, 1))
	}
	row := userRow(t, compute(t, requests, Principals{}), 1)
	if row.Daily[0] != 600*sec || row.Daily[1] != 1320*sec {
		t.Fatalf("daily = %v s, want 600 on Monday and 1320 on Tuesday", []int64{row.Daily[0] / sec, row.Daily[1] / sec})
	}
	if row.ActiveNS != 1920*sec {
		t.Fatalf("active = %d", row.ActiveNS/sec)
	}

	// A block straddling the week start: only the in-week part counts, and
	// the root counts once.
	straddle := []Request{
		req("w1", 2, "r", -300, -120, 1), // Sunday 23:55 .. 23:58 of the previous week
		req("w2", 2, "r", -60, 240, 1),   // crosses into Monday
	}
	row = userRow(t, compute(t, straddle, Principals{}), 2)
	if row.ActiveNS != 240*sec || row.Daily[0] != 240*sec || row.Requests != 0 || row.Roots != 1 {
		t.Fatalf("straddling row = %+v (active %d s)", row, row.ActiveNS/sec)
	}

	// And one straddling the week end: 7 days minus 60 s .. +120 s.
	end := int64(7 * 24 * 3600)
	row = userRow(t, compute(t, []Request{req("e1", 3, "r", end-60, end+120, 1)}, Principals{}), 3)
	if row.ActiveNS != 60*sec || row.Daily[6] != 60*sec || row.Requests != 1 {
		t.Fatalf("week-end row = %+v", row)
	}
}

func TestProjectsSplitABlockByRequestDuration(t *testing.T) {
	row := userRow(t, compute(t, []Request{
		req("a", 1, "r", 0, 90, 1),
		req("b", 1, "r", 100, 130, ProjectUnattributed),
	}, Principals{}), 1)
	// Block is 130 s; weights 90 : 30.
	if cell(row, 1).ActiveNS != 97500*int64(time.Millisecond) || cell(row, ProjectUnattributed).ActiveNS != 32500*int64(time.Millisecond) {
		t.Fatalf("projects = %+v", row.Projects)
	}
	if cell(row, 1).Roots != 1 || cell(row, ProjectUnattributed).Roots != 1 {
		t.Fatalf("project roots = %+v", row.Projects)
	}
}

func TestServicePrincipalsLeaveTheRanking(t *testing.T) {
	human := req("h", 1, "r1", 0, 60, 1)
	serviceUser := req("s", 2, "r2", 0, 60, 1)
	serviceToken := req("t", 3, "r3", 0, 30, 1)
	serviceToken.TokenID = 900
	sameUserHumanToken := req("u", 3, "r4", 100, 160, 1)
	result := compute(t, []Request{human, serviceUser, serviceToken, sameUserHumanToken}, Principals{
		UserClass:  map[int64]string{2: ClassService, 3: ClassHuman},
		TokenClass: map[int64]string{900: ClassService},
	})
	if len(result.Users) != 2 || result.Users[0].UserID != 1 && result.Users[0].UserID != 3 {
		t.Fatalf("users = %+v", result.Users)
	}
	for _, row := range result.Users {
		if row.UserID == 2 {
			t.Fatal("service user is ranked")
		}
	}
	if row := userRow(t, result, 3); row.ActiveNS != 60*sec || row.Requests != 1 {
		t.Fatalf("human part of user 3 = %+v", row)
	}
	if len(result.Service) != 2 {
		t.Fatalf("service = %+v", result.Service)
	}
	if result.Service[0].UserID != 2 || result.Service[0].TokenID != 0 || result.Service[0].ActiveNS != 60*sec {
		t.Fatalf("service user row = %+v", result.Service[0])
	}
	if result.Service[1].UserID != 3 || result.Service[1].TokenID != 900 || result.Service[1].ActiveNS != 30*sec {
		t.Fatalf("service token row = %+v", result.Service[1])
	}
}

func TestUnrankedClientsAreReportedSeparately(t *testing.T) {
	chat := req("c", 1, "r2", 0, 100, ProjectNoContext)
	chat.Client = "unknown"
	result := compute(t, []Request{req("a", 1, "r1", 0, 50, 1), chat}, Principals{})
	row := userRow(t, result, 1)
	if row.ActiveNS != 50*sec || row.OtherActiveNS != 100*sec || row.PeakConcurrency != 1 {
		t.Fatalf("row = %+v", row)
	}
	if cell(row, ProjectNoContext).ActiveNS != 0 || cell(row, ProjectNoContext).Requests != 1 {
		t.Fatalf("unranked time leaked into the project split: %+v", row.Projects)
	}
}

func TestAnomalyFlagsDoNotExclude(t *testing.T) {
	var requests []Request
	for index := 0; index < 5; index++ {
		requests = append(requests, req("p"+string(rune('a'+index)), 1, "root-"+string(rune('a'+index)), 0, 60, 1))
	}
	result := compute(t, requests, Principals{}, func(settings *Settings) {
		settings.MaxConcurrentRoots = 3
		settings.MaxSingleRequestRoots = 4
	})
	row := userRow(t, result, 1)
	if row.ActiveNS != 300*sec {
		t.Fatalf("flagged row lost time: %d", row.ActiveNS/sec)
	}
	codes := map[string]Flag{}
	for _, flag := range row.Flags {
		codes[flag.Code] = flag
	}
	if codes[FlagConcurrency].Value != 5 || codes[FlagConcurrency].Threshold != 3 {
		t.Fatalf("flags = %+v", row.Flags)
	}
	if codes[FlagSingleRequestRoots].Value != 5 || codes[FlagSingleRequestRoots].Threshold != 4 {
		t.Fatalf("flags = %+v", row.Flags)
	}
}

func TestSideRequestsWithoutSessionCountUsageOnly(t *testing.T) {
	compaction := req("x", 1, "", 0, 600, ProjectNoContext)
	compaction.Role, compaction.NodeKey, compaction.CostUSD, compaction.Billed = "compaction", "", 0.5, true
	compaction.Tokens = Tokens{Uncached: 10, Output: 5}
	title := req("y", 1, "", 0, 600, ProjectNoContext)
	title.Role, title.NodeKey = "title", ""
	row := userRow(t, compute(t, []Request{compaction, title}, Principals{}), 1)
	if row.ActiveNS != 0 || row.OtherActiveNS != 0 || row.Roots != 0 {
		t.Fatalf("side requests produced time or roots: %+v", row)
	}
	if row.Requests != 2 || row.Tokens.Total() != 15 || row.CostUSD != 0.5 || row.BilledRequests != 1 {
		t.Fatalf("usage = %+v", row)
	}

	// A sessionless main request is its own single-request root.
	main := req("z", 1, "", 0, 30, 1)
	main.NodeKey = ""
	row = userRow(t, compute(t, []Request{main}, Principals{}), 1)
	if row.ActiveNS != 30*sec || row.Roots != 1 || row.SingleRequestRoots != 1 {
		t.Fatalf("sessionless main = %+v", row)
	}
}

func TestSideRequestsInsideATreeShareItsTimeline(t *testing.T) {
	main := req("m", 1, "r", 0, 60, 1)
	title := req("t", 1, "r", 100, 102, 1)
	title.Role = "title"
	row := userRow(t, compute(t, []Request{main, title}, Principals{}), 1)
	if row.ActiveNS != 102*sec || row.Roots != 1 {
		t.Fatalf("row = %+v", row)
	}
}

func TestInferredSessionsAreLabelled(t *testing.T) {
	inferred := req("i", 1, "r", 0, 40, 1)
	inferred.Inferred = true
	row := userRow(t, compute(t, []Request{inferred, req("k", 1, "r2", 0, 20, 1)}, Principals{}), 1)
	if row.InferredNS != 40*sec {
		t.Fatalf("inferred = %d", row.InferredNS/sec)
	}
	found := false
	for _, flag := range row.Flags {
		found = found || flag.Code == FlagInferred
	}
	if !found {
		t.Fatalf("flags = %+v", row.Flags)
	}
}

func TestCacheWarmRequestsAreUsageOnly(t *testing.T) {
	work := req("w", 1, "r", 0, 60, 1)
	var warmers []Request
	for index := int64(0); index < 20; index++ {
		warm := req("h"+string(rune('a'+index)), 1, "r", 120+index*170, 121+index*170, 1)
		warm.CacheWarm = true
		warm.Tokens = Tokens{CacheRead: 100}
		warmers = append(warmers, warm)
	}
	row := userRow(t, compute(t, append([]Request{work}, warmers...), Principals{}), 1)
	if row.ActiveNS != 60*sec {
		t.Fatalf("cache warmers stretched the session to %d s", row.ActiveNS/sec)
	}
	if row.Requests != 21 || row.Tokens.CacheRead != 2000 {
		t.Fatalf("usage = %+v", row)
	}
	// A cache warmer without any session identity is usage only.
	lone := req("l", 1, "", 0, 1, 1)
	lone.CacheWarm, lone.NodeKey = true, ""
	if row := userRow(t, compute(t, []Request{lone}, Principals{}), 1); row.Roots != 0 || row.ActiveNS != 0 {
		t.Fatalf("lone warmer = %+v", row)
	}
}

func TestCoverageAndUnresolvedCallers(t *testing.T) {
	known := req("a", 1, "r", 0, 10, 1)
	unknown := req("b", 1, "r2", 0, 10, ProjectNoContext)
	unknown.IdentityKey = ""
	anonymous := req("c", 0, "r3", 0, 10, ProjectNoContext)
	result := compute(t, []Request{known, unknown, anonymous}, Principals{Groups: map[int64]int64{1: 7}})
	row := userRow(t, result, 1)
	if row.Coverage() != 0.5 || row.GroupID != 7 {
		t.Fatalf("coverage=%v group=%d", row.Coverage(), row.GroupID)
	}
	if userRow(t, result, 0).Requests != 1 {
		t.Fatal("unresolved callers must be collected under user 0")
	}
	if (UserRow{}).Coverage() != 0 {
		t.Fatal("empty coverage")
	}
}

func TestRankingOrder(t *testing.T) {
	result := compute(t, []Request{
		req("a", 5, "r1", 0, 10, 1),
		req("b", 3, "r2", 0, 50, 1),
		req("c", 4, "r3", 0, 50, 1),
	}, Principals{})
	if result.Users[0].UserID != 3 || result.Users[1].UserID != 4 || result.Users[2].UserID != 5 {
		t.Fatalf("order = %d %d %d", result.Users[0].UserID, result.Users[1].UserID, result.Users[2].UserID)
	}
}
