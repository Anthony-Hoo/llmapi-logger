package orgreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/security"
)

type memoryData struct {
	mu         sync.Mutex
	requests   []Request
	identities []SealedIdentity
	loads      int
}

func (data *memoryData) LoadOrgRequests(_ context.Context, fromNS, toNS int64) ([]Request, error) {
	data.mu.Lock()
	defer data.mu.Unlock()
	data.loads++
	out := []Request{}
	for _, request := range data.requests {
		if request.StartNS >= fromNS && request.StartNS < toNS {
			out = append(out, request)
		}
	}
	return out, nil
}

func (data *memoryData) LoadOrgIdentities(context.Context, int64, int64) ([]SealedIdentity, error) {
	data.mu.Lock()
	defer data.mu.Unlock()
	return append([]SealedIdentity(nil), data.identities...), nil
}

type memorySnapshots struct {
	mu         sync.Mutex
	weeks      map[string]WeeklySnapshot
	pending    int
	unanalysed int
	saves      int
	failLoad   error
}

func (store *memorySnapshots) SaveWeeklySnapshot(_ context.Context, snapshot WeeklySnapshot) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.weeks == nil {
		store.weeks = map[string]WeeklySnapshot{}
	}
	// Round-trip through JSON like a database would.
	encoded, _ := json.Marshal(snapshot)
	var copied WeeklySnapshot
	_ = json.Unmarshal(encoded, &copied)
	store.weeks[snapshot.Week] = copied
	store.saves++
	return nil
}

func (store *memorySnapshots) LoadWeeklySnapshot(_ context.Context, week string) (WeeklySnapshot, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failLoad != nil {
		return WeeklySnapshot{}, false, store.failLoad
	}
	snapshot, ok := store.weeks[week]
	return snapshot, ok, nil
}

func (store *memorySnapshots) CountOrgPendingAudits(context.Context, int64, int64, int) (PendingAudits, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return PendingAudits{Pending: store.pending, Unanalysed: store.unanalysed}, nil
}

// fakeProgress reports coverage for weeks ending at or before coveredUntil,
// by a pass that began at passStart.
type fakeProgress struct {
	mu           sync.Mutex
	coveredUntil int64
	passStart    int64
}

func (progress *fakeProgress) AnalysisBackfillCovered(untilNS, sinceNS int64) bool {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	return untilNS <= progress.coveredUntil && progress.passStart >= sinceNS
}

type reportFixture struct {
	service   *Service
	data      *memoryData
	snapshots *memorySnapshots
	repo      *memoryRepository
	now       *time.Time
}

// newReportFixture: users 1 (group 1) and 2 (no group) work in week
// 2026-11-02 on the "demo" repository and a scratch directory; "now" is the
// following Wednesday.
func newReportFixture(t *testing.T) reportFixture {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{5}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	seal := func(key, auditID string, identity Identity) SealedIdentity {
		aad, _ := IdentityAAD(auditID, 1)
		encoded, _ := json.Marshal(identity)
		sealed, err := cipher.Encrypt(aad, encoded)
		if err != nil {
			t.Fatal(err)
		}
		return SealedIdentity{Key: key, AuditID: auditID, Version: 1, Enc: sealed}
	}
	data := &memoryData{identities: []SealedIdentity{
		seal("demo", "u1-0", Identity{Remotes: []string{"git.example.com/team/demo"}}),
		seal("scratch", "u2-0", Identity{Cwd: "/home/dev/scratch"}),
	}}
	base := testWeekStart.Add(10 * time.Hour)
	for index := int64(0); index < 3; index++ {
		at := base.Add(time.Duration(index) * 2 * time.Minute).UnixNano()
		data.requests = append(data.requests,
			Request{AuditID: "u1-" + string(rune('0'+index)), StartNS: at, EndNS: at + int64(time.Minute), UserID: 1, TokenID: 11,
				Client: "codex", Role: "main", RootKey: "r1", NodeKey: "r1", IdentityKey: "demo", Tokens: Tokens{Output: 100}, CostUSD: 1},
			Request{AuditID: "u2-" + string(rune('0'+index)), StartNS: at, EndNS: at + 2*int64(time.Minute), UserID: 2, TokenID: 22,
				Client: "codex", Role: "main", RootKey: "r2", NodeKey: "r2", IdentityKey: "scratch", Tokens: Tokens{Output: 10}, CostUSD: 0.1})
	}
	repo := &memoryRepository{nextID: 100, catalog: Catalog{
		Groups:   []Group{{ID: 1, Name: "Platform", Enabled: true, CreatedAtNS: 1, UpdatedAtNS: 1}},
		Projects: []Project{{ID: 10, Name: "Demo", Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "demo"}}, CreatedAtNS: 1, UpdatedAtNS: 1}},
		Members:  []Member{{UserID: 1, GroupID: 1, UpdatedAtNS: 1}},
	}}
	snapshots := &memorySnapshots{}
	now := testWeekStart.AddDate(0, 0, 9)
	service, err := NewService(context.Background(), Options{
		Settings: testSettings(), Repository: repo, Data: data, Snapshots: snapshots, Cipher: cipher,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reportFixture{service: service, data: data, snapshots: snapshots, repo: repo, now: &now}
}

func TestWeeklyReportRanksFiltersAndSwitchesMetric(t *testing.T) {
	fixture := newReportFixture(t)
	ctx := context.Background()
	report, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Frozen || !report.Complete || len(report.Users) != 2 {
		t.Fatalf("report = %+v", report)
	}
	// User 2 has longer requests: 2+2+2 min chained = 6 min vs 5 min.
	if report.Users[0].UserID != 2 || report.Users[0].Rank != 1 || report.Users[1].UserID != 1 {
		t.Fatalf("hours ranking = %d, %d", report.Users[0].UserID, report.Users[1].UserID)
	}
	if len(report.Projects) != 1 || report.Projects[0].Name != "Demo" || report.Users[1].Projects[0].Project != 10 {
		t.Fatalf("projects = %+v / %+v", report.Projects, report.Users[1].Projects)
	}
	if report.Users[0].Projects[0].Project != ProjectUnattributed || report.Users[0].Coverage != 1 {
		t.Fatalf("user 2 = %+v", report.Users[0])
	}
	byCost, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02", Metric: MetricCost})
	if err != nil || byCost.Users[0].UserID != 1 {
		t.Fatalf("cost ranking = %+v %v", byCost.Users, err)
	}
	group := int64(1)
	grouped, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02", GroupID: &group})
	if err != nil || len(grouped.Users) != 1 || grouped.Users[0].UserID != 1 || grouped.Totals.Users != 1 {
		t.Fatalf("grouped = %+v %v", grouped.Users, err)
	}
	missing := int64(9)
	if _, err := fixture.service.Weekly(ctx, WeeklyQuery{GroupID: &missing}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown group = %v", err)
	}
	if _, err := fixture.service.Weekly(ctx, WeeklyQuery{Metric: "lines"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad metric = %v", err)
	}
	if _, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-04"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mid-week label = %v", err)
	}
}

func TestFreezeJobAndRegenerate(t *testing.T) {
	fixture := newReportFixture(t)
	ctx := context.Background()

	// Pending audits postpone the freeze until the deadline.
	fixture.snapshots.pending = 3
	fixture.service.SnapshotTick(ctx)
	fixture.service.WaitSnapshots()
	// Weeks past the 72 h deadline freeze anyway; last week (ended two days
	// ago) waits.
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; ok || fixture.snapshots.saves != freezeLookbackWeeks-1 {
		t.Fatalf("pending freeze: saves = %d", fixture.snapshots.saves)
	}
	fixture.snapshots.pending = 0
	// The tick is rate limited: a second tick right away does nothing.
	fixture.service.SnapshotTick(ctx)
	fixture.service.WaitSnapshots()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; ok {
		t.Fatal("rate limit ignored")
	}
	*fixture.now = fixture.now.Add(freezeCheckInterval + time.Second)
	fixture.service.SnapshotTick(ctx)
	fixture.service.WaitSnapshots()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; !ok || fixture.snapshots.saves != freezeLookbackWeeks {
		t.Fatalf("saves = %d weeks = %v", fixture.snapshots.saves, len(fixture.snapshots.weeks))
	}
	if _, ok := fixture.snapshots.weeks["2026-11-09"]; ok {
		t.Fatal("the current week was frozen")
	}

	// A rule change after freezing does not alter the frozen week...
	if _, err := fixture.service.UpdateProject(ctx, 10, ProjectInput{Name: "Demo", Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "scratch"}}}); err != nil {
		t.Fatal(err)
	}
	frozen, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02"})
	if err != nil || !frozen.Frozen || frozen.Users[1].UserID != 1 || frozen.Users[1].Projects[0].Project != 10 || frozen.Users[0].Projects[0].Project != ProjectUnattributed {
		t.Fatalf("frozen week changed: %+v %v", frozen.Users, err)
	}
	// ...until it is regenerated.
	if err := fixture.service.Regenerate(ctx, "2026-11-02"); err != nil {
		t.Fatal(err)
	}
	regenerated, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02"})
	if err != nil || regenerated.Users[0].Projects[0].Project != 10 || regenerated.Users[1].Projects[0].Project != ProjectUnattributed {
		t.Fatalf("regenerated = %+v %v", regenerated.Users, err)
	}
	if err := fixture.service.Regenerate(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("regenerating the current week = %v", err)
	}

	// Retention removes the evidence; the frozen snapshot still answers, with
	// the project name it had when frozen.
	fixture.data.mu.Lock()
	fixture.data.requests, fixture.data.identities = nil, nil
	fixture.data.mu.Unlock()
	if err := fixture.service.DeleteProject(ctx, 10); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02"})
	if err != nil || len(after.Users) != 2 || after.Projects[0].Name != "Demo" {
		t.Fatalf("snapshot after retention = %+v %v", after, err)
	}
	project, err := fixture.service.ProjectWeekly(ctx, 10, "2026-11-02")
	if err != nil || project.Project.Name != "Demo" || len(project.Contributors) != 1 || project.Contributors[0].UserID != 2 {
		t.Fatalf("project report = %+v %v", project, err)
	}
}

func TestPendingAuditsFreezeAfterTheDeadline(t *testing.T) {
	fixture := newReportFixture(t)
	fixture.snapshots.pending = 1
	*fixture.now = testWeekStart.AddDate(0, 0, 7).Add(freezeDeadline + time.Minute)
	fixture.service.SnapshotTick(context.Background())
	fixture.service.WaitSnapshots()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; !ok {
		t.Fatal("deadline did not force the freeze")
	}
}

func TestUnanalysedAuditsWaitForTheBackfill(t *testing.T) {
	fixture := newReportFixture(t)
	progress := &fakeProgress{}
	fixture.service.progress = progress
	fixture.snapshots.unanalysed = 2
	tick := func() {
		*fixture.now = fixture.now.Add(freezeCheckInterval + time.Second)
		fixture.service.SnapshotTick(context.Background())
		fixture.service.WaitSnapshots()
	}
	weekEnd := testWeekStart.AddDate(0, 0, 7)

	// Last week has unanalysed audits the backfill has not reached: it waits.
	tick()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; ok {
		t.Fatal("froze before the backfill reached the week")
	}
	// A pass that began before the week ended does not count.
	progress.mu.Lock()
	progress.coveredUntil, progress.passStart = weekEnd.UnixNano(), weekEnd.UnixNano()
	progress.mu.Unlock()
	tick()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; ok {
		t.Fatal("froze on a pass that began before the grace period ended")
	}
	// A later pass reached past the week: what is left was skipped.
	progress.mu.Lock()
	progress.passStart = weekEnd.Add(freezeGrace).UnixNano()
	progress.mu.Unlock()
	tick()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; !ok {
		t.Fatal("did not freeze once the backfill covered the week")
	}
}

func TestUnanalysedAuditsWithoutProgressWaitForTheDeadline(t *testing.T) {
	fixture := newReportFixture(t)
	fixture.snapshots.unanalysed = 1
	fixture.service.SnapshotTick(context.Background())
	fixture.service.WaitSnapshots()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; ok {
		t.Fatal("froze with unanalysed audits and no backfill progress")
	}
	*fixture.now = testWeekStart.AddDate(0, 0, 7).Add(freezeDeadline + time.Minute)
	fixture.service.SnapshotTick(context.Background())
	fixture.service.WaitSnapshots()
	if _, ok := fixture.snapshots.weeks["2026-11-02"]; !ok {
		t.Fatal("deadline did not force the freeze")
	}
}

func TestSelfReportOnlyContainsTheCaller(t *testing.T) {
	fixture := newReportFixture(t)
	*fixture.now = testWeekStart.Add(3 * 24 * time.Hour)
	self, err := fixture.service.Self(context.Background(), 1)
	if err != nil || self.Row == nil || self.Row.UserID != 1 || len(self.Projects) != 1 || self.Week != "2026-11-02" {
		t.Fatalf("self = %+v %v", self, err)
	}
	encoded, _ := json.Marshal(self)
	if bytes.Contains(encoded, []byte(`"user_id":2`)) {
		t.Fatal("self report leaked another user")
	}
	anonymous, err := fixture.service.Self(context.Background(), 0)
	if err != nil || anonymous.Row != nil {
		t.Fatalf("anonymous = %+v %v", anonymous, err)
	}
}

func TestTrendAndLiveCache(t *testing.T) {
	fixture := newReportFixture(t)
	ctx := context.Background()
	trend, err := fixture.service.Trend(ctx, 3, nil)
	if err != nil || len(trend.Weeks) != 3 || trend.Weeks[1].Week != "2026-11-02" || trend.Weeks[1].ActiveNS == 0 || trend.Weeks[2].ActiveNS != 0 {
		t.Fatalf("trend = %+v %v", trend, err)
	}
	if len(trend.Projects) != 1 || trend.Projects[0].ID != 10 {
		t.Fatalf("trend projects = %+v", trend.Projects)
	}
	loads := fixture.data.loads
	if _, err := fixture.service.Weekly(ctx, WeeklyQuery{Week: "2026-11-02"}); err != nil {
		t.Fatal(err)
	}
	if fixture.data.loads != loads {
		t.Fatal("live week was recomputed inside the cache window")
	}
	if _, err := fixture.service.Trend(ctx, MaxTrendWeeks+1, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many weeks = %v", err)
	}
}
