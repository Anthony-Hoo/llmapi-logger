package orgreport

import (
	"math"
	"reflect"
	"testing"
	"time"
)

const sec = int64(time.Second)

func TestBuildBlocksMergesAtTheIdleGapBoundary(t *testing.T) {
	gap := 180 * sec
	tests := []struct {
		name      string
		spans     []Span
		durations []int64
	}{
		{"empty", nil, nil},
		{"single request keeps its real duration", []Span{{0, 14 * sec, 1}}, []int64{14 * sec}},
		{"point request has no duration", []Span{{5 * sec, 5 * sec, 1}}, []int64{0}},
		{"end before start is a point", []Span{{5 * sec, 1 * sec, 1}}, []int64{0}},
		{"gap equal to threshold merges", []Span{{0, 10 * sec, 1}, {190 * sec, 200 * sec, 1}}, []int64{200 * sec}},
		{"gap one ns over threshold splits", []Span{{0, 10 * sec, 1}, {190*sec + 1, 200 * sec, 1}}, []int64{10 * sec, 10*sec - 1}},
		{"overlapping spans are unioned", []Span{{0, 100 * sec, 1}, {20 * sec, 50 * sec, 2}, {90 * sec, 130 * sec, 1}}, []int64{130 * sec}},
		{"unsorted input", []Span{{400 * sec, 410 * sec, 1}, {0, 10 * sec, 1}, {100 * sec, 110 * sec, 1}}, []int64{110 * sec, 10 * sec}},
		{"gap is measured from the block end, not the last start", []Span{{0, 300 * sec, 1}, {10 * sec, 20 * sec, 1}, {470 * sec, 480 * sec, 1}}, []int64{480 * sec}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blocks := BuildBlocks(test.spans, gap)
			got := make([]int64, 0, len(blocks))
			for _, block := range blocks {
				got = append(got, block.Duration())
			}
			if len(test.durations) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(got, test.durations) {
				t.Fatalf("durations = %v, want %v", got, test.durations)
			}
		})
	}
}

func TestBuildBlocksWeightsByDurationThenCount(t *testing.T) {
	blocks := BuildBlocks([]Span{{0, 30 * sec, 1}, {30 * sec, 40 * sec, 2}}, 180*sec)
	if len(blocks) != 1 || blocks[0].Weights[1] != 30*sec || blocks[0].Weights[2] != 10*sec || blocks[0].Spans != 2 {
		t.Fatalf("blocks = %+v", blocks)
	}
	points := BuildBlocks([]Span{{0, 0, 1}, {1, 1, 1}, {2, 2, 2}}, 180*sec)
	if points[0].Weights[1] != 2 || points[0].Weights[2] != 1 {
		t.Fatalf("point weights = %v, want counts", points[0].Weights)
	}
}

func TestAllocateIsProportionalAndExact(t *testing.T) {
	tests := []struct {
		amount  int64
		weights map[ProjectKey]int64
		want    map[ProjectKey]int64
	}{
		{100, map[ProjectKey]int64{1: 3, 2: 1}, map[ProjectKey]int64{1: 75, 2: 25}},
		{10, map[ProjectKey]int64{1: 1, 2: 1, 3: 1}, map[ProjectKey]int64{1: 4, 2: 3, 3: 3}},
		{0, map[ProjectKey]int64{1: 1}, map[ProjectKey]int64{}},
		{50, map[ProjectKey]int64{}, map[ProjectKey]int64{}},
		{50, map[ProjectKey]int64{1: 0}, map[ProjectKey]int64{}},
		{7 * 24 * 3600 * sec, map[ProjectKey]int64{ProjectUnattributed: 7, 5: 3}, map[ProjectKey]int64{ProjectUnattributed: 7 * 24 * 3600 * sec * 7 / 10, 5: 7 * 24 * 3600 * sec * 3 / 10}},
	}
	for _, test := range tests {
		got := Allocate(test.amount, test.weights)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("Allocate(%d, %v) = %v, want %v", test.amount, test.weights, got, test.want)
		}
		var sum int64
		for _, part := range got {
			sum += part
		}
		if len(got) > 0 && sum != test.amount {
			t.Errorf("parts sum to %d, want %d", sum, test.amount)
		}
	}
}

func TestOverlap(t *testing.T) {
	tests := []struct{ start, end, from, to, want int64 }{
		{0, 10, 0, 10, 10},
		{0, 10, 5, 20, 5},
		{-5, 5, 0, 10, 5},
		{0, 10, 10, 20, 0},
		{3, 3, 0, 10, 0},
		{0, 100, 40, 60, 20},
	}
	for _, test := range tests {
		if got := Overlap(test.start, test.end, test.from, test.to); got != test.want {
			t.Errorf("Overlap(%d,%d,%d,%d) = %d, want %d", test.start, test.end, test.from, test.to, got, test.want)
		}
	}
}

func TestSweepPeakAndAverage(t *testing.T) {
	tests := []struct {
		name      string
		intervals []Interval
		peak      int
		busy, sum int64
	}{
		{"none", nil, 0, 0, 0},
		{"touching is not concurrent", []Interval{{0, 10}, {10, 20}}, 1, 20, 20},
		{"nested", []Interval{{0, 100}, {10, 20}, {15, 30}}, 3, 100, 125},
		{"two islands", []Interval{{0, 10}, {5, 15}, {100, 110}}, 2, 25, 30},
		{"point counts towards peak only", []Interval{{5, 5}}, 1, 0, 0},
		{"reversed interval ignored", []Interval{{10, 5}, {0, 4}}, 1, 4, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Sweep(test.intervals)
			if got.Peak != test.peak || got.BusyNS != test.busy || got.SumNS != test.sum {
				t.Fatalf("Sweep = %+v, want peak=%d busy=%d sum=%d", got, test.peak, test.busy, test.sum)
			}
		})
	}
	if average := Sweep([]Interval{{0, 100}, {10, 20}, {15, 30}}).Average(); math.Abs(average-1.25) > 1e-9 {
		t.Fatalf("average = %v, want 1.25", average)
	}
}

func TestInheritIdentities(t *testing.T) {
	requests := []Request{
		// Node n1: the first two requests precede the git scan.
		{AuditID: "a1", StartNS: 1, RootKey: "r1", NodeKey: "n1"},
		{AuditID: "a2", StartNS: 2, RootKey: "r1", NodeKey: "n1"},
		{AuditID: "a3", StartNS: 3, RootKey: "r1", NodeKey: "n1", IdentityKey: "repo-a"},
		{AuditID: "a4", StartNS: 4, RootKey: "r1", NodeKey: "n1"},
		{AuditID: "a5", StartNS: 5, RootKey: "r1", NodeKey: "n1", IdentityKey: "repo-b"},
		{AuditID: "a6", StartNS: 6, RootKey: "r1", NodeKey: "n1"},
		// Node n2 of the same root never identifies itself: root majority.
		{AuditID: "a7", StartNS: 7, RootKey: "r1", NodeKey: "n2"},
		// A request with a root but no node: root majority too.
		{AuditID: "a8", StartNS: 8, RootKey: "r1"},
		// Another root without any identity, and a request without any root.
		{AuditID: "a9", StartNS: 9, RootKey: "r2", NodeKey: "n3"},
		{AuditID: "a10", StartNS: 10},
		// Majority by count: repo-b wins in root r3.
		{AuditID: "b1", StartNS: 1, RootKey: "r3", NodeKey: "m1", IdentityKey: "repo-a"},
		{AuditID: "b2", StartNS: 2, RootKey: "r3", NodeKey: "m2", IdentityKey: "repo-b"},
		{AuditID: "b3", StartNS: 3, RootKey: "r3", NodeKey: "m2", IdentityKey: "repo-b"},
		{AuditID: "b4", StartNS: 4, RootKey: "r3", NodeKey: "m3"},
	}
	inherited := InheritIdentities(requests)
	want := map[string]string{
		"a1": "repo-a", "a2": "repo-a", "a3": "repo-a", "a4": "repo-a", "a5": "repo-b", "a6": "repo-b",
		"a7": "repo-a", "a8": "repo-a", "a9": "", "a10": "",
		"b1": "repo-a", "b2": "repo-b", "b3": "repo-b", "b4": "repo-b",
	}
	for _, request := range requests {
		if request.IdentityKey != want[request.AuditID] {
			t.Errorf("%s identity = %q, want %q", request.AuditID, request.IdentityKey, want[request.AuditID])
		}
	}
	if inherited != 7 {
		t.Fatalf("inherited = %d, want 7", inherited)
	}
}

func TestMajorityTieGoesToTheIdentitySeenFirst(t *testing.T) {
	requests := []Request{
		{AuditID: "x2", StartNS: 2, RootKey: "r", NodeKey: "b", IdentityKey: "second"},
		{AuditID: "x1", StartNS: 1, RootKey: "r", NodeKey: "a", IdentityKey: "first"},
		{AuditID: "x3", StartNS: 3, RootKey: "r", NodeKey: "c"},
	}
	InheritIdentities(requests)
	if requests[2].IdentityKey != "first" {
		t.Fatalf("tie went to %q", requests[2].IdentityKey)
	}
}

func TestWeekHelpers(t *testing.T) {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	settings := Settings{Location: location, WeekStart: time.Monday}
	// 2026-11-04 is a Wednesday.
	week := settings.WeekOf(time.Date(2026, 11, 4, 15, 0, 0, 0, location))
	if week.Label() != "2026-11-02" || week.End.Sub(week.Start) != 7*24*time.Hour {
		t.Fatalf("week = %v .. %v", week.Start, week.End)
	}
	// Sunday 23:30 local still belongs to the Monday week.
	if got := settings.WeekOf(time.Date(2026, 11, 8, 23, 30, 0, 0, location)).Label(); got != "2026-11-02" {
		t.Fatalf("sunday night week = %s", got)
	}
	// The same instant seen from UTC is Sunday 15:30 there; the local week rules.
	if got := settings.WeekOf(time.Date(2026, 11, 8, 15, 30, 0, 0, time.UTC)).Label(); got != "2026-11-02" {
		t.Fatalf("utc instant week = %s", got)
	}
	if _, err := settings.ParseWeek("2026-11-03"); err == nil {
		t.Fatal("a Tuesday was accepted as a week start")
	}
	if _, err := settings.ParseWeek("not-a-date"); err == nil {
		t.Fatal("garbage was accepted")
	}
	parsed, err := settings.ParseWeek("2026-11-02")
	if err != nil || !parsed.Start.Equal(week.Start) || parsed.Previous().Label() != "2026-10-26" {
		t.Fatalf("ParseWeek = %+v, %v", parsed, err)
	}
	sunday := Settings{Location: time.UTC, WeekStart: time.Sunday}
	if got := sunday.WeekOf(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)).Label(); got != "2026-11-01" {
		t.Fatalf("sunday week = %s", got)
	}
	// A daylight-saving week keeps seven local days.
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	dst := Settings{Location: berlin, WeekStart: time.Monday}.WeekOf(time.Date(2026, 10, 25, 12, 0, 0, 0, berlin))
	if dst.End.Sub(dst.Start) != 169*time.Hour || len(dst.Days()) != 8 {
		t.Fatalf("dst week length = %v", dst.End.Sub(dst.Start))
	}
}
