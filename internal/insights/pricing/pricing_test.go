package pricing

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
)

func mustLoad(t *testing.T, override string) *Table {
	t.Helper()
	table, err := Load(override)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func writeOverride(t *testing.T, content string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "prices.json")
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestEmbeddedSnapshotLoadsAndCoversMajorFamilies(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, "")
	if table.Snapshot() == "" {
		t.Fatal("snapshot date missing")
	}
	for _, model := range []string{"gpt-4.1", "gpt-4o", "o3", "gpt-5", "claude-sonnet-4-5", "claude-opus-4-1",
		"claude-haiku-4-5", "gemini-2.5-pro", "gemini-2.0-flash", "deepseek-chat", "deepseek-reasoner"} {
		if _, ok := table.Lookup(model); !ok {
			t.Errorf("Lookup(%q) unknown", model)
		}
	}
}

func TestLookupChain(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, "")
	cases := []struct {
		model string
		want  string // expected entry id, "" for unknown
	}{
		{"openai/gpt-4.1", "openai/gpt-4.1"},
		{"OpenAI/GPT-4.1", "openai/gpt-4.1"},
		{"gpt-4.1", "openai/gpt-4.1"},
		{"azure/gpt-4.1", "openai/gpt-4.1"},
		{"claude-sonnet-4-5-20250929", "anthropic/claude-sonnet-4-5"},
		{"claude-sonnet-4-20250514", "anthropic/claude-sonnet-4"},
		{"claude-opus-4-1-20250805", "anthropic/claude-opus-4-1"},
		{"claude-opus-4-20250514", "anthropic/claude-opus-4"},
		{"claude-sonnet-4-5@20250929", "anthropic/claude-sonnet-4-5"},
		{"gpt-4o-mini-2024-07-18", "openai/gpt-4o-mini"},
		{"gpt-4o-2024-08-06", "openai/gpt-4o"},
		{"gpt-4", ""},
		{"gpt-4.1x", ""},
		{"unknown-model", ""},
		{"", ""},
	}
	for _, testCase := range cases {
		_, id, ok := table.lookup(testCase.model)
		if testCase.want == "" {
			if ok {
				t.Errorf("lookup(%q) = %q, want unknown", testCase.model, id)
			}
			continue
		}
		if !ok || id != testCase.want {
			t.Errorf("lookup(%q) = %q (%v), want %q", testCase.model, id, ok, testCase.want)
		}
	}
}

func TestAmbiguousBareNameIsUnknown(t *testing.T) {
	t.Parallel()
	override := writeOverride(t, `{"models":{
		"vendor-a/shared-model":{"input":1,"output":2},
		"vendor-b/shared-model":{"input":3,"output":4}}}`)
	table := mustLoad(t, override)
	for _, model := range []string{"shared-model", "shared-model-2025"} {
		if _, ok := table.Lookup(model); ok {
			t.Errorf("Lookup(%q) resolved an ambiguous family", model)
		}
	}
	if _, ok := table.Lookup("vendor-a/shared-model"); !ok {
		t.Error("exact id must still resolve")
	}
}

func TestCostUsesCacheRatesAndFallsBackToInput(t *testing.T) {
	t.Parallel()
	override := writeOverride(t, `{"models":{
		"x/full":{"input":2,"output":10,"cache_read":0.5,"cache_write":3},
		"x/bare":{"input":2,"output":10},
		"x/free-cache":{"input":2,"output":10,"cache_read":0}}}`)
	table := mustLoad(t, override)
	usage := insights.Usage{
		UncachedInput: ptr(1_000_000), CacheRead: ptr(2_000_000), CacheWrite: ptr(1_000_000), Output: ptr(100_000),
	}
	at := time.Unix(1_700_000_000, 0)
	want := map[string]float64{
		"x/full":       2 + 1 + 3 + 1,
		"x/bare":       2 + 4 + 2 + 1,
		"x/free-cache": 2 + 0 + 2 + 1,
	}
	for model, expected := range want {
		cost := table.Cost(usage, model, at)
		if cost == nil || math.Abs(*cost-expected) > 1e-9 {
			t.Errorf("Cost(%s) = %v, want %v", model, cost, expected)
		}
	}
	if table.Cost(usage, "no-such-model", at) != nil {
		t.Error("unknown model must have nil cost")
	}
	if cost := table.Cost(insights.Usage{}, "x/full", at); cost == nil || *cost != 0 {
		t.Errorf("empty usage cost = %v, want 0", cost)
	}
}

func TestOverrideReplacesEntriesAndKeepsTheRest(t *testing.T) {
	t.Parallel()
	override := writeOverride(t, `{"models":{"openai/gpt-4.1":{"input":9,"output":9,"context":1234}}}`)
	table := mustLoad(t, override)
	entry, ok := table.Lookup("gpt-4.1")
	if !ok || entry.Input != 9 || entry.ContextWindow != 1234 {
		t.Fatalf("override entry = %+v ok=%v", entry, ok)
	}
	if window := table.ContextWindow("gpt-4.1"); window == nil || *window != 1234 {
		t.Fatalf("ContextWindow = %v", window)
	}
	if _, ok := table.Lookup("gpt-4o"); !ok {
		t.Fatal("embedded entries must survive an override")
	}
	if table.ContextWindow("nope") != nil {
		t.Fatal("unknown model must not have a window")
	}
}

func TestScheduleMultipliers(t *testing.T) {
	t.Parallel()
	override := writeOverride(t, `{"schedules":[
		{"model":"deepseek-*","start":"16:30","end":"00:30","multiplier":0.5},
		{"model":"gpt-4o","weekdays":[6,0],"start":"00:00","end":"12:00","multiplier":2}]}`)
	table := mustLoad(t, override)
	if !table.HasSchedules() {
		t.Fatal("HasSchedules = false")
	}
	usage := insights.Usage{UncachedInput: ptr(1_000_000)}
	base := *table.Cost(usage, "deepseek-chat", time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	cases := []struct {
		at   time.Time
		want float64
	}{
		{time.Date(2026, 10, 14, 17, 0, 0, 0, time.UTC), base * 0.5}, // inside, before midnight
		{time.Date(2026, 10, 15, 0, 15, 0, 0, time.UTC), base * 0.5}, // wrapped past midnight
		{time.Date(2026, 10, 15, 0, 30, 0, 0, time.UTC), base},       // end is exclusive
		{time.Date(2026, 10, 14, 16, 29, 0, 0, time.UTC), base},
	}
	for _, testCase := range cases {
		if got := *table.Cost(usage, "deepseek-chat", testCase.at); math.Abs(got-testCase.want) > 1e-12 {
			t.Errorf("deepseek at %v = %v, want %v", testCase.at, got, testCase.want)
		}
	}
	gptBase := *table.Cost(usage, "gpt-4o", time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)) // Wednesday
	saturday := *table.Cost(usage, "gpt-4o", time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC))
	if math.Abs(saturday-gptBase*2) > 1e-12 {
		t.Errorf("weekday schedule = %v, want %v", saturday, gptBase*2)
	}
}

func TestLoadRejectsInvalidOverrides(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"not json":          `{`,
		"unknown field":     `{"models":{},"extra":1}`,
		"negative rate":     `{"models":{"a/b":{"input":-1,"output":1}}}`,
		"empty id":          `{"models":{" ":{"input":1,"output":1}}}`,
		"case duplicate":    `{"models":{"a/b":{"input":1,"output":1},"A/B":{"input":1,"output":1}}}`,
		"bad clock":         `{"schedules":[{"model":"a","start":"25:00","end":"01:00","multiplier":1}]}`,
		"same start end":    `{"schedules":[{"model":"a","start":"01:00","end":"01:00","multiplier":1}]}`,
		"zero multiplier":   `{"schedules":[{"model":"a","start":"01:00","end":"02:00","multiplier":0}]}`,
		"bad glob":          `{"schedules":[{"model":"[","start":"01:00","end":"02:00","multiplier":1}]}`,
		"bad weekday":       `{"schedules":[{"model":"a","weekdays":[7],"start":"01:00","end":"02:00","multiplier":1}]}`,
		"off-grid start":    `{"schedules":[{"model":"a","start":"12:15","end":"13:00","multiplier":1}]}`,
		"off-grid end":      `{"schedules":[{"model":"a","start":"12:00","end":"13:45","multiplier":1}]}`,
		"trailing document": `{"models":{}} {}`,
		"trailing garbage":  `{"models":{}} garbage`,
	} {
		if _, err := Load(writeOverride(t, content)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "override") {
		t.Errorf("missing file error = %v", err)
	}
}

func ptr(value int64) *int64 { return &value }

func TestExamplePricingFileLoads(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, filepath.Join("..", "..", "..", "configs", "insights-pricing.example.json"))
	entry, ok := table.Lookup("example-provider/example-large")
	if !ok || entry.Input != 3.0 || entry.ContextWindow != 200000 {
		t.Fatalf("example entry = %+v ok=%v", entry, ok)
	}
	if _, ok := table.Lookup("my-gateway-alias"); !ok || !table.HasSchedules() {
		t.Fatal("example aliases or schedules were not loaded")
	}
}

func TestLoadRejectsOffGridScheduleBoundaryWithClearError(t *testing.T) {
	t.Parallel()
	_, err := Load(writeOverride(t, `{"schedules":[{"model":"a","start":"12:15","end":"13:00","multiplier":1}]}`))
	if err == nil || !strings.Contains(err.Error(), "schedule 0") || !strings.Contains(err.Error(), "30-minute boundary") {
		t.Fatalf("error = %v, want a schedule 0 30-minute boundary error", err)
	}
	if _, err := Load(writeOverride(t, `{"schedules":[{"model":"a","start":"12:30","end":"13:00","multiplier":1}]}`)); err != nil {
		t.Fatalf("half-hour boundaries must load: %v", err)
	}
}
