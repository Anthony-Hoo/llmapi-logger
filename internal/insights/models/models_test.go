package models

import (
	"testing"
)

func mustLoad(t *testing.T, overrides map[string]int64) *Table {
	t.Helper()
	table, err := Load(overrides)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestEmbeddedTableCoversMajorFamilies(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, nil)
	want := map[string]int64{
		"gpt-4.1": 1047576, "gpt-4o": 128000, "o3": 200000, "gpt-5": 400000,
		"claude-sonnet-4-5": 200000, "claude-opus-4-1": 200000, "claude-haiku-4-5": 200000,
		"gemini-2.5-pro": 1048576, "gemini-2.0-flash": 1048576, "deepseek-chat": 128000, "deepseek-reasoner": 128000,
	}
	for model, window := range want {
		if got := table.ContextWindow(model); got == nil || *got != window {
			t.Errorf("ContextWindow(%q) = %v, want %d", model, got, window)
		}
	}
}

func TestLookupChain(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, nil)
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
		id, ok := table.lookup(testCase.model)
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
	table := mustLoad(t, map[string]int64{"vendor-a/shared-model": 1000, "vendor-b/shared-model": 2000})
	for _, model := range []string{"shared-model", "shared-model-2025"} {
		if window := table.ContextWindow(model); window != nil {
			t.Errorf("ContextWindow(%q) resolved an ambiguous family to %d", model, *window)
		}
	}
	if window := table.ContextWindow("vendor-a/shared-model"); window == nil || *window != 1000 {
		t.Error("exact id must still resolve")
	}
}

func TestOverridesReplaceAndAddEntries(t *testing.T) {
	t.Parallel()
	table := mustLoad(t, map[string]int64{"OpenAI/GPT-4.1": 1234, "my-gateway-alias": 200000})
	if window := table.ContextWindow("gpt-4.1-2025-04-14"); window == nil || *window != 1234 {
		t.Fatalf("override window = %v", window)
	}
	if window := table.ContextWindow("my-gateway-alias"); window == nil || *window != 200000 {
		t.Fatalf("alias window = %v", window)
	}
	if window := table.ContextWindow("gpt-4o"); window == nil || *window != 128000 {
		t.Fatal("embedded entries must survive an override")
	}
	if table.ContextWindow("nope") != nil {
		t.Fatal("unknown model must not have a window")
	}
	// Overrides never leak into a later load.
	if window := mustLoad(t, nil).ContextWindow("gpt-4.1"); window == nil || *window != 1047576 {
		t.Fatalf("fresh table = %v", window)
	}
}

func TestLoadRejectsInvalidOverrides(t *testing.T) {
	t.Parallel()
	for name, overrides := range map[string]map[string]int64{
		"empty id":       {"": 1},
		"space":          {"a model": 1},
		"padded":         {" a": 1},
		"nul":            {"a\x00b": 1},
		"zero":           {"a": 0},
		"negative":       {"a": -1},
		"case duplicate": {"a/b": 1, "A/B": 2},
	} {
		if _, err := Load(overrides); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}
