package insights

import (
	"encoding/json"
	"testing"
)

// Epoch nanoseconds exceed 2^53, so every *_ns field must travel as a JSON
// string like the audit API does; *_ms fields stay numbers.
func TestAPITypesEncodeNanosecondsAsStrings(t *testing.T) {
	const ns = int64(1760000000123456789)
	ms := 12.5
	values := map[string]any{
		"overview": OverviewResponse{FromNS: ns, ToNS: ns + 1},
		"card":     SessionCard{FirstNS: ns, LastNS: ns + 1},
		"step":     TrendStep{StartedAtNS: ns, FirstEventMS: &ms},
		"node":     TreeNode{FirstNS: ns, LastNS: ns + 1},
	}
	want := map[string][]string{
		"overview": {"from_ns", "to_ns"},
		"card":     {"first_ns", "last_ns"},
		"step":     {"started_at_ns"},
		"node":     {"first_ns", "last_ns"},
	}
	for name, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, field := range want[name] {
			if _, ok := decoded[field].(string); !ok {
				t.Errorf("%s.%s = %T, want JSON string", name, field, decoded[field])
			}
		}
	}
	raw, _ := json.Marshal(TrendStep{FirstEventMS: &ms})
	var step map[string]any
	_ = json.Unmarshal(raw, &step)
	if _, ok := step["first_event_ms"].(float64); !ok {
		t.Errorf("first_event_ms = %T, want JSON number", step["first_event_ms"])
	}
}
