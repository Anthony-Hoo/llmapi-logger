package streamevidence

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
)

func decode(t *testing.T, text string) any {
	t.Helper()
	var value any
	if err := auditmodel.DecodeJSON([]byte(text), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func encode(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestLeftoverRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, value, held string
		present           bool
		want              string // "" when held
	}{
		{"equal", `{"a":1}`, `{"a":1}`, true, ""},
		{"absent place", `null`, `0`, false, `null`},
		{"null is not reported yet", `null`, `{"x":1}`, true, ""},
		{"empty string starts a field", `""`, `"filled"`, true, ""},
		{"empty array starts a field", `[]`, `[1]`, true, ""},
		{"empty object starts a field", `{}`, `{"a":1}`, true, ""},
		{"empty of another type", `""`, `[1]`, true, `""`},
		{"replaced scalar", `1`, `9`, true, `1`},
		{"objects keep only differing keys", `{"a":1,"b":2,"c":{"d":3,"e":4}}`, `{"a":1,"b":5,"c":{"d":3}}`, true, `{"b":2,"c":{"e":4}}`},
		{"arrays are compared whole", `[1,2]`, `[1,3]`, true, `[1,2]`},
	}
	for _, test := range cases {
		got, keep := Leftover(decode(t, test.value), decode(t, test.held), test.present)
		if test.want == "" {
			if keep {
				t.Errorf("%s: kept %s", test.name, encode(t, got))
			}
			continue
		}
		if !keep || encode(t, got) != test.want {
			t.Errorf("%s: leftover = %s (%v), want %s", test.name, encode(t, got), keep, test.want)
		}
	}
}

func TestMergeSetKeepsReportedValues(t *testing.T) {
	t.Parallel()
	target := decode(t, `{"status":"in_progress","usage":null,"output":[],"nested":{"a":1,"b":2}}`).(map[string]any)
	MergeSet(target, decode(t, `{"status":"completed","usage":{"x":1},"output":[1],"nested":{"b":3},"error":null}`).(map[string]any))
	MergeSet(target, decode(t, `{"usage":null}`).(map[string]any))
	if got := encode(t, target); got != `{"error":null,"nested":{"a":1,"b":3},"output":[1],"status":"completed","usage":{"x":1}}` {
		t.Fatalf("merged = %s", got)
	}
}

func TestResidueEntries(t *testing.T) {
	t.Parallel()
	residue := NewResidue()
	if !residue.Empty() {
		t.Fatal("new residue is not empty")
	}
	residue.Keep(4, []string{"choices", Position(0), "x"}, "same")
	residue.Keep(5, []string{"choices", Position(0), "x"}, "same")
	residue.Keep(6, []string{"choices", Position(0), "x"}, "same")
	residue.Keep(8, []string{"choices", Position(0), "x"}, "same")
	residue.Keep(9, []string{"delta"}, map[string]any{"a": 1})
	residue.Keep(9, []string{"delta", "b"}, 2) // leftovers of one event merge
	residue.KeepEvent(Event{Index: 1, Data: []byte(`{"type":"x.unknown"}`), Object: map[string]any{"type": "x.unknown"}})
	residue.Keep(1, []string{"ignored"}, true) // the event is kept whole already`n	residue.Keep(9, []string{"delta", "a", "deeper"}, 3) // under a kept scalar: covered
	residue.KeepEvent(Event{Index: 2, Data: []byte(`not json`)})
	residue.KeepUnknownKeys(3, nil, map[string]any{"type": "known", "x_probe": "value"}, "type")
	entries, err := residue.Entries()
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"data":{"type":"x.unknown"},"index":1},{"index":2,"text":"not json"},{"data":{"x_probe":"value"},"index":3},` +
		`{"count":3,"data":{"choices":{"0":{"x":"same"}}},"index":4},{"data":{"choices":{"0":{"x":"same"}}},"index":8},{"data":{"delta":{"a":1,"b":2}},"index":9}]`
	if got := encode(t, entries); got != want {
		t.Fatalf("entries = %s\nwant      %s", got, want)
	}
}

func TestResidueLimit(t *testing.T) {
	t.Parallel()
	residue := NewResidue()
	residue.Keep(0, []string{"x"}, strings.Repeat("a", MaxResidueBytes))
	if _, err := residue.Entries(); !errors.Is(err, ErrResidueTooLarge) {
		t.Fatalf("error = %v, want ErrResidueTooLarge", err)
	}
	invalid := NewResidue()
	invalid.KeepEvent(Event{Index: 0, Data: []byte{0xff, 0xfe}})
	if _, err := invalid.Entries(); err == nil {
		t.Fatal("non-UTF-8 event data was kept as text")
	}
}

func TestDecodeEventsReportsReservedMarkers(t *testing.T) {
	t.Parallel()
	events := []base.SSEEvent{{Event: "a", Data: []byte(`{"x":1}`)}, {Data: []byte(`{"$llmapi_logger_item_v1":0}`)}, {Data: []byte(`[DONE]`)}}
	decoded, err := DecodeEvents(events)
	if !errors.Is(err, auditmodel.ErrReservedMarker) || len(decoded) != 3 || decoded[0].Object == nil || decoded[2].Object != nil {
		t.Fatalf("decoded = %+v, %v", decoded, err)
	}
}

func TestDescribeAndEventsHash(t *testing.T) {
	t.Parallel()
	events := []base.SSEEvent{
		{Event: "message_start", Data: []byte(`{"a":1}`)},
		{Event: "content_block_delta", Data: []byte(`{"b":2}`)},
		{Event: "content_block_delta", Data: []byte(`{"c":3}`)},
		{Event: "", Data: []byte("[DONE]")},
	}
	description := Describe(events)
	if got := encode(t, description); got != `{"data_lengths":[7,7,7,6],"names":[["message_start",1],["content_block_delta",2],["",1]],"sha256":"`+
		description["sha256"].(string)+`"}` {
		t.Fatalf("description = %s", got)
	}
	// Pinned, and recomputed outside Go from the documented framing: the
	// framing is part of the stored format.
	const pinned = "3f21d1539f9e9828f6fb8859dd7fc9e917b028b6ae46fe8b726422ad37c16c86"
	if got := description["sha256"]; got != pinned {
		t.Errorf("events hash = %s, pinned %s", got, pinned)
	}
	if empty := Describe(nil); encode(t, empty) != `{"data_lengths":[],"names":[],"sha256":"`+empty["sha256"].(string)+`"}` {
		t.Fatalf("empty description = %s", encode(t, empty))
	}
	changed := func(mutate func([]base.SSEEvent) []base.SSEEvent) bool {
		copied := make([]base.SSEEvent, len(events))
		copy(copied, events)
		return encode(t, Describe(mutate(copied))["sha256"]) != encode(t, description["sha256"])
	}
	cases := map[string]func([]base.SSEEvent) []base.SSEEvent{
		"order": func(values []base.SSEEvent) []base.SSEEvent {
			values[1], values[2] = values[2], values[1]
			return values
		},
		"name": func(values []base.SSEEvent) []base.SSEEvent { values[0].Event = "message_stop"; return values },
		"data": func(values []base.SSEEvent) []base.SSEEvent { values[3].Data = []byte("[DONE] "); return values },
		"name/data boundary": func(values []base.SSEEvent) []base.SSEEvent {
			values[0] = base.SSEEvent{Event: "message_start{", Data: []byte(`"a":1}`)}
			return values
		},
		"one event less": func(values []base.SSEEvent) []base.SSEEvent { return values[:3] },
	}
	for name, mutate := range cases {
		if !changed(mutate) {
			t.Errorf("%s: the hash does not bind it", name)
		}
	}
}
