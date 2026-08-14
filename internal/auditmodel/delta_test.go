package auditmodel

import "testing"

func TestDeltaSupportsAppendRetryTruncateAndEdit(t *testing.T) {
	t.Parallel()
	ref := func(slot, value string) ObjectRef {
		return ObjectRef{Slot: slot, ObjectHash: ContentHash([]byte(value)), SemanticHash: ContentHash([]byte("semantic-" + value))}
	}
	base := []ObjectRef{ref("messages", "a"), ref("messages", "b"), ref("messages", "c")}
	tests := []struct {
		name    string
		current []ObjectRef
	}{
		{name: "append", current: append(append([]ObjectRef(nil), base...), ref("messages", "d"))},
		{name: "retry", current: append([]ObjectRef(nil), base...)},
		{name: "truncate", current: append([]ObjectRef(nil), base[:1]...)},
		{name: "edit middle", current: []ObjectRef{base[0], ref("messages", "x"), base[2]}},
		{name: "rollback and branch", current: []ObjectRef{base[0], ref("messages", "branch")}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			operations := BuildDelta(base, test.current)
			rebuilt, err := ApplyDelta(base, operations)
			if err != nil {
				t.Fatalf("ApplyDelta: %v", err)
			}
			if len(rebuilt) != len(test.current) {
				t.Fatalf("rebuilt len = %d, want %d", len(rebuilt), len(test.current))
			}
			for index := range rebuilt {
				if !equalRef(rebuilt[index], test.current[index]) {
					t.Fatalf("ref %d mismatch", index)
				}
			}
		})
	}
}

func TestApplyDeltaRejectsIncompleteOrOutOfBoundsOperations(t *testing.T) {
	t.Parallel()
	base := []ObjectRef{{Slot: "input", ObjectHash: ContentHash([]byte("a"))}}
	for _, operations := range [][]ContextOp{
		{{Operation: OperationRetain, Count: 2}},
		{{Operation: OperationInsert, Count: 1}},
		{},
	} {
		if _, err := ApplyDelta(base, operations); err == nil {
			t.Fatalf("expected invalid delta for %+v", operations)
		}
	}
}
