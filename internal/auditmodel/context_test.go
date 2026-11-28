package auditmodel

import (
	"errors"
	"testing"
)

func contextTestRef(slot string, seed byte) ObjectRef {
	hash := make([]byte, 32)
	semantic := make([]byte, 32)
	for index := range hash {
		hash[index] = seed
		semantic[index] = seed ^ 0xff
	}
	return ObjectRef{Slot: slot, ObjectHash: hash, SemanticHash: semantic}
}

func TestContextBase(t *testing.T) {
	request := []ObjectRef{contextTestRef(SlotMessages, 1)}
	response := []ObjectRef{contextTestRef(SlotChoice, 2)}
	if base, err := ContextBase(false, ParentBaseRoot, request, response); err != nil || base != nil {
		t.Fatalf("root base=%v err=%v", base, err)
	}
	if _, err := ContextBase(false, ParentBaseRequest, nil, nil); !errors.Is(err, ErrRootBase) {
		t.Fatalf("root with request base err=%v", err)
	}
	for _, invalid := range []string{ParentBaseRoot, "", "other"} {
		if _, err := ContextBase(true, invalid, request, response); !errors.Is(err, ErrParentBase) {
			t.Fatalf("parent with base %q err=%v", invalid, err)
		}
	}
	base, err := ContextBase(true, ParentBaseRequest, request, response)
	if err != nil || len(base) != 1 || &base[0] != &request[0] {
		t.Fatalf("request base=%v err=%v", base, err)
	}
	backing := make([]ObjectRef, 1, 4)
	copy(backing, request)
	base, err = ContextBase(true, ParentBasePostTurn, backing, response)
	if err != nil || len(base) != 2 || base[1].Slot != SlotChoice {
		t.Fatalf("post_turn base=%v err=%v", base, err)
	}
	if &base[0] == &backing[0] {
		t.Fatal("post_turn base appended into the parent's backing array")
	}
}

func TestApplyContext(t *testing.T) {
	base := []ObjectRef{contextTestRef(SlotMessages, 1), contextTestRef(SlotMessages, 2)}
	inserted := contextTestRef(SlotMessages, 3)
	want := []ObjectRef{base[0], inserted}
	operations := BuildDelta(base, want)
	got, err := ApplyContext(base, operations, len(want), SequenceHash(want))
	if err != nil || len(got) != 2 || !EqualHash(SequenceHash(got), SequenceHash(want)) {
		t.Fatalf("apply=%v err=%v", got, err)
	}
	if _, err := ApplyContext(base, operations, 3, SequenceHash(want)); !errors.Is(err, ErrContextSequence) {
		t.Fatalf("count mismatch err=%v", err)
	}
	if _, err := ApplyContext(base, operations, 2, SequenceHash(base)); !errors.Is(err, ErrContextSequence) {
		t.Fatalf("hash mismatch err=%v", err)
	}
	bad := []ContextOp{{Operation: OperationRetain, Count: 3}}
	if _, err := ApplyContext(base, bad, 3, nil); !errors.Is(err, ErrReconstruction) {
		t.Fatalf("over-long retain err=%v", err)
	}
	if _, err := ApplyContext(base, []ContextOp{{Operation: OperationRetain, Count: 1}}, 1, nil); !errors.Is(err, ErrReconstruction) {
		t.Fatalf("unconsumed base err=%v", err)
	}
	if _, err := ApplyContext(nil, []ContextOp{{Operation: "move", Count: 1}}, 0, nil); !errors.Is(err, ErrReconstruction) {
		t.Fatalf("unknown operation err=%v", err)
	}
	// Same refs as ApplyDelta, which copies.
	copied, err := ApplyDelta(base, operations)
	if err != nil || !EqualHash(SequenceHash(copied), SequenceHash(got)) {
		t.Fatalf("ApplyDelta=%v err=%v", copied, err)
	}
}
