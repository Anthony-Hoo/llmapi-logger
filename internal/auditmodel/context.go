package auditmodel

import (
	"bytes"
	"errors"
)

// Parent bases of turns.parent_base.
const (
	ParentBaseRoot     = "root"
	ParentBaseRequest  = "request"
	ParentBasePostTurn = "post_turn"
)

var (
	// ErrParentBase reports a turn with a parent whose parent_base is neither
	// request nor post_turn.
	ErrParentBase = errors.New("auditmodel: invalid non-root parent base")
	// ErrRootBase reports a turn without a parent whose parent_base is not root.
	ErrRootBase = errors.New("auditmodel: root turn has non-root base")
	// ErrContextSequence reports materialised request refs whose count or
	// sequence hash differ from the values stored on the turn.
	ErrContextSequence = errors.New("auditmodel: stored turn sequence hash mismatch")
)

// ContextBase returns the refs a turn's context operations apply to: nothing
// for a root turn, the parent's request refs for parent_base request, and the
// parent's request refs followed by its response refs for post_turn. The
// post_turn base is a new slice, so a caller's memoised parentRequest is never
// appended into; otherwise parentRequest is returned as it is.
func ContextBase(hasParent bool, parentBase string, parentRequest, parentResponse []ObjectRef) ([]ObjectRef, error) {
	if !hasParent {
		if parentBase != ParentBaseRoot {
			return nil, ErrRootBase
		}
		return nil, nil
	}
	switch parentBase {
	case ParentBaseRequest:
		return parentRequest, nil
	case ParentBasePostTurn:
		return append(append([]ObjectRef(nil), parentRequest...), parentResponse...), nil
	default:
		return nil, ErrParentBase
	}
}

// ApplyContext applies one turn's context operations to its base and checks
// the result against the turn's stored request_item_count and
// request_sequence_hash. A malformed operation returns ErrReconstruction; a
// count or hash that differs returns ErrContextSequence.
func ApplyContext(base []ObjectRef, operations []ContextOp, itemCount int, sequenceHash []byte) ([]ObjectRef, error) {
	result, err := ApplyImmutableDelta(base, operations)
	if err != nil {
		return nil, err
	}
	if len(result) != itemCount || !bytes.Equal(SequenceHash(result), sequenceHash) {
		return nil, ErrContextSequence
	}
	return result, nil
}

// ApplyImmutableDelta is ApplyDelta without copying the refs: the result
// shares hash slices with base and operations, which must be immutable
// stored values. Any malformed operation returns ErrReconstruction itself.
func ApplyImmutableDelta(base []ObjectRef, operations []ContextOp) ([]ObjectRef, error) {
	result := make([]ObjectRef, 0, len(base)+len(operations))
	position := 0
	for _, op := range operations {
		switch op.Operation {
		case OperationRetain, OperationDelete:
			if op.Count <= 0 || op.Count > len(base)-position || op.Ref != nil {
				return nil, ErrReconstruction
			}
			if op.Operation == OperationRetain {
				result = append(result, base[position:position+op.Count]...)
			}
			position += op.Count
		case OperationInsert:
			if op.Count != 1 || op.Ref == nil || len(op.Ref.ObjectHash) == 0 || op.Ref.Slot == "" {
				return nil, ErrReconstruction
			}
			result = append(result, *op.Ref)
		default:
			return nil, ErrReconstruction
		}
	}
	if position != len(base) {
		return nil, ErrReconstruction
	}
	return result, nil
}
