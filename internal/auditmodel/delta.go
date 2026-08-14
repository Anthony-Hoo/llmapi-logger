package auditmodel

import "fmt"

// BuildDelta preserves the longest common prefix and suffix. The middle is
// represented as one delete range followed by inserts. This is linear, stable,
// and correct for append, retry, truncation, rollback, and arbitrary edits.
func BuildDelta(base, current []ObjectRef) []ContextOp {
	prefix := 0
	for prefix < len(base) && prefix < len(current) && equalRef(base[prefix], current[prefix]) {
		prefix++
	}

	baseSuffix := len(base)
	currentSuffix := len(current)
	for baseSuffix > prefix && currentSuffix > prefix && equalRef(base[baseSuffix-1], current[currentSuffix-1]) {
		baseSuffix--
		currentSuffix--
	}

	operations := make([]ContextOp, 0, 3+currentSuffix-prefix)
	if prefix > 0 {
		operations = append(operations, ContextOp{Operation: OperationRetain, Count: prefix})
	}
	if deleted := baseSuffix - prefix; deleted > 0 {
		operations = append(operations, ContextOp{Operation: OperationDelete, Count: deleted})
	}
	for index := prefix; index < currentSuffix; index++ {
		ref := cloneRef(current[index])
		operations = append(operations, ContextOp{Operation: OperationInsert, Count: 1, Ref: &ref})
	}
	if suffix := len(base) - baseSuffix; suffix > 0 {
		operations = append(operations, ContextOp{Operation: OperationRetain, Count: suffix})
	}
	return operations
}

func ApplyDelta(base []ObjectRef, operations []ContextOp) ([]ObjectRef, error) {
	result := make([]ObjectRef, 0, len(base)+len(operations))
	position := 0
	for index, operation := range operations {
		switch operation.Operation {
		case OperationRetain:
			if operation.Count <= 0 || position+operation.Count > len(base) || operation.Ref != nil {
				return nil, fmt.Errorf("%w: invalid retain at %d", ErrReconstruction, index)
			}
			for _, ref := range base[position : position+operation.Count] {
				result = append(result, cloneRef(ref))
			}
			position += operation.Count
		case OperationDelete:
			if operation.Count <= 0 || position+operation.Count > len(base) || operation.Ref != nil {
				return nil, fmt.Errorf("%w: invalid delete at %d", ErrReconstruction, index)
			}
			position += operation.Count
		case OperationInsert:
			if operation.Count != 1 || operation.Ref == nil || len(operation.Ref.ObjectHash) == 0 || operation.Ref.Slot == "" {
				return nil, fmt.Errorf("%w: invalid insert at %d", ErrReconstruction, index)
			}
			result = append(result, cloneRef(*operation.Ref))
		default:
			return nil, fmt.Errorf("%w: unknown operation %q", ErrReconstruction, operation.Operation)
		}
	}
	if position != len(base) {
		return nil, fmt.Errorf("%w: delta left %d base refs", ErrReconstruction, len(base)-position)
	}
	return result, nil
}

func DeltaCost(operations []ContextOp) int {
	cost := 0
	for _, operation := range operations {
		if operation.Operation == OperationDelete || operation.Operation == OperationInsert {
			cost += operation.Count
		}
	}
	return cost
}

func equalRef(left, right ObjectRef) bool {
	return left.Slot == right.Slot && EqualHash(left.ObjectHash, right.ObjectHash)
}

func cloneRef(value ObjectRef) ObjectRef {
	value.ObjectHash = append([]byte(nil), value.ObjectHash...)
	value.SemanticHash = append([]byte(nil), value.SemanticHash...)
	return value
}
