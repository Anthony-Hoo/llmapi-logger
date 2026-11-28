package bundle

import (
	"bytes"
	"errors"
	"strings"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
)

// orderState enforces the line order of B.3 item 4 within a segment:
//   - the lines of one conversation are contiguous, and within it
//     (turns.created_at_ns, audit_id) strictly increases;
//   - audits without a turn come after every audit with one, with
//     (started_at_ns, audit_id) strictly increasing.
//
// The order of the conversations themselves is not fixed: B.3 groups by
// conversation without naming a sort key.
type orderState struct {
	turnless     bool
	inGroup      bool
	conversation string
	finished     map[string]bool
	lastTime     int64
	lastAudit    string
}

var errOrder = errors.New("line out of segment order")

// next checks record against the lines before it and reports whether it
// starts a new conversation group, which ends the parent memo of the last.
func (state *orderState) next(record *archive.Record) (bool, error) {
	if state.finished == nil {
		state.finished = make(map[string]bool)
	}
	audit := record.Audit
	if record.Turn == nil {
		if !state.turnless {
			if state.inGroup {
				state.finished[state.conversation] = true
			}
			state.turnless, state.inGroup = true, false
			state.lastTime, state.lastAudit = audit.StartedAtNS, audit.AuditID
			return true, nil
		}
		if !after(audit.StartedAtNS, audit.AuditID, state.lastTime, state.lastAudit) {
			return false, errOrder
		}
		state.lastTime, state.lastAudit = audit.StartedAtNS, audit.AuditID
		return false, nil
	}
	if state.turnless {
		return false, errOrder
	}
	conversation, created := record.Turn.Row.ConversationID, record.Turn.Row.CreatedAtNS
	if !state.inGroup || conversation != state.conversation {
		if state.finished[conversation] {
			return false, errOrder
		}
		if state.inGroup {
			state.finished[state.conversation] = true
		}
		state.inGroup, state.conversation = true, conversation
		state.lastTime, state.lastAudit = created, audit.AuditID
		return true, nil
	}
	if !after(created, audit.AuditID, state.lastTime, state.lastAudit) {
		return false, errOrder
	}
	state.lastTime, state.lastAudit = created, audit.AuditID
	return false, nil
}

func after(time int64, id string, lastTime int64, lastID string) bool {
	return time > lastTime || time == lastTime && strings.Compare(id, lastID) > 0
}

// turnRefs are the materialised request refs and the response refs of a
// turn written earlier in the segment: the base of its children's deltas.
type turnRefs struct {
	request  []auditmodel.ObjectRef
	response []auditmodel.ObjectRef
}

func refsEqual(left, right []auditmodel.ObjectRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Slot != right[index].Slot || !bytes.Equal(left[index].ObjectHash, right[index].ObjectHash) ||
			!bytes.Equal(left[index].SemanticHash, right[index].SemanticHash) {
			return false
		}
	}
	return true
}

func cloneRefs(refs []auditmodel.ObjectRef) []auditmodel.ObjectRef {
	out := make([]auditmodel.ObjectRef, len(refs))
	for index, ref := range refs {
		out[index] = auditmodel.ObjectRef{Slot: ref.Slot, ObjectHash: bytes.Clone(ref.ObjectHash), SemanticHash: bytes.Clone(ref.SemanticHash)}
	}
	return out
}

// materialize applies context to the turn's row on a scratch turn and
// returns the refs, or the error of Turn.Materialize.
func materialize(row archive.TurnRow, context archive.RequestContext, parent *turnRefs) ([]auditmodel.ObjectRef, error) {
	scratch := archive.Turn{Row: row, Context: context}
	var request, response []auditmodel.ObjectRef
	if parent != nil {
		request, response = parent.request, parent.response
	}
	if err := scratch.Materialize(request, response); err != nil {
		return nil, err
	}
	if scratch.RequestRefs == nil {
		return []auditmodel.ObjectRef{}, nil
	}
	return scratch.RequestRefs, nil
}
