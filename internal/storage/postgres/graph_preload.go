package postgres

import (
	"bytes"
	"database/sql"
	"fmt"
	"llmapi-logger/internal/auditmodel"
)

// Bound both recursion output and payload memory. Exceeding a limit is an
// explicit reconstruction failure, never a silently truncated history. They
// are variables only so tests can lower them to reach the limits.
var maxAncestorHeaders = 65536
var maxAncestorReferenceRows = 262144

// loadRequestRefs keeps at most memoEndpointLimit endpoints and
// memoReferenceLimit references in its memo, clearing it when either would
// be exceeded, and never memoizes a result longer than memoReferenceLimit.
const (
	memoEndpointLimit  = 32
	memoReferenceLimit = 65536
)

func preloadAncestorHeaders(tx dbTransaction, turnID string, memo map[string][]auditmodel.ObjectRef, limit int) (map[string]storedTurnHeader, error) {
	cached := make([]string, 0, len(memo))
	for id := range memo {
		cached = append(cached, id)
	}
	// UNION (not UNION ALL) terminates corrupt cycles without an ever-growing
	// path array. No ORDER BY forces materialization beyond the explicit limit.
	rows, err := tx.Query(`WITH RECURSIVE ancestors AS (
 SELECT turn_id,parent_turn_id,parent_base,request_item_count,request_sequence_hash FROM turns WHERE turn_id=$1
 UNION
 SELECT t.turn_id,t.parent_turn_id,t.parent_base,t.request_item_count,t.request_sequence_hash
 FROM turns t JOIN ancestors a ON t.turn_id=a.parent_turn_id
 WHERE NOT (t.turn_id = ANY($2::text[]))
 ) SELECT turn_id,parent_turn_id,parent_base,request_item_count,request_sequence_hash FROM ancestors LIMIT $3`, turnID, cached, limit+1)
	if err != nil {
		return nil, fmt.Errorf("postgres writer: preload ancestor headers: %w", err)
	}
	defer rows.Close()
	headers := make(map[string]storedTurnHeader)
	for rows.Next() {
		var id string
		var parent sql.NullString
		var header storedTurnHeader
		if err := rows.Scan(&id, &parent, &header.ParentBase, &header.RequestItemCount, &header.RequestSequenceHash); err != nil {
			return nil, err
		}
		if parent.Valid {
			header.ParentTurnID = &parent.String
		}
		headers[id] = header
		if len(headers) > limit {
			return nil, localWriteError("postgres writer: ancestor header limit exceeded")
		}
	}
	return headers, rows.Err()
}

func preloadAncestorReferences(tx dbTransaction, turnIDs, responseIDs []string, limit int) (map[string][]auditmodel.ContextOp, map[string][]auditmodel.ObjectRef, error) {
	operations := make(map[string][]auditmodel.ContextOp, len(turnIDs))
	responses := make(map[string][]auditmodel.ObjectRef, len(responseIDs))
	rows, err := tx.Query(`SELECT turn_id,operation,item_count,slot,object_hash,semantic_hash FROM (SELECT turn_id,op_index,operation,item_count,slot,object_hash,semantic_hash FROM turn_context_ops WHERE turn_id=ANY($1::text[]) LIMIT $2) bounded ORDER BY turn_id,op_index`, turnIDs, limit+1)
	if err != nil {
		return nil, nil, err
	}
	used := 0
	for rows.Next() {
		var id string
		var op auditmodel.ContextOp
		var slot sql.NullString
		var objectHash, semanticHash []byte
		if err := rows.Scan(&id, &op.Operation, &op.Count, &slot, &objectHash, &semanticHash); err != nil {
			rows.Close()
			return nil, nil, err
		}
		used++
		if used > limit {
			rows.Close()
			return nil, nil, localWriteError("postgres writer: ancestor reference limit exceeded")
		}
		if op.Operation == auditmodel.OperationInsert {
			op.Ref = &auditmodel.ObjectRef{Slot: slot.String, ObjectHash: objectHash, SemanticHash: semanticHash}
		}
		operations[id] = append(operations[id], op)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	if len(responseIDs) == 0 {
		return operations, responses, nil
	}
	rows, err = tx.Query(`SELECT turn_id,slot,object_hash,semantic_hash FROM (SELECT turn_id,ordinal,slot,object_hash,semantic_hash FROM turn_response_items WHERE turn_id=ANY($1::text[]) LIMIT $2) bounded ORDER BY turn_id,ordinal`, responseIDs, limit-used+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ref auditmodel.ObjectRef
		if err := rows.Scan(&id, &ref.Slot, &ref.ObjectHash, &ref.SemanticHash); err != nil {
			return nil, nil, err
		}
		used++
		if used > limit {
			return nil, nil, localWriteError("postgres writer: ancestor reference limit exceeded")
		}
		responses[id] = append(responses[id], ref)
	}
	return operations, responses, rows.Err()
}

// candidateChainRefLimit bounds the request refs one save keeps for its
// parent candidates. A save over it evaluates them as before, walking each
// chain on its own. It is a variable only so tests can lower it.
var candidateChainRefLimit = maxAncestorReferenceRows

// chainFrame is what one save knows about a turn on a candidate's chain.
type chainFrame struct {
	parent    string
	hasParent bool
	// depth counts the turns from this one to its root, itself included.
	depth int
	// rows counts the context-op rows of those turns and the response rows
	// of their post_turn parents: what a walk from this turn reads.
	rows int
}

// candidateChains holds, for one save, the verified request refs of its
// parent candidates and the frames of their chains. It lives in that save's
// transaction only and is sized by the candidates' chains: one entry per
// turn walked and one request per candidate.
type candidateChains struct {
	refs   map[string][]auditmodel.ObjectRef
	frames map[string]chainFrame
	// total counts the refs held in refs.
	total int
}

// memo returns a loadRequestRefs memo that answers every candidate, or an
// empty one when the chains were not loaded.
func (chains *candidateChains) memo() map[string][]auditmodel.ObjectRef {
	memo := make(map[string][]auditmodel.ObjectRef)
	if chains != nil {
		for id, refs := range chains.refs {
			memo[id] = refs
		}
	}
	return memo
}

// loadCandidateChains loads the request refs of every candidate, oldest
// first, so a candidate's walk stops at the newest older candidate on its
// chain instead of going back to the root: the chains are walked about once
// in all, instead of once per candidate.
//
// The result has to leave the evaluation exactly as it was, when each
// candidate was walked in the given order with one bounded memo. The refs
// are the same, since the same rows are verified and applied the same way.
// What could differ is a refusal: the preload limits apply to the part of a
// chain one walk reads, and that part is longer when candidates are walked
// newest first. So it replays the old walks' accounting from the frames and
// returns nil, sending the caller down the old path, whenever an old walk
// would have been refused; also when any walk here fails, and when the refs
// would outgrow candidateChainRefLimit.
func loadCandidateChains(transaction dbTransaction, candidates []turnCandidate) *candidateChains {
	chains := &candidateChains{refs: make(map[string][]auditmodel.ObjectRef), frames: make(map[string]chainFrame)}
	for index := len(candidates) - 1; index >= 0; index-- {
		if err := chains.load(transaction, candidates[index].turnID); err != nil {
			return nil
		}
		if chains.total > candidateChainRefLimit {
			return nil
		}
	}
	if !chains.withinLegacyLimits(candidates) {
		return nil
	}
	return chains
}

// load walks turnID's chain back to its root or to a candidate already
// loaded, as loadRequestRefs does, recording each frame.
func (chains *candidateChains) load(transaction dbTransaction, turnID string) error {
	if _, loaded := chains.refs[turnID]; loaded {
		return nil
	}
	headers, err := preloadAncestorHeaders(transaction, turnID, chains.refs, maxAncestorHeaders)
	if err != nil {
		return err
	}
	type frame struct {
		id     string
		header storedTurnHeader
	}
	var path []frame
	seen := make(map[string]bool)
	current := turnID
	var result []auditmodel.ObjectRef
	for {
		if seen[current] {
			return localWriteError("postgres writer: turn parent cycle")
		}
		seen[current] = true
		if cached, ok := chains.refs[current]; ok {
			result = cached
			break
		}
		header, exists := headers[current]
		if !exists {
			return fmt.Errorf("postgres writer: load turn header: %w", sql.ErrNoRows)
		}
		if header.RequestItemCount > maxAncestorReferenceRows {
			return localWriteError("postgres writer: reconstructed reference limit exceeded")
		}
		if header.ParentTurnID != nil && header.ParentBase != "request" && header.ParentBase != "post_turn" {
			return localWriteError("postgres writer: invalid non-root parent base")
		}
		if header.ParentTurnID == nil && header.ParentBase != "root" {
			return localWriteError("postgres writer: root turn has non-root base")
		}
		path = append(path, frame{current, header})
		if header.ParentTurnID == nil {
			break
		}
		current = *header.ParentTurnID
	}
	ids := make([]string, 0, len(path))
	responseIDs := make([]string, 0, len(path))
	for _, frame := range path {
		ids = append(ids, frame.id)
		if frame.header.ParentBase == "post_turn" {
			responseIDs = append(responseIDs, *frame.header.ParentTurnID)
		}
	}
	operationsByTurn, responsesByTurn, err := preloadAncestorReferences(transaction, ids, responseIDs, maxAncestorReferenceRows)
	if err != nil {
		return err
	}
	for i := len(path) - 1; i >= 0; i-- {
		frame := path[i]
		operations := operationsByTurn[frame.id]
		stats := chainFrame{depth: 1, rows: len(operations)}
		base := result
		if parentID := frame.header.ParentTurnID; parentID != nil {
			parent, known := chains.frames[*parentID]
			if !known {
				return localWriteError("postgres writer: candidate chain frame missing")
			}
			stats.parent, stats.hasParent = *parentID, true
			stats.depth += parent.depth
			stats.rows += parent.rows
			if frame.header.ParentBase == "post_turn" {
				response := responsesByTurn[*parentID]
				stats.rows += len(response)
				// Do not append into a loaded candidate's backing array.
				base = append(append([]auditmodel.ObjectRef(nil), base...), response...)
			}
		}
		result, err = applyImmutableRefs(base, operations)
		if err != nil {
			return err
		}
		if len(result) != frame.header.RequestItemCount || !bytes.Equal(auditmodel.SequenceHash(result), frame.header.RequestSequenceHash) {
			return localWriteError("postgres writer: stored turn sequence hash mismatch")
		}
		chains.frames[frame.id] = stats
	}
	chains.refs[turnID] = result
	chains.total += len(result)
	return nil
}

// withinLegacyLimits replays the walks the candidates got before, one per
// candidate in evaluation order with one memo bounded as loadRequestRefs
// bounds it, and reports whether every one stayed within the preload limits.
// A walk then read the candidate's chain down to the first turn in the memo.
func (chains *candidateChains) withinLegacyLimits(candidates []turnCandidate) bool {
	memo := make(map[string]int)
	for _, candidate := range candidates {
		id := candidate.turnID
		if _, hit := memo[id]; hit {
			continue
		}
		frame := chains.frames[id]
		depth, rows := frame.depth, frame.rows
		for current := frame; current.hasParent; current = chains.frames[current.parent] {
			if _, hit := memo[current.parent]; hit {
				stop := chains.frames[current.parent]
				depth -= stop.depth
				rows -= stop.rows
				break
			}
		}
		if depth > maxAncestorHeaders || rows > maxAncestorReferenceRows {
			return false
		}
		size := len(chains.refs[id])
		total := size
		for _, held := range memo {
			total += held
		}
		if len(memo) >= memoEndpointLimit || total > memoReferenceLimit {
			clear(memo)
		}
		if size <= memoReferenceLimit {
			memo[id] = size
		}
	}
	return true
}
