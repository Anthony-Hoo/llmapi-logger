package postgres

import (
	"database/sql"
	"fmt"
	"llmapi-logger/internal/auditmodel"
)

// Bound both recursion output and payload memory. Exceeding a limit is an
// explicit reconstruction failure, never a silently truncated history.
const maxAncestorHeaders = 65536
const maxAncestorReferenceRows = 262144

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
	rows, err := tx.Query(`SELECT turn_id,operation,item_count,slot,object_hash,semantic_hash FROM turn_context_ops WHERE turn_id=ANY($1::text[]) ORDER BY turn_id,op_index LIMIT $2`, turnIDs, limit+1)
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
	rows, err = tx.Query(`SELECT turn_id,slot,object_hash,semantic_hash FROM turn_response_items WHERE turn_id=ANY($1::text[]) ORDER BY turn_id,ordinal LIMIT $2`, responseIDs, limit-used+1)
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
