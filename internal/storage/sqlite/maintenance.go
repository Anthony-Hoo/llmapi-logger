package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
)

type retentionRequest struct {
	CutoffNS   int64
	AuditLimit int
	GapLimit   int
	Result     RetentionResult
}

// DeleteExpired removes one bounded batch of terminal audits and gaps. When a
// retained turn depends on an expiring parent, its already-verified request
// sequence is first materialized as a root checkpoint so reconstruction does
// not depend on deleted history.
func (store *Store) DeleteExpired(ctx context.Context, cutoffNS int64, auditLimit, gapLimit int) (RetentionResult, error) {
	if cutoffNS <= 0 {
		return RetentionResult{}, errors.New("sqlite: invalid retention cutoff")
	}
	if auditLimit < 0 || auditLimit > RetentionBatchLimit || gapLimit < 0 || gapLimit > RetentionBatchLimit || (auditLimit == 0 && gapLimit == 0) {
		return RetentionResult{}, fmt.Errorf("sqlite: retention limits must each be between 0 and %d, with at least one positive", RetentionBatchLimit)
	}
	request := &retentionRequest{CutoffNS: cutoffNS, AuditLimit: auditLimit, GapLimit: gapLimit}
	if err := store.submitSync(ctx, writeRequest{kind: writeDeleteExpired, data: request}); err != nil {
		return RetentionResult{}, err
	}
	return request.Result, nil
}

func deleteExpired(transaction *sql.Tx, request *retentionRequest) error {
	if request == nil || request.CutoffNS <= 0 ||
		request.AuditLimit < 0 || request.AuditLimit > RetentionBatchLimit ||
		request.GapLimit < 0 || request.GapLimit > RetentionBatchLimit ||
		(request.AuditLimit == 0 && request.GapLimit == 0) {
		return errors.New("sqlite writer: invalid retention request")
	}

	auditIDs, err := selectExpiredAuditIDs(transaction, request.CutoffNS, request.AuditLimit)
	if err != nil {
		return err
	}
	if err := deleteAuditBatch(transaction, auditIDs); err != nil {
		return err
	}

	gaps, err := transaction.Exec(`
DELETE FROM audit_gaps
WHERE id IN (
    SELECT id
    FROM audit_gaps
    WHERE ended_at_ns < ?
    ORDER BY ended_at_ns, id
    LIMIT ?
)`, request.CutoffNS, request.GapLimit)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete expired gaps: %w", err)
	}
	deletedGaps, err := gaps.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: count deleted gaps: %w", err)
	}

	request.Result = RetentionResult{
		DeletedAudits: len(auditIDs),
		DeletedGaps:   int(deletedGaps),
	}
	return nil
}

func selectExpiredAuditIDs(transaction *sql.Tx, cutoffNS int64, limit int) ([]string, error) {
	if limit == 0 {
		return nil, nil
	}
	rows, err := transaction.Query(`
SELECT audit_id
FROM audit_records
WHERE ended_at_ns IS NOT NULL
  AND started_at_ns < ?
  AND parse_status <> 'processing'
ORDER BY started_at_ns, audit_id
LIMIT ?`, cutoffNS, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: select expired audits: %w", err)
	}
	defer rows.Close()
	var auditIDs []string
	for rows.Next() {
		var auditID string
		if err := rows.Scan(&auditID); err != nil {
			return nil, fmt.Errorf("sqlite writer: scan expired audit: %w", err)
		}
		auditIDs = append(auditIDs, auditID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite writer: iterate expired audits: %w", err)
	}
	return auditIDs, nil
}

func deleteAuditBatch(transaction *sql.Tx, auditIDs []string) error {
	if len(auditIDs) == 0 {
		return nil
	}
	turnIDs, err := selectTurnIDsForAudits(transaction, auditIDs)
	if err != nil {
		return err
	}
	if err := checkpointRetainedChildren(transaction, turnIDs); err != nil {
		return err
	}
	if err := deleteTurnsLeafFirst(transaction, turnIDs); err != nil {
		return err
	}

	arguments := stringsToAny(auditIDs)
	result, err := transaction.Exec(`DELETE FROM audit_records WHERE audit_id IN (`+placeholders(len(arguments))+`)`, arguments...)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete expired audits: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite writer: count deleted audits: %w", err)
	}
	if deleted != int64(len(auditIDs)) {
		return errors.New("sqlite writer: expired audit batch changed during deletion")
	}
	if err := garbageCollectConversationObjects(transaction); err != nil {
		return err
	}
	return nil
}

func selectTurnIDsForAudits(transaction *sql.Tx, auditIDs []string) ([]string, error) {
	if len(auditIDs) == 0 {
		return nil, nil
	}
	arguments := stringsToAny(auditIDs)
	rows, err := transaction.Query(`
SELECT turn_id
FROM turns
WHERE audit_id IN (`+placeholders(len(arguments))+`)
ORDER BY created_at_ns, turn_id`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sqlite writer: select expired turns: %w", err)
	}
	defer rows.Close()
	var turnIDs []string
	for rows.Next() {
		var turnID string
		if err := rows.Scan(&turnID); err != nil {
			return nil, fmt.Errorf("sqlite writer: scan expired turn: %w", err)
		}
		turnIDs = append(turnIDs, turnID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite writer: iterate expired turns: %w", err)
	}
	return turnIDs, nil
}

type retentionCheckpoint struct {
	TurnID string
	Refs   []auditmodel.ObjectRef
}

func checkpointRetainedChildren(transaction *sql.Tx, expiredTurnIDs []string) error {
	if len(expiredTurnIDs) == 0 {
		return nil
	}
	arguments := stringsToAny(expiredTurnIDs)
	rows, err := transaction.Query(`
SELECT turn_id
FROM turns
WHERE parent_turn_id IN (`+placeholders(len(arguments))+`)
  AND turn_id NOT IN (`+placeholders(len(arguments))+`)
ORDER BY created_at_ns, turn_id`, append(arguments, arguments...)...)
	if err != nil {
		return fmt.Errorf("sqlite writer: select retention checkpoint turns: %w", err)
	}
	var childTurnIDs []string
	for rows.Next() {
		var turnID string
		if err := rows.Scan(&turnID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite writer: scan retention checkpoint turn: %w", err)
		}
		childTurnIDs = append(childTurnIDs, turnID)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlite writer: close retention checkpoint turns: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite writer: iterate retention checkpoint turns: %w", err)
	}

	memo := make(map[string][]auditmodel.ObjectRef)
	checkpoints := make([]retentionCheckpoint, 0, len(childTurnIDs))
	for _, turnID := range childTurnIDs {
		refs, err := loadRequestRefs(transaction, turnID, memo, make(map[string]bool))
		if err != nil {
			return fmt.Errorf("sqlite writer: materialize retention checkpoint: %w", err)
		}
		checkpoints = append(checkpoints, retentionCheckpoint{TurnID: turnID, Refs: refs})
	}
	for _, checkpoint := range checkpoints {
		if _, err := transaction.Exec(`DELETE FROM turn_context_ops WHERE turn_id = ?`, checkpoint.TurnID); err != nil {
			return fmt.Errorf("sqlite writer: clear retention checkpoint delta: %w", err)
		}
		result, err := transaction.Exec(`
UPDATE turns
SET parent_turn_id = NULL,
    parent_base = 'root',
    link_reason = 'retention_checkpoint',
    link_confidence = 100
WHERE turn_id = ?`, checkpoint.TurnID)
		if err != nil {
			return fmt.Errorf("sqlite writer: update retention checkpoint turn: %w", err)
		}
		if err := requireOneRow(result, "update retention checkpoint turn"); err != nil {
			return err
		}
		if err := insertContextOperations(transaction, checkpoint.TurnID, auditmodel.BuildDelta(nil, checkpoint.Refs)); err != nil {
			return fmt.Errorf("sqlite writer: save retention checkpoint delta: %w", err)
		}
		rebuilt, err := loadRequestRefs(transaction, checkpoint.TurnID, make(map[string][]auditmodel.ObjectRef), make(map[string]bool))
		if err != nil || len(rebuilt) != len(checkpoint.Refs) ||
			!auditmodel.EqualHash(auditmodel.SequenceHash(rebuilt), auditmodel.SequenceHash(checkpoint.Refs)) {
			return errors.New("sqlite writer: retention checkpoint verification failed")
		}
	}
	return nil
}

func deleteTurnsLeafFirst(transaction *sql.Tx, turnIDs []string) error {
	if len(turnIDs) == 0 {
		return nil
	}
	arguments := stringsToAny(turnIDs)
	remaining := len(turnIDs)
	for remaining > 0 {
		result, err := transaction.Exec(`
DELETE FROM turns
WHERE turn_id IN (`+placeholders(len(arguments))+`)
  AND NOT EXISTS (
      SELECT 1 FROM turns AS child
      WHERE child.parent_turn_id = turns.turn_id
  )`, arguments...)
		if err != nil {
			return fmt.Errorf("sqlite writer: delete expired turns: %w", err)
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlite writer: count deleted turns: %w", err)
		}
		if deleted <= 0 || deleted > int64(remaining) {
			return errors.New("sqlite writer: expired turn graph is cyclic or still referenced")
		}
		remaining -= int(deleted)
	}
	return nil
}

func garbageCollectConversationObjects(transaction *sql.Tx) error {
	statements := []struct {
		name string
		sql  string
	}{
		{name: "conversations", sql: `
DELETE FROM conversations
WHERE NOT EXISTS (
    SELECT 1 FROM turns WHERE turns.conversation_id = conversations.conversation_id
)`},
		{name: "content objects", sql: `
DELETE FROM content_objects
WHERE NOT EXISTS (
          SELECT 1 FROM turns WHERE turns.request_envelope_hash = content_objects.object_hash
      )
  AND NOT EXISTS (
          SELECT 1 FROM turns WHERE turns.response_envelope_hash = content_objects.object_hash
      )
  AND NOT EXISTS (
          SELECT 1 FROM turn_context_ops WHERE turn_context_ops.object_hash = content_objects.object_hash
      )
  AND NOT EXISTS (
          SELECT 1 FROM turn_response_items WHERE turn_response_items.object_hash = content_objects.object_hash
      )`},
		{name: "binary objects", sql: `
DELETE FROM binary_objects
WHERE NOT EXISTS (
    SELECT 1 FROM content_binary_refs WHERE content_binary_refs.binary_hash = binary_objects.binary_hash
)`},
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(statement.sql); err != nil {
			return fmt.Errorf("sqlite writer: garbage collect %s: %w", statement.name, err)
		}
	}
	return nil
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
