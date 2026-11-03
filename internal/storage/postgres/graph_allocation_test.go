package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"llmapi-logger/internal/auditmodel"
	"os"
	"runtime"
	"testing"
)

// This frozen legacy algorithm exists only to compare reconstruction semantics
// and allocation growth against the PostgreSQL implementation.
func loadRequestRefsRecursiveBaseline(transaction dbTransaction, turnID string, memo map[string][]auditmodel.ObjectRef, visiting map[string]bool) ([]auditmodel.ObjectRef, error) {
	if cached, exists := memo[turnID]; exists {
		return cloneObjectRefs(cached), nil
	}
	// Graph validation failures, including corrupt stored ancestors, roll back
	// only this save; like reconstruction failures they must not discard
	// unrelated writes that share the batch.
	if visiting[turnID] {
		return nil, localWriteError("sqlite writer: turn parent cycle")
	}
	visiting[turnID] = true
	defer delete(visiting, turnID)

	var header storedTurnHeader
	var parent sql.NullString
	if err := transaction.QueryRow(`
SELECT parent_turn_id, parent_base, request_item_count, request_sequence_hash
FROM turns WHERE turn_id = $1`, turnID).Scan(&parent, &header.ParentBase, &header.RequestItemCount, &header.RequestSequenceHash); err != nil {
		return nil, fmt.Errorf("sqlite writer: load turn header: %w", err)
	}
	if parent.Valid {
		header.ParentTurnID = &parent.String
	}
	base := []auditmodel.ObjectRef(nil)
	if header.ParentTurnID != nil {
		parentRequest, err := loadRequestRefsRecursiveBaseline(transaction, *header.ParentTurnID, memo, visiting)
		if err != nil {
			return nil, err
		}
		base = parentRequest
		if header.ParentBase == "post_turn" {
			parentResponse, err := loadResponseRefs(transaction, *header.ParentTurnID)
			if err != nil {
				return nil, err
			}
			base = append(base, parentResponse...)
		} else if header.ParentBase != "request" {
			return nil, localWriteError("sqlite writer: invalid non-root parent base")
		}
	} else if header.ParentBase != "root" {
		return nil, localWriteError("sqlite writer: root turn has non-root base")
	}
	operations, err := loadContextOperations(transaction, turnID)
	if err != nil {
		return nil, err
	}
	result, err := auditmodel.ApplyDelta(base, operations)
	if err != nil {
		return nil, err
	}
	if len(result) != header.RequestItemCount || !bytes.Equal(auditmodel.SequenceHash(result), header.RequestSequenceHash) {
		return nil, localWriteError("sqlite writer: stored turn sequence hash mismatch")
	}
	memo[turnID] = cloneObjectRefs(result)
	return result, nil
}

func TestGraphIterativeReconstructionAllocation(t *testing.T) {
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	depth := 32
	if os.Getenv("LOGGER_STORAGE_BENCH") == "1" {
		depth = 128
	}
	request := make([]graphTestItem, 64)
	for i := range request {
		request[i] = graphItem("user_message", map[string]any{"role": "user", "content": fmt.Sprintf("stable context %d", i)})
	}
	previous := ""
	for i := 0; i < depth; i++ {
		id := fmt.Sprintf("allocation-%03d", i)
		response := fmt.Sprintf("response-%03d", i)
		saveGraphTestTurn(t, store, cipher, id, previous, response, int64(100+i), request, nil)
		previous = response
	}
	tx, err := store.readerDB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	leaf := fmt.Sprintf("allocation-%03d", depth-1)
	measure := func(legacy bool) (uint64, int, []auditmodel.ObjectRef, int) {
		counted := &graphCountingTransaction{dbTransaction: tx}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var refs []auditmodel.ObjectRef
		var memo map[string][]auditmodel.ObjectRef
		for i := 0; i < 3; i++ {
			memo = make(map[string][]auditmodel.ObjectRef)
			if legacy {
				refs, err = loadRequestRefsRecursiveBaseline(counted, leaf, memo, make(map[string]bool))
			} else {
				refs, err = loadRequestRefs(counted, leaf, memo, make(map[string]bool))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / 3, len(memo), refs, counted.queries / 3
	}
	oldBytes, oldMemo, oldRefs, oldQueries := measure(true)
	newBytes, newMemo, newRefs, newQueries := measure(false)
	if !bytes.Equal(auditmodel.SequenceHash(oldRefs), auditmodel.SequenceHash(newRefs)) {
		t.Fatal("optimized refs differ")
	}
	if newMemo != 1 || oldMemo != depth {
		t.Fatalf("memo endpoints=%d legacy=%d depth=%d", newMemo, oldMemo, depth)
	}
	t.Logf("depth=%d refs=64 legacy_total_alloc=%d iterative_total_alloc=%d ratio=%.3f legacy_memo=%d iterative_memo=%d legacy_queries=%d iterative_queries=%d", depth, oldBytes, newBytes, float64(newBytes)/float64(oldBytes), oldMemo, newMemo, oldQueries, newQueries)
	if newBytes >= oldBytes {
		t.Fatal("iterative reconstruction did not reduce allocation")
	}
}

type graphCountingTransaction struct {
	dbTransaction
	queries int
}

func (tx *graphCountingTransaction) Query(query string, args ...any) (*sql.Rows, error) {
	tx.queries++
	return tx.dbTransaction.Query(query, args...)
}
func (tx *graphCountingTransaction) QueryRow(query string, args ...any) *sql.Row {
	tx.queries++
	return tx.dbTransaction.QueryRow(query, args...)
}
