package postgres

import (
	"bytes"
	"context"
	"errors"
	"llmapi-logger/internal/storage"
)

const maxAnalysisDetailNodes = 20001

func (store *Store) LoadAnalysisDetailChain(ctx context.Context, root []byte, limit int) ([]storage.AnalysisDetailObject, error) {
	if ctx == nil || len(root) != 32 || limit < 1 || limit > maxAnalysisDetailNodes {
		return nil, errors.New("postgres: invalid analysis detail lookup")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `WITH RECURSIVE chain AS (
 SELECT hash, parent_hash, payload_enc, 1 AS depth FROM analysis_detail_objects WHERE hash = $1
 UNION ALL
 SELECT n.hash, n.parent_hash, n.payload_enc, c.depth + 1
 FROM analysis_detail_objects n JOIN chain c ON n.hash = c.parent_hash
 WHERE c.depth < $2
 ) SELECT hash, parent_hash, payload_enc FROM chain ORDER BY depth`, root, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []storage.AnalysisDetailObject
	for rows.Next() {
		var object storage.AnalysisDetailObject
		if err := rows.Scan(&object.Hash, &object.ParentHash, &object.PayloadEnc); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, rows.Err()
}

func (store *Store) ExistingAnalysisDetailObjects(ctx context.Context, hashes [][]byte) (map[string]bool, error) {
	if ctx == nil || len(hashes) > maxAnalysisDetailNodes {
		return nil, errors.New("postgres: invalid analysis detail lookup")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	result := make(map[string]bool)
	for start := 0; start < len(hashes); start += 1000 {
		end := min(start+1000, len(hashes))
		args := make([]any, end-start)
		for i, h := range hashes[start:end] {
			if len(h) != 32 {
				return nil, errors.New("postgres: invalid analysis hash")
			}
			args[i] = h
		}
		rows, err := store.readerDB.QueryContext(ctx, `SELECT hash FROM analysis_detail_objects WHERE hash IN (`+placeholders(len(args))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hash []byte
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return nil, err
			}
			result[string(hash)] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func saveAnalysisDetailObjects(tx dbTransaction, row AnalysisRow) error {
	if len(row.DetailRoot) != 0 && len(row.DetailRoot) != 32 || len(row.DetailObjects) > maxAnalysisDetailNodes {
		return localWriteError("postgres: invalid analysis detail root")
	}
	if len(row.DetailObjects) != 0 && len(row.DetailRoot) != 32 {
		return localWriteError("postgres: unrooted analysis detail objects")
	}
	for _, object := range row.DetailObjects {
		if len(object.Hash) != 32 || len(object.ParentHash) != 0 && len(object.ParentHash) != 32 || len(object.PayloadEnc) == 0 || bytes.Equal(object.Hash, object.ParentHash) {
			return localWriteError("postgres: invalid analysis detail object")
		}
		if _, err := tx.Exec(`INSERT INTO analysis_detail_objects(hash,parent_hash,payload_enc) VALUES ($1,$2,$3) ON CONFLICT(hash) DO NOTHING`, object.Hash, nullableBytes(object.ParentHash), object.PayloadEnc); err != nil {
			return err
		}
		var parent []byte
		if err := tx.QueryRow(`SELECT parent_hash FROM analysis_detail_objects WHERE hash=$1`, object.Hash).Scan(&parent); err != nil {
			return err
		}
		if !bytes.Equal(parent, object.ParentHash) {
			return localWriteError("postgres: analysis detail parent mismatch")
		}
	}
	return nil
}

// selectAnalysisDetailRoots returns the distinct detail roots that the given
// audits' analysis rows reference. Callers read them before the rows are
// deleted so the chains can be pruned afterwards.
func selectAnalysisDetailRoots(tx dbTransaction, auditIDs []string) ([][]byte, error) {
	return queryColumn[[]byte](tx, stringsToAny(auditIDs), `SELECT DISTINCT detail_root FROM audit_analysis
WHERE detail_root IS NOT NULL AND audit_id IN (%s)`, "select analysis detail roots")
}

// pruneAnalysisDetailChains deletes the prefix nodes on the chains that start
// at roots once no analysis row and no child node references them. It walks
// toward the chain heads one level per round and stops at the first node that
// is still shared, so the cost follows the released chains instead of the
// size of analysis_detail_objects. Both reference checks use indexes
// (analysis_detail_parent_idx, audit_analysis_detail_root_idx); a full
// reachability sweep inside the single writer transaction would block every
// audit write once the table grows.
func pruneAnalysisDetailChains(tx dbTransaction, roots [][]byte) error {
	candidates := distinctHashes(roots)
	for len(candidates) > 0 {
		parents, err := queryColumn[[]byte](tx, hashesToAny(candidates), `DELETE FROM analysis_detail_objects n
WHERE n.hash IN (%s)
  AND NOT EXISTS (SELECT 1 FROM analysis_detail_objects c WHERE c.parent_hash = n.hash)
  AND NOT EXISTS (SELECT 1 FROM audit_analysis a WHERE a.detail_root = n.hash)
RETURNING n.parent_hash`, "prune analysis detail objects")
		if err != nil {
			return err
		}
		// distinctHashes also drops the NULL parents of chain heads.
		candidates = distinctHashes(parents)
	}
	return nil
}
