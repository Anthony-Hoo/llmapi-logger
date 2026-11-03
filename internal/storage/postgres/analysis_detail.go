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

func garbageCollectAnalysisDetails(tx dbTransaction) error {
	_, err := tx.Exec(`WITH RECURSIVE live(hash) AS (
 SELECT detail_root FROM audit_analysis WHERE detail_root IS NOT NULL
 UNION
 SELECT n.parent_hash FROM analysis_detail_objects n JOIN live l ON n.hash=l.hash WHERE n.parent_hash IS NOT NULL
 ) DELETE FROM analysis_detail_objects n WHERE NOT EXISTS(SELECT 1 FROM live WHERE live.hash=n.hash)`)
	return err
}
