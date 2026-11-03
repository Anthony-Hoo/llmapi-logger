package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"llmapi-logger/internal/auditmodel"
)

const graphHashQueryBatch = 400

func readTurnGraph(ctx context.Context, transaction dbTransaction, auditID string) (*TurnGraph, error) {
	var graph TurnGraph
	var parentTurnID, previousResponseID, responseID sql.NullString
	var requestItemCount, responseItemCount int
	err := transaction.QueryRowContext(ctx, `
SELECT turn_id, conversation_id, parent_turn_id, parent_base,
       link_reason, link_confidence, request_layout, response_layout,
       request_envelope_hash, response_envelope_hash,
       request_item_count, response_item_count,
       request_sequence_hash, response_sequence_hash,
       request_reconstruction_hash, response_reconstruction_hash,
       reconstruction_status, previous_response_id, response_id, created_at_ns
FROM turns
WHERE audit_id = $1`, auditID).Scan(
		&graph.TurnID,
		&graph.ConversationID,
		&parentTurnID,
		&graph.ParentBase,
		&graph.LinkReason,
		&graph.LinkConfidence,
		&graph.RequestLayout,
		&graph.ResponseLayout,
		&graph.RequestEnvelopeHash,
		&graph.ResponseEnvelopeHash,
		&requestItemCount,
		&responseItemCount,
		&graph.RequestSequenceHash,
		&graph.ResponseSequenceHash,
		&graph.RequestReconstructionHash,
		&graph.ResponseReconstructionHash,
		&graph.ReconstructionStatus,
		&previousResponseID,
		&responseID,
		&graph.CreatedAtNS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: read turn graph header: %w", err)
	}
	graph.ParentTurnID = nullStringPointer(parentTurnID)
	graph.PreviousResponseID = nullStringPointer(previousResponseID)
	graph.ResponseID = nullStringPointer(responseID)
	graph.RequestEnvelopeHash = cloneBytes(graph.RequestEnvelopeHash)
	graph.ResponseEnvelopeHash = cloneBytes(graph.ResponseEnvelopeHash)
	graph.RequestSequenceHash = cloneBytes(graph.RequestSequenceHash)
	graph.ResponseSequenceHash = cloneBytes(graph.ResponseSequenceHash)
	graph.RequestReconstructionHash = cloneBytes(graph.RequestReconstructionHash)
	graph.ResponseReconstructionHash = cloneBytes(graph.ResponseReconstructionHash)

	memo := make(map[string][]auditmodel.ObjectRef)
	graph.RequestRefs, err = loadRequestRefs(transaction, graph.TurnID, memo, make(map[string]bool))
	if err != nil {
		return nil, fmt.Errorf("postgres: reconstruct turn request refs: %w", err)
	}
	graph.ResponseRefs, err = loadResponseRefs(transaction, graph.TurnID)
	if err != nil {
		return nil, fmt.Errorf("postgres: read turn response refs: %w", err)
	}
	if len(graph.RequestRefs) != requestItemCount || len(graph.ResponseRefs) != responseItemCount ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.RequestRefs), graph.RequestSequenceHash) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.ResponseRefs), graph.ResponseSequenceHash) {
		return nil, errors.New("postgres: turn graph sequence verification failed")
	}

	hashes := make([][]byte, 0, len(graph.RequestRefs)+len(graph.ResponseRefs)+2)
	hashes = append(hashes, graph.RequestEnvelopeHash, graph.ResponseEnvelopeHash)
	for _, ref := range graph.RequestRefs {
		hashes = append(hashes, ref.ObjectHash)
	}
	for _, ref := range graph.ResponseRefs {
		hashes = append(hashes, ref.ObjectHash)
	}
	graph.Objects, err = readGraphObjects(ctx, transaction, hashes)
	if err != nil {
		return nil, err
	}
	objectHashes := make([][]byte, 0, len(graph.Objects))
	for _, object := range graph.Objects {
		objectHashes = append(objectHashes, object.Hash)
	}
	graph.Binaries, err = readGraphBinaries(ctx, transaction, objectHashes)
	if err != nil {
		return nil, err
	}
	return &graph, nil
}

func readGraphObjects(ctx context.Context, transaction dbTransaction, hashes [][]byte) ([]auditmodel.StoredContent, error) {
	return readContentObjects(ctx, transaction, hashes, true)
}

func readContentObjects(ctx context.Context, transaction dbTransaction, hashes [][]byte, requireAll bool) ([]auditmodel.StoredContent, error) {
	unique := uniqueHashes(hashes)
	objects := make(map[string]auditmodel.StoredContent, len(unique))
	for start := 0; start < len(unique); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(unique))
		arguments := make([]any, 0, end-start)
		for _, hash := range unique[start:end] {
			arguments = append(arguments, hash)
		}
		rows, err := transaction.QueryContext(ctx, `
SELECT object_hash, semantic_hash, kind, compression,
       plaintext_length, encoded_length, data_enc
FROM content_objects
WHERE object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return nil, fmt.Errorf("postgres: read graph content objects: %w", err)
		}
		for rows.Next() {
			var object auditmodel.StoredContent
			if err := rows.Scan(
				&object.Hash,
				&object.SemanticHash,
				&object.Kind,
				&object.Compression,
				&object.PlaintextLength,
				&object.EncodedLength,
				&object.DataEnc,
			); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres: scan graph content object: %w", err)
			}
			object.Hash = cloneBytes(object.Hash)
			object.SemanticHash = cloneBytes(object.SemanticHash)
			object.DataEnc = cloneBytes(object.DataEnc)
			objects[hex.EncodeToString(object.Hash)] = object
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("postgres: close graph content rows: %w", err)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("postgres: iterate graph content objects: %w", err)
		}
	}
	if requireAll && len(objects) != len(unique) {
		return nil, errors.New("postgres: turn graph references a missing content object")
	}
	result := make([]auditmodel.StoredContent, 0, len(unique))
	for _, hash := range unique {
		if object, ok := objects[hex.EncodeToString(hash)]; ok {
			result = append(result, object)
		}
	}
	return result, nil
}

func readGraphBinaries(ctx context.Context, transaction dbTransaction, objectHashes [][]byte) ([]auditmodel.StoredBinary, error) {
	unique := uniqueHashes(objectHashes)
	binaries := make(map[string]auditmodel.StoredBinary)
	for start := 0; start < len(unique); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(unique))
		arguments := make([]any, 0, end-start)
		for _, hash := range unique[start:end] {
			arguments = append(arguments, hash)
		}
		rows, err := transaction.QueryContext(ctx, `
SELECT DISTINCT b.binary_hash, b.media_type, b.compression,
       b.plaintext_length, b.encoded_length, b.data_enc
FROM content_binary_refs AS r
JOIN binary_objects AS b ON b.binary_hash = r.binary_hash
WHERE r.object_hash IN (`+placeholders(len(arguments))+`)`, arguments...)
		if err != nil {
			return nil, fmt.Errorf("postgres: read graph binary objects: %w", err)
		}
		for rows.Next() {
			var binary auditmodel.StoredBinary
			if err := rows.Scan(
				&binary.Hash,
				&binary.MediaType,
				&binary.Compression,
				&binary.PlaintextLength,
				&binary.EncodedLength,
				&binary.DataEnc,
			); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("postgres: scan graph binary object: %w", err)
			}
			binary.Hash = cloneBytes(binary.Hash)
			binary.DataEnc = cloneBytes(binary.DataEnc)
			binaries[hex.EncodeToString(binary.Hash)] = binary
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("postgres: close graph binary rows: %w", err)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("postgres: iterate graph binary objects: %w", err)
		}
	}
	result := make([]auditmodel.StoredBinary, 0, len(binaries))
	keys := make([]string, 0, len(binaries))
	for key := range binaries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, binaries[key])
	}
	return result, nil
}

func uniqueHashes(values [][]byte) [][]byte {
	seen := make(map[string][]byte, len(values))
	for _, value := range values {
		if len(value) != 32 {
			continue
		}
		key := hex.EncodeToString(value)
		if _, exists := seen[key]; !exists {
			seen[key] = cloneBytes(value)
		}
	}
	result := make([][]byte, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	// Stable order keeps tests and query responses deterministic.
	sort.Slice(result, func(left, right int) bool { return bytes.Compare(result[left], result[right]) < 0 })
	return result
}

func placeholders(count int, offset ...int) string {
	if count <= 0 {
		return "NULL"
	}
	start := 0
	if len(offset) > 0 {
		start = offset[0]
	}
	values := make([]string, count)
	for i := range values {
		values[i] = parameter(start + i + 1)
	}
	return strings.Join(values, ",")
}

// parameter returns an explicitly numbered PostgreSQL bind parameter.
func parameter(index int) string { return fmt.Sprintf("$%d", index) }

// LookupAuditObjects returns existing encrypted objects for the preparation
// cache. Missing objects are omitted. Callers must authenticate and validate
// returned ciphertext before reusing it; presence alone is not evidence.
func (store *Store) LookupAuditObjects(ctx context.Context, contentHashes, binaryHashes [][]byte) ([]auditmodel.StoredContent, []auditmodel.StoredBinary, error) {
	if ctx == nil {
		return nil, nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, nil, ErrClosed
	}
	for _, group := range [][][]byte{contentHashes, binaryHashes} {
		for _, hash := range group {
			if len(hash) != 32 {
				return nil, nil, errors.New("postgres: invalid object lookup hash")
			}
		}
	}
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: begin object lookup: %w", err)
	}
	defer transaction.Rollback()
	contents, err := readContentObjects(ctx, transaction, contentHashes, false)
	if err != nil {
		return nil, nil, err
	}
	unique := uniqueHashes(binaryHashes)
	binaries := make([]auditmodel.StoredBinary, 0, len(unique))
	for start := 0; start < len(unique); start += graphHashQueryBatch {
		end := min(start+graphHashQueryBatch, len(unique))
		args := make([]any, end-start)
		for i, hash := range unique[start:end] {
			args[i] = hash
		}
		rows, err := transaction.QueryContext(ctx, `SELECT binary_hash, media_type, compression, plaintext_length, encoded_length, data_enc FROM binary_objects WHERE binary_hash IN (`+placeholders(len(args))+`) ORDER BY binary_hash`, args...)
		if err != nil {
			return nil, nil, fmt.Errorf("postgres: lookup binary objects: %w", err)
		}
		for rows.Next() {
			var binary auditmodel.StoredBinary
			if err := rows.Scan(&binary.Hash, &binary.MediaType, &binary.Compression, &binary.PlaintextLength, &binary.EncodedLength, &binary.DataEnc); err != nil {
				rows.Close()
				return nil, nil, fmt.Errorf("postgres: scan binary lookup: %w", err)
			}
			binary.Hash = cloneBytes(binary.Hash)
			binary.DataEnc = cloneBytes(binary.DataEnc)
			binaries = append(binaries, binary)
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, nil, err
	}
	return contents, binaries, nil
}

// ReadImportTurnGraph reconstructs imported references inside the importer's
// uncommitted transaction so verification can fail before any data is visible.
func ReadImportTurnGraph(ctx context.Context, tx *sql.Tx, auditID string) (*TurnGraph, error) {
	if ctx == nil || tx == nil || auditID == "" {
		return nil, errors.New("postgres: invalid import graph read")
	}
	return readTurnGraph(ctx, tx, auditID)
}
