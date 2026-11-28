package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// archiveChangeStampDomain starts the change stamp preimage (design M.1).
const archiveChangeStampDomain = "llmapi-logger/archive-change-stamp/v1\x00"

// stampTable is one per-audit table of the change stamp: its primary key
// columns in key order, each text or a 64-bit integer, and how its rows are
// found from the audit id ($1).
type stampTable struct {
	name    string
	key     []stampColumn
	filter  string
	ordered string
}

type stampColumn struct {
	name    string
	integer bool
}

func textKey(name string) stampColumn    { return stampColumn{name: name} }
func integerKey(name string) stampColumn { return stampColumn{name: name, integer: true} }

const (
	stampByAudit = `audit_id = $1`
	stampByTurn  = `turn_id IN (SELECT turn_id FROM turns WHERE audit_id = $1)`
)

// archiveStampTables are the tables of M.1 in the order the stamp encodes
// them. Content objects, binary objects and their reference rows are not in
// it: they are content addressed, never updated, and cannot be deleted while
// a member references them (M.1 rows 6 and 7).
var archiveStampTables = []stampTable{
	{name: "audit_records", key: []stampColumn{textKey("audit_id")}, filter: stampByAudit},
	{name: "http_stages", key: []stampColumn{textKey("audit_id"), textKey("stage")}, filter: stampByAudit},
	{name: "http_headers", key: []stampColumn{textKey("audit_id"), textKey("stage"), textKey("kind"), textKey("name"), integerKey("value_index")}, filter: stampByAudit},
	{name: "http_header_blocks", key: []stampColumn{textKey("audit_id")}, filter: stampByAudit},
	{name: "body_streams", key: []stampColumn{textKey("audit_id"), textKey("stage")}, filter: stampByAudit},
	{name: "body_chunks", key: []stampColumn{textKey("audit_id"), textKey("stage"), integerKey("seq")}, filter: stampByAudit},
	{name: "stream_timelines", key: []stampColumn{textKey("audit_id"), textKey("stage")}, filter: stampByAudit},
	{name: "parsed_results", key: []stampColumn{textKey("audit_id")}, filter: stampByAudit},
	{name: "token_links", key: []stampColumn{textKey("audit_id")}, filter: stampByAudit},
	{name: "audit_project_identity", key: []stampColumn{textKey("audit_id")}, filter: stampByAudit},
	{name: "integrity_events", key: []stampColumn{integerKey("sequence")}, filter: stampByAudit},
	{name: "turns", key: []stampColumn{textKey("turn_id")}, filter: stampByAudit},
	{name: "turn_context_ops", key: []stampColumn{textKey("turn_id"), integerKey("op_index")}, filter: stampByTurn},
	{name: "turn_response_items", key: []stampColumn{textKey("turn_id"), integerKey("ordinal")}, filter: stampByTurn},
}

// stampEncoder writes the E.1 notation the stamp uses: B, T, I and L.
type stampEncoder struct{ w io.Writer }

func (e stampEncoder) bytes(value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = e.w.Write(length[:])
	_, _ = e.w.Write(value)
}

func (e stampEncoder) text(value string) { e.bytes([]byte(value)) }

func (e stampEncoder) integer(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	e.bytes(encoded[:])
}

// archiveChangeStamp computes the change stamp of one audit in transaction
// (design M.1, Q1 乙): SHA-256 over the domain and, for every table of
// archiveStampTables in order, T(table) L(n) and for each row in primary key
// order B(primary key encoding) I(xmin). The primary key encoding is its
// columns' T or I concatenated. It reads only key columns and xmin, which is
// in the tuple header, so no ciphertext is fetched. exists is false when the
// audit has no audit_records row; the stamp is then still the stamp of the
// (empty) row sets.
func archiveChangeStamp(ctx context.Context, transaction dbTransaction, auditID string) (stamp [32]byte, exists bool, err error) {
	digest := sha256.New()
	exists, err = writeArchiveChangeStampInput(ctx, transaction, auditID, digest)
	if err != nil {
		return [32]byte{}, false, err
	}
	copy(stamp[:], digest.Sum(nil))
	return stamp, exists, nil
}

// writeArchiveChangeStampInput writes the stamp preimage to w.
func writeArchiveChangeStampInput(ctx context.Context, transaction dbTransaction, auditID string, w io.Writer) (bool, error) {
	if _, err := io.WriteString(w, archiveChangeStampDomain); err != nil {
		return false, err
	}
	encoder := stampEncoder{w: w}
	exists := false
	for _, table := range archiveStampTables {
		rows, err := readStampRows(ctx, transaction, table, auditID)
		if err != nil {
			return false, err
		}
		if table.name == "audit_records" {
			exists = len(rows) == 1
		}
		encoder.text(table.name)
		encoder.integer(int64(len(rows)))
		for _, row := range rows {
			encoder.bytes(row.key)
			encoder.integer(row.xmin)
		}
	}
	return exists, nil
}

type stampRow struct {
	key  []byte
	xmin int64
}

func readStampRows(ctx context.Context, transaction dbTransaction, table stampTable, auditID string) ([]stampRow, error) {
	columns := make([]string, 0, len(table.key))
	for _, column := range table.key {
		columns = append(columns, column.name)
	}
	keyList := strings.Join(columns, ", ")
	rows, err := transaction.QueryContext(ctx, `SELECT `+keyList+`, xmin::text::bigint FROM `+table.name+
		` WHERE `+table.filter+` ORDER BY `+keyList, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read change stamp rows: %w", err)
	}
	var result []stampRow
	texts := make([]string, len(table.key))
	integers := make([]int64, len(table.key))
	destinations := make([]any, len(table.key)+1)
	for index, column := range table.key {
		if column.integer {
			destinations[index] = &integers[index]
		} else {
			destinations[index] = &texts[index]
		}
	}
	var xmin int64
	destinations[len(table.key)] = &xmin
	for rows.Next() {
		if err := rows.Scan(destinations...); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan change stamp row: %w", err)
		}
		var key strings.Builder
		encoder := stampEncoder{w: &key}
		for index, column := range table.key {
			if column.integer {
				encoder.integer(integers[index])
			} else {
				encoder.text(texts[index])
			}
		}
		result = append(result, stampRow{key: []byte(key.String()), xmin: xmin})
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: change stamp rows: %w", err)
	}
	return result, nil
}
