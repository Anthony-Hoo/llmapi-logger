package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"
)

// archiveChangeStampDomain starts the change stamp preimage (design M.1).
const archiveChangeStampDomain = "llmapi-logger/archive-change-stamp/v1\x00"

// stampTable is one per-audit table of the change stamp: its primary key
// columns in key order, each text or a 64-bit integer, and whether its rows
// are found through the audit's turn (turn_id) rather than by audit_id.
type stampTable struct {
	name   string
	key    []stampColumn
	byTurn bool
}

type stampColumn struct {
	name    string
	integer bool
}

func textKey(name string) stampColumn    { return stampColumn{name: name} }
func integerKey(name string) stampColumn { return stampColumn{name: name, integer: true} }

// archiveStampTables are the tables of M.1 in the order the stamp encodes
// them. Content objects, binary objects and their reference rows are not in
// it: they are content addressed, never updated, and cannot be deleted while
// a member references them (M.1 rows 6 and 7).
var archiveStampTables = []stampTable{
	{name: "audit_records", key: []stampColumn{textKey("audit_id")}},
	{name: "http_stages", key: []stampColumn{textKey("audit_id"), textKey("stage")}},
	{name: "http_headers", key: []stampColumn{textKey("audit_id"), textKey("stage"), textKey("kind"), textKey("name"), integerKey("value_index")}},
	{name: "http_header_blocks", key: []stampColumn{textKey("audit_id")}},
	{name: "body_streams", key: []stampColumn{textKey("audit_id"), textKey("stage")}},
	{name: "body_chunks", key: []stampColumn{textKey("audit_id"), textKey("stage"), integerKey("seq")}},
	{name: "stream_timelines", key: []stampColumn{textKey("audit_id"), textKey("stage")}},
	{name: "parsed_results", key: []stampColumn{textKey("audit_id")}},
	{name: "token_links", key: []stampColumn{textKey("audit_id")}},
	{name: "audit_project_identity", key: []stampColumn{textKey("audit_id")}},
	{name: "integrity_events", key: []stampColumn{integerKey("sequence")}},
	{name: "turns", key: []stampColumn{textKey("turn_id")}},
	{name: "turn_context_ops", key: []stampColumn{textKey("turn_id"), integerKey("op_index")}, byTurn: true},
	{name: "turn_response_items", key: []stampColumn{textKey("turn_id"), integerKey("ordinal")}, byTurn: true},
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
	stamps, err := archiveChangeStamps(ctx, transaction, []string{auditID})
	if err != nil {
		return [32]byte{}, false, err
	}
	result := stamps[auditID]
	return result.stamp, result.exists, nil
}

type archiveStamp struct {
	stamp  [32]byte
	exists bool
}

// archiveChangeStamps computes the stamps of many audits with one query per
// table for every archiveStampBatch audits, so the writer's intent
// registration does not pay a round trip per table and member. The bytes are
// those archiveChangeStamp gives for each audit alone.
func archiveChangeStamps(ctx context.Context, transaction dbTransaction, auditIDs []string) (map[string]archiveStamp, error) {
	result := make(map[string]archiveStamp, len(auditIDs))
	for start := 0; start < len(auditIDs); start += archiveStampBatch {
		end := min(start+archiveStampBatch, len(auditIDs))
		ids := auditIDs[start:end]
		digests := make(map[string]hash.Hash, len(ids))
		for _, id := range ids {
			digests[id] = sha256.New()
		}
		exists, err := writeArchiveChangeStampInputs(ctx, transaction, ids, func(id string) io.Writer { return digests[id] })
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			var stamp [32]byte
			copy(stamp[:], digests[id].Sum(nil))
			result[id] = archiveStamp{stamp: stamp, exists: exists[id]}
		}
	}
	return result, nil
}

const archiveStampBatch = 400

// writeArchiveChangeStampInput writes the stamp preimage of one audit to w.
func writeArchiveChangeStampInput(ctx context.Context, transaction dbTransaction, auditID string, w io.Writer) (bool, error) {
	exists, err := writeArchiveChangeStampInputs(ctx, transaction, []string{auditID}, func(string) io.Writer { return w })
	return exists[auditID], err
}

// writeArchiveChangeStampInputs writes the stamp preimage of each audit to
// the writer output returns for it. The audit ids must be distinct.
func writeArchiveChangeStampInputs(ctx context.Context, transaction dbTransaction, auditIDs []string, output func(string) io.Writer) (map[string]bool, error) {
	for _, id := range auditIDs {
		if _, err := io.WriteString(output(id), archiveChangeStampDomain); err != nil {
			return nil, err
		}
	}
	exists := make(map[string]bool, len(auditIDs))
	for _, table := range archiveStampTables {
		rows, err := readStampRows(ctx, transaction, table, auditIDs)
		if err != nil {
			return nil, err
		}
		for _, id := range auditIDs {
			encoder := stampEncoder{w: output(id)}
			own := rows[id]
			if table.name == "audit_records" {
				exists[id] = len(own) == 1
			}
			encoder.text(table.name)
			encoder.integer(int64(len(own)))
			for _, row := range own {
				encoder.bytes(row.key)
				encoder.integer(row.xmin)
			}
		}
	}
	return exists, nil
}

type stampRow struct {
	key  []byte
	xmin int64
}

// readStampRows reads one table's key columns and xmin for the audits, in
// primary key order within each audit.
func readStampRows(ctx context.Context, transaction dbTransaction, table stampTable, auditIDs []string) (map[string][]stampRow, error) {
	columns := make([]string, 0, len(table.key))
	for _, column := range table.key {
		columns = append(columns, "r."+column.name)
	}
	keyList := strings.Join(columns, ", ")
	owner, from := "r.audit_id", table.name+` AS r`
	if table.byTurn {
		owner, from = "t.audit_id", table.name+` AS r JOIN turns AS t ON t.turn_id = r.turn_id`
	}
	rows, err := transaction.QueryContext(ctx, `SELECT `+owner+`, `+keyList+`, r.xmin::text::bigint FROM `+from+
		` WHERE `+owner+` IN (`+placeholders(len(auditIDs))+`) ORDER BY `+owner+`, `+keyList, stringsToAny(auditIDs)...)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read change stamp rows: %w", err)
	}
	result := make(map[string][]stampRow, len(auditIDs))
	var auditID string
	texts := make([]string, len(table.key))
	integers := make([]int64, len(table.key))
	destinations := make([]any, len(table.key)+2)
	destinations[0] = &auditID
	for index, column := range table.key {
		if column.integer {
			destinations[index+1] = &integers[index]
		} else {
			destinations[index+1] = &texts[index]
		}
	}
	var xmin int64
	destinations[len(table.key)+1] = &xmin
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
		result[auditID] = append(result[auditID], stampRow{key: []byte(key.String()), xmin: xmin})
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: change stamp rows: %w", err)
	}
	return result, nil
}
