package auditbench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"llmapi-logger/internal/storage"
)

// Distribution is the output of the dist subcommand: aggregates only.
type Distribution struct {
	Conversations       int64 `json:"conversations"`
	Turns               int64 `json:"turns"`
	AuditsWithoutTurn   int64 `json:"audits_without_turn"`
	NoTurnRequestBytes  int64 `json:"audits_without_turn_request_bytes"`
	NoTurnResponseBytes int64 `json:"audits_without_turn_response_bytes"`
	// CrossConversationParents counts turns whose parent belongs to another
	// conversation; a non-zero value makes the sharing ratio a lower bound.
	CrossConversationParents int64            `json:"turns_with_parent_in_other_conversation"`
	TurnsPerConversation     []Bucket         `json:"turns_per_conversation"`
	TurnsPerConvDay          []Bucket         `json:"turns_per_conversation_day"`
	BytesPerConversation     []Bucket         `json:"stored_bytes_per_conversation"`
	Sharing                  SharingRatio     `json:"object_sharing"`
	ByProtocol               map[string]int64 `json:"conversations_by_protocol"`
	Notes                    []string         `json:"notes"`
}

// Bucket counts values in [Low, High].
type Bucket struct {
	Low   int64 `json:"low"`
	High  int64 `json:"high"`
	Count int64 `json:"count"`
	Sum   int64 `json:"sum"`
}

// SharingRatio compares packing every conversation's objects separately with
// one store for all of them (design section 5.4).
type SharingRatio struct {
	PerConversationStored    int64   `json:"per_conversation_stored_bytes"`
	GlobalStored             int64   `json:"global_stored_bytes"`
	PerConversationPlaintext int64   `json:"per_conversation_plaintext_bytes"`
	GlobalPlaintext          int64   `json:"global_plaintext_bytes"`
	StoredRatio              float64 `json:"stored_ratio"`
	PlaintextRatio           float64 `json:"plaintext_ratio"`
	BinaryPerConversation    int64   `json:"binary_per_conversation_stored_bytes"`
	BinaryGlobal             int64   `json:"binary_global_stored_bytes"`
}

// conversationObjects lists, per conversation, every content object its
// turns reference: inserted context items, response items and both
// envelopes. Retained items come from ancestor turns of the same
// conversation and are therefore already in the set.
const conversationObjects = `
WITH refs AS (
    SELECT t.conversation_id, o.object_hash
    FROM turns AS t JOIN turn_context_ops AS o ON o.turn_id = t.turn_id
    WHERE o.operation = 'insert'
    UNION
    SELECT t.conversation_id, r.object_hash
    FROM turns AS t JOIN turn_response_items AS r ON r.turn_id = t.turn_id
    UNION
    SELECT conversation_id, request_envelope_hash FROM turns
    UNION
    SELECT conversation_id, response_envelope_hash FROM turns
)`

// objectSets extends conversationObjects with the sized content objects and
// the binary objects they reference, both per conversation.
const objectSets = `,
objects AS (
    SELECT r.conversation_id, c.object_hash, c.encoded_length, c.plaintext_length
    FROM refs AS r JOIN content_objects AS c ON c.object_hash = r.object_hash
),
binaries AS (
    SELECT DISTINCT o.conversation_id, b.binary_hash, b.encoded_length
    FROM objects AS o
    JOIN content_binary_refs AS cb ON cb.object_hash = o.object_hash
    JOIN binary_objects AS b ON b.binary_hash = cb.binary_hash
)`

func runDist(ctx context.Context, getenv func(string) string, schema string, timeout time.Duration) (Distribution, error) {
	var result Distribution
	dsn := getenv(DatabaseEnv)
	if dsn == "" {
		return result, fmt.Errorf("set %s to the PostgreSQL connection string", DatabaseEnv)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return result, errors.New("invalid PostgreSQL connection configuration")
	}
	config.RuntimeParams["application_name"] = "audit-bench-dist"
	config.RuntimeParams["default_transaction_read_only"] = "on"
	if schema != "" {
		config.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize()
	}
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return result, safeError("connect to PostgreSQL", err)
	}
	defer connection.Close(context.Background())
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, safeError("begin read-only transaction", err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
		return result, safeError("set statement timeout", err)
	}
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('turns') IS NOT NULL AND to_regclass('audit_records') IS NOT NULL`).Scan(&present); err != nil {
		return result, safeError("inspect schema", err)
	}
	if !present {
		return result, errors.New("no audit tables in the current schema; pass --schema")
	}
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM conversations), (SELECT count(*) FROM turns)`).Scan(&result.Conversations, &result.Turns); err != nil {
		return result, safeError("count conversations", err)
	}
	result.ByProtocol = make(map[string]int64)
	rows, err := tx.Query(ctx, `SELECT protocol, count(*) FROM conversations GROUP BY 1`)
	if err != nil {
		return result, safeError("count conversations by protocol", err)
	}
	for rows.Next() {
		var protocol string
		var count int64
		if err := rows.Scan(&protocol, &count); err != nil {
			rows.Close()
			return result, safeError("count conversations by protocol", err)
		}
		result.ByProtocol[protocol] = count
	}
	rows.Close()
	if err := tx.QueryRow(ctx, `
SELECT count(*),
       COALESCE(sum((SELECT b.observed_length FROM body_streams AS b WHERE b.audit_id = a.audit_id AND b.stage = $1)), 0),
       COALESCE(sum((SELECT b.observed_length FROM body_streams AS b WHERE b.audit_id = a.audit_id AND b.stage = $2)), 0)
FROM audit_records AS a
WHERE NOT EXISTS (SELECT 1 FROM turns AS t WHERE t.audit_id = a.audit_id)`, storage.StageRequestReceived, storage.StageResponseReceived).
		Scan(&result.AuditsWithoutTurn, &result.NoTurnRequestBytes, &result.NoTurnResponseBytes); err != nil {
		return result, safeError("count audits without turn", err)
	}
	// Buckets are powers of two: [1,1], [2,3], [4,7], ... computed in SQL so
	// only bucket counts leave the database.
	bucketQuery := func(inner string) ([]Bucket, error) {
		rows, err := tx.Query(ctx, `
SELECT floor(log(2::numeric, greatest(value, 1)::numeric))::int AS bucket, count(*), sum(value)::bigint
FROM (`+inner+`) AS v GROUP BY 1 ORDER BY 1`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		buckets := make([]Bucket, 0)
		for rows.Next() {
			var exponent int
			var bucket Bucket
			if err := rows.Scan(&exponent, &bucket.Count, &bucket.Sum); err != nil {
				return nil, err
			}
			bucket.Low = int64(1) << exponent
			bucket.High = int64(1)<<(exponent+1) - 1
			buckets = append(buckets, bucket)
		}
		return buckets, rows.Err()
	}
	if result.TurnsPerConversation, err = bucketQuery(`SELECT count(*) AS value FROM turns GROUP BY conversation_id`); err != nil {
		return result, safeError("turns per conversation", err)
	}
	if result.TurnsPerConvDay, err = bucketQuery(`SELECT count(*) AS value FROM turns GROUP BY conversation_id, created_at_ns / 86400000000000`); err != nil {
		return result, safeError("turns per conversation day", err)
	}
	if result.BytesPerConversation, err = bucketQuery(conversationObjects + objectSets + `,
sized AS (
    SELECT conversation_id, encoded_length FROM objects
    UNION ALL
    SELECT conversation_id, encoded_length FROM binaries
)
SELECT sum(encoded_length) AS value FROM sized GROUP BY conversation_id`); err != nil {
		return result, safeError("bytes per conversation", err)
	}
	// A parent in another conversation would carry retained items the
	// per-conversation sets miss; the ratio is then a lower bound.
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM turns AS child JOIN turns AS parent ON parent.turn_id = child.parent_turn_id
WHERE parent.conversation_id <> child.conversation_id`).Scan(&result.CrossConversationParents); err != nil {
		return result, safeError("cross-conversation parents", err)
	}
	sharing := &result.Sharing
	if err := tx.QueryRow(ctx, conversationObjects+objectSets+`
SELECT COALESCE((SELECT sum(encoded_length) FROM objects), 0)::bigint,
       COALESCE((SELECT sum(encoded_length) FROM content_objects WHERE object_hash IN (SELECT object_hash FROM objects)), 0)::bigint,
       COALESCE((SELECT sum(plaintext_length) FROM objects), 0)::bigint,
       COALESCE((SELECT sum(plaintext_length) FROM content_objects WHERE object_hash IN (SELECT object_hash FROM objects)), 0)::bigint,
       COALESCE((SELECT sum(encoded_length) FROM binaries), 0)::bigint,
       COALESCE((SELECT sum(encoded_length) FROM binary_objects WHERE binary_hash IN (SELECT binary_hash FROM binaries)), 0)::bigint`).
		Scan(&sharing.PerConversationStored, &sharing.GlobalStored, &sharing.PerConversationPlaintext, &sharing.GlobalPlaintext,
			&sharing.BinaryPerConversation, &sharing.BinaryGlobal); err != nil {
		return result, safeError("object sharing", err)
	}
	if sharing.GlobalStored+sharing.BinaryGlobal > 0 {
		sharing.StoredRatio = round3(float64(sharing.PerConversationStored+sharing.BinaryPerConversation) / float64(sharing.GlobalStored+sharing.BinaryGlobal))
	}
	if sharing.GlobalPlaintext > 0 {
		sharing.PlaintextRatio = round3(float64(sharing.PerConversationPlaintext) / float64(sharing.GlobalPlaintext))
	}
	result.Notes = []string{
		"Only counts, lengths and hashes were read, in one read-only repeatable-read transaction; no content column was selected.",
		"Stored bytes are encoded_length (after compression, before encryption); plaintext bytes are plaintext_length.",
		"Per-conversation sets include the envelopes, inserted context items and response items of every turn of the conversation.",
		"Conversation days use UTC days of turns.created_at_ns, which is the parse time.",
	}
	return result, nil
}

func renderDistribution(result Distribution, output io.Writer) {
	var builder strings.Builder
	builder.WriteString("# audit-bench distribution\n\n")
	table(&builder, []string{"Measure", "Value"}, [][]string{
		{"conversations (count)", fmt.Sprint(result.Conversations)},
		{"turns (count)", fmt.Sprint(result.Turns)},
		{"audits without a turn (count)", fmt.Sprint(result.AuditsWithoutTurn)},
		{"turns whose parent is in another conversation (count; non-zero makes the ratio a lower bound)", fmt.Sprint(result.CrossConversationParents)},
		{"audits without a turn, inbound request bodies (MB)", megabytes(result.NoTurnRequestBytes)},
		{"audits without a turn, upstream response bodies (MB)", megabytes(result.NoTurnResponseBytes)},
	})
	protocolRows := make([][]string, 0, len(result.ByProtocol))
	for _, key := range sortedKeys(result.ByProtocol) {
		protocolRows = append(protocolRows, []string{key, fmt.Sprint(result.ByProtocol[key])})
	}
	table(&builder, []string{"Protocol", "Conversations (count)"}, protocolRows)
	for _, histogram := range []struct {
		title, unit string
		buckets     []Bucket
		bytes       bool
	}{
		{"Turns per conversation", "turns", result.TurnsPerConversation, false},
		{"Turns per conversation and UTC day", "turns", result.TurnsPerConvDay, false},
		{"Stored object bytes per conversation (content and binary)", "bytes", result.BytesPerConversation, true},
	} {
		fmt.Fprintf(&builder, "## %s\n\n", histogram.title)
		rows := make([][]string, 0, len(histogram.buckets))
		for _, bucket := range histogram.buckets {
			sum := fmt.Sprint(bucket.Sum)
			if histogram.bytes {
				sum = megabytes(bucket.Sum)
			}
			rows = append(rows, []string{fmt.Sprintf("%d - %d", bucket.Low, bucket.High), fmt.Sprint(bucket.Count), sum})
		}
		sumHeader := "Sum (" + histogram.unit + ")"
		if histogram.bytes {
			sumHeader = "Sum (MB)"
		}
		table(&builder, []string{"Range (" + histogram.unit + ")", "Conversations (count)", sumHeader}, rows)
	}
	sharing := result.Sharing
	builder.WriteString("## Object sharing (design 5.4)\n\n")
	table(&builder, []string{"Measure", "Value"}, [][]string{
		{"sum over conversations of deduplicated content objects, stored (MB)", megabytes(sharing.PerConversationStored)},
		{"globally deduplicated content objects, stored (MB)", megabytes(sharing.GlobalStored)},
		{"sum over conversations of deduplicated binary objects, stored (MB)", megabytes(sharing.BinaryPerConversation)},
		{"globally deduplicated binary objects, stored (MB)", megabytes(sharing.BinaryGlobal)},
		{"ratio, stored content and binary (x)", fmt.Sprintf("%.3f", sharing.StoredRatio)},
		{"sum over conversations, content plaintext (MB)", megabytes(sharing.PerConversationPlaintext)},
		{"global, content plaintext (MB)", megabytes(sharing.GlobalPlaintext)},
		{"ratio, content plaintext (x)", fmt.Sprintf("%.3f", sharing.PlaintextRatio)},
	})
	for _, note := range result.Notes {
		builder.WriteString("- " + note + "\n")
	}
	_, _ = io.WriteString(output, builder.String())
}
