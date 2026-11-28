package archive

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ColumnClass says how one column of an archived table is archived (E.3).
type ColumnClass string

const (
	// ClassDigest: in the archive and covered by the record digest, either
	// directly or, for an encrypted column, by the hash of its plaintext.
	ClassDigest ColumnClass = "digest"
	// ClassArchived: in the archive, not covered by the record digest.
	ClassArchived ColumnClass = "archived"
	// ClassExcluded: not in the archive; Reason says why.
	ClassExcluded ColumnClass = "excluded"
)

// Column is one entry of the column specification. Field is where the value
// is archived, as a path into the line ("audit_records.status_code",
// "http_stages[].stage"), into an objects or gaps file entry
// ("objects:content_object.data", "gaps:gap.id"), or "audit_id" for the key
// columns of child tables, which the line's audit_id gives. Field is empty for
// an excluded column; Reason is set for an excluded column and, as a note,
// for a few others.
type Column struct {
	Table  string
	Name   string
	Class  ColumnClass
	Field  string
	Reason string
}

// ArchivedTables are the 20 tables of E.3, in the order of the format
// document.
var ArchivedTables = []string{
	"audit_records", "http_stages", "http_headers", "http_header_blocks",
	"body_streams", "body_chunks", "stream_timelines", "parsed_results",
	"token_links", "turns", "turn_context_ops", "turn_response_items",
	"conversations", "content_objects", "binary_objects", "content_binary_refs",
	"content_external_refs", "audit_project_identity", "integrity_events", "audit_gaps",
}

// DerivedTables reference archived tables but are recomputable and not
// archived (design 4.4).
var DerivedTables = []string{"audit_analysis", "agent_spawn_hints", "analysis_detail_objects"}

// RootTables are the tables whose direct or indirect referrers must all be
// archived or derived (J.1 step 3).
var RootTables = []string{"audit_records", "turns", "content_objects", "binary_objects", "conversations"}

const (
	reasonStorageEncoding = "storage encoding of the ciphertext container; the plaintext and its length are archived"
	reasonUpdatedAt       = "changes with every later turn of the conversation; not a property of one audit (Q7)"
	noteContextOps        = "archived only in the delta request context; the digest covers the materialised refs instead (Q6)"
	noteKey               = "key column given by the enclosing record"
)

// Columns is the column specification of E.3 and Q7: every column of every
// archived table, as schema version 7 defines it.
var Columns = buildColumns()

func buildColumns() []Column {
	var columns []Column
	add := func(table string, class ColumnClass, field string, names ...string) {
		for _, name := range names {
			path := field
			if strings.HasSuffix(field, ".") {
				path = field + name
			}
			columns = append(columns, Column{Table: table, Name: name, Class: class, Field: path})
		}
	}
	addOne := func(table, name string, class ColumnClass, field, reason string) {
		columns = append(columns, Column{Table: table, Name: name, Class: class, Field: field, Reason: reason})
	}
	exclude := func(table, reason string, names ...string) {
		for _, name := range names {
			columns = append(columns, Column{Table: table, Name: name, Class: ClassExcluded, Reason: reason})
		}
	}

	add("audit_records", ClassDigest, "audit_records.",
		"audit_id", "schema_generation", "started_at_ns", "ended_at_ns", "route_id", "protocol",
		"parser_name", "method", "path")
	addOne("audit_records", "request_uri_enc", ClassDigest, "audit_records.request_uri", "projected Request-URI (D.3)")
	add("audit_records", ClassDigest, "audit_records.",
		"mode", "status_code", "ttft_ns", "forward_status", "capture_status", "parse_status",
		"blocked_by", "block_code", "error_code", "newapi_request_id", "caller_status",
		"caller_attempts", "caller_next_at_ns", "caller_updated_at_ns", "api_key_fpr",
		"parse_save_failures", "parse_next_at_ns", "capture_version")
	addOne("audit_records", "user_agent_enc", ClassDigest, "audit_records.user_agent", "projected values (D.3)")

	addOne("http_stages", "audit_id", ClassDigest, "audit_id", noteKey)
	add("http_stages", ClassDigest, "http_stages[].",
		"stage", "state", "proto", "method", "host", "status_code", "content_length",
		"started_at_ns", "ended_at_ns", "error_code", "content_type", "content_encoding")

	addOne("http_headers", "audit_id", ClassDigest, "audit_id", noteKey)
	add("http_headers", ClassDigest, "headers.values[].", "stage", "kind", "name", "value_index")
	addOne("http_headers", "value_length", ClassDigest, "headers.values[].value", "the length of value, or length for a credential")
	addOne("http_headers", "value_enc", ClassDigest, "headers.values[].value", "projected value (D.3)")

	addOne("http_header_blocks", "audit_id", ClassDigest, "headers.block_present", "the row's existence")
	addOne("http_header_blocks", "block_enc", ClassDigest, "headers.values", "decoded into the flat list and headers.block_stages; the block plaintext is never archived")
	exclude("http_header_blocks", reasonStorageEncoding, "compression", "plaintext_length")

	addOne("body_streams", "audit_id", ClassDigest, "audit_id", noteKey)
	add("body_streams", ClassDigest, "body_streams[].",
		"stage", "source_stage", "observed_length", "stored_length", "sha256", "hash_complete",
		"eof_seen", "state", "retention_state", "first_observed_at_ns", "last_observed_at_ns",
		"chunk_count", "stream_event_count", "stream_timeline_complete", "error_code")

	addOne("body_chunks", "audit_id", ClassDigest, "audit_id", noteKey)
	add("body_chunks", ClassDigest, "raw_chunks[].", "stage", "seq", "offset", "plaintext_length", "observed_at_ns")
	addOne("body_chunks", "data_enc", ClassDigest, "raw_chunks[].sha256", "plaintext in objects:raw_chunk.data_b64; the digest covers its SHA-256")
	exclude("body_chunks", reasonStorageEncoding, "encoded_length", "compression")

	addOne("stream_timelines", "audit_id", ClassDigest, "audit_id", noteKey)
	add("stream_timelines", ClassDigest, "stream_timelines[].",
		"stage", "event_count", "first_event_at_ns", "last_event_at_ns", "timeline_complete", "plaintext_length")
	exclude("stream_timelines", reasonStorageEncoding, "compression")
	addOne("stream_timelines", "timeline_enc", ClassDigest, "stream_timelines[].timeline_b64", "the digest covers the plaintext's SHA-256")

	addOne("parsed_results", "audit_id", ClassDigest, "audit_id", noteKey)
	add("parsed_results", ClassDigest, "parsed_results.",
		"parser_name", "parser_version", "status", "request_model", "response_model",
		"requested_stream", "observed_stream", "response_id", "usage_input", "usage_output",
		"usage_total", "error_type", "error_code", "message_count", "tool_call_count", "has_tool_call")
	addOne("parsed_results", "parsed_json_enc", ClassDigest, "parsed_results.parsed_json", "decompressed JSON, or parsed_json_ref and objects:parsed_json_part over 1 MiB; the digest covers its SHA-256")
	add("parsed_results", ClassDigest, "parsed_results.", "parsed_at_ns", "upstream_error_class")

	addOne("token_links", "audit_id", ClassDigest, "audit_id", noteKey)
	add("token_links", ClassDigest, "token_links.",
		"newapi_user_id", "username", "newapi_token_id", "token_name", "linked_at_ns",
		"billing_state", "quota", "quota_per_unit", "billed_prompt_tokens",
		"billed_completion_tokens", "billing_attempts")

	addOne("turns", "turn_id", ClassDigest, "turn.turns.turn_id", "")
	addOne("turns", "audit_id", ClassDigest, "audit_id", noteKey)
	add("turns", ClassDigest, "turn.turns.",
		"conversation_id", "parent_turn_id", "parent_base", "link_reason", "link_confidence",
		"request_layout", "response_layout", "request_envelope_hash", "response_envelope_hash",
		"request_item_count", "response_item_count", "request_sequence_hash", "response_sequence_hash",
		"request_reconstruction_hash", "response_reconstruction_hash", "reconstruction_status",
		"previous_response_id", "response_id", "created_at_ns")

	addOne("turn_context_ops", "turn_id", ClassArchived, "turn.turns.turn_id", noteKey)
	for _, name := range []string{"op_index", "operation", "item_count", "slot", "object_hash", "semantic_hash"} {
		addOne("turn_context_ops", name, ClassArchived, "turn.request_context.ops[]."+name, noteContextOps)
	}

	addOne("turn_response_items", "turn_id", ClassDigest, "turn.turns.turn_id", noteKey)
	add("turn_response_items", ClassDigest, "turn.response_items[].", "ordinal", "slot", "object_hash", "semantic_hash")

	add("conversations", ClassDigest, "conversation.", "conversation_id", "protocol", "key_hash", "created_at_ns")
	exclude("conversations", reasonUpdatedAt, "updated_at_ns")

	add("content_objects", ClassDigest, "turn.objects[].", "object_hash", "semantic_hash")
	addOne("content_objects", "kind", ClassDigest, "turn.objects[].object_kind", "")
	exclude("content_objects", reasonStorageEncoding, "compression")
	add("content_objects", ClassDigest, "turn.objects[].", "plaintext_length")
	exclude("content_objects", reasonStorageEncoding, "encoded_length")
	addOne("content_objects", "data_enc", ClassArchived, "objects:content_object.data", "bound by object_hash, its content address")
	addOne("content_objects", "created_at_ns", ClassArchived, "objects:content_object.created_at_ns", "first write time, shared by every audit that references the object")

	add("binary_objects", ClassDigest, "turn.binaries[].", "binary_hash", "media_type")
	exclude("binary_objects", reasonStorageEncoding, "compression")
	add("binary_objects", ClassDigest, "turn.binaries[].", "plaintext_length")
	exclude("binary_objects", reasonStorageEncoding, "encoded_length")
	addOne("binary_objects", "data_enc", ClassArchived, "objects:binary_object.data_b64", "bound by binary_hash, its content address")
	addOne("binary_objects", "created_at_ns", ClassArchived, "objects:binary_object.created_at_ns", "first write time, shared by every audit that references the object")

	add("content_binary_refs", ClassDigest, "turn.binary_refs[].", "object_hash", "json_pointer", "binary_hash", "media_type", "encoding")

	add("content_external_refs", ClassDigest, "turn.external_refs[].", "object_hash", "json_pointer", "ref_kind", "value_hash")
	addOne("content_external_refs", "value_enc", ClassDigest, "turn.external_refs[].value", "the digest covers the plaintext's SHA-256")

	addOne("audit_project_identity", "audit_id", ClassDigest, "audit_id", noteKey)
	add("audit_project_identity", ClassDigest, "audit_project_identity.",
		"identity_version", "extracted_at_ns", "source", "body_scanned", "identity_fpr",
		"remote_fpr", "repo_root_fpr", "cwd_fpr")
	addOne("audit_project_identity", "identity_enc", ClassDigest, "audit_project_identity.identity", "the digest covers the plaintext's SHA-256")

	addOne("integrity_events", "sequence", ClassDigest, "integrity_events[].sequence", "")
	addOne("integrity_events", "audit_id", ClassDigest, "audit_id", noteKey)
	add("integrity_events", ClassDigest, "integrity_events[].",
		"event_type", "previous_mac", "payload_digest", "event_mac", "created_at_ns")

	add("audit_gaps", ClassArchived, "gaps:gap.",
		"id", "started_at_ns", "ended_at_ns", "reason", "request_count", "detail", "created_at_ns")
	return columns
}

// ManifestTables returns the manifest's tables field (F.1): for every
// archived table, its archived columns (digest or archived class) in
// specification order.
func ManifestTables() map[string][]string {
	tables := make(map[string][]string, len(ArchivedTables))
	for _, column := range Columns {
		if column.Class == ClassExcluded {
			continue
		}
		tables[column.Table] = append(tables[column.Table], column.Name)
	}
	return tables
}

// ForeignKey is one foreign key: Table references References.
type ForeignKey struct {
	Table      string
	References string
}

// Schema is the part of a database schema the coverage check reads: the
// columns of every table and every foreign key.
type Schema struct {
	Columns     map[string][]string
	ForeignKeys []ForeignKey
}

// ErrCoverage reports a schema the column specification does not cover.
var ErrCoverage = errors.New("archive: column specification does not cover the schema")

// CheckSpecification checks that the specification is internally
// consistent: known tables only, every archived table present, no duplicate
// column, a valid class, a field for every archived column, a reason for
// every excluded one.
func CheckSpecification() error {
	return checkSpecification(Columns)
}

func checkSpecification(columns []Column) error {
	archived := make(map[string]bool, len(ArchivedTables))
	for _, table := range ArchivedTables {
		archived[table] = true
	}
	seen := make(map[string]bool, len(columns))
	tables := make(map[string]bool)
	var problems []string
	for _, column := range columns {
		key := column.Table + "." + column.Name
		switch {
		case !archived[column.Table]:
			problems = append(problems, key+": table is not an archived table")
		case seen[key]:
			problems = append(problems, key+": listed twice")
		}
		seen[key] = true
		tables[column.Table] = true
		switch column.Class {
		case ClassDigest, ClassArchived:
			if column.Field == "" {
				problems = append(problems, key+": archived without a field")
			}
		case ClassExcluded:
			if strings.TrimSpace(column.Reason) == "" || column.Field != "" {
				problems = append(problems, key+": excluded needs a reason and no field")
			}
		default:
			problems = append(problems, key+": unknown class "+string(column.Class))
		}
	}
	for _, table := range ArchivedTables {
		if !tables[table] {
			problems = append(problems, table+": archived table without columns")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrCoverage, strings.Join(problems, "; "))
	}
	return nil
}

// CheckSchema compares a database schema with the specification (J.1): a
// column an archived table has and the specification lacks, or the reverse,
// and a table that references a root table directly or through other tables
// but is neither archived nor derived, each produce one problem naming
// "table.column" or the table. The PostgreSQL coverage test calls it with
// the schema read from information_schema and pg_constraint.
func CheckSchema(schema Schema) error {
	if err := CheckSpecification(); err != nil {
		return err
	}
	var problems []string
	specified := make(map[string]map[string]bool)
	for _, column := range Columns {
		if specified[column.Table] == nil {
			specified[column.Table] = make(map[string]bool)
		}
		specified[column.Table][column.Name] = true
	}
	for _, table := range ArchivedTables {
		actual, ok := schema.Columns[table]
		if !ok {
			problems = append(problems, table+": archived table missing from the schema")
			continue
		}
		present := make(map[string]bool, len(actual))
		for _, name := range actual {
			present[name] = true
			if !specified[table][name] {
				problems = append(problems, table+"."+name+": column not in the specification")
			}
		}
		for name := range specified[table] {
			if !present[name] {
				problems = append(problems, table+"."+name+": specified column missing from the schema")
			}
		}
	}
	allowed := make(map[string]bool)
	for _, table := range append(slices.Clone(ArchivedTables), DerivedTables...) {
		allowed[table] = true
	}
	for _, table := range ReferringTables(schema.ForeignKeys) {
		if !allowed[table] {
			problems = append(problems, table+": references an archived table but is neither archived nor derived")
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w: %s", ErrCoverage, strings.Join(problems, "; "))
	}
	return nil
}

// ReferringTables returns, sorted, every table that references a root table
// directly or through a chain of foreign keys. A root table that references
// another root table is included.
func ReferringTables(foreignKeys []ForeignKey) []string {
	closure := make(map[string]bool)
	for _, root := range RootTables {
		closure[root] = true
	}
	referring := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for _, key := range foreignKeys {
			if closure[key.References] && key.Table != key.References && !referring[key.Table] {
				referring[key.Table] = true
				closure[key.Table] = true
				changed = true
			}
		}
	}
	tables := make([]string, 0, len(referring))
	for table := range referring {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables
}
